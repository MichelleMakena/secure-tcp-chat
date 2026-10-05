"""
Stage 13 hardened Tkinter interface with persistent logging and graceful shutdown.

Unlike Stage 12A, this version is connected to a real backend.  The backend
performs RSA, AES-GCM, TCP and file operations in worker threads and reports
results through a thread-safe event queue.  Tkinter widgets are modified only
by the main GUI thread.
"""

from __future__ import annotations

import os
import queue
import subprocess
import sys
import threading
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Optional, Protocol

import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from tkinter.scrolledtext import ScrolledText


class GUIBackend(Protocol):
    """Operations required by the reusable GUI."""

    def start(self) -> None: ...

    def send_chat(self, plaintext: str) -> None: ...

    def send_file(self, file_path: str | Path) -> None: ...

    def disconnect(self, reason: str) -> None: ...

    def close(self, notify: bool = False) -> None: ...

    def report_exception(self, context: str, error: BaseException, notify: bool = True) -> None: ...

    log_path: Path


BackendFactory = Callable[[Callable[[str, dict[str, Any]], None]], GUIBackend]


@dataclass(frozen=True)
class GUIEvent:
    """One event transferred safely from a worker to Tkinter."""

    event_type: str
    payload: dict[str, Any]


class SecureChatGUI:
    """Real encrypted chat and file-transfer graphical interface."""

    QUEUE_POLL_INTERVAL_MS = 75

    def __init__(
        self,
        root: tk.Tk,
        role_name: str,
        peer_name: str,
        start_button_text: str,
        backend_factory: BackendFactory,
    ) -> None:
        self.root = root
        self.role_name = role_name
        self.peer_name = peer_name
        self.start_button_text = start_button_text

        self.ui_queue: queue.Queue[GUIEvent] = queue.Queue()
        self.stop_event = threading.Event()

        self.connection_thread: Optional[threading.Thread] = None
        self.message_thread: Optional[threading.Thread] = None
        self.file_thread: Optional[threading.Thread] = None
        self.disconnect_thread: Optional[threading.Thread] = None
        self.close_thread: Optional[threading.Thread] = None

        self.is_connected = False
        self.secure_session_ready = False
        self.selected_file: Optional[Path] = None
        self.closing = False

        self.connection_status = tk.StringVar(value="Disconnected")
        self.security_status = tk.StringVar(value="Secure session not established")
        self.selected_file_status = tk.StringVar(value="No file selected")

        self.backend = backend_factory(self._backend_callback)

        self._configure_window()
        self._build_interface()
        self._set_controls_for_disconnected_state()

        self.root.protocol("WM_DELETE_WINDOW", self.close_application)
        self.root.after(self.QUEUE_POLL_INTERVAL_MS, self._process_ui_queue)

        self._append_log("Stage 13 hardened GUI initialised.")
        self._append_log("Real RSA/AES/TCP operations use background threads and a thread-safe GUI queue.")
        self._append_log(f"Persistent rotating audit log: {self.backend.log_path}")

    # ------------------------------------------------------------------
    # Window construction
    # ------------------------------------------------------------------

    def _configure_window(self) -> None:
        self.root.title(f"{self.role_name} — Secure TCP Chat")

        try:
            self.root.state("zoomed")
        except tk.TclError:
            width = min(1100, self.root.winfo_screenwidth() - 80)
            height = min(780, self.root.winfo_screenheight() - 100)
            self.root.geometry(f"{width}x{height}")

        self.root.minsize(780, 600)
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(1, weight=1)

        style = ttk.Style()
        try:
            style.theme_use("vista")
        except tk.TclError:
            pass

        style.configure("Title.TLabel", font=("Segoe UI", 17, "bold"))
        style.configure("Heading.TLabel", font=("Segoe UI", 10, "bold"))
        style.configure("Status.TLabel", font=("Segoe UI", 10))

    def _build_interface(self) -> None:
        self._build_header()
        self._build_main_area()
        self._build_footer()

    def _build_header(self) -> None:
        header = ttk.Frame(self.root, padding=(15, 12))
        header.grid(row=0, column=0, sticky="ew")
        header.columnconfigure(0, weight=1)

        ttk.Label(
            header,
            text=f"{self.role_name}'s Secure TCP Chat Application",
            style="Title.TLabel",
        ).grid(row=0, column=0, sticky="w")

        ttk.Label(
            header,
            text="RSA-2048 OAEP-SHA-256 | AES-256-GCM | Length-prefixed TCP",
        ).grid(row=1, column=0, sticky="w", pady=(3, 10))

        status_frame = ttk.LabelFrame(header, text="Session Status", padding=10)
        status_frame.grid(row=2, column=0, sticky="ew")
        status_frame.columnconfigure(1, weight=1)

        ttk.Label(status_frame, text="TCP status:", style="Heading.TLabel").grid(
            row=0, column=0, sticky="w", padx=(0, 8)
        )
        ttk.Label(
            status_frame,
            textvariable=self.connection_status,
            style="Status.TLabel",
        ).grid(row=0, column=1, sticky="w")

        ttk.Label(
            status_frame,
            text="Cryptographic status:",
            style="Heading.TLabel",
        ).grid(row=1, column=0, sticky="w", padx=(0, 8), pady=(6, 0))
        ttk.Label(
            status_frame,
            textvariable=self.security_status,
            style="Status.TLabel",
        ).grid(row=1, column=1, sticky="w", pady=(6, 0))

        self.progress_bar = ttk.Progressbar(status_frame, mode="determinate", maximum=100)
        self.progress_bar.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(10, 0))

    def _build_main_area(self) -> None:
        main = ttk.Panedwindow(self.root, orient=tk.VERTICAL)
        main.grid(row=1, column=0, sticky="nsew", padx=15, pady=(0, 10))

        chat_frame = ttk.LabelFrame(main, text="Encrypted Conversation", padding=10)
        log_frame = ttk.LabelFrame(main, text="Security and Session Log", padding=10)
        main.add(chat_frame, weight=3)
        main.add(log_frame, weight=2)

        chat_frame.columnconfigure(0, weight=1)
        chat_frame.rowconfigure(0, weight=1)
        self.chat_display = ScrolledText(
            chat_frame,
            wrap=tk.WORD,
            state=tk.DISABLED,
            font=("Segoe UI", 10),
            height=14,
        )
        self.chat_display.grid(row=0, column=0, sticky="nsew")
        self.chat_display.tag_configure(
            "local",
            justify="right",
            lmargin1=180,
            lmargin2=180,
            rmargin=10,
            spacing1=5,
            spacing3=8,
        )
        self.chat_display.tag_configure(
            "remote",
            justify="left",
            lmargin1=10,
            lmargin2=10,
            rmargin=180,
            spacing1=5,
            spacing3=8,
        )

        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)
        self.security_log = ScrolledText(
            log_frame,
            wrap=tk.WORD,
            state=tk.DISABLED,
            font=("Consolas", 9),
            height=10,
        )
        self.security_log.grid(row=0, column=0, sticky="nsew")

    def _build_footer(self) -> None:
        footer = ttk.Frame(self.root, padding=(15, 0, 15, 15))
        footer.grid(row=2, column=0, sticky="ew")
        footer.columnconfigure(0, weight=1)

        message_frame = ttk.LabelFrame(footer, text="Secure Message", padding=10)
        message_frame.grid(row=0, column=0, sticky="ew")
        message_frame.columnconfigure(0, weight=1)

        self.message_entry = ttk.Entry(message_frame, font=("Segoe UI", 10))
        self.message_entry.grid(row=0, column=0, sticky="ew", padx=(0, 8))
        self.message_entry.bind("<Return>", lambda _event: self.send_message())

        self.send_button = ttk.Button(
            message_frame,
            text="Send Encrypted Message",
            command=self.send_message,
        )
        self.send_button.grid(row=0, column=1)

        file_frame = ttk.Frame(footer)
        file_frame.grid(row=1, column=0, sticky="ew", pady=(10, 0))
        file_frame.columnconfigure(1, weight=1)

        self.file_button = ttk.Button(
            file_frame,
            text="Select and Send File",
            command=self.select_file,
        )
        self.file_button.grid(row=0, column=0, padx=(0, 10))
        ttk.Label(file_frame, textvariable=self.selected_file_status).grid(
            row=0, column=1, sticky="w"
        )

        session_frame = ttk.Frame(footer)
        session_frame.grid(row=2, column=0, sticky="ew", pady=(12, 0))

        self.start_button = ttk.Button(
            session_frame,
            text=self.start_button_text,
            command=self.start_connection_workflow,
        )
        self.start_button.pack(side=tk.LEFT)

        self.disconnect_button = ttk.Button(
            session_frame,
            text="Disconnect Secure Session",
            command=self.disconnect_session,
        )
        self.disconnect_button.pack(side=tk.LEFT, padx=(10, 0))

        self.clear_log_button = ttk.Button(
            session_frame,
            text="Clear Visible Log",
            command=self.clear_log,
        )
        self.clear_log_button.pack(side=tk.RIGHT)

        self.open_log_button = ttk.Button(
            session_frame,
            text="Open Log Folder",
            command=self.open_log_folder,
        )
        self.open_log_button.pack(side=tk.RIGHT, padx=(0, 10))

    # ------------------------------------------------------------------
    # Backend callback and worker launchers
    # ------------------------------------------------------------------

    def _backend_callback(self, event_type: str, payload: dict[str, Any]) -> None:
        """Called by backend threads; never updates widgets directly."""
        self.ui_queue.put(GUIEvent(event_type=event_type, payload=payload))

    def start_connection_workflow(self) -> None:
        if self.connection_thread is not None and self.connection_thread.is_alive():
            return

        self.stop_event.clear()
        self.start_button.configure(state=tk.DISABLED)
        self.connection_status.set("Starting secure connection workflow...")
        self.security_status.set("RSA/AES key exchange in progress")
        self.progress_bar.configure(value=0)

        self.connection_thread = threading.Thread(
            target=self._start_backend_worker,
            name=f"{self.role_name}-start-worker",
            daemon=True,
        )
        self.connection_thread.start()

    def _start_backend_worker(self) -> None:
        try:
            self.backend.start()
        except Exception:
            # The backend already reports the detailed failure through the queue.
            pass

    def send_message(self) -> None:
        if not self.secure_session_ready:
            messagebox.showwarning(
                "Secure Session Required",
                "Establish the secure session before sending a message.",
            )
            return

        message = self.message_entry.get().strip()
        if not message:
            messagebox.showwarning("Empty Message", "Enter a message before selecting Send.")
            return
        if len(message.encode("utf-8")) > 64 * 1024:
            messagebox.showerror("Message Too Large", "The message exceeds the permitted size.")
            return
        if self.message_thread is not None and self.message_thread.is_alive():
            messagebox.showinfo("Message Pending", "Wait for the current message to be sent.")
            return

        self.message_entry.delete(0, tk.END)
        self.send_button.configure(state=tk.DISABLED)
        self.message_thread = threading.Thread(
            target=self._send_message_worker,
            args=(message,),
            name=f"{self.role_name}-message-worker",
            daemon=True,
        )
        self.message_thread.start()

    def _send_message_worker(self, message: str) -> None:
        try:
            self.backend.send_chat(message)
        except Exception as error:
            self.backend.report_exception("Message-sending worker failed", error)
        finally:
            self._backend_callback("message_worker_finished", {})

    def select_file(self) -> None:
        if not self.secure_session_ready:
            messagebox.showwarning(
                "Secure Session Required",
                "Establish the secure session before selecting a file.",
            )
            return
        if self.file_thread is not None and self.file_thread.is_alive():
            messagebox.showinfo("Transfer Active", "Wait for the current file transfer to finish.")
            return

        selected = filedialog.askopenfilename(title=f"Select file to send to {self.peer_name}")
        if not selected:
            return

        file_path = Path(selected)
        if not file_path.is_file():
            messagebox.showerror("Invalid File", "The selected path is not a readable file.")
            return

        self.selected_file = file_path
        self.selected_file_status.set(f"Selected: {file_path.name}")
        self.file_button.configure(state=tk.DISABLED)
        self.progress_bar.configure(value=0)

        self.file_thread = threading.Thread(
            target=self._send_file_worker,
            args=(file_path,),
            name=f"{self.role_name}-file-worker",
            daemon=True,
        )
        self.file_thread.start()

    def _send_file_worker(self, file_path: Path) -> None:
        try:
            self.backend.send_file(file_path)
        except Exception as error:
            self.backend.report_exception("File-transfer worker failed", error)
        finally:
            self._backend_callback("file_worker_finished", {})

    def disconnect_session(self) -> None:
        if self.disconnect_thread is not None and self.disconnect_thread.is_alive():
            return
        if not self.is_connected:
            return

        self.disconnect_button.configure(state=tk.DISABLED)
        self.connection_status.set("Disconnecting secure session...")
        self.disconnect_thread = threading.Thread(
            target=self._disconnect_worker,
            name=f"{self.role_name}-disconnect-worker",
            daemon=True,
        )
        self.disconnect_thread.start()

    def _disconnect_worker(self) -> None:
        try:
            self.backend.disconnect(f"{self.role_name} ended the Stage 13 GUI session.")
        except Exception as error:
            self.backend.report_exception("Disconnect worker failed", error)

    # ------------------------------------------------------------------
    # Tkinter event processing
    # ------------------------------------------------------------------

    def _process_ui_queue(self) -> None:
        try:
            while True:
                event = self.ui_queue.get_nowait()
                self._handle_ui_event(event)
        except queue.Empty:
            pass

        try:
            if self.root.winfo_exists():
                self.root.after(self.QUEUE_POLL_INTERVAL_MS, self._process_ui_queue)
        except tk.TclError:
            pass

    def _handle_ui_event(self, event: GUIEvent) -> None:
        payload = event.payload
        event_type = event.event_type

        if event_type == "status":
            self.connection_status.set(str(payload.get("message", "Working...")))
            if payload.get("progress") is not None:
                self.progress_bar.configure(value=float(payload["progress"]))

        elif event_type == "log":
            self._append_log(str(payload.get("message", "")))

        elif event_type == "connected":
            self.is_connected = True
            self.secure_session_ready = True
            self.connection_status.set(f"Connected to {self.peer_name}")
            self.security_status.set("AES-256-GCM secure session ready")
            self.progress_bar.configure(value=100)
            self._append_log(str(payload.get("message", "Secure session ready.")))
            if payload.get("session_id"):
                self._append_log(f"Session identifier: {payload['session_id']}")
            self._set_controls_for_connected_state()
            self.message_entry.focus_set()

        elif event_type == "chat":
            sender = str(payload.get("sender", self.peer_name))
            message = str(payload.get("message", ""))
            local = bool(payload.get("local", sender == self.role_name))
            self._append_chat_message(sender=sender, message=message, local=local)

        elif event_type == "file_started":
            file_name = str(payload.get("file_name", "file"))
            sender = str(payload.get("sender", self.peer_name))
            self.selected_file_status.set(f"Receiving from {sender}: {file_name}")
            self.progress_bar.configure(value=0)
            self._append_log(str(payload.get("message", f"Receiving {file_name}.")))

        elif event_type == "file_progress":
            if payload.get("progress") is not None:
                self.progress_bar.configure(value=float(payload["progress"]))
            if payload.get("message"):
                self.connection_status.set(str(payload["message"]))

        elif event_type == "file_sent":
            self.progress_bar.configure(value=100)
            self.connection_status.set(f"Connected to {self.peer_name}")
            self.selected_file_status.set(str(payload.get("message", "File sent successfully.")))
            self._append_log(str(payload.get("message", "File sent successfully.")))
            if self.secure_session_ready:
                self.file_button.configure(state=tk.NORMAL)

        elif event_type == "file_received":
            self.progress_bar.configure(value=100)
            self.connection_status.set(f"Connected to {self.peer_name}")
            message = str(payload.get("message", "Verified file received."))
            path = str(payload.get("path", ""))
            self.selected_file_status.set(message)
            self._append_log(message)
            if path:
                self._append_log(f"Saved verified file: {path}")
                messagebox.showinfo("Encrypted File Received", f"{message}\n\nSaved to:\n{path}")

        elif event_type == "message_worker_finished":
            if self.secure_session_ready:
                self.send_button.configure(state=tk.NORMAL)

        elif event_type == "file_worker_finished":
            if self.secure_session_ready:
                self.file_button.configure(state=tk.NORMAL)
            self.connection_status.set(
                f"Connected to {self.peer_name}" if self.secure_session_ready else "Disconnected"
            )

        elif event_type == "disconnected":
            self.is_connected = False
            self.secure_session_ready = False
            self.connection_status.set("Disconnected")
            self.security_status.set("Secure session not established")
            self.progress_bar.configure(value=0)
            self._append_log(str(payload.get("message", "Secure session disconnected safely.")))
            self._set_controls_for_disconnected_state()

        elif event_type == "warning":
            message = str(payload.get("message", "Secure-chat warning."))
            self._append_log(f"WARNING: {message}")
            if not self.closing:
                messagebox.showwarning("Secure Chat Warning", message)

        elif event_type == "error":
            message = str(payload.get("message", "Unknown secure-chat error."))
            self._append_log(f"ERROR: {message}")
            if not self.closing:
                messagebox.showerror("Secure Chat Error", message)
            if not self.secure_session_ready:
                self._set_controls_for_disconnected_state()

    # ------------------------------------------------------------------
    # Display helpers and controls
    # ------------------------------------------------------------------

    def _append_chat_message(self, sender: str, message: str, local: bool) -> None:
        timestamp = datetime.now().strftime("%H:%M:%S")
        display_text = f"{sender} — {timestamp}\n{message}\n\n"
        self.chat_display.configure(state=tk.NORMAL)
        self.chat_display.insert(tk.END, display_text, "local" if local else "remote")
        self.chat_display.configure(state=tk.DISABLED)
        self.chat_display.see(tk.END)

    def _append_log(self, message: str) -> None:
        if not message:
            return
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.security_log.configure(state=tk.NORMAL)
        self.security_log.insert(tk.END, f"[{timestamp}] [{self.role_name}] {message}\n")
        self.security_log.configure(state=tk.DISABLED)
        self.security_log.see(tk.END)

    def clear_log(self) -> None:
        """Clear only the on-screen view; the persistent audit log remains."""
        self.security_log.configure(state=tk.NORMAL)
        self.security_log.delete("1.0", tk.END)
        self.security_log.configure(state=tk.DISABLED)
        self._append_log("Visible security log cleared; persistent audit log retained.")

    def open_log_folder(self) -> None:
        """Open the folder containing Alice's or Bob's rotating log files."""
        folder = Path(self.backend.log_path).resolve().parent
        try:
            if sys.platform.startswith("win"):
                os.startfile(folder)  # type: ignore[attr-defined]
            elif sys.platform == "darwin":
                subprocess.Popen(["open", str(folder)])
            else:
                subprocess.Popen(["xdg-open", str(folder)])
        except Exception as error:
            self.backend.report_exception("Unable to open the log folder", error)

    def _set_controls_for_disconnected_state(self) -> None:
        self.start_button.configure(state=tk.NORMAL)
        self.send_button.configure(state=tk.DISABLED)
        self.file_button.configure(state=tk.DISABLED)
        self.disconnect_button.configure(state=tk.DISABLED)
        self.message_entry.configure(state=tk.DISABLED)

    def _set_controls_for_connected_state(self) -> None:
        self.start_button.configure(state=tk.DISABLED)
        self.send_button.configure(state=tk.NORMAL)
        self.file_button.configure(state=tk.NORMAL)
        self.disconnect_button.configure(state=tk.NORMAL)
        self.message_entry.configure(state=tk.NORMAL)

    def close_application(self) -> None:
        """Close through a worker so DISCONNECT/ACK cannot freeze Tkinter."""
        if self.closing:
            return

        should_close = messagebox.askyesno(
            "Close Secure Chat",
            f"Do you want to close {self.role_name}'s application?",
        )
        if not should_close:
            return

        self.closing = True
        self.stop_event.set()
        self.start_button.configure(state=tk.DISABLED)
        self.send_button.configure(state=tk.DISABLED)
        self.file_button.configure(state=tk.DISABLED)
        self.disconnect_button.configure(state=tk.DISABLED)
        self.connection_status.set("Closing securely...")

        self.close_thread = threading.Thread(
            target=self._close_backend_worker,
            name=f"{self.role_name}-close-worker",
            daemon=True,
        )
        self.close_thread.start()
        self.root.after(100, self._poll_close_worker)

    def _close_backend_worker(self) -> None:
        try:
            if self.is_connected:
                self.backend.disconnect(f"{self.role_name} closed the Stage 13 GUI window.")
            else:
                self.backend.close(notify=False)
        except Exception as error:
            self.backend.report_exception("GUI shutdown worker failed", error, notify=False)
            try:
                self.backend.close(notify=False)
            except Exception:
                pass

    def _poll_close_worker(self) -> None:
        if self.close_thread is not None and self.close_thread.is_alive():
            self.root.after(100, self._poll_close_worker)
            return
        try:
            self.root.destroy()
        except tk.TclError:
            pass
