"""Launch Bob's real Stage 13 secure TCP chat GUI."""

from __future__ import annotations

import tkinter as tk

from gui_backend import BobGUIBackend
from gui_common import SecureChatGUI


def main() -> None:
    root = tk.Tk()
    SecureChatGUI(
        root=root,
        role_name="Bob",
        peer_name="Alice",
        start_button_text="Connect to Alice",
        backend_factory=lambda callback: BobGUIBackend(callback=callback),
    )
    root.mainloop()


if __name__ == "__main__":
    main()
