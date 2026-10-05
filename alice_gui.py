"""Launch Alice's real Stage 13 secure TCP chat GUI."""

from __future__ import annotations

import tkinter as tk

from gui_backend import AliceGUIBackend
from gui_common import SecureChatGUI


def main() -> None:
    root = tk.Tk()
    SecureChatGUI(
        root=root,
        role_name="Alice",
        peer_name="Bob",
        start_button_text="Start Alice Server",
        backend_factory=lambda callback: AliceGUIBackend(callback=callback),
    )
    root.mainloop()


if __name__ == "__main__":
    main()
