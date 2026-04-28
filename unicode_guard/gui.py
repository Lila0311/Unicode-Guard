"""Tkinter GUI for local Unicode attack review."""

from __future__ import annotations

import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from .scanner import format_text_report, scan_path, scan_text


class UnicodeGuardApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Unicode Guard")
        self.geometry("1100x720")
        self.minsize(900, 560)
        self._build()

    def _build(self) -> None:
        toolbar = ttk.Frame(self, padding=(8, 8, 8, 4))
        toolbar.pack(fill=tk.X)

        ttk.Button(toolbar, text="Open File", command=self.open_file).pack(side=tk.LEFT)
        ttk.Button(toolbar, text="Scan Text", command=self.scan_current_text).pack(side=tk.LEFT, padx=(8, 0))
        ttk.Button(toolbar, text="Save Clean Copy", command=self.save_clean_copy).pack(side=tk.LEFT, padx=(8, 0))

        self.status = ttk.Label(toolbar, text="Ready")
        self.status.pack(side=tk.RIGHT)

        panes = ttk.PanedWindow(self, orient=tk.HORIZONTAL)
        panes.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        text_frame = ttk.Frame(panes)
        result_frame = ttk.Frame(panes)
        panes.add(text_frame, weight=3)
        panes.add(result_frame, weight=2)

        self.text = tk.Text(text_frame, wrap=tk.NONE, undo=True)
        self.text.pack(fill=tk.BOTH, expand=True)

        self.results = tk.Text(result_frame, wrap=tk.WORD, state=tk.DISABLED)
        self.results.pack(fill=tk.BOTH, expand=True)

        self.current_path: Path | None = None
        self.clean_text = ""

    def open_file(self) -> None:
        selected = filedialog.askopenfilename(title="Open source file")
        if not selected:
            return
        path = Path(selected)
        data = path.read_text(encoding="utf-8", errors="replace")
        self.current_path = path
        self.text.delete("1.0", tk.END)
        self.text.insert("1.0", data)
        self.scan_current_text()

    def scan_current_text(self) -> None:
        content = self.text.get("1.0", tk.END)
        path = str(self.current_path) if self.current_path else "<editor>"
        report = scan_text(content, path)
        self.clean_text = report.clean_text or ""
        self._set_results(format_text_report([report]))
        self.status.config(text="PASS" if report.passed else f"FAIL {report.summary}")

    def save_clean_copy(self) -> None:
        if not self.clean_text:
            self.scan_current_text()
        selected = filedialog.asksaveasfilename(
            title="Save cleaned copy",
            initialfile=(self.current_path.name + ".clean" if self.current_path else "cleaned_source.txt"),
        )
        if not selected:
            return
        Path(selected).write_text(self.clean_text, encoding="utf-8")
        messagebox.showinfo("Unicode Guard", "Clean copy saved.")

    def _set_results(self, value: str) -> None:
        self.results.config(state=tk.NORMAL)
        self.results.delete("1.0", tk.END)
        self.results.insert("1.0", value)
        self.results.config(state=tk.DISABLED)


def main() -> None:
    UnicodeGuardApp().mainloop()


if __name__ == "__main__":
    main()
