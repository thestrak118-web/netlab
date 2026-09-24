"""Read-only monospace detail pane used by the protocol pages."""

from __future__ import annotations

from PySide6.QtWidgets import QPlainTextEdit


class DetailPane(QPlainTextEdit):
    def __init__(self, placeholder: str, parent=None) -> None:
        super().__init__(parent)
        self.setObjectName("Mono")
        self.setReadOnly(True)
        self.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self._placeholder = placeholder
        self.clear_detail()

    def clear_detail(self) -> None:
        self.setPlainText(self._placeholder)

    def show_lines(self, lines) -> None:
        self.setPlainText("\n".join(lines))


def kv(label: str, value, width: int = 22) -> str:
    from netlab.util.format import DASH
    text = DASH if value is None or value == "" else str(value)
    return "  %-*s %s" % (width, label, text)
