"""Dark analyst theme."""

from __future__ import annotations

BG = "#12151a"
PANEL = "#181c23"
PANEL_ALT = "#1e232c"
BORDER = "#2a313c"
TEXT = "#dfe4ec"
MUTED = "#8b94a4"
ACCENT = "#4f8cff"
GREEN = "#32d296"
AMBER = "#f0a020"
RED = "#f0506e"
PURPLE = "#b58cff"
CYAN = "#3fd2d8"

PROTO_COLORS = {
    "TCP": "#6fa8ff",
    "UDP": "#3fd2d8",
    "DNS": "#b58cff",
    "mDNS": "#9f7ce8",
    "LLMNR": "#9f7ce8",
    "TLS": "#32d296",
    "HTTP": "#f0a020",
    "ICMP": "#f0506e",
    "ICMPv6": "#f0506e",
    "ARP": "#d7a3ff",
    "MALFORMED": "#f0506e",
}

STYLESHEET = f"""
QWidget {{
    background: {BG};
    color: {TEXT};
    font-family: "Inter", "Cantarell", "DejaVu Sans", sans-serif;
    font-size: 13px;
}}
QMainWindow, QDialog {{ background: {BG}; }}

/* Labels and checkboxes must not paint the window background over the
   panel they sit on, or cards and banners show dark bands. */
QLabel, QCheckBox, QRadioButton {{ background: transparent; }}
QGroupBox {{
    border: 1px solid {BORDER};
    border-radius: 8px;
    margin-top: 14px;
    padding: 14px 12px 12px 12px;
    font-weight: 600;
}}
QGroupBox::title {{
    subcontrol-origin: margin;
    left: 12px;
    padding: 0 6px;
    color: {MUTED};
}}

#Sidebar {{
    background: {PANEL};
    border-right: 1px solid {BORDER};
}}
#Sidebar QListWidget {{
    background: transparent;
    border: none;
    outline: none;
    padding: 6px 4px;
}}
#Sidebar QListWidget::item {{
    padding: 9px 14px;
    margin: 1px 6px;
    border-radius: 6px;
    color: {MUTED};
}}
#Sidebar QListWidget::item:selected {{
    background: {ACCENT};
    color: #ffffff;
    font-weight: 600;
}}
#Sidebar QListWidget::item:hover:!selected {{
    background: {PANEL_ALT};
    color: {TEXT};
}}
/* Grouped mode navigation (Intercepter-NG-style sections). Header rows are
   made non-selectable in code and coloured there; leaves style like the old
   flat nav. */
#NavTree {{
    background: transparent;
    border: none;
    outline: none;
    padding: 4px 4px 10px 4px;
}}
#NavTree::branch {{ background: transparent; }}
#NavTree::item {{
    padding: 7px 14px;
    margin: 1px 6px;
    border-radius: 6px;
    color: {MUTED};
}}
#NavTree::item:selected {{
    background: {ACCENT};
    color: #ffffff;
    font-weight: 600;
}}
#NavTree::item:hover:!selected {{
    background: {PANEL_ALT};
    color: {TEXT};
}}
#BrandLabel {{
    font-size: 17px;
    font-weight: 700;
    color: {TEXT};
    padding: 16px 16px 2px 16px;
}}
#BrandSub {{
    color: {MUTED};
    font-size: 11px;
    padding: 0 16px 12px 16px;
}}

/* Intercepter-NG-style top navigation: mode tabs, then a thinner page row. */
#ModeRow {{ background: {PANEL}; }}
#PageRow {{ background: {BG}; border-bottom: 1px solid {BORDER}; }}
/* Intercepter-NG-style mode strip: big icons, the active mode lit up with a
   filled tile rather than a thin underline. */
QTabBar#ModeBar {{ qproperty-drawBase: 0; qproperty-iconSize: 26px; }}
QTabBar#ModeBar::tab {{
    background: transparent;
    color: {MUTED};
    padding: 9px 18px;
    margin: 3px 3px;
    border: 1px solid transparent;
    border-radius: 8px;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 0.6px;
    min-width: 64px;
}}
QTabBar#ModeBar::tab:selected {{
    color: #eafff5;
    background: {ACCENT};
    border: 1px solid {ACCENT};
}}
QTabBar#ModeBar::tab:hover:!selected {{
    color: {TEXT};
    background: {PANEL_ALT};
}}
QTabBar#PageBar::tab {{
    background: transparent;
    color: {MUTED};
    padding: 5px 12px;
    margin: 2px 2px;
    border: 1px solid transparent;
    border-radius: 6px;
    font-size: 12px;
}}
QTabBar#PageBar::tab:selected {{
    background: {ACCENT};
    color: #ffffff;
}}
QTabBar#PageBar::tab:hover:!selected {{
    background: {PANEL_ALT};
    color: {TEXT};
}}

#Toolbar {{
    background: {PANEL};
    border-bottom: 1px solid {BORDER};
}}
#ToolbarSep {{
    color: {BORDER};
    max-width: 1px;
    margin: 2px 4px;
}}

QLabel#PageTitle {{ font-size: 19px; font-weight: 700; padding: 2px 0; }}
QLabel#PacketTally {{
    color: {GREEN}; font-family: "DejaVu Sans Mono", monospace;
    font-weight: 700; padding: 0 10px;
}}
QLabel#PageHint  {{ color: {MUTED}; font-size: 12px; }}
QLabel#SectionTitle {{ font-size: 14px; font-weight: 600; padding: 4px 0; }}

QFrame#Card {{
    background: {PANEL};
    border: 1px solid {BORDER};
    border-radius: 8px;
}}
QLabel#CardValue {{ font-size: 22px; font-weight: 700; }}
QLabel#CardLabel {{ color: {MUTED}; font-size: 11px; text-transform: uppercase;
                    letter-spacing: 0.6px; }}
QLabel#CardNote  {{ color: {MUTED}; font-size: 11px; }}

QPushButton {{
    background: {PANEL_ALT};
    border: 1px solid {BORDER};
    border-radius: 6px;
    padding: 7px 14px;
    color: {TEXT};
}}
QPushButton:hover  {{ background: #262d38; }}
QPushButton:pressed {{ background: #2f3743; }}
QPushButton:disabled {{ color: #5a626f; background: #171a20; }}
QPushButton#Primary {{
    background: {ACCENT}; border-color: {ACCENT}; color: #ffffff; font-weight: 600;
}}
QPushButton#Primary:hover {{ background: #6c9dff; }}
QPushButton#Danger {{
    background: {RED}; border-color: {RED}; color: #ffffff; font-weight: 600;
}}
QPushButton#Danger:hover {{ background: #f36a85; }}
/* Drill-down back button: quiet, no fill, so it reads as navigation. */
QPushButton#BackButton {{
    background: transparent; border: none; color: {MUTED};
    font-weight: 600; padding: 2px 8px;
}}
QPushButton#BackButton:hover {{ color: {ACCENT}; background: transparent; }}
/* These must come after the #Primary/#Danger rules: an id selector wins over
   the plain QPushButton:disabled rule, so disabled accent buttons would
   otherwise still look clickable. */
QPushButton#Primary:disabled, QPushButton#Danger:disabled {{
    background: #171a20; border-color: {BORDER}; color: #5a626f;
}}

QSpinBox::up-button, QSpinBox::down-button {{
    background: {BORDER};
    border: none;
    width: 16px;
    margin: 1px;
    border-radius: 3px;
}}
QSpinBox::up-button:hover, QSpinBox::down-button:hover {{ background: #46505f; }}
QSpinBox::up-arrow {{
    image: none; width: 0; height: 0;
    border-left: 4px solid transparent; border-right: 4px solid transparent;
    border-bottom: 5px solid {TEXT};
}}
QSpinBox::down-arrow {{
    image: none; width: 0; height: 0;
    border-left: 4px solid transparent; border-right: 4px solid transparent;
    border-top: 5px solid {TEXT};
}}

QLineEdit, QComboBox, QSpinBox, QPlainTextEdit, QTextEdit {{
    background: {PANEL_ALT};
    border: 1px solid {BORDER};
    border-radius: 6px;
    padding: 6px 9px;
    selection-background-color: {ACCENT};
}}
QLineEdit:focus, QComboBox:focus, QSpinBox:focus {{ border-color: {ACCENT}; }}
QLineEdit[invalid="true"] {{ border-color: {RED}; }}
QComboBox::drop-down {{ border: none; width: 20px; }}
QComboBox QAbstractItemView {{
    background: {PANEL_ALT};
    border: 1px solid {BORDER};
    selection-background-color: {ACCENT};
    outline: none;
}}

QTableView {{
    background: {PANEL};
    alternate-background-color: #1b1f27;
    gridline-color: {BORDER};
    border: 1px solid {BORDER};
    border-radius: 8px;
    selection-background-color: #2d4a7a;
    selection-color: #ffffff;
    outline: none;
}}
QHeaderView::section {{
    background: {PANEL_ALT};
    color: {MUTED};
    border: none;
    border-right: 1px solid {BORDER};
    border-bottom: 1px solid {BORDER};
    padding: 7px 8px;
    font-weight: 600;
}}
QTableView::item {{ padding: 3px 6px; }}

QScrollBar:vertical   {{ background: transparent; width: 11px; margin: 2px; }}
QScrollBar:horizontal {{ background: transparent; height: 11px; margin: 2px; }}
QScrollBar::handle {{ background: #39414e; border-radius: 5px; min-height: 28px;
                      min-width: 28px; }}
QScrollBar::handle:hover {{ background: #4a5464; }}
QScrollBar::add-line, QScrollBar::sub-line {{ height: 0; width: 0; }}
QScrollBar::add-page, QScrollBar::sub-page {{ background: none; }}

QStatusBar {{ background: {PANEL}; border-top: 1px solid {BORDER}; color: {MUTED}; }}
QStatusBar::item {{ border: none; }}

QSplitter::handle {{ background: {BORDER}; }}
QSplitter::handle:horizontal {{ width: 1px; }}
QSplitter::handle:vertical {{ height: 1px; }}

QTabWidget::pane {{ border: 1px solid {BORDER}; border-radius: 8px; top: -1px; }}
QTabBar::tab {{
    background: transparent; color: {MUTED};
    padding: 8px 16px; border: none; border-bottom: 2px solid transparent;
}}
QTabBar::tab:selected {{ color: {TEXT}; border-bottom: 2px solid {ACCENT};
                         font-weight: 600; }}

QCheckBox::indicator, QRadioButton::indicator {{
    width: 15px; height: 15px; border: 1px solid {BORDER};
    border-radius: 3px; background: {PANEL_ALT};
}}
QCheckBox::indicator:checked {{ background: {ACCENT}; border-color: {ACCENT}; }}

QProgressBar {{
    background: {PANEL_ALT}; border: 1px solid {BORDER};
    border-radius: 6px; text-align: center; height: 16px;
}}
QProgressBar::chunk {{ background: {ACCENT}; border-radius: 5px; }}

QToolTip {{
    background: {PANEL_ALT}; color: {TEXT};
    border: 1px solid {BORDER}; padding: 5px;
}}

#Banner {{
    background: #2a2013; border: 1px solid #5c4420;
    border-radius: 8px; padding: 10px;
}}
#BannerError {{
    background: #2c1720; border: 1px solid #6b2337;
    border-radius: 8px; padding: 10px;
}}
#BannerInfo {{
    background: #13202e; border: 1px solid #244766;
    border-radius: 8px; padding: 10px;
}}
QLabel#Mono, QPlainTextEdit#Mono, QTextEdit#Mono {{
    font-family: "JetBrains Mono", "DejaVu Sans Mono", monospace;
    font-size: 12px;
}}
"""
