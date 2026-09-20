APP_STYLE = r"""
QWidget { background: #0b1018; color: #dce7f5; font-family: "Segoe UI"; font-size: 10pt; }
QMainWindow { background: #070b11; }
QFrame#Sidebar { background: #0d1420; border-right: 1px solid #1d2b3d; }
QFrame#Card { background: #111a27; border: 1px solid #213047; border-radius: 10px; }
QLabel#Brand { font-size: 20pt; font-weight: 700; color: #65e3bd; }
QLabel#PageTitle { font-size: 20pt; font-weight: 650; color: #f3f7fb; }
QLabel#Muted { color: #8fa2b8; }
QLabel#Success { color: #65e3bd; font-weight: 600; }
QLabel#Warning { color: #ffca6b; }
QPushButton { background: #182538; border: 1px solid #2b405b; padding: 8px 14px; border-radius: 6px; }
QPushButton:hover { background: #20324a; border-color: #4d739b; }
QPushButton:pressed { background: #122033; }
QPushButton#Primary { background: #00a77e; border-color: #16c99a; color: white; font-weight: 650; }
QPushButton#Primary:hover { background: #08b88c; }
QPushButton#Nav { text-align: left; padding: 10px 14px; border: none; background: transparent; color: #9fb1c5; }
QPushButton#Nav:checked { background: #152538; color: #65e3bd; border-left: 3px solid #36d7a5; }
QLineEdit, QTextEdit, QPlainTextEdit, QComboBox, QSpinBox { background: #0a111b; border: 1px solid #293a50; border-radius: 6px; padding: 7px; selection-background-color: #087f62; }
QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus, QComboBox:focus { border-color: #36d7a5; }
QTabWidget::pane { border: 1px solid #213047; border-radius: 6px; }
QTabBar::tab { background: #111a27; padding: 9px 16px; color: #8fa2b8; }
QTabBar::tab:selected { color: #65e3bd; border-bottom: 2px solid #36d7a5; }
QProgressBar { border: 1px solid #293a50; border-radius: 5px; text-align: center; background: #0a111b; }
QProgressBar::chunk { background: #12b98d; border-radius: 4px; }
QTableWidget { background: #0a111b; alternate-background-color: #0e1723; border: 1px solid #213047; gridline-color: #213047; }
QHeaderView::section { background: #152131; color: #b8c7d9; padding: 7px; border: none; border-right: 1px solid #26384d; }
QScrollBar:vertical { width: 10px; background: #0a111b; }
QScrollBar::handle:vertical { background: #31445a; border-radius: 5px; min-height: 24px; }
QToolTip { background: #152131; color: white; border: 1px solid #3c5570; }
"""

