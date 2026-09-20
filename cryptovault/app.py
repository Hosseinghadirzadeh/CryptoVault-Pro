from __future__ import annotations

import sys

from PySide6.QtCore import QCoreApplication
from PySide6.QtWidgets import QApplication

from cryptovault.gui.main_window import MainWindow


def main() -> int:
    QCoreApplication.setOrganizationName("CryptoVault")
    QCoreApplication.setApplicationName("CryptoVault Pro")
    application = QApplication(sys.argv)
    application.setStyle("Fusion")
    window = MainWindow()
    window.show()
    return application.exec()


if __name__ == "__main__":
    raise SystemExit(main())
