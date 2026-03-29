import sys
import os
from PyQt6.QtWidgets import (
    QApplication,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QPushButton,
    QLineEdit,
    QListWidget,
    QMessageBox,
    QLabel,
    QMainWindow,
    QFrame
)
from client_.api_client import APIClient


class MainWindow(QWidget):
    def __init__(self, api_base=None):
        super().__init__()
        self.setWindowTitle('My Items')
        self.resize(420, 480)

        # API client
        self.client = APIClient(base_url=api_base or "http://localhost:5000")

        # UI
        main = QVBoxLayout()

        # Input form
        form = QHBoxLayout()
        self.input = QLineEdit()
        self.input.setPlaceholderText('Enter new item name')
        self.add_btn = QPushButton('Add')
        self.add_btn.clicked.connect(self.on_add)
        form.addWidget(self.input)
        form.addWidget(self.add_btn)

        # Refresh button
        self.refresh_btn = QPushButton('Refresh')
        self.refresh_btn.clicked.connect(self.load_items)

        # List of items
        self.list = QListWidget()

        # Assemble layout
        main.addLayout(form)
        main.addWidget(self.refresh_btn)
        main.addWidget(self.list)

        self.setLayout(main)

        self.load_items()

    def load_items(self):
        try:
            items = self.client.get_items()
        except Exception as e:
            QMessageBox.warning(self, 'Error', f'Could not fetch items from server:\n{e}')
            return

        self.list.clear()
        for it in items:
            self.list.addItem(f"{it['id']}: {it['name']}")

    def on_add(self):
        name = self.input.text().strip()
        if not name:
            return

        try:
            self.client.add_item(name)
            self.input.clear()
            self.load_items()
        except Exception as e:
            QMessageBox.critical(self, 'Error', f'Could not add item:\n{e}')


if __name__ == '__main__':
    app = QApplication(sys.argv)
    server_url = os.environ.get('SERVER_URL', 'http://localhost:5000')
    window = MainWindow(api_base=server_url)
    window.show()
    sys.exit(app.exec())
