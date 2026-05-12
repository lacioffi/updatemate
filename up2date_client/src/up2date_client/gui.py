import sys
import json
from datetime import datetime

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget,
    QVBoxLayout, QHBoxLayout, QSplitter,
    QPushButton, QTableWidget, QTableWidgetItem, QHeaderView,
    QTabWidget, QTreeWidget, QTreeWidgetItem,
    QTextEdit, QAbstractItemView, QLabel,
)
from PyQt5.QtCore import Qt, QTimer, QThread, pyqtSignal
from PyQt5.QtGui import QColor, QFont

from up2date_client.process_monitor import ProcessMonitor
from up2date_client.api_client import APIClient


_COLS = ["Time", "PID", "Program Name", "Process Name", "Company", "Version", "Signed", "Known Version", "Reviews"]

_GREEN = QColor("#2ecc71")
_RED   = QColor("#e74c3c")


class HealthCheckWorker(QThread):
    status_changed = pyqtSignal(bool)

    def __init__(self, api_client):
        super().__init__()
        self.api_client = api_client
        self.running = True

    def run(self):
        while self.running:
            try:
                self.api_client.health_check()
                self.status_changed.emit(True)
            except Exception:
                self.status_changed.emit(False)
            self.msleep(30000)

    def stop(self):
        self.running = False


class SoftwareDataWorker(QThread):
    data_ready = pyqtSignal(dict)

    def __init__(self, api_client, program_name, file_version):
        super().__init__()
        self.api_client = api_client
        self.program_name = program_name
        self.file_version = file_version

    def run(self):
        data = {
            "program_name": self.program_name,
            "file_version": self.file_version,
            "is_known": False,
            "review_count": 0,
            "report": None,
            "reviews": None
        }

        try:
            report = self.api_client.get_software_report(self.program_name)
            data["report"] = report.get("report", {})
            data["is_known"] = True
        except Exception:
            pass

        try:
            reviews = self.api_client.get_version_reviews(self.file_version)
            data["reviews"] = reviews.get("reviews", [])
            data["review_count"] = len(data["reviews"])
        except Exception:
            pass

        self.data_ready.emit(data)

def _item(text: str, color: QColor | None = None) -> QTableWidgetItem:
    it = QTableWidgetItem(str(text))
    it.setFlags(it.flags() & ~Qt.ItemIsEditable)
    it.setTextAlignment(Qt.AlignVCenter | Qt.AlignLeft)
    if color:
        it.setForeground(color)
    return it


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Up2Date — Process Monitor")
        self.resize(1100, 700)

        self._monitor = ProcessMonitor()
        self._monitor.process_ready.connect(self._on_process)
        self._monitor.monitor_error.connect(self._on_error)
        self._monitor.status_changed.connect(self.statusBar().showMessage)

        self._api_client = APIClient()
        self._server_status_label = None
        self._health_worker = HealthCheckWorker(self._api_client)
        self._health_worker.status_changed.connect(self._set_server_status)
        self._health_worker.start()

        self._records: list[dict] = []
        self._build_ui()

    # ------------------------------------------------------------------

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(8, 8, 8, 4)
        root.setSpacing(6)

        # toolbar
        bar = QHBoxLayout()
        self._start_btn = QPushButton("Start Monitoring")
        self._start_btn.setFixedWidth(160)
        self._start_btn.clicked.connect(self._toggle)
        clear_btn = QPushButton("Clear")
        clear_btn.setFixedWidth(80)
        clear_btn.clicked.connect(self._clear)

        self._server_status_label = QLabel("Server: Checking...")
        self._server_status_label.setFixedWidth(200)
        self._set_server_status(False)

        bar.addWidget(self._server_status_label)
        bar.addStretch()
        bar.addWidget(clear_btn)
        bar.addWidget(self._start_btn)
        root.addLayout(bar)

        splitter = QSplitter(Qt.Vertical)
        root.addWidget(splitter)

        # process table
        self._table = QTableWidget(0, len(_COLS))
        self._table.setHorizontalHeaderLabels(_COLS)
        hdr = self._table.horizontalHeader()
        hdr.setStretchLastSection(True)
        for i in range(len(_COLS) - 1):
            hdr.setSectionResizeMode(i, QHeaderView.ResizeToContents)
        self._table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self._table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self._table.selectionModel().selectionChanged.connect(self._on_select)
        splitter.addWidget(self._table)

        # detail tabs
        tabs = QTabWidget()

        self._props_tree = QTreeWidget()
        self._props_tree.setHeaderLabels(["Property", "Value"])
        self._props_tree.header().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        tabs.addTab(self._props_tree, "File Properties")

        self._sig_tree = QTreeWidget()
        self._sig_tree.setHeaderLabels(["Field", "Value"])
        self._sig_tree.header().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        tabs.addTab(self._sig_tree, "Signatures")

        self._raw = QTextEdit()
        self._raw.setReadOnly(True)
        self._raw.setFont(QFont("Courier New", 9))
        tabs.addTab(self._raw, "Raw JSON")

        self._report_text = QTextEdit()
        self._report_text.setReadOnly(True)
        self._report_text.setFont(QFont("Courier New", 9))
        tabs.addTab(self._report_text, "Software Report")

        self._reviews_text = QTextEdit()
        self._reviews_text.setReadOnly(True)
        self._reviews_text.setFont(QFont("Courier New", 9))
        tabs.addTab(self._reviews_text, "Reviews")

        splitter.addWidget(tabs)
        splitter.setSizes([400, 300])

        self.statusBar().showMessage("Ready — press Start Monitoring")

    # ------------------------------------------------------------------

    def _toggle(self):
        if self._monitor.isRunning():
            self._monitor.stop()
            self._monitor.wait(2000)
            self._start_btn.setText("Start Monitoring")
            self.statusBar().showMessage("Stopped")
        else:
            self._monitor.start()
            self._start_btn.setText("Stop Monitoring")

    def _clear(self):
        self._table.setRowCount(0)
        self._records.clear()
        self._props_tree.clear()
        self._sig_tree.clear()
        self._raw.clear()
        self._report_text.clear()
        self._reviews_text.clear()

    def _set_server_status(self, is_online: bool):
        color = _GREEN if is_online else _RED
        status = "Online" if is_online else "Offline"
        self._server_status_label.setText(f"Server: {status}")
        self._server_status_label.setStyleSheet(f"color: {color.name()};")

    # ------------------------------------------------------------------

    def _on_process(self, pe_data: dict):
        meta = pe_data["_meta"]
        fp   = pe_data.get("file_properties", {})
        sfi  = fp.get("StringFileInfo") or {}
        sigs = pe_data.get("signatures", [])

        row = self._table.rowCount()
        self._table.insertRow(row)
        self._records.append(pe_data)

        signed      = bool(sigs)
        signed_text = "Yes" if signed else "No"
        signed_col  = _GREEN if signed else _RED

        company_name = sfi.get("CompanyName", "") or ""
        file_version = fp.get("FileVersion", "") or ""
        program_name = sfi.get("ProductName", "") or ""

        for col, (text, color) in enumerate([
            (datetime.now().strftime("%H:%M:%S"), None),
            (str(meta["pid"]),                    None),
            (program_name,                        None),
            (meta["process_name"],                None),
            (company_name,                        None),
            (file_version,                        None),
            (signed_text,                         signed_col),
            ("",                                  None),
            ("",                                  None),
        ]):
            self._table.setItem(row, col, _item(text, color))

        self._table.scrollToBottom()
        self.statusBar().showMessage(
            f"Detected: {program_name} (PID {meta['pid']})"
        )

        #if sigs:
            #worker = SoftwareDataWorker(self._api_client, program_name, file_version)
            #worker.data_ready.connect(lambda data: self._on_software_data(row, data))
            #worker.start()

    def _on_error(self, msg: str):
        self.statusBar().showMessage(f"Error: {msg}")
        self._start_btn.setText("Start Monitoring")

    def _on_software_data(self, row: int, data: dict):
        known_text = "✓" if data["is_known"] else ""
        known_col = _GREEN if data["is_known"] else None
        review_count = str(data["review_count"])

        self._table.setItem(row, 6, _item(known_text, known_col))
        self._table.setItem(row, 7, _item(review_count, None))

        if row < len(self._records):
            self._records[row]["_software_data"] = data

    # ------------------------------------------------------------------

    def _on_select(self):
        rows = self._table.selectionModel().selectedRows()
        if rows and rows[0].row() < len(self._records):
            self._show_detail(self._records[rows[0].row()])

    def _show_detail(self, pe_data: dict):
        self._raw.setPlainText(json.dumps(pe_data, indent=2, default=str))

        self._props_tree.clear()
        fp  = pe_data.get("file_properties", {})
        sfi = fp.get("StringFileInfo") or {}

        def branch(label: str, data: dict):
            node = QTreeWidgetItem([label])
            for k, v in data.items():
                QTreeWidgetItem(node, [str(k), str(v) if v is not None else ""])
            node.setExpanded(True)
            self._props_tree.addTopLevelItem(node)

        branch("Process Info",    pe_data.get("_meta", {}))
        branch("String File Info", sfi)
        ffi = fp.get("FixedFileInfo") or {}
        if ffi:
            branch("Fixed File Info", ffi)

        self._sig_tree.clear()
        for i, sig in enumerate(pe_data.get("signatures", [])):
            sig_node = QTreeWidgetItem([f"Signature {i + 1}"])
            QTreeWidgetItem(sig_node, ["Hash", sig.get("hash", "")])
            certs_node = QTreeWidgetItem(["Certificates"])
            for j, cert in enumerate(sig.get("certificates", [])):
                cert_node = QTreeWidgetItem([f"Certificate {j + 1}"])
                for k, v in cert.items():
                    if k != "signature":
                        QTreeWidgetItem(cert_node, [k, str(v)])
                cert_node.setExpanded(True)
                certs_node.addChild(cert_node)
            certs_node.setExpanded(True)
            sig_node.addChild(certs_node)
            sig_node.setExpanded(True)
            self._sig_tree.addTopLevelItem(sig_node)

        software_data = pe_data.get("_software_data", {})
        report = software_data.get("report")
        if report:
            self._report_text.setPlainText(json.dumps(report, indent=2, default=str))
        else:
            self._report_text.setPlainText("No report data available")

        reviews = software_data.get("reviews", [])
        if reviews:
            self._reviews_text.setPlainText(json.dumps(reviews, indent=2, default=str))
        else:
            self._reviews_text.setPlainText("No reviews available")

    # ------------------------------------------------------------------

    def closeEvent(self, event):
        self._health_worker.stop()
        if self._monitor.isRunning():
            self._monitor.stop()
        event.accept()


def run_app():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    run_app()
