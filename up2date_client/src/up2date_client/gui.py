import sys
import json
from datetime import datetime
import logging

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget,
    QVBoxLayout, QHBoxLayout, QSplitter,
    QPushButton, QTableWidget, QTableWidgetItem, QHeaderView,
    QTabWidget, QTreeWidget, QTreeWidgetItem,
    QTextEdit, QAbstractItemView, QLabel,
    QLineEdit, QComboBox,
)
from PyQt5.QtCore import Qt, QTimer, QThread, pyqtSignal
from PyQt5.QtGui import QColor, QFont

from up2date_client.file_manager import analyze_pe
from up2date_client.process_monitor import ProcessMonitor
from up2date_client.api_client import APIClient
from up2date_client import heuristics


_COLS = ["Time", "PID", "Program Name", "Process Name", "Company", "Version", "Signed", "Known Version", "Reviews", "Heuristic Results"]

_GREEN = QColor("#2ecc71")
_RED   = QColor("#e74c3c")

logging.basicConfig(level=logging.INFO)

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

class ProcessGetDetailsWorker(QThread):
        details_ready = pyqtSignal(dict)
        error_occurred = pyqtSignal(str)
    
        def __init__(self, program_name: str, version_id: str, api_client: APIClient):
            super().__init__()
            self.program_name = program_name
            self.version_id = version_id
            self._api_client = api_client
            self.process_details = {"report":"", "reviews": [], "versions": []}           
    
        def run(self):
            try:
                response = self._api_client.get_software_report(self.program_name)
                report = response.get("report", {})
                logging.info(f"(1) {self.program_name} - Getting report from server")
                if report:
                    logging.info(f"(2) {self.program_name} - Fetched report (non-null)")
                else:
                    logging.info(f"(2) {self.program_name} - No report found")
                self.process_details["report"] = report

                #Get reviews for existing version:
                logging.info(f"(3) {self.program_name} - Getting reviews for version {self.version_id}")
                reviews_response = self._api_client.get_version_reviews(self.version_id)
                reviews = reviews_response.get("reviews", [])
                try:
                    reviews = json.loads(reviews) if isinstance(reviews, str) else reviews
                    logging.info(f"(4) {self.program_name} - Fetched reviews for version {self.version_id}")
                except Exception as e:
                    logging.info(f"(4) {self.program_name} - No reviews found for version {self.version_id}")
                self.process_details["reviews"] = reviews

                #Get known versions list:
                logging.info(f"(5) {self.program_name} - Getting known versions for {self.program_name}")
                versions_response = self._api_client.get_software_versions(self.program_name)
                versions = versions_response.get("versions", [])
                if versions:
                    logging.info(f"(6) {self.program_name} - Fetched known versions for {self.program_name}")
                else:
                    logging.info(f"(6) {self.program_name} - No known versions found for {self.program_name}")
                self.process_details["versions"] = versions

                self.details_ready.emit(self.process_details)

            except Exception as exc:
                logging.error(f"Error fetching software report for {self.program_name}: {exc}")
                self.error_occurred.emit(f"Failed to retrieve software report: {exc}")

class ProcessHeuristicsWorker(QThread):
    details_ready = pyqtSignal(dict)
    error_occurred = pyqtSignal(str)

    def __init__(self, program_data: dict):
        super().__init__()
        self.program_data = program_data
        self.heuristic_results = {}

    def run(self):
        try:
            program_name = self.program_data["_meta"].get("program_name", "")
            logging.info(f"Running heuristics for {program_name}")

            reviews = self.program_data.get("_meta", {}).get("reviews", [])
            versions = self.program_data.get("_meta", {}).get("versions", [])
            fp = self.program_data.get("file_properties", {})
            current_file_version = fp.get("FileVersion", "") or ""

            results = {}
            ok_count = 0
            bad_count = 0

            for func_name in ["check_freeze_replay_attack", "check_widespread_malware", "check_targeted_malware"]:
                try:
                    func = getattr(heuristics, func_name)
                    if func_name == "check_freeze_replay_attack":
                        status, comment = func(reviews, versions, current_file_version)
                    else:
                        status, comment = func(reviews)
                    results[func_name] = {"status": status, "comment": comment}
                    if status == "OK":
                        ok_count += 1
                    elif status == "BAD":
                        bad_count += 1
                except Exception as e:
                    logging.error(f"Error running heuristic {func_name}: {e}")
                    results[func_name] = {"status": "ERROR", "comment": str(e)}

            self.heuristic_results = {
                "ok_count": ok_count,
                "bad_count": bad_count,
                "results": results
            }

            self.details_ready.emit(self.heuristic_results)
            logging.info(f"Heuristics completed for {program_name}: {ok_count} OK, {bad_count} BAD")

        except Exception as exc:
            logging.error(f"Error running heuristics: {exc}")
            self.error_occurred.emit(f"Failed to run heuristics: {exc}")


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

        self._workers = []

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

        self._versions_text = QTextEdit()
        self._versions_text.setReadOnly(True)
        self._versions_text.setFont(QFont("Courier New", 9))
        tabs.addTab(self._versions_text, "Known Versions")

        self._heuristic_text = QTextEdit()
        self._heuristic_text.setReadOnly(True)
        self._heuristic_text.setFont(QFont("Courier New", 9))
        tabs.addTab(self._heuristic_text, "Heuristic Analysis")

        # Submit Review tab
        self._submit_review_widget = QWidget()
        submit_layout = QVBoxLayout(self._submit_review_widget)

        reviewer_layout = QHBoxLayout()
        self._reviewer_label = QLabel("Reviewer:")
        reviewer_layout.addWidget(self._reviewer_label)
        self._reviewer_input = QLineEdit()
        reviewer_layout.addWidget(self._reviewer_input)
        submit_layout.addLayout(reviewer_layout)

        comment_layout = QHBoxLayout()
        self._comment_label = QLabel("Comment:")
        comment_layout.addWidget(self._comment_label)
        self._comment_input = QTextEdit()
        self._comment_input.setMaximumHeight(80)
        comment_layout.addWidget(self._comment_input)
        submit_layout.addLayout(comment_layout)

        review_layout = QHBoxLayout()
        self._review_label = QLabel("Review:")
        review_layout.addWidget(self._review_label)
        self._review_dropdown = QComboBox()
        self._review_dropdown.addItems(["ok", "vulnerable", "malicious", "degraded"])
        review_layout.addWidget(self._review_dropdown)
        review_layout.addStretch()
        submit_layout.addLayout(review_layout)

        self._submit_btn = QPushButton("Submit Review")
        self._submit_btn.clicked.connect(self._submit_review)
        submit_layout.addWidget(self._submit_btn)
        submit_layout.addStretch()

        tabs.addTab(self._submit_review_widget, "Submit Review")

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
        self._versions_text.clear()

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

        version_id = pe_data["_meta"].get("software_version_id", "")

        if version_id and any(r["_meta"].get("software_version_id") == version_id for r in self._records):
            logging.info(f"Duplicate software version {version_id} detected, skipping")
            return

        row = self._table.rowCount()
        self._table.insertRow(row)
        self._records.append(pe_data)

        signed      = bool(sigs)
        signed_text = "Yes" if signed else "No"
        signed_col  = _GREEN if signed else _RED

        loading_col = "LOADING..." if signed else ""

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
            (loading_col,                         None),
            (loading_col,                         None),
            (loading_col,                         None),
        ]):
            self._table.setItem(row, col, _item(text, color))

        self._table.scrollToBottom()
        self.statusBar().showMessage(
            f"Detected: {program_name} (PID {meta['pid']})"
        )

        if sigs and program_name:
            getDetailsWorker = ProcessGetDetailsWorker(program_name, version_id, self._api_client)
            self._workers.append(getDetailsWorker)  # keep reference to prevent GC
            self._workers[-1].details_ready.connect(lambda x: self._update_program_with_details(details=x, version_id=version_id))
            self._workers[-1].start()




    def _on_error(self, msg: str):
        self.statusBar().showMessage(f"Error: {msg}")
        self._start_btn.setText("Start Monitoring")
        logging.error(f"Process monitor error: {msg}")

    # ------------------------------------------------------------------

    def _update_program_with_details(self, details: dict, version_id: str):
        #Get row for specific version_id:
        record_index = None
        for i, record in enumerate(self._records):
            if record["_meta"].get("software_version_id") == version_id:
                record_index = i
                break

        if record_index is None:
            logging.warning(f"Record with version_id {version_id} not found")
            return

        table_row = record_index
        program_name = self._records[record_index]['_meta'].get('program_name', '')
        logging.info(f"(7) {program_name} - Updating UI with fetched details")

        #Update the record with fetched details:
        self._records[record_index]["_meta"]["report"] = details["report"]
        self._records[record_index]["_meta"]["versions"] = details.get("versions", [])
        self._records[record_index]["_meta"]["reviews"] = details.get("reviews", [])

        #Check if version was seen before to update "Known Version" column:
        version_seen = False
        for version in details.get("versions", []):
            try:
                v = json.loads(version) if isinstance(version, str) else version
                if v.get("software_version_id") == version_id:
                    version_seen = True
                    break
            except:
                continue

        if version_seen:
            self._table.setItem(table_row, len(_COLS) - 3, _item("YES", _GREEN))
        else:
            self._table.setItem(table_row, len(_COLS) - 3, _item("NO", _RED))

        #Check number of reviews to update "Reviews" column:
        reviews = details.get("reviews", [])
        if reviews:
            if isinstance(reviews, list):
                good_reviews = 0
                bad_reviews = 0
                for review in reviews:
                    r = json.loads(review) if isinstance(review, str) else review
                    review_value = r.get("review", "N/A")
                    if review_value == "ok":
                        good_reviews += 1
                    else:
                        bad_reviews += 1
                self._table.setItem(table_row, len(_COLS) - 2, _item(f"{good_reviews} OK/{len(reviews)}"))
            else:
                self._table.setItem(table_row, len(_COLS) - 2, _item("0"))
        else:
            self._table.setItem(table_row, len(_COLS) - 2, _item("0"))

        heuristicsWorker = ProcessHeuristicsWorker(self._records[record_index])
        self._workers.append(heuristicsWorker)
        self._workers[-1].details_ready.connect(lambda x: self._update_program_with_heuristic_details(details=x, version_id=version_id))
        self._workers[-1].start()




    def _update_program_with_heuristic_details(self, details: dict, version_id: str):
        record_index = None
        for i, record in enumerate(self._records):
            if record["_meta"].get("software_version_id") == version_id:
                record_index = i
                break

        if record_index is None:
            logging.warning(f"Record with version_id {version_id} not found")
            return

        table_row = record_index
        ok_count = details.get("ok_count", 0)
        bad_count = details.get("bad_count", 0)

        self._records[record_index]["_meta"]["heuristic_results"] = details

        heuristic_text = f"{ok_count} OK / {bad_count} BAD"
        self._table.setItem(table_row, len(_COLS) - 1, _item(heuristic_text))

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

        report = pe_data.get("_meta").get("report", "")
        if report:
            self._report_text.setPlainText(report)
        else:
            self._report_text.setPlainText("No report data available")

        reviews = pe_data.get("_meta").get("reviews", [])
        if reviews:
            if isinstance(reviews, list):
                review_lines = []
                for review in reviews:
                    try:
                        r = json.loads(review) if isinstance(review, str) else review
                        reviewer = r.get("reviewer", "N/A")
                        comment = r.get("comment", "N/A")
                        review_value = r.get("review", "N/A")
                        time_received = r.get("time_received", "N/A")
                        review_lines.append(f"Reviewer: {reviewer}\nComment: {comment}\nReview: {review_value}\nTime Received: {time_received}\n---\n")
                    except:
                        review_lines.append(str(review))
                self._reviews_text.setPlainText("\n".join(review_lines))
            else:
                self._reviews_text.setPlainText(str(reviews))
        else:
            self._reviews_text.setPlainText("No review data available")


        versions = pe_data.get("_meta", {}).get("versions", [])
        if versions:
            version_lines = []
            for version in versions:
                try:
                    v = json.loads(version) if isinstance(version, str) else version
                    first_seen = v.get("first_seen", "N/A")
                    version_id = v.get("software_version_id", "N/A")
                    product_version = v.get("file_properties", {}).get("StringFileInfo", {}).get("ProductVersion", "N/A")
                    version_lines.append(f"Version ID: {version_id}\nFirst Seen: {first_seen}\nProduct Version: {product_version}\n")
                except:
                    version_lines = [versions]
            self._versions_text.setPlainText("\n".join(version_lines))
        else:
            self._versions_text.setPlainText("No known versions available")

        heuristic_results = pe_data.get("_meta", {}).get("heuristic_results", {})
        if heuristic_results and "results" in heuristic_results:
            ok_count = heuristic_results.get("ok_count", 0)
            bad_count = heuristic_results.get("bad_count", 0)
            results = heuristic_results.get("results", {})

            heuristic_lines = [f"Summary: {ok_count} OK / {bad_count} BAD\n"]
            heuristic_lines.append("=" * 50)

            for check_name, check_result in results.items():
                status = check_result.get("status", "UNKNOWN")
                comment = check_result.get("comment", "")
                heuristic_lines.append(f"\n{check_name}")
                heuristic_lines.append(f"Status: {status}")
                heuristic_lines.append(f"Comment: {comment}")

            self._heuristic_text.setPlainText("\n".join(heuristic_lines))
        else:
            self._heuristic_text.setPlainText("No heuristic analysis available")

    def _submit_review(self):
        rows = self._table.selectionModel().selectedRows()
        if not rows:
            self.statusBar().showMessage("Error: No software selected")
            return

        record = self._records[rows[0].row()]
        version_id = record["_meta"].get("software_version_id", "")

        if not version_id:
            self.statusBar().showMessage("Error: No version ID found")
            return

        reviewer = self._reviewer_input.text().strip()
        comment = self._comment_input.toPlainText().strip()
        review = self._review_dropdown.currentText()

        if not reviewer or not comment:
            self.statusBar().showMessage("Error: Reviewer and comment are required")
            return

        try:
            #Also submit the software version data if not already present, to ensure the review is linked to a known version in the system:
            version_data = {
                "file_properties": record.get("file_properties", {}),
                "signatures": record.get("signatures", [])
            }
            self._api_client.add_software_version(json.dumps(version_data))

            review_data = {
                "reviewer": reviewer,
                "comment": comment,
                "review": review
            }
            response = self._api_client.add_version_review(version_id, json.dumps(review_data))
            self._reviewer_input.clear()
            self._comment_input.clear()
            self._review_dropdown.setCurrentIndex(0)
            self.statusBar().showMessage(f"Review submitted successfully")
            logging.info(f"Review submitted for version {version_id}: {response}")
        except Exception as e:
            self.statusBar().showMessage(f"Error submitting review: {str(e)}")
            logging.error(f"Error submitting review: {e}")

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
