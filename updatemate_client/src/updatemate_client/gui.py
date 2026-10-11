import sys
import os
import json
import base64
from datetime import datetime
from pathlib import Path
import logging

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget,
    QVBoxLayout, QHBoxLayout, QSplitter,
    QPushButton, QTableWidget, QTableWidgetItem, QHeaderView,
    QTabWidget,
    QTextEdit, QAbstractItemView, QLabel,
    QLineEdit, QComboBox,
    QDialog, QDialogButtonBox, QFormLayout,
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QColor, QFont, QPixmap

from updatemate_client.process_monitor import ProcessMonitor
from updatemate_client.api_client import APIClient
from updatemate_client import heuristics
from updatemate_client import ai_analysis
from updatemate_client import auth as identity


_COLS = ["Time", "Program Name", "Process Name", "Company", "Version", "Signed", "Reviews", "Heuristic Results (OK / BAD / Unknown)", "AI Suggestion"]
_VERSION_COLS = ["Version", "First Seen", "Signed By", "Reviews (OK / Bad / Total)", "Current"]

_GREEN = QColor("#2ecc71")
_RED   = QColor("#e74c3c")

logging.basicConfig(level=logging.INFO)

_CONFIG_PATH = Path.home() / ".updatemate_config.json"

def _load_config():
    """Load saved config and inject values into the environment (env var takes precedence)."""
    try:
        if _CONFIG_PATH.exists():
            config = json.loads(_CONFIG_PATH.read_text(encoding="utf-8"))
            for env_key in ("ABUSECH_API_KEY", "GEMINI_API_KEY"):
                if not os.environ.get(env_key):
                    val = config.get(env_key, "")
                    if val:
                        os.environ[env_key] = val
    except Exception:
        pass

def _save_config(updates: dict):
    try:
        config = {}
        if _CONFIG_PATH.exists():
            config = json.loads(_CONFIG_PATH.read_text(encoding="utf-8"))
        config.update(updates)
        _CONFIG_PATH.write_text(json.dumps(config, indent=2), encoding="utf-8")
    except Exception:
        pass


class ConfigurationDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Configuration")
        self.setMinimumWidth(520)

        layout = QVBoxLayout(self)

        form = QFormLayout()

        self._abusech_key_input = QLineEdit()
        self._abusech_key_input.setPlaceholderText("Enter your abuse.ch API key…")
        self._abusech_key_input.setText(os.environ.get("ABUSECH_API_KEY", ""))
        form.addRow("abuse.ch API Key:", self._abusech_key_input)

        self._gemini_key_input = QLineEdit()
        self._gemini_key_input.setPlaceholderText("Enter your Gemini API key…")
        self._gemini_key_input.setText(os.environ.get("GEMINI_API_KEY", ""))
        form.addRow("Gemini API Key:", self._gemini_key_input)

        layout.addLayout(form)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def api_key(self) -> str:
        return self._abusech_key_input.text().strip()

    def gemini_api_key(self) -> str:
        return self._gemini_key_input.text().strip()


class CaptchaDialog(QDialog):
    """Shown before submitting a review that might not turn out to be
    developer-verified (Section 6.5 of the paper): displays the challenge
    image returned by GET /captcha/new and collects the user's typed
    answer. We always show this ahead of submission rather than trying to
    predict client-side whether the review will end up developer-verified
    -- the server is the only party that can determine that, and a
    developer solving an unnecessary CAPTCHA is harmless, minor friction,
    not a correctness problem."""

    def __init__(self, image_bytes: bytes, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Quick human check")
        self.setMinimumWidth(280)

        layout = QVBoxLayout(self)

        layout.addWidget(QLabel("Type the characters shown below to submit your review:"))

        image_label = QLabel()
        pixmap = QPixmap()
        pixmap.loadFromData(image_bytes, "PNG")
        image_label.setPixmap(pixmap)
        image_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(image_label)

        self._answer_input = QLineEdit()
        self._answer_input.setPlaceholderText("Enter the characters…")
        layout.addWidget(self._answer_input)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def answer(self) -> str:
        return self._answer_input.text().strip()


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
            self.process_details = {"report":"", "reviews": [], "versions": [], "version_summaries": []}

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
                    logging.info(f"(4) {self.program_name} - No reviews found for version {self.version_id}: {e}")
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

                # Build a per-version summary (label, first-seen date, signer,
                # and review count) so the GUI can show every known version
                # of this software side by side, not just the one currently
                # running. Review counts aren't included in the versions
                # list itself, so each known version needs its own lookup.
                summaries = []
                for raw_version in versions:
                    try:
                        vdata = json.loads(raw_version) if isinstance(raw_version, str) else raw_version
                    except Exception:
                        continue
                    vid = vdata.get("software_version_id", "") or ""
                    summaries.append({
                        "version_id": vid,
                        "label": _extract_version_label(vdata),
                        "first_seen": vdata.get("first_seen", "") or "",
                        "signer": _extract_signer_label(vdata),
                        "ok_count": 0,
                        "bad_count": 0,
                        "total_count": 0,
                    })
                    if not vid:
                        continue
                    try:
                        vreviews_response = self._api_client.get_version_reviews(vid)
                        vreviews = vreviews_response.get("reviews", [])
                        vreviews = json.loads(vreviews) if isinstance(vreviews, str) else vreviews
                        if isinstance(vreviews, list):
                            ok_count = 0
                            bad_count = 0
                            for review in vreviews:
                                r = json.loads(review) if isinstance(review, str) else review
                                if r.get("review") == "ok":
                                    ok_count += 1
                                else:
                                    bad_count += 1
                            summaries[-1]["ok_count"] = ok_count
                            summaries[-1]["bad_count"] = bad_count
                            summaries[-1]["total_count"] = ok_count + bad_count
                    except Exception as e:
                        logging.info(f"(6b) {self.program_name} - Could not fetch review count for version {vid}: {e}")

                self.process_details["version_summaries"] = summaries

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
            version_id = self.program_data.get("_meta", {}).get("software_version_id", "")
            fp = self.program_data.get("file_properties", {})
            current_file_version = fp.get("FileVersion", "") or ""

            results = {}
            ok_count = 0
            bad_count = 0
            unknown_count = 0

            file_hash = self.program_data.get("sha256", "")

            for func_name in ["check_known_version", "check_freeze_replay_attack", "check_bad_software", "check_CA_change", "check_targeted_malware", "check_abusech", "check_circl_hashlookup"]:
                try:
                    func = getattr(heuristics, func_name)
                    if func_name == "check_known_version":
                        status, comment = func(versions, version_id)
                    elif func_name == "check_freeze_replay_attack":
                        status, comment = func(reviews, versions, current_file_version)
                    elif func_name == "check_CA_change":
                        status, comment = func(versions, version_id)
                    elif func_name in ("check_abusech", "check_circl_hashlookup"):
                        status, comment = func(file_hash)
                    else:
                        status, comment = func(reviews)
                    results[func_name] = {"status": status, "comment": comment}
                    if status == "OK":
                        ok_count += 1
                    elif status == "BAD":
                        bad_count += 1
                    elif status == "UNKNOWN":
                        unknown_count += 1
                except Exception as e:
                    logging.error(f"Error running heuristic {func_name}: {e}")
                    results[func_name] = {"status": "ERROR", "comment": str(e)}

            self.heuristic_results = {
                "ok_count": ok_count,
                "bad_count": bad_count,
                "unknown_count": unknown_count,
                "results": results
            }

            self.details_ready.emit(self.heuristic_results)
            logging.info(f"Heuristics completed for {program_name}: {ok_count} OK, {bad_count} BAD")

        except Exception as exc:
            logging.error(f"Error running heuristics: {exc}")
            self.error_occurred.emit(f"Failed to run heuristics: {exc}")


class ProcessAIAnalysisWorker(QThread):
    details_ready  = pyqtSignal(dict)
    error_occurred = pyqtSignal(str)

    def __init__(self, program_data: dict, heuristic_results: dict):
        super().__init__()
        self.program_data      = program_data
        self.heuristic_results = heuristic_results

    def run(self):
        program_name = self.program_data.get("_meta", {}).get("program_name", "")
        try:
            logging.info(f"Running AI analysis for {program_name}")
            verdict, analysis = ai_analysis.analyze_with_gemini(
                self.program_data, self.heuristic_results
            )
            self.details_ready.emit({"verdict": verdict, "analysis": analysis})
            logging.info(f"AI analysis done for {program_name}: {verdict!r}")
        except Exception as exc:
            logging.error(f"AI analysis failed for {program_name}: {exc}")
            self.error_occurred.emit(str(exc))


def _item(text: str, color: QColor | None = None) -> QTableWidgetItem:
    it = QTableWidgetItem(str(text))
    it.setFlags(it.flags() & ~Qt.ItemIsEditable)
    it.setTextAlignment(Qt.AlignVCenter | Qt.AlignLeft)
    if color:
        it.setForeground(color)
    return it


def _extract_version_label(vdata: dict) -> str:
    """Human-readable version string for a stored version entry. Prefers
    StringFileInfo.ProductVersion, which the server always preserves;
    file_properties.FileVersion is only present on a version's first,
    client-side submission, not after a server round-trip (classes.py's
    FileProperties doesn't carry that top-level key through)."""
    fp = vdata.get("file_properties", {}) or {}
    sfi = fp.get("StringFileInfo", {}) or {}
    return (
        sfi.get("ProductVersion")
        or sfi.get("FileVersion")
        or fp.get("FileVersion")
        or "Unknown"
    )


def _extract_signer_label(vdata: dict) -> str:
    """Human-readable signer for a stored version entry: the publisher
    name from its file metadata, falling back to the leaf certificate's
    subject when CompanyName wasn't recorded."""
    fp = vdata.get("file_properties", {}) or {}
    sfi = fp.get("StringFileInfo", {}) or {}
    company = sfi.get("CompanyName")
    if company:
        return company
    sigs = vdata.get("signatures") or []
    if sigs:
        certs = sigs[0].get("certificates") or []
        if certs:
            return certs[-1].get("subject", "Unknown")
    return "Unsigned / Unknown"



class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("UpdateMate — Process Monitor")
        self.resize(1100, 700)

        self._monitor = ProcessMonitor()
        self._monitor.process_ready.connect(self._on_process)
        self._monitor.monitor_error.connect(self._on_error)
        self._monitor.status_changed.connect(self.statusBar().showMessage)

        self._api_client = APIClient()
        # Local reviewer identity: a keypair generated on first run and
        # reused after that (~/.updatemate/identity.pem). Every review this
        # client submits is signed with it -- see auth.load_or_create_identity
        # and auth.build_signed_review in updatemate_client/auth.py.
        self._identity_private_key, _ = identity.load_or_create_identity()
        self._server_status_label = None
        self._health_worker = HealthCheckWorker(self._api_client)
        self._health_worker.status_changed.connect(self._set_server_status)
        self._health_worker.start()

        self._workers = []

        self._records: list[dict] = []
        _load_config()
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

        config_btn = QPushButton("Configuration")
        config_btn.setFixedWidth(110)
        config_btn.clicked.connect(self._open_config)

        bar.addWidget(self._server_status_label)
        bar.addStretch()
        bar.addWidget(config_btn)
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

        self._reviews_text = QTextEdit()
        self._reviews_text.setReadOnly(True)
        self._reviews_text.setFont(QFont("Courier New", 9))
        tabs.addTab(self._reviews_text, "Reviews")

        self._heuristic_text = QTextEdit()
        self._heuristic_text.setReadOnly(True)
        self._heuristic_text.setFont(QFont("Courier New", 9))
        tabs.addTab(self._heuristic_text, "Heuristic Analysis")

        self._ai_text = QTextEdit()
        self._ai_text.setReadOnly(True)
        self._ai_text.setFont(QFont("Courier New", 9))
        tabs.addTab(self._ai_text, "AI Analysis")

        # Known Versions tab: every version of the selected software known
        # to the community ledger, and how many reviews each one has.
        self._versions_table = QTableWidget(0, len(_VERSION_COLS))
        self._versions_table.setHorizontalHeaderLabels(_VERSION_COLS)
        v_hdr = self._versions_table.horizontalHeader()
        v_hdr.setStretchLastSection(True)
        for i in range(len(_VERSION_COLS) - 1):
            v_hdr.setSectionResizeMode(i, QHeaderView.ResizeToContents)
        self._versions_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self._versions_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        tabs.addTab(self._versions_table, "Known Versions")

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
        self._reviews_text.clear()
        self._heuristic_text.clear()
        self._ai_text.clear()
        self._versions_table.setRowCount(0)

    def _set_server_status(self, is_online: bool):
        color = _GREEN if is_online else _RED
        status = "Online" if is_online else "Offline"
        self._server_status_label.setText(f"Server: {status}")
        self._server_status_label.setStyleSheet(f"color: {color.name()};")

    def _open_config(self):
        dialog = ConfigurationDialog(self)
        if dialog.exec_() == QDialog.Accepted:
            abusech_key = dialog.api_key()
            gemini_key  = dialog.gemini_api_key()
            os.environ["ABUSECH_API_KEY"] = abusech_key
            os.environ["GEMINI_API_KEY"]  = gemini_key
            _save_config({"ABUSECH_API_KEY": abusech_key, "GEMINI_API_KEY": gemini_key})
            self.statusBar().showMessage("Configuration saved")

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
            (program_name,                        None),
            (meta["process_name"],                None),
            (company_name,                        None),
            (file_version,                        None),
            (signed_text,                         signed_col),
            (loading_col,                         None),  # Reviews
            (loading_col,                         None),  # Heuristic Results
            (loading_col,                         None),  # AI Suggestion
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
        self._records[record_index]["_meta"]["version_summaries"] = details.get("version_summaries", [])

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
                self._table.setItem(table_row, len(_COLS) - 3, _item(f"{good_reviews} OK/{len(reviews)}"))
            else:
                self._table.setItem(table_row, len(_COLS) - 3, _item("0"))
        else:
            self._table.setItem(table_row, len(_COLS) - 3, _item("0"))

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
        ok_count      = details.get("ok_count", 0)
        bad_count     = details.get("bad_count", 0)
        unknown_count = details.get("unknown_count", 0)

        self._records[record_index]["_meta"]["heuristic_results"] = details

        self._table.setItem(table_row, len(_COLS) - 2, _item(""))
        cell = QLabel(
            f'<span style="color:#2ecc71;">{ok_count}</span>'
            f' / '
            f'<span style="color:#e74c3c;">{bad_count}</span>'
            f' / '
            f'<span style="color:#95a5a6;">{unknown_count}</span>'
        )
        cell.setAlignment(Qt.AlignVCenter | Qt.AlignLeft)
        cell.setContentsMargins(4, 0, 0, 0)
        cell.setStyleSheet("background: transparent;")
        self._table.setCellWidget(table_row, len(_COLS) - 2, cell)

        ai_worker = ProcessAIAnalysisWorker(self._records[record_index], details)
        self._workers.append(ai_worker)
        self._workers[-1].details_ready.connect(
            lambda x, vid=version_id: self._update_program_with_ai_analysis(details=x, version_id=vid)
        )
        self._workers[-1].start()

    def _update_program_with_ai_analysis(self, details: dict, version_id: str):
        record_index = None
        for i, record in enumerate(self._records):
            if record["_meta"].get("software_version_id") == version_id:
                record_index = i
                break

        if record_index is None:
            return

        verdict  = details.get("verdict", "")
        analysis = details.get("analysis", "")
        self._records[record_index]["_meta"]["ai_analysis"] = details

        verdict_lower = verdict.lower()
        if any(kw in verdict_lower for kw in ("safe", "good", "clean", "known good", "legitimate")):
            color = _GREEN
        elif any(kw in verdict_lower for kw in ("danger", "malicious", "bad", "suspicious", "caution", "risky")):
            color = _RED
        else:
            color = None

        self._table.setItem(record_index, len(_COLS) - 1, _item(verdict or "—", color))

        # If this row is currently selected, refresh the AI Analysis tab
        rows = self._table.selectionModel().selectedRows()
        if rows and rows[0].row() == record_index:
            self._ai_text.setPlainText(
                f"Verdict: {verdict}\n\n{analysis}" if analysis else verdict
            )

    def _on_select(self):

        rows = self._table.selectionModel().selectedRows()
        if rows and rows[0].row() < len(self._records):
            self._show_detail(self._records[rows[0].row()])

    def _show_detail(self, pe_data: dict):
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
                        badge = " [DEVELOPER VERIFIED]" if r.get("developer_verified") else ""
                        review_lines.append(f"Reviewer: {reviewer}{badge}\nComment: {comment}\nReview: {review_value}\nTime Received: {time_received}\n---\n")
                    except:
                        review_lines.append(str(review))
                self._reviews_text.setPlainText("\n".join(review_lines))
            else:
                self._reviews_text.setPlainText(str(reviews))
        else:
            self._reviews_text.setPlainText("No review data available")


        heuristic_results = pe_data.get("_meta", {}).get("heuristic_results", {})
        if heuristic_results and "results" in heuristic_results:
            ok_count      = heuristic_results.get("ok_count", 0)
            bad_count     = heuristic_results.get("bad_count", 0)
            unknown_count = heuristic_results.get("unknown_count", 0)
            results       = heuristic_results.get("results", {})

            heuristic_lines = [f"Summary: {ok_count} OK / {bad_count} BAD / {unknown_count} Unknown\n"]
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

        ai_result = pe_data.get("_meta", {}).get("ai_analysis", {})
        if ai_result:
            verdict  = ai_result.get("verdict", "")
            analysis = ai_result.get("analysis", "")
            self._ai_text.setPlainText(
                f"Verdict: {verdict}\n\n{analysis}" if analysis else verdict or "No result"
            )
        else:
            self._ai_text.setPlainText("AI analysis not yet available or not configured.")

        self._populate_versions_table(pe_data)

    def _populate_versions_table(self, pe_data: dict):
        """Fills the "Known Versions" tab with every version of the
        selected software the community ledger knows about, and how many
        reviews each one has received, so a user can see the full release
        history of a product rather than just the version they're running."""
        summaries = pe_data.get("_meta", {}).get("version_summaries", [])
        current_version_id = pe_data.get("_meta", {}).get("software_version_id", "")

        self._versions_table.setRowCount(0)

        if not summaries:
            return

        for summary in summaries:
            row = self._versions_table.rowCount()
            self._versions_table.insertRow(row)

            is_current = bool(current_version_id) and summary.get("version_id") == current_version_id
            ok_count = summary.get("ok_count", 0)
            bad_count = summary.get("bad_count", 0)
            total_count = summary.get("total_count", ok_count + bad_count)

            for col, (text, color) in enumerate([
                (summary.get("label", "Unknown"),                              None),
                (summary.get("first_seen", "") or "—",                         None),
                (summary.get("signer", "Unknown"),                             None),
                (f"{ok_count} OK / {bad_count} Bad / {total_count} Total",     None),
                ("Current" if is_current else "",                             _GREEN if is_current else None),
            ]):
                self._versions_table.setItem(row, col, _item(text, color))

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

            # A CAPTCHA is only required for reviews that don't turn out to
            # be developer-verified (Section 6.5), but the client can't know
            # that in advance -- only the server can determine it -- so we
            # always fetch and solve one here rather than guess.
            challenge = self._api_client.get_captcha()
            image_bytes = base64.b64decode(challenge["image_base64"])
            captcha_dialog = CaptchaDialog(image_bytes, self)
            if captcha_dialog.exec_() != QDialog.Accepted:
                self.statusBar().showMessage("Review submission cancelled")
                return

            review_data = identity.build_signed_review(
                self._identity_private_key, version_id, reviewer, comment, review
            )
            review_data["captcha_challenge_id"] = challenge["challenge_id"]
            review_data["captcha_answer"] = captcha_dialog.answer()
            response = self._api_client.add_version_review(version_id, json.dumps(review_data))
            self._reviewer_input.clear()
            self._comment_input.clear()
            self._review_dropdown.setCurrentIndex(0)
            if response.get("developer_verified"):
                self.statusBar().showMessage("Review submitted successfully (developer-verified ✓)")
            else:
                self.statusBar().showMessage("Review submitted successfully")
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
