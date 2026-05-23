"""
Windows process detection via WMI.

Watches for new process creation events and runs analyze_pe() on each
executable, emitting the results as a Qt signal.

Detection path:
  1. Win32_ProcessStartTrace (admin, ETW-backed) – faster, event-driven.
  2. __InstanceCreationEvent WITHIN 1 (no admin) – ~1 s polling latency.
"""

from wsgiref.simple_server import software_version

import pythoncom
import win32com.client
from PyQt5.QtCore import QThread, pyqtSignal

from up2date_client.file_manager import analyze_pe

_ETW_QUERY = "SELECT * FROM Win32_ProcessStartTrace"
_POLL_QUERY = (
    "SELECT * FROM __InstanceCreationEvent WITHIN 1 "
    "WHERE TargetInstance ISA 'Win32_Process'"
)

import ctypes
import ctypes.wintypes as wintypes

_k32 = ctypes.WinDLL("kernel32", use_last_error=True)
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000


def _get_process_path(pid: int) -> str | None:
    buf = ctypes.create_unicode_buffer(32768)
    size = wintypes.DWORD(32768)
    handle = _k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return None
    try:
        ok = _k32.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size))
        return buf.value if ok else None
    finally:
        _k32.CloseHandle(handle)


class ProcessMonitor(QThread):
    """
    Emits process_ready(pe_data) for every detected executable.

    pe_data["_meta"]:
        pid          – process ID
        path         – full image path
        process_name – basename
        using_etw    – True when Win32_ProcessStartTrace is available
    """

    process_ready  = pyqtSignal(dict)
    monitor_error  = pyqtSignal(str)
    status_changed = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._running = False

    def run(self):
        pythoncom.CoInitialize()
        try:
            locator = win32com.client.Dispatch("WbemScripting.SWbemLocator")
            service = locator.ConnectServer(".", "root/cimv2")

            using_etw = False
            try:
                watcher = service.ExecNotificationQuery(_ETW_QUERY)
                using_etw = True
                self.status_changed.emit("Monitoring (ETW – admin mode)")
            except Exception:
                watcher = service.ExecNotificationQuery(_POLL_QUERY)
                self.status_changed.emit("Monitoring (polling – ~1 s latency)")

            self._running = True
            while self._running:
                try:
                    event = watcher.NextEvent(500)
                except Exception:
                    continue

                try:
                    pid, path = self._extract(event, using_etw)
                except Exception:
                    continue

                if not pid or not path or not path.lower().endswith(".exe"):
                    continue

                try:
                    pe_data = analyze_pe(path)
                except Exception:
                    continue

                # Calculate version_id (must match server's implementation)
                program_name = pe_data.get("file_properties", {}).get("StringFileInfo", {}).get("ProductName")

                signed = False
                if pe_data.get("signatures") and len(pe_data["signatures"]) > 0:
                    signed = True

                if signed:
                    software_version_hash = pe_data.get("signatures", [{}])[0].get("hash")
                    software_version_id = program_name.replace(" ", "_")  + "-" + software_version_hash
                else:
                    software_version_id =  program_name.replace(" ", "_")  + "-" + pe_data.get("file_properties", {}).get("FileVersion", "").replace(" ", "_") 
                    software_version_hash = "unsigned"

                pe_data["_meta"] = {
                    "pid": pid,
                    "path": path,
                    "process_name": path.split("\\")[-1],
                    "using_etw": using_etw,
                    "program_name": program_name,
                    "software_version_id": software_version_id,
                    "report": "",
                    "reviews": [],
                }
                self.process_ready.emit(pe_data)

        except Exception as exc:
            self.monitor_error.emit(str(exc))
        finally:
            pythoncom.CoUninitialize()

    def stop(self):
        self._running = False

    def _extract(self, event, using_etw: bool) -> tuple[int | None, str | None]:
        if using_etw:
            pid  = int(event.ProcessID)
            path = _get_process_path(pid)
        else:
            proc = event.TargetInstance
            pid  = int(proc.ProcessId)
            path = getattr(proc, "ExecutablePath", None) or _get_process_path(pid)
        return pid, path
