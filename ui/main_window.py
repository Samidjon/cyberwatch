import ipaddress

from PySide6.QtCore import Qt, QThread, Signal, QTimer
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QMainWindow, QWidget, QHBoxLayout, QVBoxLayout, QLabel, QPushButton,
    QFrame, QComboBox, QProgressBar, QTabWidget, QTableWidget, QTableWidgetItem,
    QHeaderView, QMessageBox, QFileDialog, QTextEdit, QCheckBox, QSpinBox,
    QAbstractItemView, QLineEdit,
)

from cyberwatch.network import get_local_networks, discover_devices, scan_common_tcp_ports, PORTS
from cyberwatch.storage import Store, now_text

STYLE = """
QMainWindow { background: #edf3f9; }
QWidget {
    color: #18334d;
    font-family: 'Segoe UI';
    font-size: 10pt;
}
QLabel, QCheckBox { background: transparent; } 
QWidget#CentralRoot { background: #edf3f9; }
QWidget#TabSurface { background: #ffffff; }
QFrame#Sidebar {
    background: #ffffff;
    border: 1px solid #d8e4ef;
    border-radius: 16px;
}
QFrame#Panel {
    background: #ffffff;
    border: 1px solid #d6e2ee;
    border-radius: 13px;
}
QLabel#Brand {
    color: #087bd1;
    font-size: 25px;
    font-weight: 800;
    letter-spacing: 2px;
}
QLabel#Subtitle { color: #647b92; font-size: 10px; letter-spacing: 1.5px; }
QLabel#Section { color: #28669d; font-size: 10px; font-weight: 800; letter-spacing: 1.4px; }
QLabel#Muted { color: #5c7188; font-size: 9pt; }
QLabel#Metric { color: #153a59; font-size: 28px; font-weight: 800; }
QLabel#MetricTitle { color: #546e87; font-size: 9pt; font-weight: 700; letter-spacing: 0.6px; }
QLabel#MetricHint { color: #71849a; font-size: 8pt; }
QPushButton {
    background: #e8f1fa;
    color: #1e5c91;
    border: 1px solid #c4d8ea;
    border-radius: 8px;
    padding: 10px 13px;
    font-weight: 600;
}
QPushButton:hover { background: #d8eafa; border-color: #5ba6e5; }
QPushButton:pressed { background: #c7e0f7; }
QPushButton:disabled { background: #f1f5f9; color: #9aa9b7; border-color: #dce5ee; }
QPushButton#Primary {
    background: #087bd1;
    color: #ffffff;
    border: 1px solid #087bd1;
    font-weight: 800;
}
QPushButton#Primary:hover { background: #066ab6; border-color: #066ab6; }
QPushButton#Secondary { background: #ffffff; color: #1e5c91; border: 1px solid #bcd1e4; }
QPushButton#Danger { background: #fff1f0; color: #a72a2a; border: 1px solid #f2c7c4; }
QComboBox, QSpinBox, QLineEdit {
    background: #fbfdff;
    color: #17344f;
    border: 1px solid #c7d8e8;
    border-radius: 8px;
    padding: 9px 10px;
    selection-background-color: #cce7ff;
    selection-color: #143c60;
}
QComboBox:hover, QSpinBox:hover, QLineEdit:hover { border-color: #87b5dd; }
QComboBox:focus, QSpinBox:focus, QLineEdit:focus { border: 1px solid #087bd1; }
QComboBox QAbstractItemView { background: #ffffff; color: #17344f; selection-background-color: #d9edff; }
QTableWidget {
    background: #ffffff;
    alternate-background-color: #f5f9fd;
    color: #203b55;
    border: 1px solid #d9e4ee;
    border-radius: 9px;
    gridline-color: #e5edf5;
    selection-background-color: #d5ebff;
    selection-color: #123a5e;
    outline: 0;
}
QTableWidget::item { padding: 7px 8px; border: 0; }
QTableWidget::item:selected { background: #d5ebff; color: #123a5e; }
QHeaderView::section {
    background: #eaf2fa;
    color: #355d7f;
    padding: 11px 10px;
    border: 0;
    border-bottom: 1px solid #cfddea;
    font-size: 9pt;
    font-weight: 800;
}
QTabWidget::pane { background: #ffffff; border: 1px solid #d6e2ee; border-radius: 10px; top: -1px; }
QTabBar::tab {
    background: #e5edf6;
    color: #536d85;
    padding: 11px 18px;
    border: 1px solid #d6e1ec;
    border-top-left-radius: 8px;
    border-top-right-radius: 8px;
    margin-right: 4px;
    font-weight: 700;
}
QTabBar::tab:selected { background: #ffffff; color: #087bd1; border-bottom: 3px solid #087bd1; }
QProgressBar {
    background: #e3edf7;
    border: 1px solid #ccdae8;
    border-radius: 5px;
    height: 15px;
    text-align: center;
    color: #234661;
    font-size: 8pt;
    font-weight: 700;
}
QProgressBar::chunk { background: #1399e6; border-radius: 4px; }
QCheckBox { color: #294963; spacing: 8px; font-weight: 600; }
QCheckBox::indicator { width: 17px; height: 17px; }
QCheckBox::indicator:unchecked { background: #ffffff; border: 1px solid #9db2c5; border-radius: 4px; }
QCheckBox::indicator:checked { background: #087bd1; border: 1px solid #087bd1; border-radius: 4px; }
QTextEdit { background: #fbfdff; color: #29465f; border: 1px solid #d6e2ee; border-radius: 8px; padding: 9px; }
QScrollBar:vertical { background: #edf3f9; width: 12px; margin: 2px; }
QScrollBar::handle:vertical { background: #bdcfdf; border-radius: 5px; min-height: 24px; }
QScrollBar::handle:vertical:hover { background: #8eacc6; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QFrame#MetricOnline { background:#ffffff; border:1px solid #d6e2ee; border-left:5px solid #169866; border-radius:12px; }
QFrame#MetricKnown { background:#ffffff; border:1px solid #d6e2ee; border-left:5px solid #087bd1; border-radius:12px; }
QFrame#MetricEvents { background:#ffffff; border:1px solid #d6e2ee; border-left:5px solid #db8b16; border-radius:12px; }
"""


class DiscoveryWorker(QThread):
    progress = Signal(int, int)
    completed = Signal(list, str)
    failed = Signal(str)

    def __init__(self, network_info, parent=None):
        super().__init__(parent)
        self.network_info = network_info

    def run(self):
        try:
            devices = discover_devices(
                self.network_info,
                lambda done, total: self.progress.emit(done, total),
            )
            self.completed.emit(devices, self.network_info["network"])
        except Exception as exc:
            self.failed.emit(str(exc))


class PortScanWorker(QThread):
    progress = Signal(int, int)
    completed = Signal(str, list)
    failed = Signal(str)

    def __init__(self, target_ip, network, parent=None):
        super().__init__(parent)
        self.target_ip = target_ip
        self.network = network

    def run(self):
        try:
            results = scan_common_tcp_ports(
                self.target_ip, self.network,
                lambda done, total: self.progress.emit(done, total),
            )
            self.completed.emit(self.target_ip, results)
        except Exception as exc:
            self.failed.emit(str(exc))


def _item(text, color=None, data=None):
    item = QTableWidgetItem(str(text))
    item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
    if color:
        item.setForeground(QColor(color))
    if data is not None:
        item.setData(Qt.ItemDataRole.UserRole, data)
    return item


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CyberWatch // Local Network Observatory")
        self.resize(1400, 900)
        self.setMinimumSize(1120, 740)
        self.setStyleSheet(STYLE)
        self.store = Store()
        self.networks = []
        self.current_network = None
        self.devices_cache = []
        self.discovery_worker = None
        self.port_worker = None
        self.port_results_by_ip = {}
        self.last_scan_at = None

        self.monitor_timer = QTimer(self)
        self.monitor_timer.timeout.connect(self.start_discovery)
        self._build_ui()
        self._load_history()
        self._refresh_networks()
        self._refresh_metrics()
        self._set_status("Ready", "#63e7ff")

    def _build_ui(self):
        root = QWidget()
        root.setObjectName("CentralRoot")
        self.setCentralWidget(root)
        outer = QHBoxLayout(root)
        outer.setContentsMargins(18, 18, 18, 18)
        outer.setSpacing(16)

        sidebar = QFrame()
        sidebar.setObjectName("Sidebar")
        sidebar.setFixedWidth(292)
        side = QVBoxLayout(sidebar)
        side.setContentsMargins(20, 22, 20, 20)
        side.setSpacing(13)
        brand = QLabel("CYBERWATCH")
        brand.setObjectName("Brand")
        side.addWidget(brand)
        subtitle = QLabel("LOCAL NETWORK MONITOR")
        subtitle.setObjectName("Subtitle")
        side.addWidget(subtitle)
        side.addSpacing(14)

        section = QLabel("SCAN CONFIGURATION")
        section.setObjectName("Section")
        side.addWidget(section)
        side.addWidget(QLabel("Local network interface"))
        self.network_combo = QComboBox()
        self.network_combo.currentIndexChanged.connect(self._on_network_changed)
        side.addWidget(self.network_combo)
        self.refresh_networks_btn = QPushButton("↻  Refresh network adapters")
        self.refresh_networks_btn.setObjectName("Secondary")
        self.refresh_networks_btn.setToolTip("Re-detect available Wi-Fi and Ethernet interfaces")
        self.refresh_networks_btn.clicked.connect(self._refresh_networks)
        side.addWidget(self.refresh_networks_btn)
        self.network_label = QLabel("Detecting interfaces…")
        self.network_label.setObjectName("Muted")
        self.network_label.setWordWrap(True)
        side.addWidget(self.network_label)

        self.scan_btn = QPushButton("▶  SCAN LOCAL NETWORK")
        self.scan_btn.setObjectName("Primary")
        self.scan_btn.setMinimumHeight(44)
        self.scan_btn.setToolTip("Discover responding devices on the selected private LAN")
        self.scan_btn.clicked.connect(self.start_discovery)
        side.addWidget(self.scan_btn)
        self.monitor_check = QCheckBox("Enable periodic monitoring")
        self.monitor_check.toggled.connect(self._toggle_monitoring)
        side.addWidget(self.monitor_check)
        interval_row = QHBoxLayout()
        interval_row.addWidget(QLabel("Interval"))
        self.interval_spin = QSpinBox()
        self.interval_spin.setRange(30, 3600)
        self.interval_spin.setValue(60)
        self.interval_spin.setSuffix(" sec")
        self.interval_spin.valueChanged.connect(self._interval_changed)
        interval_row.addWidget(self.interval_spin)
        side.addLayout(interval_row)

        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.progress.setTextVisible(True)
        side.addWidget(self.progress)
        self.progress_label = QLabel("Waiting for scan")
        self.progress_label.setObjectName("Muted")
        self.progress_label.setWordWrap(True)
        side.addWidget(self.progress_label)
        side.addSpacing(12)
        monitor_heading = QLabel("MONITOR STATUS")
        monitor_heading.setObjectName("Section")
        side.addWidget(monitor_heading)
        self.status_label = QLabel("● Ready")
        self.status_label.setStyleSheet("color:#087fae;font-weight:800;")
        side.addWidget(self.status_label)
        self.last_scan_label = QLabel("Last scan: never")
        self.last_scan_label.setObjectName("Muted")
        self.last_scan_label.setWordWrap(True)
        side.addWidget(self.last_scan_label)
        side.addStretch(1)
        disclaimer = QLabel(
            "Use only on networks you own or are authorized to monitor. Discovery is limited to "
            "a private local subnet; port checks target one selected host."
        )
        disclaimer.setObjectName("Muted")
        disclaimer.setWordWrap(True)
        side.addWidget(disclaimer)
        outer.addWidget(sidebar)

        content = QVBoxLayout()
        content.setSpacing(14)
        outer.addLayout(content, 1)
        header = QFrame()
        header.setObjectName("Panel")
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(22, 18, 22, 18)
        header_text = QVBoxLayout()
        overline = QLabel("CYBERSECURITY  /  LOCAL NETWORK")
        overline.setObjectName("Section")
        title = QLabel("Devices, services and network changes")
        title.setStyleSheet("font-size:23px;font-weight:700;color:#173650;")
        self.range_label = QLabel("No local network selected")
        self.range_label.setObjectName("Muted")
        header_text.addWidget(overline)
        header_text.addWidget(title)
        header_text.addWidget(self.range_label)
        header_layout.addLayout(header_text)
        header_layout.addStretch(1)
        self.header_status = QLabel("● READY")
        self.header_status.setStyleSheet("color:#087fae;font-weight:800;padding:8px 12px;background:#e6f4ff;border-radius:10px;")
        header_layout.addWidget(self.header_status)
        content.addWidget(header)

        metrics = QHBoxLayout()
        metrics.setSpacing(10)
        self.metric_online = self._metric_card("ONLINE NOW", "0", "Responding in selected network", "MetricOnline")
        self.metric_known = self._metric_card("KNOWN DEVICES", "0", "Seen in previous scans", "MetricKnown")
        self.metric_events = self._metric_card("RECENT EVENTS", "0", "Stored monitoring events", "MetricEvents")
        for card in (self.metric_online, self.metric_known, self.metric_events):
            metrics.addWidget(card)
        content.addLayout(metrics)

        self.tabs = QTabWidget()
        devices_tab = QWidget()
        devices_tab.setObjectName("TabSurface")
        devices_layout = QVBoxLayout(devices_tab)
        devices_layout.setContentsMargins(8, 10, 8, 8)
        toolbar = QHBoxLayout()
        toolbar.setSpacing(8)
        devices_heading = QLabel("Discovered devices")
        devices_heading.setStyleSheet("font-size:14px;font-weight:800;color:#1b3f5d;")
        toolbar.addWidget(devices_heading)
        self.device_search = QLineEdit()
        self.device_search.setPlaceholderText("Search IP, hostname or MAC…")
        self.device_search.setToolTip("Filter the device table without changing the saved inventory")
        self.device_search.setClearButtonEnabled(True)
        self.device_search.setMinimumWidth(190)
        self.device_search.textChanged.connect(self._populate_device_table_from_cache)
        toolbar.addWidget(self.device_search, 1)
        self.port_scan_btn = QPushButton("⌕  CHECK PORTS")
        self.port_scan_btn.setToolTip("Check a fixed list of common TCP ports on the selected device")
        self.port_scan_btn.setEnabled(False)
        self.port_scan_btn.clicked.connect(self.start_port_scan)
        toolbar.addWidget(self.port_scan_btn)
        self.open_device_btn = QPushButton("↗  OPEN IP")
        self.open_device_btn.setObjectName("Secondary")
        self.open_device_btn.setEnabled(False)
        self.open_device_btn.clicked.connect(self.open_selected_ip)
        toolbar.addWidget(self.open_device_btn)
        devices_layout.addLayout(toolbar)

        self.device_table = QTableWidget(0, 5)
        self.device_table.setHorizontalHeaderLabels(["STATUS", "IP ADDRESS", "MAC ADDRESS", "HOSTNAME", "LAST SEEN"])
        self.device_table.setAlternatingRowColors(True)
        self.device_table.setShowGrid(False)
        self.device_table.verticalHeader().setDefaultSectionSize(40)
        self.device_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.device_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.device_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.device_table.verticalHeader().setVisible(False)
        for col in (0, 1, 2, 4):
            self.device_table.horizontalHeader().setSectionResizeMode(col, QHeaderView.ResizeMode.ResizeToContents)
        self.device_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.device_table.itemSelectionChanged.connect(self._update_selected_details)
        devices_layout.addWidget(self.device_table, 1)

        details = QFrame()
        details.setObjectName("Panel")
        details_layout = QVBoxLayout(details)
        details_layout.setContentsMargins(12, 10, 12, 10)
        self.selected_title = QLabel("Select a device to inspect")
        self.selected_title.setStyleSheet("font-size:12px;font-weight:800;color:#126aab;")
        details_layout.addWidget(self.selected_title)
        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        self.details_text.setMinimumHeight(150)
        self.details_text.setMaximumHeight(210)
        self.details_text.setText(
            "Select a discovered host and use SCAN PORTS ON SELECTED to check a short list of "
            "common TCP ports. This is an exposure check, not a vulnerability scan."
        )
        details_layout.addWidget(self.details_text)
        devices_layout.addWidget(details)
        self.tabs.addTab(devices_tab, "NETWORK DEVICES")

        events_tab = QWidget()
        events_tab.setObjectName("TabSurface")
        events_layout = QVBoxLayout(events_tab)
        events_layout.setContentsMargins(8, 10, 8, 8)
        events_toolbar = QHBoxLayout()
        events_heading = QLabel("Change and scan event history")
        events_heading.setStyleSheet("font-size:14px;font-weight:800;color:#1b3f5d;")
        events_toolbar.addWidget(events_heading)
        events_toolbar.addStretch(1)
        self.event_search = QLineEdit()
        self.event_search.setPlaceholderText("Filter events by text, IP or level…")
        self.event_search.setToolTip("Filters the displayed event log; CSV export still includes the full log")
        self.event_search.setClearButtonEnabled(True)
        self.event_search.setMaximumWidth(300)
        self.event_search.textChanged.connect(self._populate_event_table_from_cache)
        events_toolbar.addWidget(self.event_search)
        export_btn = QPushButton("↓  EXPORT CSV")
        export_btn.clicked.connect(self.export_events)
        events_toolbar.addWidget(export_btn)
        events_layout.addLayout(events_toolbar)
        self.event_table = QTableWidget(0, 4)
        self.event_table.setHorizontalHeaderLabels(["TIMESTAMP", "LEVEL", "IP ADDRESS", "EVENT"])
        self.event_table.setAlternatingRowColors(True)
        self.event_table.setShowGrid(False)
        self.event_table.verticalHeader().setDefaultSectionSize(38)
        self.event_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.event_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.event_table.verticalHeader().setVisible(False)
        for col in (0, 1, 2):
            self.event_table.horizontalHeader().setSectionResizeMode(col, QHeaderView.ResizeMode.ResizeToContents)
        self.event_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        events_layout.addWidget(self.event_table)
        self.tabs.addTab(events_tab, "EVENT LOG")
        content.addWidget(self.tabs, 1)
        footer = QLabel("CYBERWATCH  •  PRIVATE LAN ONLY  •  FIXED TCP PORT CHECKS  •  LOCAL SQLITE HISTORY")
        footer.setObjectName("Muted")
        content.addWidget(footer)

    def _metric_card(self, title, value, hint="", object_name="Panel"):
        card = QFrame()
        card.setObjectName(object_name)
        layout = QVBoxLayout(card)
        layout.setContentsMargins(17, 14, 15, 13)
        layout.setSpacing(4)
        title_label = QLabel(title)
        title_label.setObjectName("MetricTitle")
        value_label = QLabel(value)
        value_label.setObjectName("Metric")
        hint_label = QLabel(hint)
        hint_label.setObjectName("MetricHint")
        layout.addWidget(title_label)
        layout.addWidget(value_label)
        layout.addWidget(hint_label)
        card.value_label = value_label
        return card

    def _set_status(self, message, color="#087fae"):
        # Translate the previous theme's bright colors to readable light-theme colors.
        color_map = {
            "#63e7ff": "#087fae",
            "#72f0be": "#168057",
            "#ffc77d": "#a96300",
            "#ffb86b": "#a96300",
            "#ff8585": "#bd3030",
        }
        color = color_map.get(color.lower(), color)
        self.status_label.setText(f"● {message}")
        self.status_label.setStyleSheet(f"color:{color};font-weight:800;")
        self.header_status.setText(f"● {message.upper()}")
        self.header_status.setStyleSheet(
            f"color:{color};font-weight:800;padding:8px 12px;"
            "background:#f0f6fb;border-radius:10px;"
        )

    def _refresh_networks(self):
        previous = self.current_network.get("ip") if self.current_network else None
        self.networks = get_local_networks()
        self.network_combo.blockSignals(True)
        self.network_combo.clear()
        for item in self.networks:
            self.network_combo.addItem(f"{item['interface']} — {item['ip']} ({item['network']})")
        self.network_combo.blockSignals(False)
        if self.networks:
            target_index = next((i for i, item in enumerate(self.networks) if item.get("ip") == previous), 0)
            self.network_combo.setCurrentIndex(target_index)
            self._on_network_changed(target_index)
        else:
            self.current_network = None
            self.network_label.setText("No private IPv4 interface detected. Connect to Wi-Fi or Ethernet, then refresh adapters.")
            self.range_label.setText("No local network detected")
            self.scan_btn.setEnabled(False)
            self._set_status("No LAN interface", "#ffb86b")
            self._refresh_metrics()

    def _on_network_changed(self, index):
        if index < 0 or index >= len(self.networks):
            return
        self.current_network = self.networks[index]
        note = self.current_network.get("note", "")
        self.network_label.setText(
            f"Address: {self.current_network['ip']}\nScan range: {self.current_network['network']}\n{note}"
        )
        self.range_label.setText(
            f"Interface: {self.current_network['interface']}  •  Local IP: {self.current_network['ip']}  •  Range: {self.current_network['network']}"
        )
        self.scan_btn.setEnabled(True)
        self._refresh_metrics()

    def _load_history(self):
        self._populate_device_table(self.store.get_devices())
        self._populate_event_table(self.store.get_events())

    def _populate_device_table(self, devices):
        self.devices_cache = devices
        self._populate_device_table_from_cache()

    def _populate_device_table_from_cache(self, *_):
        selected_ip = self._selected_ip() if hasattr(self, "device_table") else ""
        query = self.device_search.text().strip().casefold() if hasattr(self, "device_search") else ""
        devices = self.devices_cache
        if query:
            devices = [
                device for device in devices
                if query in " ".join(str(device.get(key, "")) for key in ("ip", "mac", "hostname", "status")).casefold()
            ]
        self.device_table.setRowCount(0)
        selected_row = -1
        for device in devices:
            row = self.device_table.rowCount()
            self.device_table.insertRow(row)
            online = bool(device.get("online", True))
            values = [
                ("● ONLINE" if online else "● OFFLINE", "#168057" if online else "#66788a"),
                (device.get("ip", ""), None),
                (device.get("mac", "") or "—", None),
                (device.get("hostname", "") or "Unknown", None),
                (device.get("last_seen", "") or "—", None),
            ]
            for col, (value, color) in enumerate(values):
                cell = _item(value, color, device.get("ip") if col == 1 else None)
                self.device_table.setItem(row, col, cell)
            if selected_ip and device.get("ip") == selected_ip:
                selected_row = row
        if selected_row >= 0:
            self.device_table.selectRow(selected_row)
        if hasattr(self, "selected_title"):
            self._update_selected_details()

    def _populate_event_table(self, events):
        self.events_cache = events
        self._populate_event_table_from_cache()

    def _populate_event_table_from_cache(self, *_):
        query = self.event_search.text().strip().casefold() if hasattr(self, "event_search") else ""
        events = self.events_cache if hasattr(self, "events_cache") else []
        if query:
            events = [
                event for event in events
                if query in " ".join(str(event.get(key, "")) for key in ("timestamp", "level", "ip", "message")).casefold()
            ]
        self.event_table.setRowCount(0)
        for event in events:
            row = self.event_table.rowCount()
            self.event_table.insertRow(row)
            level = event.get("level", "INFO")
            color = "#9b6100" if level == "REVIEW" else "#087fae"
            values = [event.get("timestamp", ""), level, event.get("ip", "") or "—", event.get("message", "")]
            for col, value in enumerate(values):
                self.event_table.setItem(row, col, _item(value, color if col == 1 else None))

    def _refresh_metrics(self):
        network_name = self.current_network["network"] if self.current_network else None
        devices = self.store.get_devices(network=network_name)
        events = self.store.get_events()
        self.metric_online.value_label.setText(str(sum(1 for device in devices if device.get("online"))))
        self.metric_known.value_label.setText(str(len(devices)))
        self.metric_events.value_label.setText(str(len(events)))
        self._populate_device_table(devices)
        self._populate_event_table(events)

    def start_discovery(self):
        if self.discovery_worker and self.discovery_worker.isRunning():
            return
        if not self.current_network:
            QMessageBox.warning(self, "No local network", "Connect to a private IPv4 network, then restart CyberWatch.")
            return
        try:
            network = ipaddress.ip_network(self.current_network["network"], strict=False)
            if not network.is_private or network.num_addresses > 256 or ipaddress.ip_address(self.current_network["ip"]) not in network:
                raise ValueError
        except ValueError:
            QMessageBox.warning(self, "Unsafe scan range", "CyberWatch only scans one private LAN with at most 254 host addresses.")
            return

        self.scan_btn.setEnabled(False)
        self.progress.setValue(0)
        self.progress_label.setText(f"Discovering hosts in {self.current_network['network']}…")
        self._set_status("Scanning LAN", "#ffc77d")
        self.discovery_worker = DiscoveryWorker(dict(self.current_network), self)
        self.discovery_worker.progress.connect(self._on_discovery_progress)
        self.discovery_worker.completed.connect(self._on_discovery_complete)
        self.discovery_worker.failed.connect(self._on_discovery_error)
        self.discovery_worker.start()

    def _on_discovery_progress(self, done, total):
        self.progress.setValue(int(done * 100 / max(total, 1)))
        self.progress_label.setText(f"Checking local hosts: {done}/{total}")

    def _on_discovery_complete(self, devices, network):
        self.last_scan_at = now_text()
        self.last_scan_label.setText(f"Last scan: {self.last_scan_at}")
        self.scan_btn.setEnabled(True)
        self.progress.setValue(100)
        if devices:
            self.store.record_discovery(devices, network)
            self.progress_label.setText(f"Scan complete: {len(devices)} responding/known hosts")
            self.store.add_event("INFO", "", f"Completed discovery scan of {network}: {len(devices)} hosts")
            self._set_status("Monitoring ready", "#63e7ff")
        else:
            self.progress_label.setText("No devices returned. ICMP may be blocked or the interface may be wrong.")
            self.store.add_event("REVIEW", "", f"Scan returned no devices for {network}")
            self._set_status("No hosts returned", "#ffb86b")
        self._refresh_metrics()

    def _on_discovery_error(self, message):
        self.scan_btn.setEnabled(True)
        self.progress_label.setText("Scan failed")
        self.store.add_event("REVIEW", "", f"Discovery scan failed: {message}")
        self._set_status("Scan failed", "#ff8585")
        self._refresh_metrics()
        QMessageBox.warning(self, "Discovery failed", message)

    def _toggle_monitoring(self, enabled):
        if enabled:
            self.monitor_timer.start(self.interval_spin.value() * 1000)
            self.store.add_event("INFO", "", f"Periodic monitoring enabled: every {self.interval_spin.value()} seconds")
            self._set_status("Auto-monitor ON", "#72f0be")
            if not (self.discovery_worker and self.discovery_worker.isRunning()):
                self.start_discovery()
        else:
            self.monitor_timer.stop()
            self.store.add_event("INFO", "", "Periodic monitoring disabled")
            self._set_status("Auto-monitor OFF", "#63e7ff")
        self._refresh_metrics()

    def _interval_changed(self, value):
        if self.monitor_check.isChecked():
            self.monitor_timer.start(value * 1000)

    def _update_selected_details(self):
        target = self._selected_ip()
        if not target:
            self.selected_title.setText("Select a device to inspect")
            if hasattr(self, "open_device_btn"):
                self.open_device_btn.setEnabled(False)
                self.port_scan_btn.setEnabled(False)
            return
        device = next((item for item in self.devices_cache if item.get("ip") == target), {})
        if hasattr(self, "open_device_btn"):
            self.open_device_btn.setEnabled(True)
            self.port_scan_btn.setEnabled(bool(device.get("online", True)) and not (self.port_worker and self.port_worker.isRunning()))
        self.selected_title.setText(f"{device.get('hostname') or 'Unknown device'} • {target}")
        lines = [
            f"IP address: {target}",
            f"MAC address: {device.get('mac') or 'Unknown'}",
            f"First seen: {device.get('first_seen') or '—'}",
            f"Last seen: {device.get('last_seen') or '—'}",
        ]

        scan = self.port_results_by_ip.get(target)
        if scan:
            lines.extend(["", f"LAST PORT CHECK — {scan['scanned_at']}"])
            results = scan.get("results", [])
            opened = [row for row in results if row.get("state") == "OPEN"]
            unknown = [row for row in results if row.get("state") == "unknown"]
            if opened:
                lines.append(f"OPEN PORTS ({len(opened)}):")
                for row in opened:
                    review = "  • REVIEW EXPOSURE" if row.get("review") else ""
                    lines.append(f"  {row['port']}/TCP  {row['service']}  — OPEN{review}")
            else:
                lines.append("No open ports detected in the tested port list.")
            if unknown:
                lines.append("Could not determine state for: " + ", ".join(
                    f"{row['port']}/TCP" for row in unknown
                ))
            lines.append("Checked ports: " + ", ".join(str(row['port']) for row in results))
            lines.append("Note: only 11 common TCP ports are tested; other ports may still be open.")
        else:
            lines.extend([
                "",
                "PORT CHECK: Not run for this device yet.",
                "Select CHECK PORTS to test 11 common TCP ports on this private LAN host.",
            ])
        self.details_text.setPlainText("\n".join(lines))

    def _selected_ip(self):
        row = self.device_table.currentRow()
        item = self.device_table.item(row, 1) if row >= 0 else None
        return (item.data(Qt.ItemDataRole.UserRole) or item.text()) if item else ""

    def start_port_scan(self):
        if self.port_worker and self.port_worker.isRunning():
            return
        target = self._selected_ip()
        if not target:
            QMessageBox.information(self, "Select a device", "Select a row in the device table first.")
            return
        if not self.current_network:
            return
        device = next((item for item in self.devices_cache if item.get("ip") == target), {})
        if not device.get("online", True):
            QMessageBox.information(self, "Device offline", "This device is marked offline. Run discovery again before checking ports.")
            return
        if target == self.current_network["ip"]:
            answer = QMessageBox.question(
                self, "Check this computer?",
                "This checks a fixed list of common TCP ports on your own computer. Continue?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if answer != QMessageBox.StandardButton.Yes:
                return

        self.port_scan_btn.setEnabled(False)
        self.progress.setValue(0)
        self.progress_label.setText(f"Checking fixed TCP port list on {target}…")
        self._set_status("Checking ports", "#ffc77d")
        self.port_worker = PortScanWorker(target, self.current_network["network"], self)
        self.port_worker.progress.connect(self._on_port_progress)
        self.port_worker.completed.connect(self._on_ports_complete)
        self.port_worker.failed.connect(self._on_ports_error)
        self.port_worker.finished.connect(self._on_port_worker_finished)
        self.port_worker.start()

    def _on_port_progress(self, done, total):
        self.progress.setValue(int(done * 100 / max(total, 1)))
        self.progress_label.setText(f"Checking TCP ports: {done}/{total}")

    def _on_ports_complete(self, target, results):
        opens = [row for row in results if row["state"] == "OPEN"]
        # Cache results before refreshing the device table. Table refresh triggers
        # selection-change callbacks; _update_selected_details now restores the
        # device metadata AND the last port scan instead of overwriting the results.
        self.port_results_by_ip[target] = {
            "scanned_at": now_text(),
            "results": results,
        }
        if opens:
            self.store.log_port_results(target, results)
            self.store.add_event("INFO", target, f"Checked {len(PORTS)} common TCP ports; {len(opens)} open")
        else:
            self.store.add_event("INFO", target, f"Checked {len(PORTS)} common TCP ports; none found open")
        self.progress.setValue(100)
        self.progress_label.setText(f"Port check complete: {len(opens)} open")
        self._set_status("Monitoring ready", "#63e7ff")
        self._refresh_metrics()
        self._update_selected_details()

    def _on_port_worker_finished(self):
        self._update_selected_details()

    def _on_ports_error(self, message):
        self._update_selected_details()
        self.progress_label.setText("Port check failed")
        self.store.add_event("REVIEW", "", f"Port check failed: {message}")
        self._set_status("Port check failed", "#ff8585")
        self._refresh_metrics()
        QMessageBox.warning(self, "Port check failed", message)

    def open_selected_ip(self):
        target = self._selected_ip()
        if not target:
            QMessageBox.information(self, "Select a device", "Select a device first.")
            return
        import webbrowser
        webbrowser.open(f"http://{target}")

    def export_events(self):
        destination, _ = QFileDialog.getSaveFileName(self, "Export event log", "cyberwatch-events.csv", "CSV files (*.csv)")
        if not destination:
            return
        try:
            count = self.store.export_events_csv(destination)
            QMessageBox.information(self, "Export complete", f"Exported {count} events to:\n{destination}")
        except OSError as exc:
            QMessageBox.warning(self, "Export failed", str(exc))

    def closeEvent(self, event):
        if self.discovery_worker and self.discovery_worker.isRunning():
            QMessageBox.information(self, "Scan in progress", "Wait for the network discovery scan to finish before closing CyberWatch.")
            event.ignore()
            return
        if self.port_worker and self.port_worker.isRunning():
            QMessageBox.information(self, "Port check in progress", "Wait for the port check to finish.")
            event.ignore()
            return
        self.monitor_timer.stop()
        event.accept()
