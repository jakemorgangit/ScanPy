# PyIPScanner.py

import sys
import os
import re
import socket
import subprocess
import json
import sqlite3
import requests
import traceback
from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QLineEdit, QPushButton,
    QTableWidget, QTableWidgetItem, QVBoxLayout, QHBoxLayout,
    QProgressBar, QMessageBox, QHeaderView, QCheckBox, QTextEdit, QSplitter
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QObject, QSize
from PyQt5.QtGui import QColor, QFont, QTextCursor  # Imported QTextCursor


# Determine the script's directory
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# Paths to store the SQLite database in the script's directory
DB_PATH = os.path.join(SCRIPT_DIR, "scanpy.db")


def normalize_mac(mac):
    """
    Normalizes MAC address to uppercase with colons.
    E.g., '08-EA-44-XX-YY-ZZ' or '08:EA:44:XX:YY:ZZ' -> '08:EA:44:XX:YY:ZZ'
    """
    return mac.upper().replace("-", ":").replace(".", ":").strip()


class DatabaseManager:
    """
    Manages all database operations including OUI data, network names, and configurations.
    Each method creates its own connection to ensure thread safety.
    """

    def __init__(self, db_path):
        self.db_path = db_path
        self.initialize_database()

    def initialize_database(self):
        """
        Initializes the SQLite database and creates necessary tables.
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                # Create OUI table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS oui (
                        mac_prefix TEXT PRIMARY KEY,
                        manufacturer TEXT
                    )
                ''')

                # Create Network Names table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS network_names (
                        mac_address TEXT PRIMARY KEY,
                        name TEXT,
                        comments TEXT
                    )
                ''')

                # Create Configurations table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS configurations (
                        key TEXT PRIMARY KEY,
                        value TEXT
                    )
                ''')

                conn.commit()
        except sqlite3.Error as e:
            print(f"SQLite Error (initialize_database): {e}")

    def insert_oui_data(self, mac_prefix, manufacturer):
        """
        Inserts a new OUI entry into the database.
        Each call creates its own connection.
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT OR REPLACE INTO oui (mac_prefix, manufacturer)
                    VALUES (?, ?)
                ''', (mac_prefix, manufacturer))
                conn.commit()
        except sqlite3.Error as e:
            print(f"SQLite Error (insert_oui_data): {e}")

    def get_manufacturer(self, mac):
        """
        Retrieves the manufacturer name based on the MAC address.
        Each call creates its own connection.
        """
        mac_prefix = ':'.join(mac.split(':')[:3])
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT manufacturer FROM oui
                    WHERE mac_prefix = ?
                ''', (mac_prefix,))
                result = cursor.fetchone()
                return result[0] if result else "Unknown"
        except sqlite3.Error as e:
            print(f"SQLite Error (get_manufacturer): {e}")
            return "Unknown"

    def load_network_names(self):
        """
        Loads network names and comments from the database.
        Returns a dictionary with MAC addresses as keys.
        Each call creates its own connection.
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT mac_address, name, comments FROM network_names')
                rows = cursor.fetchall()
                return {normalize_mac(row[0]): {"Name": row[1], "Comments": row[2]} for row in rows}
        except sqlite3.Error as e:
            print(f"SQLite Error (load_network_names): {e}")
            return {}

    def update_network_name(self, mac, name, comments):
        """
        Updates or inserts a network name and comments for a given MAC address.
        Each call creates its own connection.
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT OR REPLACE INTO network_names (mac_address, name, comments)
                    VALUES (?, ?, ?)
                ''', (mac, name, comments))
                conn.commit()
        except sqlite3.Error as e:
            print(f"SQLite Error (update_network_name): {e}")

    def get_config(self, key):
        """
        Retrieves a configuration value based on the key.
        Each call creates its own connection.
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT value FROM configurations
                    WHERE key = ?
                ''', (key,))
                result = cursor.fetchone()
                return result[0] if result else None
        except sqlite3.Error as e:
            print(f"SQLite Error (get_config): {e}")
            return None

    def set_config(self, key, value):
        """
        Sets or updates a configuration value based on the key.
        Each call creates its own connection.
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT OR REPLACE INTO configurations (key, value)
                    VALUES (?, ?)
                ''', (key, value))
                conn.commit()
        except sqlite3.Error as e:
            print(f"SQLite Error (set_config): {e}")

    def close(self):
        """
        Placeholder for closing the database connection if persistent connections are used in future.
        Currently, connections are managed using context managers.
        """
        pass


def download_oui():
    """
    Downloads the OUI database from the IEEE website.
    Returns the content as a string if successful, None otherwise.
    """
    url = "https://standards-oui.ieee.org/oui/oui.txt"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"  # Mimic a browser request
    }
    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        print("OUI database downloaded successfully.")
        return response.text
    except Exception as e:
        print(f"Failed to download OUI database: {e}")
        return None


def parse_oui(oui_text):
    """
    Parses the OUI text and yields (mac_prefix, manufacturer) tuples.
    """
    for line in oui_text.splitlines():
        # Example line: '08-EA-44   (hex)		Extreme Networks Headquarters'
        match = re.match(r'^([0-9A-F]{2}[:-]){2}[0-9A-F]{2}\s+\(hex\)\s+(.*)', line)
        if match:
            mac_prefix = normalize_mac(match.group(0).split()[0])
            manufacturer = match.group(2).strip()
            yield (mac_prefix, manufacturer)


class Stream(QObject):
    """
    Redirects stdout and stderr to the GUI console.
    """
    text_written = pyqtSignal(str)

    def write(self, text):
        self.text_written.emit(str(text))

    def flush(self):
        pass  # No action needed for flush


class ScanThread(QThread):
    """
    Worker thread for scanning the network.
    Emits progress signals with scan results.
    """
    progress = pyqtSignal(int, object)  # Changed to object to allow None
    finished = pyqtSignal()

    def __init__(self, ip_list, ignore_down=False, network_names=None, db_manager=None):
        super().__init__()
        self.ip_list = ip_list
        self.ignore_down = ignore_down
        self.network_names = network_names if network_names else {}
        self.db_manager = db_manager
        self._is_running = True  # Flag to control thread running

    def run(self):
        try:
            total = len(self.ip_list)
            count = 0

            for ip in self.ip_list:
                if not self._is_running:
                    break  # Stop the scan if flag is unset
                result = {"Status": "Down", "Name": "", "IPAddress": ip,
                          "Manufacturer": "", "MACAddress": "", "OpenPorts": "", "Comments": ""}
                # Ping to check if host is up
                if self.ping_host(ip):
                    print(f"{ip} is up.")
                    result["Status"] = "Up"
                    # Get hostname
                    try:
                        hostname = socket.gethostbyaddr(ip)[0]
                        result["Name"] = hostname
                        print(f"Hostname for {ip}: {hostname}")
                    except:
                        print(f"Hostname for {ip} not found.")
                        result["Name"] = ""
                    # Get MAC Address
                    mac = self.get_mac(ip)
                    if mac:
                        normalized_mac = normalize_mac(mac)
                        result["MACAddress"] = normalized_mac
                        # Get Manufacturer from DB
                        manufacturer = self.db_manager.get_manufacturer(normalized_mac)
                        result["Manufacturer"] = manufacturer
                        print(f"MAC Address for {ip}: {normalized_mac}, Manufacturer: {manufacturer}")
                        # Override Name and Comments if exists
                        if normalized_mac in self.network_names:
                            if "Name" in self.network_names[normalized_mac]:
                                result["Name"] = self.network_names[normalized_mac]["Name"]
                                print(f"Using saved name for {mac}: {result['Name']}")
                            if "Comments" in self.network_names[normalized_mac]:
                                result["Comments"] = self.network_names[normalized_mac]["Comments"]
                                print(f"Using saved comments for {mac}: {result['Comments']}")
                    else:
                        print(f"MAC Address for {ip} not found.")
                        result["Manufacturer"] = "Unknown"
                    # Check open ports
                    open_ports = []
                    if self.check_port(ip, 22):
                        open_ports.append("22")
                        print(f"Port 22 is open on {ip}.")
                    if self.check_port(ip, 3389):
                        open_ports.append("3389")
                        print(f"Port 3389 is open on {ip}.")
                    result["OpenPorts"] = ", ".join(open_ports)
                else:
                    print(f"{ip} is down.")
                # Update progress
                count += 1
                percent = int((count / total) * 100)
                if not self.ignore_down or result["Status"] == "Up":
                    self.progress.emit(percent, result)
                else:
                    self.progress.emit(percent, None)

            self.finished.emit()
        except Exception:
            print("Exception in ScanThread:")
            traceback.print_exc()
            self.finished.emit()

    def stop(self):
        """
        Stops the scanning process.
        """
        self._is_running = False

    def ping_host(self, ip):
        """
        Pings the host to check if it's up.
        """
        try:
            # Ping command varies by OS
            param = '-n' if sys.platform.startswith('win') else '-c'
            # Timeout parameter differs between Windows and Unix
            timeout_param = '-w' if sys.platform.startswith('win') else '-W'
            timeout = '1000' if sys.platform.startswith('win') else '1'
            command = ['ping', param, '1', timeout_param, timeout, ip]
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return result.returncode == 0
        except:
            return False

    def get_mac(self, ip):
        """
        Retrieves the MAC address from the ARP table.
        """
        try:
            if sys.platform.startswith('win'):
                command = ['arp', '-a', ip]
                output = subprocess.check_output(command, encoding='utf-8')
                match = re.search(r'([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}', output)
                if match:
                    return match.group(0).replace("-", ":")
            else:
                # Unix-like systems
                command = ['arp', '-n', ip]
                output = subprocess.check_output(command, encoding='utf-8')
                match = re.search(r'([0-9A-Fa-f]{2}[:]){5}[0-9A-Fa-f]{2}', output)
                if match:
                    return match.group(0).upper()
        except:
            return None

    def check_port(self, ip, port):
        """
        Checks if a specific port is open on the host.
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(0.5)
                result = sock.connect_ex((ip, port))
                return result == 0
        except:
            return False


class NetworkScanner(QWidget):
    """
    Main application window for the Network Scanner.
    """
    def __init__(self):
        super().__init__()
        self.db_manager = DatabaseManager(DB_PATH)
        self.network_names = self.db_manager.load_network_names()
        self.init_ui()

    def init_ui(self):
        # Set Window Title
        self.setWindowTitle("ScanPy - Python Network Scanner")
        self.resize(900, 800)  # Allow window to be resizable

        # Main Layout using QSplitter for resizable panes
        main_layout = QVBoxLayout()

        splitter = QSplitter(Qt.Vertical)

        # Upper part: Controls and Table
        upper_widget = QWidget()
        upper_layout = QVBoxLayout()

        # Top Layout for IP Range, Scan Button, and Checkbox
        top_layout = QHBoxLayout()

        # IP Range Label and TextBox
        self.lbl_range = QLabel("IP Range (e.g., 192.168.4.1-192.168.5.254):")
        self.txt_range = QLineEdit()
        self.txt_range.setFixedWidth(600)
        top_layout.addWidget(self.lbl_range)
        top_layout.addWidget(self.txt_range)

        # Scan Button
        self.btn_scan = QPushButton("Start Scan")
        self.btn_scan.clicked.connect(self.start_scan)
        top_layout.addWidget(self.btn_scan)

        # Checkbox to Ignore Disconnected Hosts
        self.checkbox_ignore = QCheckBox("Ignore Disconnected Hosts")
        top_layout.addWidget(self.checkbox_ignore)

        upper_layout.addLayout(top_layout)

        # Table for Results
        self.table = QTableWidget()
        self.table.setColumnCount(7)  # Added Comments column
        self.table.setHorizontalHeaderLabels(["Status", "Name", "IP Address",
                                             "Manufacturer", "MAC Address", "Open Ports", "Comments"])
        self.table.setEditTriggers(QTableWidget.DoubleClicked | QTableWidget.SelectedClicked)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        # Removed the per-widget stylesheet
        # self.table.setStyleSheet("background-color: #2b2b2b; color: #f0f0f0;")
        self.table.doubleClicked.connect(self.handle_double_click)
        self.table.itemChanged.connect(self.handle_item_changed)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.table.horizontalHeader().setSectionsClickable(True)
        self.table.setAlternatingRowColors(False)  # Disabled alternating row colors
        upper_layout.addWidget(self.table)

        # Progress Bar and Status Label
        progress_layout = QHBoxLayout()
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        self.status_label = QLabel("Idle")
        progress_layout.addWidget(self.progress_bar)
        progress_layout.addWidget(self.status_label)
        upper_layout.addLayout(progress_layout)

        upper_widget.setLayout(upper_layout)
        splitter.addWidget(upper_widget)

        # Lower part: Console
        console_widget = QWidget()
        console_layout = QVBoxLayout()

        console_label = QLabel("Console Output:")
        console_layout.addWidget(console_label)

        self.console = QTextEdit()
        self.console.setReadOnly(True)
        self.console.setStyleSheet("background-color: #1e1e1e; color: #d4d4d4;")
        self.console.setFont(QFont("Courier", 10))
        # Adjust the height to display approximately 6 lines
        self.console.setFixedHeight(self.console.fontMetrics().height() * 7)  # 6 lines + padding
        console_layout.addWidget(self.console)

        console_widget.setLayout(console_layout)
        splitter.addWidget(console_widget)

        main_layout.addWidget(splitter)
        self.setLayout(main_layout)
        self.show()

        # Apply saved column widths and window size from the database
        self.apply_saved_config()

        # Initialize OUI Database
        self.initialize_oui_database()

        # Setup Console Redirection
        self.redirect_console()

        # Apply dark theme
        self.set_dark_theme()  # Ensure this line is uncommented

        # Connect signals for saving window and column configurations
        self.horizontalHeader = self.table.horizontalHeader()
        self.horizontalHeader.sectionResized.connect(self.save_column_width)
        self.installEventFilter(self)  # To capture window resize events

    def set_dark_theme(self):
        """
        Applies a dark stylesheet to the application.
        """
        dark_stylesheet = """
            QWidget {
                background-color: #2b2b2b;
                color: #f0f0f0;
                font-family: Arial;
                font-size: 14px;
            }
            QLineEdit, QTableWidget, QProgressBar, QTextEdit {
                background-color: #3c3c3c;
                border: 1px solid #555555;
            }
            QPushButton {
                background-color: #555555;
                border: none;
                padding: 5px 10px;
                color: #f0f0f0;
            }
            QPushButton:hover {
                background-color: #6c6c6c;
            }
            QHeaderView::section {
                background-color: #444444;
                color: #f0f0f0;
                padding: 4px;
                border: 1px solid #555555;
                font-weight: bold;  /* Makes header text bold */
            }
            QTableWidget::item:selected {
                background-color: #5a5a5a;
                color: #ffffff;
            }
            QCheckBox {
                color: #f0f0f0;
            }
            QTextEdit {
                selection-background-color: #5a5a5a;
            }
            QProgressBar {
                text-align: center;
                color: #f0f0f0;
            }
        """
        self.setStyleSheet(dark_stylesheet)

    def set_default_ip_range(self):
        """
        Sets the default IP range to 192.168.4.1-192.168.5.254.
        """
        self.txt_range.setText("192.168.4.1-192.168.5.254")

    def apply_saved_config(self):
        """
        Applies saved window size and column widths from the database.
        """
        # Apply window size
        width = self.db_manager.get_config("window_width")
        height = self.db_manager.get_config("window_height")
        if width and height:
            try:
                self.resize(int(width), int(height))
            except:
                pass  # If conversion fails, keep default size

        # Apply column widths
        column_widths = {}
        for i, header in enumerate(["Status", "Name", "IP Address",
                                    "Manufacturer", "MAC Address", "Open Ports", "Comments"]):
            width = self.db_manager.get_config(f"column_width_{i}")
            if width:
                try:
                    self.table.setColumnWidth(i, int(width))
                except:
                    pass  # If conversion fails, keep default width

    def initialize_oui_database(self):
        """
        Initializes the OUI database. Prompts user to create or refresh if needed.
        """
        cursor = None
        try:
            with sqlite3.connect(self.db_manager.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM oui")
                count = cursor.fetchone()[0]
        except sqlite3.Error as e:
            print(f"SQLite Error (initialize_oui_database): {e}")
            count = 0  # Assume empty if error occurs

        if count == 0:
            # OUI table is empty, prompt to create from OUI.txt
            reply = QMessageBox.question(
                self, 'Initialize OUI Database',
                "The OUI database is not initialized. Do you want to download and populate it now? (takes approx 5 minutes)",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes
            )
            if reply == QMessageBox.Yes:
                oui_text = download_oui()
                if oui_text:
                    for mac_prefix, manufacturer in parse_oui(oui_text):
                        self.db_manager.insert_oui_data(mac_prefix, manufacturer)
                    QMessageBox.information(self, "Success", "OUI database has been initialized.")
                    print("OUI database has been initialized.")
                else:
                    QMessageBox.critical(self, "Error", "Failed to download OUI database.")
        else:
            # OUI table exists, prompt to refresh
            reply = QMessageBox.question(
                self, 'Refresh OUI Database',
                "The OUI database already exists. Do you want to refresh it with the latest data?",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No
            )
            if reply == QMessageBox.Yes:
                oui_text = download_oui()
                if oui_text:
                    for mac_prefix, manufacturer in parse_oui(oui_text):
                        self.db_manager.insert_oui_data(mac_prefix, manufacturer)
                    QMessageBox.information(self, "Success", "OUI database has been refreshed.")
                    print("OUI database has been refreshed.")
                else:
                    QMessageBox.critical(self, "Error", "Failed to download OUI database.")

    def redirect_console(self):
        """
        Redirects stdout and stderr to the GUI console.
        """
        self.stream = Stream()
        self.stream.text_written.connect(self.append_console_text)
        sys.stdout = self.stream
        sys.stderr = self.stream

    def append_console_text(self, text):
        """
        Appends text to the console widget.
        Maintains only the last 6 lines.
        """
        self.console.moveCursor(QTextCursor.End)
        self.console.insertPlainText(text)
        self.console.moveCursor(QTextCursor.End)

        # Maintain only the last 6 lines
        lines = self.console.toPlainText().split('\n')
        if len(lines) > 6:
            # Keep only the last 6 lines
            new_text = '\n'.join(lines[-6:])
            self.console.blockSignals(True)
            self.console.setPlainText(new_text)
            self.console.blockSignals(False)
            self.console.moveCursor(QTextCursor.End)

    def validate_ip_range(self, ip_range):
        """
        Validates the IP range format.
        """
        pattern = r"^(\d{1,3}(?:\.\d{1,3}){3})-(\d{1,3}(?:\.\d{1,3}){3})$"
        match = re.match(pattern, ip_range)
        if not match:
            return False
        start_ip, end_ip = match.groups()
        try:
            socket.inet_aton(start_ip)
            socket.inet_aton(end_ip)
            return True
        except socket.error:
            return False

    def generate_ip_range(self, start_ip, end_ip):
        """
        Generates a list of IP addresses from start_ip to end_ip.
        """
        try:
            start = list(map(int, start_ip.split('.')))
            end = list(map(int, end_ip.split('.')))
            temp = start.copy()
            ip_list = []

            ip_list.append(start_ip)
            while temp != end:
                for i in range(3, -1, -1):
                    if temp[i] < 255:
                        temp[i] += 1
                        for j in range(i+1, 4):
                            temp[j] = 0
                        break
                ip_list.append(".".join(map(str, temp)))
            return ip_list
        except:
            return None

    def start_scan(self):
        """
        Initiates or stops the network scan based on current state.
        """
        if hasattr(self, 'scan_thread') and self.scan_thread.isRunning():
            # If scanning is ongoing, stop the scan
            self.scan_thread.stop()
            self.scan_thread.wait()
            self.status_label.setText("Scan Stopped")
            self.btn_scan.setText("Start Scan")
            print("Network scan stopped by user.")
            QMessageBox.information(self, "Info", "Network scan stopped.")
            return

        # Otherwise, start a new scan
        ip_range = self.txt_range.text().strip()
        if not self.validate_ip_range(ip_range):
            QMessageBox.critical(self, "Error", "Invalid IP range format. Use format like 192.168.4.1-192.168.5.254")
            return
        start_ip, end_ip = ip_range.split('-')
        ip_list = self.generate_ip_range(start_ip, end_ip)
        if not ip_list:
            QMessageBox.critical(self, "Error", "Failed to generate IP list. Check the IP range.")
            return
        self.table.blockSignals(True)  # Prevent itemChanged signal during setup
        self.table.setRowCount(0)
        self.table.blockSignals(False)
        self.progress_bar.setValue(0)
        self.status_label.setText("Scanning...")
        self.btn_scan.setText("Stop Scan")
        print(f"Starting network scan from {start_ip} to {end_ip}.")

        ignore_down = self.checkbox_ignore.isChecked()

        # Start scanning in a separate thread
        self.scan_thread = ScanThread(ip_list, ignore_down=ignore_down,
                                      network_names=self.network_names, db_manager=self.db_manager)
        self.scan_thread.progress.connect(self.update_progress)
        self.scan_thread.finished.connect(self.scan_finished)
        self.scan_thread.start()

    def update_progress(self, percent, result):
        """
        Updates the table and progress bar with scan results.
        """
        self.progress_bar.setValue(percent)
        if result:
            row_position = self.table.rowCount()
            self.table.insertRow(row_position)
            # Status as colored indicator (green/red box)
            status_item = QTableWidgetItem()
            status_item.setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable)
            if result["Status"] == "Up":
                status_item.setBackground(QColor(0, 255, 0))  # Green
            else:
                status_item.setBackground(QColor(255, 0, 0))  # Red
            # Optionally, remove text by setting it to empty string
            # status_item.setText("")
            status_item.setToolTip(result["Status"])  # Show status on hover
            self.table.setItem(row_position, 0, status_item)
            # Name
            name_item = QTableWidgetItem(result["Name"])
            name_item.setFlags(name_item.flags() | Qt.ItemIsEditable)
            self.table.setItem(row_position, 1, name_item)
            # IP Address
            ip_item = QTableWidgetItem(result["IPAddress"])
            self.table.setItem(row_position, 2, ip_item)
            # Manufacturer
            manufacturer_item = QTableWidgetItem(result["Manufacturer"])
            self.table.setItem(row_position, 3, manufacturer_item)
            # MAC Address
            mac_item = QTableWidgetItem(result["MACAddress"])
            self.table.setItem(row_position, 4, mac_item)
            # Open Ports
            ports_item = QTableWidgetItem(result["OpenPorts"])
            self.table.setItem(row_position, 5, ports_item)
            # Comments
            comments_item = QTableWidgetItem(result["Comments"])
            comments_item.setFlags(comments_item.flags() | Qt.ItemIsEditable)
            self.table.setItem(row_position, 6, comments_item)

    def scan_finished(self):
        """
        Handles actions after the scan is complete.
        """
        if hasattr(self, 'scan_thread') and not self.scan_thread.isRunning():
            self.status_label.setText("Scan Complete")
            self.btn_scan.setText("Start Scan")
            print("Network scan completed.")
            QMessageBox.information(self, "Info", "Network scan completed.")
            # Save network names to the database
            self.save_network_names()

    def handle_double_click(self):
        """
        Handles double-click events on table rows to launch RDP or SSH.
        """
        selected_row = self.table.currentRow()
        if selected_row < 0:
            return
        ip_item = self.table.item(selected_row, 2)
        ports_item = self.table.item(selected_row, 5)
        if not ip_item or not ports_item:
            return
        ip = ip_item.text()
        ports = ports_item.text()
        if "3389" in ports:
            # Launch RDP
            try:
                subprocess.Popen(["mstsc.exe", "/v:" + ip])
                print(f"Launched RDP session to {ip}.")
            except Exception as e:
                print(f"Failed to launch RDP: {e}")
                QMessageBox.critical(self, "Error", f"Failed to launch RDP: {e}")
        elif "22" in ports:
            # Launch SSH
            try:
                # Check if 'ssh' command is available
                cmd = "where" if sys.platform.startswith('win') else "which"
                result = subprocess.run([cmd, "ssh"],
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                if result.returncode != 0:
                    raise FileNotFoundError("SSH client not found.")
                subprocess.Popen(["ssh", ip])
                print(f"Launched SSH session to {ip}.")
            except Exception as e:
                print(f"Failed to launch SSH: {e}")
                QMessageBox.critical(self, "Error", f"Failed to launch SSH: {e}")

    def handle_item_changed(self, item):
        """
        Handles changes in editable cells ("Name" and "Comments").
        """
        row = item.row()
        column = item.column()
        if column not in [1, 6]:  # Only "Name" and "Comments" are editable
            return
        mac_item = self.table.item(row, 4)
        if not mac_item:
            return
        mac = normalize_mac(mac_item.text())
        if mac not in self.network_names:
            self.network_names[mac] = {}
        if column == 1:
            # Name column
            self.network_names[mac]["Name"] = item.text()
            print(f"Updated Name for {mac}: {item.text()}")
        elif column == 6:
            # Comments column
            self.network_names[mac]["Comments"] = item.text()
            print(f"Updated Comments for {mac}: {item.text()}")
        self.db_manager.update_network_name(mac, self.network_names[mac].get("Name", ""),
                                            self.network_names[mac].get("Comments", ""))

    def save_network_names(self):
        """
        Saves the current network names and comments to the database.
        """
        # Iterate through the table and save names and comments
        for row in range(self.table.rowCount()):
            mac_item = self.table.item(row, 4)
            if not mac_item:
                continue
            mac = normalize_mac(mac_item.text())
            name_item = self.table.item(row, 1)
            comments_item = self.table.item(row, 6)
            name = name_item.text() if name_item else ""
            comments = comments_item.text() if comments_item else ""
            self.db_manager.update_network_name(mac, name, comments)
            print(f"Saved Name and Comments for {mac} to database.")

    def save_config(self):
        """
        Saves GUI configurations (window size and column widths) to the database.
        """
        # Save window size
        size = self.size()
        self.db_manager.set_config("window_width", str(size.width()))
        self.db_manager.set_config("window_height", str(size.height()))
        print(f"Saved window size: {size.width()}x{size.height()}")

        # Save column widths
        for i, header in enumerate(["Status", "Name", "IP Address",
                                    "Manufacturer", "MAC Address", "Open Ports", "Comments"]):
            width = self.table.columnWidth(i)
            self.db_manager.set_config(f"column_width_{i}", str(width))
            print(f"Saved column width for '{header}': {width}px")

    def eventFilter(self, source, event):
        """
        Filters events to capture window resize events.
        """
        if event.type() == event.Resize:
            self.save_config()
        return super().eventFilter(source, event)

    def save_column_width(self, logicalIndex, oldSize, newSize):
        """
        Saves the new column width to the database when a column is resized.
        """
        self.db_manager.set_config(f"column_width_{logicalIndex}", str(newSize))
        header = self.table.horizontalHeaderItem(logicalIndex).text()
        print(f"Column '{header}' resized to {newSize}px")

    def closeEvent(self, event):
        """
        Handles the window close event to save network names and config.
        """
        self.save_network_names()
        self.save_config()
        self.db_manager.close()
        print("Application closed.")
        event.accept()


def load_config():
    """
    Placeholder function since configurations are now handled by the database.
    """
    return {}


# Global exception handler
def excepthook(type, value, tb):
    """
    Handles uncaught exceptions and logs them to the in-GUI console.
    """
    error_message = ''.join(traceback.format_exception(type, value, tb))
    print("Unhandled exception:")
    print(error_message)


# Set the global exception handler
sys.excepthook = excepthook


# Entry Point
if __name__ == "__main__":
    app = QApplication(sys.argv)
    scanner = NetworkScanner()
    sys.exit(app.exec_())
