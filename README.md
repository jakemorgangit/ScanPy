# ScanPy

**ScanPy** (rhymes with "Scampi") is a lightweight, Python-based alternative to tools like Angry IP Scanner and Advanced IP Scanner. 
It allows users to scan IP ranges, identify active hosts, and perform advanced network management tasks. 
With a user-friendly GUI built using PyQt5, it is designed for system administrators and enthusiasts who need a powerful yet customisable network scanning tool.

![image](https://github.com/user-attachments/assets/e6d6d964-d2e4-4c00-8322-efa83ff62b73)

---

## Features

- **Customisable Scanning**: Scan a specified IP range and detect active hosts.
- **Editable Fields**: Save custom names and comments for each detected device, making management easier.
- **Saveable configuration**: Modifications to GUI layout (column width wetc) are saved
- **Connectivity**: Launch SSH or RDP sessions directly from the GUI for devices with open ports (22 or 3389).
- **OUI Database**: Fetch manufacturer details for MAC addresses using an updatable OUI database.
- **Persistent Data**: Store device names, comments, and configurations in a local SQLite database for future use.
- **Dark Mode**: A sleek dark theme for comfortable use in low-light environments.
- **Console Integration**: View real-time console logs within the application.
- **Cross-Platform**: Designed for Windows and Unix-like operating systems.

---

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/jakemorgangit/scanpy.git
   cd scanpy

2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt

3. Install the required dependencies:
   ```bash
   python ScanPy.py 


# Usage

## Launch the application

On first launch, you'll be prompted to initialise the OUI database - this takes approx 5 minutes and will populate the local database with up-to-date MAC address information from the OUI (Organizationally Unique Identifier) from https://standards-oui.ieee.org/
![image](https://github.com/user-attachments/assets/f162ad0f-5325-4581-8e6f-62feaec65006)

Once the database has been populated, you'll recevied this dialog box:

![image](https://github.com/user-attachments/assets/a1b45403-6ea0-49e8-8b6e-d1df32ca85e9)

The application is now ready to use.

Next, specify the IP range you want to scan (e.g., 192.168.1.1-192.168.1.254) in the IP range field

![image](https://github.com/user-attachments/assets/de28d0d9-9fdb-4ebc-9e76-987ab21994eb)

Click Start Scan to begin detecting devices in the specified range (you can also choose not to include any IP addresses in the range that are offline/down using the `Ignore Disconnected Hosts` tick box.

![image](https://github.com/user-attachments/assets/ac101ae8-fa8e-42ef-8457-b2eadefecb83)

The scan will now begin and any console information is logged to the console output log:

![image](https://github.com/user-attachments/assets/43d47c3e-f0f3-4417-b37e-6d3fc515cdbc)

For any hosts that have a SSH (port 22) or RDP (port 3389) port open, you can double click on the host row and launch a connection to that host

You can edit the Name and Comments fields for devices directly in the table.  These customs names and comments are saved to the local SQLLite database, and persist so are available the next time the tool is used.

Additionally, you save your GUI configurations (column width etc) and revisit them later, thanks to persistent database storage.


# Future Enhancements
- Add additional protocols for remote connections (e.g., Telnet).
- Include advanced filtering options for results.
- Implement export functionality to save scan results as CSV or JSON.
- Introduce parallelised scanning for faster results.

# Contributing
Contributions are welcome! Feel free to open issues or submit pull requests to improve functionality or fix bugs.

# License
This project is licensed under the MIT License.
