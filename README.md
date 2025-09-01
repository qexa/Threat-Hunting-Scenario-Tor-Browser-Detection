# Threat Hunting Scenario: Tor Browser Detection

🎯 Scenario Overview

**Environment:**
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Query Language: Kusto Query Language (KQL)
- Target Application: Tor Browser

**Background:**
Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

🔍 Investigation Methodology

### Phase 1: File Events Analysis
Check `DeviceFileEvents` for any `tor(.exe)` or `firefox(.exe)` file events.

### Phase 2: Process Analysis  
Check `DeviceProcessEvents` for any signs of installation or usage.

### Phase 3: Network Analysis
Check `DeviceNetworkEvents` for any signs of outgoing connections over known TOR ports.

📊 Investigation Results

🔎 File Events Investigation

**Query Used:**
```kusto
DeviceFileEvents
| where DeviceName == "rivj-tor-vm"
| where InitiatingProcessAccountName == "torboi"
| where FileName contains "tor"
| where Timestamp >= datetime(2025-04-11T22:31:26.3698616Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```

**Findings:**
Discovered user "torboi" downloaded a tor installer, or performed actions that resulted in many tor-related files being copied to the desktop and the creation of a file called "tor-shopping-list.txt" on the desktop. These events began at: `2025-04-11T22:31:26.3698616Z`

🔎 Process Events Investigation

**Query Used:**
```kusto
DeviceProcessEvents
| where DeviceName == "rivj-tor-vm"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```

**Findings:**
Evidence that user "torboi" opened the tor browser at: `Apr 11, 2025 5:32:07 PM`. Several instances of `firefox.exe` (Tor) as well as `tor.exe` were spawned afterward.

🔎 Network Events Investigation

**Query Used:**
```kusto
DeviceNetworkEvents
| where DeviceName == "rivj-tor-vm"
| where InitiatingProcessAccountName != "system"
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc
```

**Findings:**
On April 11, 2025, at 5:32 PM, virtual machine "rivj-tor-vm" had user account "torboi" successfully make a network connection to IP address `192.42.132.106`, specifically to the website: `https://www.c5yraaw54zp6bfs7n.com`. The connection was made by Tor from location: `C:\Users\torboi\Desktop\Tor Browser\Browser\TorBrowser\tor\tor.exe`

📋 Detailed Timeline Analysis

🟢 1. Installation Activity - Tor Browser Installation
**🕒 5:31:28 PM**
- User "torboi" on virtual machine "rivj-tor-vm" launched the Tor Browser installer: `tor-browser-windows-x86_64-portable-14.0.9.exe`
- Location: `C:\Users\torboi\Downloads`

🌐 2. Network Activity - Tor Network Connections

**🕒 5:32:29 PM**
- The Tor process (tor.exe) successfully connected to IP address `192.42.132.106`
- A connection was made to the hidden website: `https://www.c5yraaw54zp6bfs7n.com`

**🕒 5:32:29 PM**
- Another connection to `192.42.132.106` was logged by the same tor.exe process

**🕒 5:32:39 PM**
- The Tor Browser's Firefox component (firefox.exe) connected to `127.0.0.1` (localhost), showing it was routing traffic through the local Tor service as expected

⚙️ 3. Process Creation - Tor and Firefox Processes
**🕒 5:33:25 PM – 5:34:28 PM**
- Multiple Firefox browser processes were launched by the Tor Browser
- This likely represents the browser opening tabs or loading content
- Location: `C:\Users\torboi\Desktop\Tor Browser\Browser\firefox.exe`

📝 4. File Activity - Browser and User Files

**🕒 5:36:36 PM**
- File `formhistory.sqlite` was created in the Tor Browser folder (stores form data/autofill history)

**🕒 5:38:20 PM**
- File `webappsstore.sqlite` was created (stores local web app data like cookies or cached content)

**User File: tor-shopping-list**

**🕒 5:38:37 PM**
- File `tor-shopping-list.txt` was renamed
- A shortcut (.lnk) version was also created in the "Recent Files" folder, showing it was accessed

**🕒 5:39:02 PM**
- The `tor-shopping-list.txt` file was modified again on the Desktop

📈 Summary Timeline Table

| Time | Event Type | Summary |
|------|------------|---------|
| 5:31:28 PM | Installation | Tor Browser installer launched by user "torboi" |
| 5:32:29 PM | Network | Tor connects to hidden service IP & website |
| 5:32:39 PM | Network | Firefox connects locally to the Tor service (127.0.0.1) |
| 5:33–5:34 PM | Process Creation | Multiple Firefox processes launched by the browser |
| 5:36:36 PM | File Creation | Form history file created in Tor Browser folder |
| 5:38:20 PM | File Creation | Web storage file created (likely from browsing activity) |
| 5:38:37 PM | File Rename/Shortcut | tor-shopping-list.txt renamed and shortcut created |
| 5:39:02 PM | File Modified | tor-shopping-list.txt modified on Desktop |

🏁 Investigation Conclusion

The user "torboi" on the "rivj-tor-vm" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

🚨 Remediation Actions

**TOR usage was confirmed on the endpoint `rivj-tor-vm` by the user `torboi`. The device was isolated, and the user's direct manager was notified.**

📚 Additional KQL Queries for Tor Detection

Basic Tor Process Detection
```kusto
DeviceProcessEvents
| where FileName in~ ("firefox.exe", "tor.exe")
| where FolderPath has "Tor Browser"
```

Tor Network Traffic Detection
```kusto
DeviceNetworkEvents
| where RemotePort in (9001, 9030, 9050, 9051, 9150, 9151, 8443, 7070, 8118, 5000, 9100, 9005)
```

Known Tor Exit Nodes Detection
```kusto
DeviceNetworkEvents
| where RemoteIP in~ (
    "185.220.101.1", 
    "51.254.45.15", 
    "204.13.200.2", 
    "185.220.100.254"
)
```

🛡️ Detection Logic

- **Process Behavior:** firefox.exe launched from a user-accessible path linked to the Tor Browser
- **Network Activity:** Connections observed on ports associated with Tor network traffic
- **Exit Node Traffic:** Outbound connections matched known Tor IPs from the official list

📖 References

- [MITRE ATT&CK - Tor](https://attack.mitre.org/wiki/Software/S0183)
- [Microsoft Defender for Endpoint](https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/)
- [Kusto Query Language (KQL)](https://docs.microsoft.com/en-us/azure/data-explorer/kusto/query/)

---

**⚠️ Disclaimer:** This scenario is designed for educational and training purposes in controlled environments. Always follow your organization's policies and legal requirements when conducting threat hunting activities.

📁 Repository Structure

```
threat-hunting-scenario-tor/
│
├── README.md                    # Main documentation (this file)
├── queries/
│   ├── tor_file_events.kql     # File events detection queries
│   ├── tor_process_events.kql  # Process events detection queries
│   ├── tor_network_events.kql  # Network events detection queries
│   └── comprehensive_tor.kql   # Combined detection logic
├── docs/
│   ├── investigation_report.md # Detailed investigation findings
│   └── mitigation_steps.md     # Recommended remediation actions
├── data/
│   └── sample_logs.json        # Sample log data for testing
└── LICENSE                     # MIT License

```

---

🤝 Contributing

This is an educational resource. Feel free to:
- Submit improvements to detection queries
- Add new investigation scenarios
- Enhance documentation
- Report issues or suggestions

📄 License

MIT License - See [LICENSE](LICENSE) file for details.
