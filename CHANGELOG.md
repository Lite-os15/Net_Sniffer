# Changelog

All notable changes to **NetworkSniffer** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added
- Initial release of NetworkSniffer with dual-mode functionality:
  - **ARP Spoof Module**: Two-way ARP cache poisoning (MITM) for capturing LAN traffic
  - **Packet Sniffer Module**: Live HTTP/DNS/TCP packet inspection on selected interfaces
- Cross-platform support (Linux, macOS, Windows with Npcap)
- Interactive menu-driven interface with color-coded terminal output

### Features
- Background ARP spoofing thread that runs independently of the sniffer
- Auto-detection of default gateway IP from routing table or `/proc/net/route`
- Real-time network device scanning via ARP requests
- Credential keyword detection in HTTP POST bodies (username, password, email, login)
- DNS query capture for domain visibility even on HTTPS traffic
- Optional raw packet dump mode with full HTTP header inspection
- TCP SYN connection tracking when enabled

### Architecture
- Modular design: `arp_spoof.py` handles MITM logic, `net_sniffer.py` handles packet capture
- Thread-safe background spoofing with automatic ARP table restoration on stop
- Privilege detection and helper prompts for Linux/macOS/Windows environments

---

## [0.1.0] — 2024-XX-XX (Initial Release)

### Added
- Initial project structure and core functionality
- `arp_spoof.py`: ARP spoofing engine with MAC resolution, IP forwarding management, and session lifecycle
- `net_sniffer.py`: Packet sniffing engine with HTTP/DNS/TCP layer inspection
- `main.py`: Interactive CLI menu integrating both modules
- `requirements.txt`: Python dependencies (scapy, colorama, prettytable, psutil, wcwidth)
- `README.md`: Comprehensive documentation with Mermaid architecture diagrams
- `.gitignore`: Standard Python project exclusions

### Platforms
- **Linux**: Full support via libpcap and root privileges
- **macOS**: Full support via libpcap and root privileges  
- **Windows**: Support via Npcap (requires separate installation)

---

## [0.1.1] — Pending Future Release

### Planned Improvements
- Add unit tests for core functions (`get_mac()`, `url_extractor()`, etc.)
- GitHub Actions CI/CD pipeline for automated testing across platforms
- Enhanced credential detection with regex patterns and case-insensitive matching
- Optional HTTPS decryption support (via MITM proxy integration)
- Export captured packets to `.pcap` files
- Configuration file support for persistent settings

---

## [0.1.2] — Pending Future Release

### Planned Improvements
- WebSocket/TLS layer inspection capabilities
- Multi-interface simultaneous sniffing
- Web dashboard or GUI frontend (optional)
- Plugin architecture for custom packet handlers
- Enhanced logging with timestamped output files

---

**Project Maintainer**: Your Name  
**License**: MIT License  
**Website**: [GitHub Repository](https://github.com/Lite-os15/NetworkSniffer)

---

> 💡 **Tip**: When releasing a new version, update the `[Unreleased]` section and create a new release tag (e.g., `v0.2.0`) with a summary of changes.