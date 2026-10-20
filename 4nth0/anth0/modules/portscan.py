"""
Escaner de puertos TCP multithreaded con banner grabbing.
Uso etico unicamente: solo contra hosts propios o autorizados.
"""
import socket
import concurrent.futures
import time
from colorama import Fore, Style

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCBIND", 135: "MSRPC",
    139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB",
}


def grab_banner(ip, port, timeout=1.5):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            try:
                s.send(b"\r\n")
            except Exception:
                pass
            try:
                banner = s.recv(256).decode(errors="ignore").strip()
                return banner if banner else None
            except Exception:
                return None
    except Exception:
        return None


def scan_port(ip, port, timeout):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            if result == 0:
                return port
    except Exception:
        pass
    return None


def resolve_target(target):
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None


def run_scan(target, ports=None, timeout=1.0, max_workers=200, grab_banners=True):
    ip = resolve_target(target)
    if not ip:
        print(Fore.RED + f"[!] No se pudo resolver el host: {target}" + Style.RESET_ALL)
        return []

    if ports is None:
        ports = list(COMMON_PORTS.keys())
    elif isinstance(ports, str):
        ports = parse_port_range(ports)

    print(Fore.CYAN + f"\n[*] Objetivo: {target} ({ip})")
    print(f"[*] Escaneando {len(ports)} puertos...\n" + Style.RESET_ALL)

    start = time.time()
    open_ports = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(scan_port, ip, p, timeout): p for p in ports}
        for future in concurrent.futures.as_completed(futures):
            port = futures[future]
            result = future.result()
            if result:
                open_ports.append(result)

    open_ports.sort()
    elapsed = time.time() - start

    if not open_ports:
        print(Fore.YELLOW + "[!] No se encontraron puertos abiertos." + Style.RESET_ALL)
        return []

    print(Fore.GREEN + f"[+] {len(open_ports)} puerto(s) abierto(s):\n" + Style.RESET_ALL)
    results = []
    for port in open_ports:
        service = COMMON_PORTS.get(port, "unknown")
        banner = grab_banner(ip, port) if grab_banners else None
        line = f"    {port:>6}/tcp  {service:<12}"
        if banner:
            line += f"  -> {banner[:80]}"
        print(Fore.GREEN + line + Style.RESET_ALL)
        results.append({"port": port, "service": service, "banner": banner})

    print(Fore.CYAN + f"\n[*] Escaneo completado en {elapsed:.2f}s" + Style.RESET_ALL)
    return results


def parse_port_range(spec):
    """Acepta '1-1000', '80,443,8080' o combinaciones '1-100,443,8000-8100'"""
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            a, b = part.split("-")
            ports.update(range(int(a), int(b) + 1))
        elif part:
            ports.add(int(part))
    return sorted(ports)
