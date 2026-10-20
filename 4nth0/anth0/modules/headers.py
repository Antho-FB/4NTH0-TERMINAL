"""
Analizador de cabeceras de seguridad HTTP.
"""
import requests
from colorama import Fore, Style

SECURITY_HEADERS = {
    "Strict-Transport-Security": "Fuerza HTTPS (HSTS)",
    "Content-Security-Policy": "Previene XSS/injection controlando fuentes",
    "X-Frame-Options": "Previene clickjacking",
    "X-Content-Type-Options": "Previene MIME sniffing",
    "Referrer-Policy": "Controla informacion enviada en el header Referer",
    "Permissions-Policy": "Controla acceso a APIs del navegador",
    "X-XSS-Protection": "Proteccion XSS legacy (deprecado pero aun visto)",
}

INFO_LEAK_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-Runtime"]


def run_check(url, timeout=10):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    print(Fore.CYAN + f"\n[*] Analizando headers de: {url}\n" + Style.RESET_ALL)

    try:
        resp = requests.get(url, timeout=timeout, allow_redirects=True,
                             headers={"User-Agent": "4NTH0-SecurityScanner/1.0"})
    except requests.exceptions.RequestException as e:
        print(Fore.RED + f"[!] Error de conexion: {e}" + Style.RESET_ALL)
        return None

    print(Fore.GREEN + f"[+] Status: {resp.status_code} | Final URL: {resp.url}\n" + Style.RESET_ALL)

    present = {}
    missing = []
    for header, desc in SECURITY_HEADERS.items():
        if header in resp.headers:
            present[header] = resp.headers[header]
            print(Fore.GREEN + f"    [OK] {header}: {resp.headers[header][:60]}" + Style.RESET_ALL)
        else:
            missing.append(header)
            print(Fore.RED + f"    [FALTA] {header}  -- {desc}" + Style.RESET_ALL)

    print()
    leaks = []
    for header in INFO_LEAK_HEADERS:
        if header in resp.headers:
            leaks.append((header, resp.headers[header]))
            print(Fore.YELLOW + f"    [INFO LEAK] {header}: {resp.headers[header]}" + Style.RESET_ALL)

    score = len(present) / len(SECURITY_HEADERS) * 100
    color = Fore.GREEN if score >= 70 else Fore.YELLOW if score >= 40 else Fore.RED
    print(color + f"\n[*] Puntaje de seguridad de headers: {score:.0f}%" + Style.RESET_ALL)

    return {"present": present, "missing": missing, "leaks": leaks, "score": score}
