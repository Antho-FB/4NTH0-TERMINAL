"""
Verificador de certificados SSL/TLS: expiracion, emisor, cifrado.
"""
import ssl
import socket
import datetime
from colorama import Fore, Style


def run_check(hostname, port=443, timeout=10):
    hostname = hostname.replace("http://", "").replace("https://", "").split("/")[0]
    print(Fore.CYAN + f"\n[*] Verificando certificado SSL de: {hostname}:{port}\n" + Style.RESET_ALL)

    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()
    except ssl.SSLCertVerificationError as e:
        print(Fore.RED + f"[!] Certificado INVALIDO: {e}" + Style.RESET_ALL)
        return None
    except Exception as e:
        print(Fore.RED + f"[!] Error de conexion: {e}" + Style.RESET_ALL)
        return None

    subject = dict(x[0] for x in cert.get("subject", []))
    issuer = dict(x[0] for x in cert.get("issuer", []))
    not_after = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
    not_before = datetime.datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z")
    days_left = (not_after - datetime.datetime.utcnow()).days

    print(Fore.GREEN + f"[+] Protocolo TLS: {version}")
    print(f"[+] Cifrado: {cipher[0]} ({cipher[2]} bits)")
    print(f"[+] Common Name: {subject.get('commonName', 'N/A')}")
    print(f"[+] Emisor: {issuer.get('organizationName', issuer.get('commonName', 'N/A'))}")
    print(f"[+] Valido desde: {not_before.date()}")
    print(f"[+] Valido hasta: {not_after.date()}" + Style.RESET_ALL)

    if days_left < 0:
        print(Fore.RED + f"[!] CERTIFICADO EXPIRADO hace {-days_left} dias" + Style.RESET_ALL)
    elif days_left < 30:
        print(Fore.YELLOW + f"[!] Certificado expira en {days_left} dias" + Style.RESET_ALL)
    else:
        print(Fore.GREEN + f"[+] Certificado valido por {days_left} dias mas" + Style.RESET_ALL)

    sans = []
    for key, value in cert.get("subjectAltName", []):
        if key == "DNS":
            sans.append(value)
    if sans:
        print(Fore.CYAN + f"\n[*] Dominios alternativos (SAN): {', '.join(sans[:15])}" + Style.RESET_ALL)

    return {
        "version": version, "cipher": cipher, "subject": subject,
        "issuer": issuer, "not_before": str(not_before), "not_after": str(not_after),
        "days_left": days_left, "sans": sans,
    }
