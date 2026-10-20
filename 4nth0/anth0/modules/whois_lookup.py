"""
WHOIS lookup de dominios.
"""
import whois
from colorama import Fore, Style


def run_lookup(domain):
    domain = domain.replace("http://", "").replace("https://", "").split("/")[0]
    print(Fore.CYAN + f"\n[*] Consultando WHOIS de: {domain}\n" + Style.RESET_ALL)

    try:
        data = whois.whois(domain)
    except Exception as e:
        print(Fore.RED + f"[!] Error en la consulta WHOIS: {e}" + Style.RESET_ALL)
        return None

    fields = {
        "Registrador": data.registrar,
        "Creado": data.creation_date,
        "Expira": data.expiration_date,
        "Actualizado": data.updated_date,
        "Nameservers": data.name_servers,
        "Estado": data.status,
        "Pais": data.get("country") if hasattr(data, "get") else None,
        "Organizacion": data.org,
    }

    for key, value in fields.items():
        if value:
            print(Fore.GREEN + f"    {key:<15}: {value}" + Style.RESET_ALL)

    return fields
