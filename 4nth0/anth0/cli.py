#!/usr/bin/env python3
"""
4NTH0 - Suite de ciberseguridad en terminal.
Uso etico unicamente: sistemas propios o con autorizacion explicita.
"""
import sys
import json
import datetime
from colorama import Fore, Style

from anth0.banner import show_banner
from anth0.modules import portscan, subdomain, headers, sslcheck, hashid, pwcheck, whois_lookup

MENU = """
{cyan}  [1]  Escaner de puertos (TCP + banner grabbing)
  [2]  Enumeracion de subdominios (DNS brute force)
  [3]  Analizador de headers de seguridad HTTP
  [4]  Verificador de certificado SSL/TLS
  [5]  Identificar / crackear hash (diccionario)
  [6]  Analizador de fortaleza de contrasena
  [7]  WHOIS lookup
  [0]  Salir
{reset}"""

LAST_RESULT = {"module": None, "target": None, "data": None}


def save_report():
    if not LAST_RESULT["data"]:
        print(Fore.YELLOW + "[!] No hay resultados para guardar todavia." + Style.RESET_ALL)
        return
    filename = f"4nth0_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename, "w") as f:
        json.dump(LAST_RESULT, f, indent=2, default=str)
    print(Fore.GREEN + f"[+] Reporte guardado en: {filename}" + Style.RESET_ALL)


def confirm_authorization(target):
    print(Fore.YELLOW + f"\n[?] Confirma que tienes AUTORIZACION para probar '{target}' (s/n): " + Style.RESET_ALL, end="")
    resp = input().strip().lower()
    return resp in ("s", "si", "y", "yes")


def menu_portscan():
    target = input(Fore.CYAN + "\n  Objetivo (IP o dominio): " + Style.RESET_ALL).strip()
    if not target:
        return
    if not confirm_authorization(target):
        print(Fore.RED + "[!] Cancelado. Solo escanea objetivos autorizados." + Style.RESET_ALL)
        return
    port_spec = input(Fore.CYAN + "  Puertos (enter = top comunes, o ej '1-1000'): " + Style.RESET_ALL).strip()
    ports = port_spec if port_spec else None
    result = portscan.run_scan(target, ports=ports)
    LAST_RESULT.update(module="portscan", target=target, data=result)


def menu_subdomain():
    domain = input(Fore.CYAN + "\n  Dominio (ej: ejemplo.com): " + Style.RESET_ALL).strip()
    if not domain:
        return
    if not confirm_authorization(domain):
        print(Fore.RED + "[!] Cancelado." + Style.RESET_ALL)
        return
    result = subdomain.run_enum(domain)
    LAST_RESULT.update(module="subdomain", target=domain, data=result)


def menu_headers():
    url = input(Fore.CYAN + "\n  URL (ej: https://ejemplo.com): " + Style.RESET_ALL).strip()
    if not url:
        return
    result = headers.run_check(url)
    LAST_RESULT.update(module="headers", target=url, data=result)


def menu_ssl():
    host = input(Fore.CYAN + "\n  Host (ej: ejemplo.com): " + Style.RESET_ALL).strip()
    if not host:
        return
    result = sslcheck.run_check(host)
    LAST_RESULT.update(module="sslcheck", target=host, data=result)


def menu_hash():
    h = input(Fore.CYAN + "\n  Hash a analizar: " + Style.RESET_ALL).strip()
    if not h:
        return
    hashid.run_identify(h)
    crack = input(Fore.CYAN + "  Intentar crackear con diccionario? (s/n): " + Style.RESET_ALL).strip().lower()
    result = None
    if crack in ("s", "si", "y", "yes"):
        result = hashid.run_crack(h)
    LAST_RESULT.update(module="hashid", target=h, data=result)


def menu_pwcheck():
    import getpass
    pw = getpass.getpass(Fore.CYAN + "\n  Contrasena a analizar (oculta): " + Style.RESET_ALL)
    if not pw:
        return
    result = pwcheck.run_check(pw)
    LAST_RESULT.update(module="pwcheck", target="***", data=result)


def menu_whois():
    domain = input(Fore.CYAN + "\n  Dominio: " + Style.RESET_ALL).strip()
    if not domain:
        return
    result = whois_lookup.run_lookup(domain)
    LAST_RESULT.update(module="whois", target=domain, data=result)


ACTIONS = {
    "1": menu_portscan,
    "2": menu_subdomain,
    "3": menu_headers,
    "4": menu_ssl,
    "5": menu_hash,
    "6": menu_pwcheck,
    "7": menu_whois,
}


def main():
    show_banner()
    while True:
        print(MENU.format(cyan=Fore.CYAN + Style.BRIGHT, reset=Style.RESET_ALL))
        choice = input(Fore.MAGENTA + Style.BRIGHT + "4NTH0 > " + Style.RESET_ALL).strip()

        if choice == "0":
            print(Fore.CYAN + "\n[*] Saliendo. Hasta la proxima.\n" + Style.RESET_ALL)
            sys.exit(0)

        action = ACTIONS.get(choice)
        if action:
            try:
                action()
                if LAST_RESULT["data"]:
                    save = input(Fore.CYAN + "\n  Guardar reporte JSON? (s/n): " + Style.RESET_ALL).strip().lower()
                    if save in ("s", "si", "y", "yes"):
                        save_report()
            except KeyboardInterrupt:
                print(Fore.YELLOW + "\n[!] Operacion cancelada." + Style.RESET_ALL)
            except Exception as e:
                print(Fore.RED + f"[!] Error: {e}" + Style.RESET_ALL)
        else:
            print(Fore.RED + "[!] Opcion invalida." + Style.RESET_ALL)

        input(Fore.CYAN + "\nPresiona ENTER para continuar..." + Style.RESET_ALL)


if __name__ == "__main__":
    main()
