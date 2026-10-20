"""
Enumeracion de subdominios via DNS brute force + resolucion.
"""
import concurrent.futures
import dns.resolver
from colorama import Fore, Style

DEFAULT_WORDLIST = [
    "www", "mail", "ftp", "webmail", "smtp", "pop", "ns1", "ns2", "ns3",
    "api", "dev", "staging", "test", "admin", "portal", "vpn", "remote",
    "blog", "shop", "store", "app", "mobile", "m", "secure", "beta",
    "demo", "cdn", "static", "assets", "img", "images", "media", "docs",
    "support", "help", "status", "git", "gitlab", "github", "jenkins",
    "jira", "confluence", "wiki", "intranet", "internal", "db", "mysql",
    "sql", "backup", "old", "new", "beta2", "dashboard", "panel",
    "cpanel", "whm", "autodiscover", "autoconfig", "owa", "exchange",
    "ns", "mx", "mx1", "mx2", "email", "cloud", "cloudfront", "s3",
    "ci", "cd", "build", "monitor", "grafana", "kibana", "elastic",
    "redis", "cache", "proxy", "gateway", "gw", "lb", "test1", "test2",
    "qa", "uat", "preprod", "prod", "production", "sandbox",
]


def resolve(subdomain_fqdn, timeout=3.0):
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout
    try:
        answers = resolver.resolve(subdomain_fqdn, "A")
        return [str(a) for a in answers]
    except Exception:
        return None


def run_enum(domain, wordlist=None, max_workers=50):
    wordlist = wordlist or DEFAULT_WORDLIST
    domain = domain.strip().lower().replace("http://", "").replace("https://", "").rstrip("/")

    print(Fore.CYAN + f"\n[*] Enumerando subdominios de: {domain}")
    print(f"[*] Probando {len(wordlist)} palabras...\n" + Style.RESET_ALL)

    found = []

    def check(word):
        fqdn = f"{word}.{domain}"
        ips = resolve(fqdn)
        if ips:
            return (fqdn, ips)
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(check, w) for w in wordlist]
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                fqdn, ips = result
                print(Fore.GREEN + f"    [+] {fqdn:<35} -> {', '.join(ips)}" + Style.RESET_ALL)
                found.append({"subdomain": fqdn, "ips": ips})

    if not found:
        print(Fore.YELLOW + "[!] No se encontraron subdominios." + Style.RESET_ALL)
    else:
        print(Fore.CYAN + f"\n[*] {len(found)} subdominio(s) encontrado(s)." + Style.RESET_ALL)

    return found
