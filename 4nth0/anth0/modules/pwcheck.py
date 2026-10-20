"""
Analizador de fortaleza de contrasenas: entropia real + patrones debiles.
"""
import math
import re
from colorama import Fore, Style

COMMON_PATTERNS = [
    r"^\d+$", r"^(.)\1+$", r"123456", r"password", r"qwerty",
    r"abc123", r"letmein", r"admin", r"welcome",
]


def calc_entropy(password):
    pool = 0
    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"[0-9]", password):
        pool += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        pool += 32
    if pool == 0:
        return 0
    return len(password) * math.log2(pool)


def check_patterns(password):
    found = []
    lowered = password.lower()
    for pattern in COMMON_PATTERNS:
        if re.search(pattern, lowered):
            found.append(pattern)
    return found


def estimate_crack_time(entropy_bits):
    guesses_per_second = 1e10  # GPU offline attack estimate
    total_combinations = 2 ** entropy_bits
    seconds = total_combinations / (2 * guesses_per_second)

    if seconds < 1:
        return "instantaneo"
    elif seconds < 60:
        return f"{seconds:.1f} segundos"
    elif seconds < 3600:
        return f"{seconds/60:.1f} minutos"
    elif seconds < 86400:
        return f"{seconds/3600:.1f} horas"
    elif seconds < 31536000:
        return f"{seconds/86400:.1f} dias"
    elif seconds < 31536000 * 100:
        return f"{seconds/31536000:.1f} anos"
    else:
        return "siglos (segura)"


def run_check(password):
    print(Fore.CYAN + "\n[*] Analizando fortaleza de contrasena...\n" + Style.RESET_ALL)

    entropy = calc_entropy(password)
    patterns = check_patterns(password)
    crack_time = estimate_crack_time(entropy)

    length = len(password)
    has_lower = bool(re.search(r"[a-z]", password))
    has_upper = bool(re.search(r"[A-Z]", password))
    has_digit = bool(re.search(r"[0-9]", password))
    has_symbol = bool(re.search(r"[^a-zA-Z0-9]", password))

    print(f"    Longitud: {length} caracteres")
    print(f"    Minusculas: {'si' if has_lower else 'no'}")
    print(f"    Mayusculas: {'si' if has_upper else 'no'}")
    print(f"    Numeros: {'si' if has_digit else 'no'}")
    print(f"    Simbolos: {'si' if has_symbol else 'no'}")
    print(f"    Entropia: {entropy:.1f} bits")

    if patterns:
        print(Fore.RED + f"    [!] Patrones debiles detectados ({len(patterns)})" + Style.RESET_ALL)

    color = Fore.RED if entropy < 40 else Fore.YELLOW if entropy < 60 else Fore.GREEN
    rating = "MUY DEBIL" if entropy < 28 else "DEBIL" if entropy < 40 else \
             "MODERADA" if entropy < 60 else "FUERTE" if entropy < 80 else "MUY FUERTE"

    print(color + f"\n[*] Calificacion: {rating}")
    print(f"[*] Tiempo estimado de crackeo (ataque offline GPU): {crack_time}" + Style.RESET_ALL)

    if length < 12:
        print(Fore.YELLOW + "\n[tip] Usa al menos 12-16 caracteres para mayor seguridad." + Style.RESET_ALL)
    if not (has_lower and has_upper and has_digit and has_symbol):
        print(Fore.YELLOW + "[tip] Combina mayusculas, minusculas, numeros y simbolos." + Style.RESET_ALL)

    return {
        "entropy": entropy, "rating": rating, "crack_time": crack_time,
        "weak_patterns": patterns, "length": length,
    }
