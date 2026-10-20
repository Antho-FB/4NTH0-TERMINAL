"""
Identificador de tipo de hash + cracker por diccionario (demo educativo).
Util para auditar la fortaleza de tus propios hashes.
"""
import hashlib
import time
from colorama import Fore, Style

HASH_PATTERNS = {
    32: ["MD5", "NTLM"],
    40: ["SHA1"],
    56: ["SHA224"],
    64: ["SHA256"],
    96: ["SHA384"],
    128: ["SHA512"],
}

HASH_FUNCS = {
    "MD5": lambda s: hashlib.md5(s).hexdigest(),
    "SHA1": lambda s: hashlib.sha1(s).hexdigest(),
    "SHA224": lambda s: hashlib.sha224(s).hexdigest(),
    "SHA256": lambda s: hashlib.sha256(s).hexdigest(),
    "SHA384": lambda s: hashlib.sha384(s).hexdigest(),
    "SHA512": lambda s: hashlib.sha512(s).hexdigest(),
}

COMMON_PASSWORDS = [
    "123456", "password", "12345678", "qwerty", "123456789", "12345",
    "1234", "111111", "1234567", "dragon", "123123", "baseball",
    "abc123", "football", "monkey", "letmein", "shadow", "master",
    "666666", "qwertyuiop", "123321", "mustang", "1234567890",
    "michael", "654321", "superman", "1qaz2wsx", "7777777", "121212",
    "000000", "qazwsx", "123qwe", "killer", "trustno1", "jordan",
    "jennifer", "zxcvbnm", "asdfgh", "hunter", "buster", "soccer",
    "harley", "batman", "andrew", "tigger", "sunshine", "iloveyou",
    "fuckyou", "2000", "charlie", "robert", "thomas", "hockey",
    "ranger", "daniel", "starwars", "klaster", "112233", "george",
    "asshole", "computer", "michelle", "jessica", "pepper", "1111",
    "zxcvbn", "555555", "11111111", "131313", "freedom", "777777",
    "pass", "maggie", "159753", "aaaaaa", "ginger", "princess",
    "joshua", "cheese", "amanda", "summer", "love", "ashley",
    "6969", "nicole", "chelsea", "biteme", "matthew", "access",
    "yankees", "987654321", "dallas", "austin", "thunder", "taylor",
    "matrix", "mobilemail", "mom", "monitor", "monitoring", "montana",
    "moon", "moscow", "admin", "root", "toor", "changeme", "welcome",
    "login", "passw0rd", "p@ssw0rd", "admin123", "letmein123",
]


def identify(hash_string):
    hash_string = hash_string.strip()
    length = len(hash_string)
    candidates = HASH_PATTERNS.get(length, [])
    is_hex = all(c in "0123456789abcdefABCDEF" for c in hash_string)
    return candidates if is_hex else []


def crack_dictionary(hash_string, algo, wordlist=None, show_progress=True):
    wordlist = wordlist or COMMON_PASSWORDS
    hash_string = hash_string.strip().lower()
    func = HASH_FUNCS.get(algo)
    if not func:
        return None

    start = time.time()
    for i, word in enumerate(wordlist):
        if func(word.encode()) == hash_string:
            elapsed = time.time() - start
            return {"password": word, "attempts": i + 1, "time": elapsed}
    return None


def run_identify(hash_string):
    candidates = identify(hash_string)
    print(Fore.CYAN + f"\n[*] Analizando hash: {hash_string}\n" + Style.RESET_ALL)
    if not candidates:
        print(Fore.RED + "[!] No se pudo identificar el tipo (longitud/formato no reconocido)." + Style.RESET_ALL)
        return []
    print(Fore.GREEN + f"[+] Posible(s) algoritmo(s): {', '.join(candidates)}" + Style.RESET_ALL)
    return candidates


def run_crack(hash_string, algo=None):
    if not algo:
        candidates = identify(hash_string)
        if not candidates:
            print(Fore.RED + "[!] No se pudo identificar el algoritmo. Especificalo manualmente." + Style.RESET_ALL)
            return None
        algo = candidates[0]
        print(Fore.YELLOW + f"[*] Usando algoritmo detectado: {algo}" + Style.RESET_ALL)

    print(Fore.CYAN + f"[*] Probando diccionario de {len(COMMON_PASSWORDS)} contrasenas comunes...\n" + Style.RESET_ALL)
    result = crack_dictionary(hash_string, algo)

    if result:
        print(Fore.GREEN + f"[+] HASH CRACKEADO!")
        print(f"    Password: {result['password']}")
        print(f"    Intentos: {result['attempts']}")
        print(f"    Tiempo: {result['time']*1000:.2f}ms" + Style.RESET_ALL)
    else:
        print(Fore.YELLOW + "[!] No se encontro en el diccionario comun. "
              "Esto es buena senal (password no trivial), o el algoritmo detectado es incorrecto." + Style.RESET_ALL)

    return result
