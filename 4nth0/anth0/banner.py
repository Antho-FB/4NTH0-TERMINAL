from colorama import Fore, Style, init

init(autoreset=True)

BANNER = r"""
{c}
  _  _   _  _ _____ _  _  ___
 | || | | \| |_   _| || |/ _ \
 | __ | | .` | | | | __ | (_) |
 |_||_| |_|\_| |_| |_||_|\___/

{r}      [ Cybersecurity Toolkit v1.0 ]{reset}
"""


def show_banner():
    print(BANNER.format(c=Fore.CYAN + Style.BRIGHT, r=Fore.RED, reset=Style.RESET_ALL))
    print(Fore.YELLOW + Style.BRIGHT +
          "  ATENCION: Herramienta de pentesting. Usala SOLO en sistemas\n"
          "  propios o con autorizacion explicita por escrito del dueno.\n"
          "  El uso no autorizado contra terceros es ilegal (y una idiotez).\n"
          + Style.RESET_ALL)
