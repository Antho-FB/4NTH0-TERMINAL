<div align="center">

```
  _  _   _  _ _____ _  _  ___
 | || | | \| |_   _| || |/ _ \
 | __ | | .` | | | | __ | (_) |
 |_||_| |_|\_| |_| |_||_|\___/

      [ Cybersecurity Toolkit v1.0 ]
```

### Suite de ciberseguridad y pentesting real, en terminal, para Linux / macOS / Windows

[![Download](https://img.shields.io/badge/Download-ZIP-success?style=for-the-badge&logo=github)](https://github.com/Antho-FB/4NTH0-TERMINAL/archive/refs/heads/main.zip)
[![Python](https://img.shields.io/badge/Python-3.8+-blue?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)](LICENSE)

</div>

---

> ⚠️ **USO ETICO UNICAMENTE.** Esta herramienta esta pensada para auditar sistemas **propios** o con **autorizacion explicita por escrito** del dueno. Escanear o atacar sistemas de terceros sin permiso es ilegal en la gran mayoria de paises. El autor no se hace responsable del mal uso.

## Que es 4NTH0

Una suite de pentesting con 7 modulos reales y funcionales, pensada para correr desde cualquier terminal (CMD, PowerShell, bash, zsh) en cualquier sistema operativo. Sin dependencias raras, sin configuracion compleja: se instala con un comando y queda disponible globalmente.

## Modulos incluidos

| # | Modulo | Funcion |
|---|---|---|
| 1 | **Port Scanner** | Escaneo TCP multithreaded + banner grabbing |
| 2 | **Subdomain Enum** | Enumeracion de subdominios por fuerza bruta DNS |
| 3 | **Security Headers** | Analiza cabeceras HTTP de seguridad (HSTS, CSP, etc) |
| 4 | **SSL/TLS Checker** | Verifica certificados, expiracion y cifrado |
| 5 | **Hash ID + Cracker** | Identifica tipo de hash y prueba diccionario comun |
| 6 | **Password Strength** | Calcula entropia real y tiempo estimado de crackeo |
| 7 | **WHOIS Lookup** | Informacion de registro de dominio |

## Descarga e instalacion

### Opcion 1 — Descargar el ZIP

**[⬇️ Descargar 4NTH0 (ZIP)](https://github.com/Antho-FB/4NTH0-TERMINAL/archive/refs/heads/main.zip)**

Descomprime el archivo, abre una terminal dentro de la carpeta y corre:

```bash
pip install .
```

*(En Windows, si `pip` no se reconoce, usa `py -m pip install .`)*

### Opcion 2 — Clonar con Git

```bash
git clone https://github.com/Antho-FB/4NTH0-TERMINAL.git
cd 4NTH0-TERMINAL
pip install .
```

Requiere **Python 3.8+**.

## Uso

Una vez instalado, desde CUALQUIER terminal en CUALQUIER carpeta:

```bash
4nth0
```

Esto abre el menu interactivo. Eliges el numero del modulo y sigues las instrucciones en pantalla. Cada resultado se puede exportar a un reporte en formato JSON.

## Desinstalar

```bash
pip uninstall 4nth0
```

## Notas tecnicas

- El escaner de puertos usa threading nativo de Python, no requiere privilegios de root/admin.
- La enumeracion de subdominios usa `dnspython` para resolucion DNS real.
- El cracker de hashes usa un diccionario de contrasenas comunes (demostrativo/educativo). Para auditorias reales, edita `anth0/modules/hashid.py`, variable `COMMON_PASSWORDS`.
- Todo el codigo es legible y modificable — es tuyo, agregale lo que quieras.

---

<div align="center">
Hecho por <b>Antho-FB</b>
</div>
