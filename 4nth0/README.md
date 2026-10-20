# 4NTH0 — Cybersecurity Toolkit

Suite de pentesting/ciberseguridad real en terminal, para Linux, macOS y Windows (cmd/PowerShell).

> **USO ETICO UNICAMENTE.** Esta herramienta esta pensada para auditar sistemas **propios** o con **autorizacion explicita por escrito** del dueno. Escanear o atacar sistemas de terceros sin permiso es ilegal en la gran mayoria de paises (incluyendo Republica Dominicana, bajo la Ley 53-07 de Crimenes y Delitos de Alta Tecnologia). El autor no se hace responsable del mal uso.

## Modulos incluidos

| Modulo | Funcion |
|---|---|
| Port Scanner | Escaneo TCP multithreaded + banner grabbing |
| Subdomain Enum | Enumeracion de subdominios por fuerza bruta DNS |
| Security Headers | Analiza cabeceras HTTP de seguridad (HSTS, CSP, etc) |
| SSL/TLS Checker | Verifica certificados, expiracion y cifrado |
| Hash ID + Cracker | Identifica tipo de hash y prueba diccionario comun |
| Password Strength | Calcula entropia real y tiempo estimado de crackeo |
| WHOIS Lookup | Informacion de registro de dominio |

## Instalacion

Requiere Python 3.8+ instalado.

### Linux / macOS

```bash
cd 4nth0
pip install .
```

### Windows (CMD o PowerShell)

```cmd
cd 4nth0
pip install .
```

Si `pip` no funciona, prueba `pip3` o `python -m pip install .`

## Uso

Una vez instalado, desde CUALQUIER terminal en CUALQUIER carpeta:

```bash
4nth0
```

Se abre el menu interactivo con banner. Eliges el numero del modulo y sigues las instrucciones. Cada resultado se puede exportar a un reporte JSON.

## Desinstalar

```bash
pip uninstall 4nth0
```

## Notas tecnicas

- El escaner de puertos usa threading nativo de Python, no requiere privilegios de root/admin (solo conecta via sockets TCP normales).
- La enumeracion de subdominios usa `dnspython` para resolucion DNS real.
- El cracker de hashes usa un diccionario de ~100 contrasenas comunes (demostrativo/educativo) — para auditorias reales de passwords corporativas, usa tu propio diccionario (puedes editarlo en `anth0/modules/hashid.py`, variable `COMMON_PASSWORDS`).
- Todo el codigo es legible y modificable — es tuyo, agregale lo que quieras.
