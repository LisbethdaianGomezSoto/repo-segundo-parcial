#!/usr/bin/env python3
"""
Aplica reglas de hardening (basadas en CIS Cisco IOS Benchmark) a SW-1
y genera un informe posterior a la aplicacion (PASS/FAIL por regla).

Uso:  pip install netmiko
      python3 hardening_sw1.py
"""
import getpass
import re
from datetime import datetime
from netmiko import ConnectHandler

SWITCH = {
    "device_type": "cisco_ios",
    "host": "10.7.1.2",          # IP de gestion de SW-1
    "username": "admin",
    "password": getpass.getpass("Password de admin: "),
    "secret": getpass.getpass("Enable secret: "),
}

# Cada regla: nombre, comandos a aplicar, comando de verificacion y regex esperado
# (expect=True -> el patron debe aparecer; expect=False -> NO debe aparecer).
RULES = [
    ("Cifrar contrasenas (service password-encryption)",
     ["service password-encryption"],
     "show running-config | include service password", r"^service password-encryption", True),
    ("Enable secret configurado",
     [],
     "show running-config | include enable secret", r"^enable secret", True),
    ("Deshabilitar servidor HTTP",
     ["no ip http server", "no ip http secure-server"],
     "show running-config | include ip http", r"^ip http (secure-)?server", False),
    ("Deshabilitar servicios pequenos / PAD",
     ["no service pad"],
     "show running-config | include service pad", r"^service pad", False),
    ("Deshabilitar BOOTP",
     ["no ip bootp server"],
     "show running-config | include bootp", r"^ip bootp server", False),
    ("Sin resolucion DNS de comandos erroneos",
     ["no ip domain-lookup"],
     "show running-config | include domain-lookup", r"^no ip domain-lookup", True),
    ("Deshabilitar CDP globalmente",
     ["no cdp run"],
     "show running-config | include cdp run", r"^no cdp run", True),
    ("Timestamps en logs",
     ["service timestamps debug datetime msec localtime show-timezone",
      "service timestamps log datetime msec localtime show-timezone"],
     "show running-config | include service timestamps", r"service timestamps log datetime", True),
    ("Logging con buffer local",
     ["logging buffered 16384 informational"],
     "show running-config | include logging buffered", r"^logging buffered", True),
    ("Banner de advertencia",
     ["banner motd ^C ACCESO RESTRINGIDO. Solo personal autorizado. ^C"],
     "show running-config | include banner motd", r"^banner motd", True),
    ("Bloqueo ante intentos fallidos de login",
     ["login block-for 120 attempts 3 within 60"],
     "show running-config | include login block-for", r"^login block-for", True),
    ("SSH version 2",
     ["ip ssh version 2", "ip ssh time-out 60", "ip ssh authentication-retries 3"],
     "show ip ssh", r"SSH Enabled - version 2", True),
    ("VTY: solo SSH, timeout de sesion y login local",
     ["line vty 0 4", "transport input ssh", "exec-timeout 5 0", "login local", "exit",
      "line vty 5 15", "transport input ssh", "exec-timeout 5 0", "login local", "exit"],
     "show running-config | section line vty", r"transport input ssh", True),
    ("Consola con timeout",
     ["line con 0", "exec-timeout 5 0", "logging synchronous", "exit"],
     "show running-config | section line con", r"exec-timeout 5 0", True),
    ("Apagar puertos sin usar",
     ["interface GigabitEthernet1/0", "shutdown", "description PUERTO NO USADO", "exit"],
     "show interfaces GigabitEthernet1/0 status", r"disabled|administratively", True),
]


def main():
    inicio = datetime.now()
    informe = [f"# Informe de hardening - SW-1",
               f"Fecha: {inicio:%Y-%m-%d %H:%M:%S}",
               f"Equipo: {SWITCH['host']}", "",
               "| # | Regla | Resultado |", "|---|-------|-----------|"]
    conn = ConnectHandler(**SWITCH)
    conn.enable()

    # 1) Aplicar
    for _, comandos, *_ in RULES:
        if comandos:
            conn.send_config_set(comandos)

    # 2) Verificar
    ok = 0
    for i, (nombre, _, show, patron, esperado) in enumerate(RULES, 1):
        salida = conn.send_command(show)
        encontrado = re.search(patron, salida, re.M | re.I) is not None
        paso = encontrado == esperado
        ok += paso
        informe.append(f"| {i} | {nombre} | {'PASS' if paso else 'FAIL'} |")

    conn.save_config()
    conn.disconnect()

    informe += ["", f"**Cumplimiento: {ok}/{len(RULES)} reglas ({ok * 100 // len(RULES)}%)**"]
    nombre_archivo = f"informe_hardening_{inicio:%Y%m%d_%H%M%S}.md"
    with open(nombre_archivo, "w", encoding="utf-8") as f:
        f.write("\n".join(informe) + "\n")
    print("\n".join(informe))
    print(f"\nInforme guardado en {nombre_archivo}")


if __name__ == "__main__":
    main()
