"""Literal Cowrie inputs with behavior-specific operands and options."""

import re


ACCOUNT = r"[a-z_][a-z0-9_-]*"
UNIT = r"[a-zA-Z0-9_@-][a-zA-Z0-9_.@-]*"
PATH = r"(?:/|\./)(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+"
SECURITY_UNITS = {"auditd.service", "falco.service", "apparmor.service", "fail2ban.service"}
BACKUP_UNITS = {"restic.service", "borgbackup.service", "bacula-fd.service"}
KEY_PATH = r"(?:/root|/home/[a-z_][a-z0-9_-]*)/\.ssh/id_(?:rsa|dsa|ecdsa|ed25519)"
SYSTEM_LOG = r"/var/log/(?:auth\.log|secure|audit/audit\.log|syslog|messages)"


def exact(*spellings):
    return lambda tool, args: (tool, *args) in spellings


def operands(*spellings):
    return lambda tool, args: any(
        tool == name and len(args) == len(patterns)
        and all(re.fullmatch(pattern, arg) for pattern, arg in zip(patterns, args))
        for name, *patterns in spellings
    )


def runtime(names, flag, suffix):
    return lambda tool, args: tool in names and (
        len(args) == 2 and args[0] == flag and bool(args[1].strip())
        or len(args) == 1 and bool(re.fullmatch(PATH + re.escape(suffix), args[0]))
    )


def unit_query(units):
    return lambda tool, args: (
        tool == "systemctl" and len(args) == 2 and args[0] in {"is-active", "is-enabled", "status"} and args[1] in units
    )


# Each entry specifies the ATT&CK tactic that the exact input supports.
# General flags, free-form output, aliases and shell expansion are out of scope.
COMMAND_RULES = (
    ("T1007", "TA0007", "system_service_discovery", "Enumeración explícita de unidades de servicio.",
     exact(("systemctl", "list-units", "--type=service"), ("systemctl", "list-unit-files", "--type=service"),
           ("systemctl", "list-units", "--type=service", "--all"), ("service", "--status-all"))),
    ("T1049", "TA0007", "connection_discovery", "Consulta de sockets TCP o UDP con flags de enumeración.",
     operands(("ss", r"-[atnulpe]*[tu][atnulpe]*"), ("netstat", r"-[atnulpe]*[tu][atnulpe]*"))),
    ("T1069", "TA0007", "group_discovery", "Consulta explícita de grupos de la identidad actual o del índice de grupos sin origen identificado.",
     exact(("groups",), ("id", "-Gn"), ("getent", "group"))),
    ("T1069.001", "TA0007", "group_discovery", "Enumeración de grupos con la fuente local files o el archivo /etc/group.",
     exact(("getent", "-s", "files", "group"), ("cat", "/etc/group"))),
    ("T1087.001", "TA0007", "local_account_discovery", "Consulta del inventario local /etc/passwd.",
     exact(("cat", "/etc/passwd"), ("getent", "-s", "files", "passwd"))),
    ("T1120", "TA0007", "peripheral_discovery", "Enumeración PCI o USB sin selección de una operación de escritura.",
     exact(("lsusb",), ("lsusb", "-t"), ("lspci",), ("lspci", "-nn"))),
    ("T1124", "TA0007", "time_discovery", "Consulta explícita de la hora o del estado del reloj.",
     exact(("date", "-u"), ("date", "--utc"), ("timedatectl", "status"), ("timedatectl", "show"))),
    ("T1201", "TA0007", "password_policy", "Lectura de la política de caducidad de una cuenta identificada.",
     operands(("chage", r"(?:-l|--list)", ACCOUNT))),
    ("T1518", "TA0007", "software_inventory", "Listar paquetes instalados con un gestor de paquetes.",
     exact(("dpkg-query", "-W"), ("dpkg", "-l"), ("rpm", "-qa"), ("apt", "list", "--installed"),
           ("pacman", "-Q"), ("apk", "info"))),
    ("T1518.001", "TA0007", "security_software_discovery", "Consultar estado de una unidad de seguridad identificada.",
     unit_query(SECURITY_UNITS)),
    ("T1518.002", "TA0007", "backup_software_discovery", "Consultar estado de una unidad de copia de seguridad identificada.",
     unit_query(BACKUP_UNITS)),
    ("T1614.001", "TA0007", "language_discovery", "Lectura explícita de la configuración regional.",
     exact(("locale",), ("localectl", "status"))),
    ("T1652", "TA0007", "driver_discovery", "Enumeración de módulos cargados, incluidos controladores.",
     exact(("lsmod",), ("cat", "/proc/modules"))),
    ("T1654", "TA0007", "log_enumeration", "Enumeración de arranques presentes en el diario.",
     exact(("journalctl", "--list-boots"), ("journalctl", "--list-boots", "--no-pager"))),
    ("T1673", "TA0007", "virtual_machine_discovery", "Sondeo específico del tipo de máquina virtual.",
     exact(("systemd-detect-virt", "--vm"), ("virt-what",))),
    ("T1680", "TA0007", "storage_discovery", "Enumeración de dispositivos de bloques o espacio montado.",
     exact(("lsblk",), ("lsblk", "-f"), ("lsblk", "--fs"), ("df", "-h"), ("df", "-Th"))),
    ("T1016.002", "TA0007", "wifi_discovery", "Listado de interfaces o redes inalámbricas desde el cliente.",
     exact(("iw", "dev"), ("nmcli", "device", "wifi", "list"), ("iwconfig",))),
    ("T1016.001", "TA0007", "internet_connectivity_discovery", "Consulta explícita del estado de conectividad a Internet.",
     exact(("nmcli", "networking", "connectivity", "check"),)),
    ("T1135", "TA0007", "network_share_discovery", "Enumeración solicitada de exportaciones NFS de un destino explícito.",
     operands(("showmount", "-e", r"(?:[A-Za-z0-9-]+\.)+[A-Za-z0-9-]+"))),
    ("T1059.001", "TA0002", "powershell_execution", "Invocación explícita de código o script PowerShell.",
     runtime({"pwsh"}, "-Command", ".ps1")),
    ("T1059.006", "TA0002", "python_execution", "Invocación explícita de código o script Python.",
     runtime({"python", "python2", "python3"}, "-c", ".py")),
    ("T1059.007", "TA0002", "javascript_execution", "Invocación explícita de código o script JavaScript.",
     runtime({"node", "nodejs"}, "-e", ".js")),
    ("T1059.011", "TA0002", "lua_execution", "Invocación explícita de código o script Lua.",
     runtime({"lua", "lua5.4", "lua5.3", "luajit"}, "-e", ".lua")),
    ("T1053.002", "TA0002", "at_schedule", "Solicitud de ejecución posterior de un archivo con hora explícita.",
     operands(("at", "-f", PATH, r"(?:[01][0-9]|2[0-3]):[0-5][0-9]"))),
    ("T1053.006", "TA0003", "systemd_timer", "Solicitud explícita de habilitar una unidad .timer.",
     operands(("systemctl", "enable", UNIT + r"\.timer"), ("systemctl", "enable", "--now", UNIT + r"\.timer"))),
    ("T1098.007", "TA0003", "account_group_change", "Adición explícita de una cuenta a un grupo local privilegiado.",
     operands(("usermod", "-aG", r"(?:sudo|wheel|adm|docker|lxd)", ACCOUNT),
              ("gpasswd", "-a", ACCOUNT, r"(?:sudo|wheel|adm|docker|lxd)"))),
    ("T1003.008", "TA0006", "shadow_access", "Lectura directa del almacén de hashes protegido o combinación explícita con passwd.",
     exact(("cat", "/etc/shadow"), ("getent", "shadow"), ("unshadow", "/etc/passwd", "/etc/shadow"))),
    ("T1552.004", "TA0006", "private_key_access", "Lectura explícita de una ruta estándar de clave SSH privada.",
     operands(("cat", KEY_PATH), ("head", "-n", r"[1-9][0-9]?", KEY_PATH))),
    ("T1552.003", "TA0006", "history_credential_search", "Búsqueda literal de un marcador de credenciales en un historial de shell.",
     operands(("grep", "-i", r"(?:password|passwd|passphrase|api_key|secret|token)",
               r"(?:/root|/home/[a-z_][a-z0-9_-]*)/\.(?:bash|zsh)_history"))),
    ("T1040", "TA0007", "packet_capture", "Captura de paquetes solicitada en una interfaz con destino explícito.",
     operands(("tcpdump", "-i", r"[A-Za-z0-9_.:-]+", "-w", PATH + r"\.pcap(?:ng)?"))),
    ("T1222.002", "TA0112", "permission_change", "Permisos explícitos sobre un almacén de credenciales o una clave privada.",
     operands(("chmod", r"(?:0?[0-7]{3}|[ugo]+[+=-][rwx]{1,3})", r"(?:/etc/shadow|" + KEY_PATH + ")"))),
    ("T1690", "TA0112", "prevent_history", "Solicitud explícita de desactivar el historial de la shell.",
     exact(("unset", "HISTFILE"), ("set", "+o", "history"))),
    ("T1685.006", "TA0112", "system_log_clear", "Truncamiento a cero de un archivo de registros del sistema identificado.",
     operands(("truncate", "-s", "0", SYSTEM_LOG), ("truncate", "--size=0", SYSTEM_LOG))),
    ("T1489", "TA0040", "service_stop", "Solicitud explícita de detener un servicio identificado por una unidad .service.",
     operands(("systemctl", "stop", UNIT + r"\.service"), ("systemctl", "--now", "disable", UNIT + r"\.service"))),
    ("T1529", "TA0040", "system_shutdown", "Solicitud explícita de reinicio o apagado inmediato.",
     exact(("systemctl", "reboot"), ("systemctl", "poweroff"), ("shutdown", "-r", "now"), ("shutdown", "-h", "now"))),
    ("T1531", "TA0040", "account_access_removal", "Solicitud explícita de expirar una cuenta mediante una fecha ya vencida.",
     operands(("usermod", "--expiredate", r"(?:1|1970-01-02)", ACCOUNT),
              ("chage", "-E", r"(?:1|1970-01-02)", ACCOUNT))),
)
