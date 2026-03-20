"""
FR1 - Control de Identificación y Autenticación (IAC)
Evalúa SR 1.1 al SR 1.13 según IEC 62443-3-3
"""
import subprocess
import os
import re

def check_sr_1_1_user_auth() -> dict:
    """SR 1.1 - Identificación y autenticación de usuarios humanos"""
    results = []
    status = "PASS"

    # Comprobar si existe autenticación PAM
    pam_exists = os.path.exists("/etc/pam.d/common-auth")
    if not pam_exists:
        status = "FAIL"
        results.append("PAM no configurado en /etc/pam.d/common-auth")
    else:
        results.append("PAM configurado correctamente")

    # Comprobar si hay usuarios sin contraseña
    try:
        output = subprocess.check_output(
            ["awk", "-F:", "($2 == \"\" || $2 == \"*\") {print $1}", "/etc/shadow"],
            stderr=subprocess.DEVNULL
        ).decode().strip()
        if output:
            status = "FAIL"
            results.append(f"Usuarios sin contraseña detectados: {output}")
        else:
            results.append("Todos los usuarios tienen contraseña asignada")
    except Exception as e:
        results.append(f"No se pudo verificar /etc/shadow (requiere root): {str(e)}")
        status = "WARNING"

    return {
        "sr_id": "SR1.1",
        "fr_id": "FR1",
        "description": "Identificación y autenticación de usuarios humanos",
        "status": status,
        "details": " | ".join(results),
        "sl_level": 1
    }


def check_sr_1_3_account_management() -> dict:
    """SR 1.3 - Gestión de cuentas"""
    results = []
    status = "PASS"

    # Comprobar cuentas con UID 0 (root) distintas a root
    try:
        output = subprocess.check_output(
            ["awk", "-F:", "($3 == 0 && $1 != \"root\") {print $1}", "/etc/passwd"]
        ).decode().strip()
        if output:
            status = "FAIL"
            results.append(f"Cuentas con UID 0 distintas a root: {output}")
        else:
            results.append("No hay cuentas extra con privilegios root")
    except Exception as e:
        results.append(f"Error verificando /etc/passwd: {str(e)}")

    # Comprobar si hay cuentas de sistema sin shell deshabilitada
    try:
        with open("/etc/passwd", "r") as f:
            for line in f:
                parts = line.strip().split(":")
                if len(parts) >= 7:
                    user, uid, shell = parts[0], int(parts[2]), parts[6]
                    if uid < 1000 and uid > 0 and shell not in ["/usr/sbin/nologin", "/bin/false", "/sbin/nologin"]:
                        results.append(f"Cuenta sistema con shell activa: {user} -> {shell}")
                        status = "WARNING"
    except Exception as e:
        results.append(f"Error leyendo /etc/passwd: {str(e)}")

    return {
        "sr_id": "SR1.3",
        "fr_id": "FR1",
        "description": "Gestión de cuentas",
        "status": status,
        "details": " | ".join(results),
        "sl_level": 1
    }


def check_sr_1_7_password_strength() -> dict:
    """SR 1.7 - Fortaleza de autenticación basada en contraseña"""
    results = []
    status = "PASS"

    # Comprobar configuración de PAM para fortaleza de contraseñas
    pam_password_path = "/etc/pam.d/common-password"
    if os.path.exists(pam_password_path):
        with open(pam_password_path, "r") as f:
            content = f.read()
        if "pam_pwquality" in content or "pam_cracklib" in content:
            results.append("Política de fortaleza de contraseña activa (pwquality/cracklib)")
        else:
            status = "FAIL"
            results.append("No se encontró pam_pwquality ni pam_cracklib en common-password")
    else:
        status = "FAIL"
        results.append("No existe /etc/pam.d/common-password")

    # Comprobar /etc/login.defs para políticas de caducidad
    login_defs = "/etc/login.defs"
    if os.path.exists(login_defs):
        with open(login_defs, "r") as f:
            content = f.read()
        pass_max = re.search(r"^PASS_MAX_DAYS\s+(\d+)", content, re.MULTILINE)
        pass_min = re.search(r"^PASS_MIN_LEN\s+(\d+)", content, re.MULTILINE)
        if pass_max:
            days = int(pass_max.group(1))
            if days > 90:
                status = "WARNING"
                results.append(f"PASS_MAX_DAYS = {days} (recomendado <= 90)")
            else:
                results.append(f"PASS_MAX_DAYS = {days} OK")
        if pass_min:
            length = int(pass_min.group(1))
            if length < 8:
                status = "FAIL"
                results.append(f"PASS_MIN_LEN = {length} (recomendado >= 8)")
            else:
                results.append(f"PASS_MIN_LEN = {length} OK")

    return {
        "sr_id": "SR1.7",
        "fr_id": "FR1",
        "description": "Fortaleza de autenticación basada en contraseña",
        "status": status,
        "details": " | ".join(results),
        "sl_level": 1
    }


def check_sr_1_11_failed_logins() -> dict:
    """SR 1.11 - Intentos fallidos de inicio de sesión"""
    results = []
    status = "PASS"

    # Buscar configuración de bloqueo por intentos fallidos
    pam_auth = "/etc/pam.d/common-auth"
    if os.path.exists(pam_auth):
        with open(pam_auth, "r") as f:
            content = f.read()
        if "pam_faillock" in content or "pam_tally2" in content:
            results.append("Bloqueo por intentos fallidos configurado")
        else:
            status = "FAIL"
            results.append("No se detectó pam_faillock ni pam_tally2 en common-auth")
    else:
        status = "FAIL"
        results.append("No existe /etc/pam.d/common-auth")

    return {
        "sr_id": "SR1.11",
        "fr_id": "FR1",
        "description": "Intentos fallidos de inicio de sesión",
        "status": status,
        "details": " | ".join(results),
        "sl_level": 1
    }


def run_all_fr1_checks() -> list:
    """Ejecuta todos los checks del FR1"""
    return [
        check_sr_1_1_user_auth(),
        check_sr_1_3_account_management(),
        check_sr_1_7_password_strength(),
        check_sr_1_11_failed_logins(),
    ]