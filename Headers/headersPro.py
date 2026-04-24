#!/usr/bin/env python3
"""
catnp headersPro — Analizador de cabeceras de seguridad HTTP
Detecta ausencias, valores inválidos y misconfigurations reales.
"""
import requests
import urllib3
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt
from rich.rule import Rule
from rich import box

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
console = Console()

# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTES
# ─────────────────────────────────────────────────────────────────────────────

# Valores válidos para Referrer-Policy (spec oficial W3C)
VALID_REFERRER_POLICIES = {
    "no-referrer", "no-referrer-when-downgrade", "origin",
    "origin-when-cross-origin", "same-origin", "strict-origin",
    "strict-origin-when-cross-origin", "unsafe-url", ""
}

# Features de alto riesgo que deben declararse explícitamente
HIGH_RISK_PP_FEATURES = [
    "camera", "microphone", "geolocation", "payment",
    "usb", "bluetooth", "display-capture", "clipboard-read", "xr-spatial-tracking"
]

PERMISSIONS_POLICY_FEATURES = {
    "camera":              "Cámara del dispositivo",
    "microphone":          "Micrófono del dispositivo",
    "geolocation":         "Ubicación GPS",
    "payment":             "Payment Request API",
    "usb":                 "Dispositivos USB (WebUSB)",
    "bluetooth":           "Bluetooth (Web Bluetooth)",
    "display-capture":     "Captura de pantalla (getDisplayMedia)",
    "clipboard-read":      "Lectura del portapapeles",
    "clipboard-write":     "Escritura en el portapapeles",
    "midi":                "Dispositivos MIDI",
    "fullscreen":          "Modo pantalla completa",
    "accelerometer":       "Acelerómetro",
    "gyroscope":           "Giroscopio",
    "magnetometer":        "Magnetómetro",
    "autoplay":            "Reproducción automática",
    "notifications":       "Notificaciones push",
    "xr-spatial-tracking": "WebXR / AR-VR tracking",
    "interest-cohort":     "FLoC / Topics API",
}

# Palabras clave para detectar si un valor parece CSP o Permissions-Policy
CSP_KEYWORDS = {
    "default-src", "script-src", "style-src", "img-src", "connect-src",
    "font-src", "frame-src", "object-src", "base-uri", "form-action",
    "frame-ancestors", "upgrade-insecure-requests", "report-uri"
}
PP_KEYWORDS = {
    "camera", "microphone", "geolocation", "payment", "usb", "fullscreen",
    "autoplay", "bluetooth", "accelerometer", "gyroscope", "display-capture"
}

SEV_ORDER = ["CRÍTICO", "ALTO", "MEDIO", "BAJO", "INFO"]


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def looks_like_csp(value: str) -> bool:
    lower = value.lower()
    return any(kw in lower for kw in CSP_KEYWORDS)

def looks_like_pp(value: str) -> bool:
    lower = value.lower()
    return any(f"{kw}=" in lower or f"{kw} " in lower for kw in PP_KEYWORDS)

def parse_permissions_policy(value: str) -> dict:
    """Soporta formato nuevo (feature=()) y antiguo (feature 'none')."""
    result = {}
    parts = [p.strip() for p in value.replace(";", ",").split(",") if p.strip()]
    for part in parts:
        if "=" in part:
            key, _, val = part.partition("=")
            result[key.strip().lower()] = val.strip().strip("()")
        elif " " in part:
            tokens = part.split(None, 1)
            result[tokens[0].lower()] = tokens[1].strip("'\"") if len(tokens) > 1 else ""
    return result

def severity_color(sev: str) -> str:
    return {"CRÍTICO": "bold red", "ALTO": "red", "MEDIO": "yellow",
            "BAJO": "green", "INFO": "cyan"}.get(sev, "white")

def severity_icon(sev: str) -> str:
    return {"CRÍTICO": "🔴", "ALTO": "🟠", "MEDIO": "🟡",
            "BAJO": "🟢", "INFO": "🔵"}.get(sev, "⚪")

def worst_finding(findings: list[dict]) -> dict:
    return min(findings, key=lambda f: SEV_ORDER.index(f["sev"]) if f["sev"] in SEV_ORDER else 99)


# ─────────────────────────────────────────────────────────────────────────────
# EVALUADORES
# ─────────────────────────────────────────────────────────────────────────────

def eval_csp(value: str, all_headers) -> list[dict]:
    findings = []

    # ¿Valor intercambiado? (contiene sintaxis de PP en lugar de CSP)
    if looks_like_pp(value) and not looks_like_csp(value):
        findings.append({
            "sev": "CRÍTICO",
            "msg": "Header mal configurado: el valor parece una Permissions-Policy.",
            "detail": (
                f"Valor recibido: {value}\n"
                "Los headers CSP y Permissions-Policy parecen estar intercambiados en el servidor.\n"
                "Este header no ofrece ninguna protección CSP real."
            )
        })
        return findings

    # Solo Report-Only, sin enforcement
    if "Content-Security-Policy-Report-Only" in all_headers:
        findings.append({
            "sev": "MEDIO",
            "msg": "CSP está en modo Report-Only — no bloquea ninguna violación.",
            "detail": (
                "El header Content-Security-Policy-Report-Only solo monitorea y reporta.\n"
                "Cuando las políticas estén validadas, migrar a Content-Security-Policy."
            )
        })

    for bad in ["'unsafe-inline'", "'unsafe-eval'"]:
        if bad in value:
            findings.append({
                "sev": "ALTO",
                "msg": f"Directiva insegura detectada: {bad}",
                "detail": f"Permite ejecución de código arbitrario. Eliminar {bad} del CSP."
            })

    if not findings:
        findings.append({"sev": "BAJO", "msg": "CSP presente sin directivas críticas detectadas.", "detail": ""})

    return findings


def eval_hsts(value: str) -> list[dict]:
    if "max-age=0" in value:
        return [{"sev": "CRÍTICO",
                 "msg": "max-age=0 desactiva completamente la protección HSTS.",
                 "detail": "Cambiar a max-age=31536000 con includeSubDomains."}]
    findings = []
    if "max-age=31536000" not in value:
        findings.append({"sev": "MEDIO",
                         "msg": "max-age inferior al recomendado (mínimo 31536000 = 1 año).",
                         "detail": f"Valor actual: {value}"})
    if "includeSubDomains" not in value:
        findings.append({"sev": "BAJO",
                         "msg": "Falta includeSubDomains — subdominios no protegidos.",
                         "detail": ""})
    if not findings:
        findings.append({"sev": "BAJO", "msg": "HSTS configurado correctamente.", "detail": ""})
    return findings


def eval_xfo(value: str) -> list[dict]:
    if value.upper() in ("DENY", "SAMEORIGIN"):
        return [{"sev": "BAJO", "msg": f"Valor correcto: {value.upper()}", "detail": ""}]
    return [{"sev": "MEDIO",
             "msg": f"Valor no estándar: '{value}'",
             "detail": "Los únicos valores válidos son DENY y SAMEORIGIN."}]


def eval_xcto(value: str) -> list[dict]:
    if value.lower() == "nosniff":
        return [{"sev": "BAJO", "msg": "nosniff — correcto.", "detail": ""}]
    return [{"sev": "ALTO",
             "msg": f"Valor inválido: '{value}' — debe ser exactamente 'nosniff'.",
             "detail": "El navegador ignorará este header y realizará MIME sniffing."}]


def eval_referrer(value: str) -> list[dict]:
    if value.lower() not in VALID_REFERRER_POLICIES:
        return [{"sev": "ALTO",
                 "msg": f"Valor inválido: '{value}' — el navegador lo ignorará.",
                 "detail": (
                     "Referrer-Policy debe ser uno de los valores definidos en la spec W3C:\n"
                     "no-referrer, strict-origin, strict-origin-when-cross-origin,\n"
                     "origin, same-origin, no-referrer-when-downgrade, unsafe-url.\n"
                     "Con un valor inválido el browser aplica su política por defecto,\n"
                     "que suele filtrar URLs completas en requests cross-origin."
                 )}]
    if value.lower() in ("unsafe-url", "no-referrer-when-downgrade"):
        return [{"sev": "MEDIO",
                 "msg": f"'{value}' puede filtrar la URL completa en requests cross-origin.",
                 "detail": "Considerar 'strict-origin-when-cross-origin' o 'no-referrer'."}]
    return [{"sev": "BAJO", "msg": f"'{value}' — correcto.", "detail": ""}]


def eval_permissions_policy(value: str) -> list[dict]:
    findings = []

    # ¿Valor intercambiado?
    if looks_like_csp(value) and not looks_like_pp(value):
        findings.append({
            "sev": "CRÍTICO",
            "msg": "Header mal configurado: el valor parece un CSP, no una Permissions-Policy.",
            "detail": (
                f"Valor recibido: {value}\n"
                "Los headers CSP y Permissions-Policy parecen estar intercambiados en el servidor.\n"
                "Este header no restringe ninguna API del navegador."
            )
        })
        return findings

    parsed = parse_permissions_policy(value)

    for feature, val in parsed.items():
        if val == "*":
            findings.append({
                "sev": "ALTO",
                "msg": f"Feature '{feature}' sin restricción (valor: *).",
                "detail": f"Cualquier origen puede usar esta API. Cambiar a {feature}=()."
            })

    not_declared = [f for f in HIGH_RISK_PP_FEATURES if f not in parsed]
    if not_declared:
        findings.append({
            "sev": "MEDIO",
            "msg": "Features sensibles sin declarar — heredan permisos del contexto padre.",
            "detail": (
                "APIs afectadas: " + ", ".join(not_declared) + "\n"
                "Recomendación: " + ", ".join(f + "=()" for f in not_declared)
            )
        })

    if not findings:
        findings.append({"sev": "BAJO", "msg": "Permissions-Policy sin valores críticos.", "detail": ""})

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# RENDERIZADO
# ─────────────────────────────────────────────────────────────────────────────

def print_summary(url: str, results: dict):
    table = Table(
        title=f"\n[bold blue]Reporte de cumplimiento — {url}[/bold blue]",
        border_style="bright_blue",
        box=box.ROUNDED,
        min_width=80,
    )
    table.add_column("Cabecera",      style="white",    min_width=28)
    table.add_column("Estado",        justify="center", min_width=14)
    table.add_column("Resumen",       style="dim",      min_width=34)

    for header, data in results.items():
        if data is None:
            table.add_row(
                header,
                "[red]✘ FALTANTE[/red]",
                "[dim]No enviado por el servidor[/dim]"
            )
        else:
            w = worst_finding(data["findings"])
            sev, c = w["sev"], severity_color(w["sev"])
            if sev == "BAJO":
                estado = "[green]✔ OK[/green]"
            else:
                estado = f"[{c}]{severity_icon(sev)} {sev}[/{c}]"
            resumen = w["msg"][:48] + ("…" if len(w["msg"]) > 48 else "")
            table.add_row(header, estado, f"[{c}]{resumen}[/{c}]")

    console.print(table)


def print_detail_block(header: str, value: str, findings: list[dict]):
    w = worst_finding(findings)
    c = severity_color(w["sev"])
    console.print()
    console.rule(f"[{c}]{severity_icon(w['sev'])}  {header}[/{c}]", style=c)
    console.print(f"  [dim]Valor recibido:[/dim] [white]{value}[/white]")
    console.print()
    for f in findings:
        fc = severity_color(f["sev"])
        console.print(f"  [{fc}][{f['sev']}][/{fc}]  {f['msg']}")
        if f.get("detail"):
            for line in f["detail"].splitlines():
                console.print(f"         [dim]{line}[/dim]")


def print_permissions_detail(value: str):
    """Tabla de desglose feature por feature (solo si el valor es válido como PP)."""
    if looks_like_csp(value) and not looks_like_pp(value):
        return

    parsed = parse_permissions_policy(value)
    table = Table(
        title="\n  Desglose — features de Permissions-Policy",
        border_style="magenta",
        box=box.SIMPLE_HEAVY,
        show_lines=True,
        min_width=82,
    )
    table.add_column("Feature",      style="cyan",     min_width=22)
    table.add_column("Valor",        style="white",    min_width=12)
    table.add_column("Descripción",  style="dim",      min_width=32)
    table.add_column("Estado",       justify="center", min_width=14)

    shown = set()
    for feature, val in parsed.items():
        shown.add(feature)
        desc = PERMISSIONS_POLICY_FEATURES.get(feature, "Feature personalizada.")
        if val == "":
            status = "[green]✔ BLOQUEADA[/]"
        elif val == "*":
            status = "[bold red]✘ SIN LÍMITE[/]"
        else:
            status = f"[yellow]⚠ {val or '()'}[/]"
        table.add_row(feature, val or "()", desc, status)

    for feature in HIGH_RISK_PP_FEATURES:
        if feature not in shown:
            table.add_row(
                feature,
                "[dim]—[/dim]",
                PERMISSIONS_POLICY_FEATURES.get(feature, ""),
                "[yellow]⚠ HEREDADA[/]"
            )

    console.print(table)


def print_csp_report_only_notice(value: str):
    console.print()
    console.rule("[yellow]🟡  Content-Security-Policy-Report-Only detectado[/yellow]", style="yellow")
    preview = value[:120] + ("…" if len(value) > 120 else "")
    console.print(f"  [yellow][INFO][/yellow]  CSP en modo monitoreo — no aplica restricciones.")
    console.print(f"  [dim]Valor:[/dim] [white]{preview}[/white]")
    console.print("  [dim]Acción sugerida:[/dim] Promover a [bold]Content-Security-Policy[/bold] cuando esté validado.")


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

def analyze():
    console.clear()
    console.print(Panel.fit(
        "[bold cyan]ANALIZADOR DE CABECERAS DE SEGURIDAD[/bold cyan]",
        border_style="cyan"
    ))

    url = Prompt.ask("[bold yellow]URL del activo[/bold yellow]")
    if not url.startswith("http"):
        url = "https://" + url

    try:
        with console.status("[bold green]Escaneando...[/bold green]"):
            res = requests.get(
                url, timeout=10, verify=False,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
            )
            hdrs = res.headers  # requests usa dict case-insensitive

        # ── Evaluar ──────────────────────────────────────────────────────────
        results = {}

        val = hdrs.get("Content-Security-Policy")
        results["Content-Security-Policy"] = (
            {"value": val, "findings": eval_csp(val, hdrs)} if val else None
        )
        val = hdrs.get("Strict-Transport-Security")
        results["Strict-Transport-Security"] = (
            {"value": val, "findings": eval_hsts(val)} if val else None
        )
        val = hdrs.get("X-Frame-Options")
        results["X-Frame-Options"] = (
            {"value": val, "findings": eval_xfo(val)} if val else None
        )
        val = hdrs.get("X-Content-Type-Options")
        results["X-Content-Type-Options"] = (
            {"value": val, "findings": eval_xcto(val)} if val else None
        )
        val = hdrs.get("Referrer-Policy")
        results["Referrer-Policy"] = (
            {"value": val, "findings": eval_referrer(val)} if val else None
        )
        val = hdrs.get("Permissions-Policy")
        results["Permissions-Policy"] = (
            {"value": val, "findings": eval_permissions_policy(val)} if val else None
        )

        # ── SECCIÓN 1: Tabla resumen ─────────────────────────────────────────
        print_summary(url, results)

        # ── SECCIÓN 2: Detalle de hallazgos no-BAJO ──────────────────────────
        issues = [
            (h, d) for h, d in results.items()
            if d is None or any(f["sev"] != "BAJO" for f in d["findings"])
        ]

        if issues:
            console.print()
            console.print(Panel.fit(
                "[bold yellow]HALLAZGOS DETALLADOS[/bold yellow]",
                border_style="yellow"
            ))
            for header, data in issues:
                if data is None:
                    console.print()
                    console.rule(f"[red]🔴  {header}[/red]", style="red")
                    console.print("  [red][ALTO][/red]  Header no presente en la respuesta.")
                else:
                    non_low = [f for f in data["findings"] if f["sev"] != "BAJO"]
                    print_detail_block(header, data["value"], non_low)
                    if header == "Permissions-Policy":
                        print_permissions_detail(data["value"])

        # ── CSP-Report-Only sin CSP enforced ─────────────────────────────────
        csp_ro = hdrs.get("Content-Security-Policy-Report-Only")
        if csp_ro and results["Content-Security-Policy"] is None:
            print_csp_report_only_notice(csp_ro)

        # ── SECCIÓN 3: Resumen final ──────────────────────────────────────────
        console.print()
        counts = {s: 0 for s in SEV_ORDER}
        for data in results.values():
            if data is None:
                counts["ALTO"] += 1
            else:
                for f in data["findings"]:
                    counts[f["sev"]] += 1

        top_issues = [(s, counts[s]) for s in ["CRÍTICO", "ALTO", "MEDIO"] if counts[s] > 0]
        if not top_issues:
            console.print(Panel(
                "✅ El activo cumple con todas las políticas base de seguridad.",
                border_style="green"
            ))
        else:
            lines = [
                f"  {severity_icon(s)} [{severity_color(s)}]{n} hallazgo(s) {s}[/{severity_color(s)}]"
                for s, n in top_issues
            ]
            console.print(Panel("\n".join(lines), title="[bold]Resumen[/bold]", border_style="yellow"))

    except Exception as e:
        console.print(f"\n[bold red]✕ Error de conexión:[/bold red] {e}")


if __name__ == "__main__":
    analyze()
