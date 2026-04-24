#!/usr/bin/env python3
import requests
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

def generate_report(url):
    security_headers = {
        "Content-Security-Policy": "Previene XSS y ataques de inyección.",
        "Strict-Transport-Security": "Fuerza el uso de conexiones HTTPS seguras.",
        "X-Content-Type-Options": "Previene que el navegador adivine el tipo de contenido.",
        "X-Frame-Options": "Protege contra ataques de Clickjacking.",
        "Referrer-Policy": "Controla cuánta información de referencia se envía.",
        "Permissions-Policy": "Restringe el acceso a funciones del navegador (cámara, micro)."
    }
    
    try:
        response = requests.get(url, timeout=10)
        headers = response.headers
        console = Console(record=True) # Activamos la grabación para exportar

        table = Table(title=f"Reporte de Seguridad: {url}", show_header=True, header_style="bold cyan")
        table.add_column("Cabecera", style="bold")
        table.add_column("Estado", justify="center")
        table.add_column("Descripción técnica", style="dim")

        missing_count = 0
        for header, desc in security_headers.items():
            if header in headers:
                table.add_row(header, "[green]✔ PRESENTE[/green]", desc)
            else:
                table.add_row(header, "[red]✘ FALTANTE[/red]", desc)
                missing_count += 1

        # Resumen visual
        color = "red" if missing_count > 2 else "green"
        console.print(Panel(f"Activo: {url}\nCabeceras faltantes: {missing_count}", title="Resumen", border_style=color))
        console.print(table)

        # GUARDAR COMO HTML PROFESIONAL
#        filename = url.replace("https://", "").replace("/", "_") + ".html"
#        console.save_html(filename)
#        print(f"\n[✔] Reporte visual guardado como: {filename}")

    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    target = input("Introduce la URL: ")
    if not target.startswith("http"): target = "https://" + target
    generate_report(target)
