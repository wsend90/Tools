#!/bin/bash

ARCHIVO_IPS="activos.txt"

if [ ! -f "$ARCHIVO_IPS" ]; then
    echo "Error: El archivo $ARCHIVO_IPS no existe."
    exit 1
fi

echo "Iniciando comprobación de activos..."
echo "------------------------------------------------"

while IFS= read -r ip || [ -n "$ip" ]; do

    # Quitar posibles espacios o retornos de carro (archivos Windows)
    ip=$(echo "$ip" | tr -d '\r' | xargs)

    # Saltar líneas vacías
    [ -z "$ip" ] && continue

    # Hacer ping (2 intentos, espera 2 segundos)
    if ping -c 1 -W 2 "$ip" > /dev/null 2>&1; then
        printf "%-9s %-15s  %s\n" "[ OK ]" "$ip" "está activo"
    else
        printf "%-9s %-15s  %s\n" "[ FALLO ]" "$ip" "no responde"
    fi

done < "$ARCHIVO_IPS"

echo "------------------------------------------------"
echo "Escaneo finalizado."