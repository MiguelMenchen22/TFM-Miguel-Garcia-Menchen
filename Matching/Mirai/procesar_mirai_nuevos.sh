#!/bin/bash
# ============================================================
# procesar_mirai_nuevos.sh
# Procesa los pcaps numerados de Mirai (greeth_flood 1-5 y
# udpplain 1-5) con Tstat y Tshark.
#
# Respeta la estructura existente:
#   ArchivosTstat/
#     ├── CSV/Mirai/   ← CSVs fusionados tcp+udp (nuevo)
#     ├── TCP/         ← sin tocar
#     └── UDP/         ← sin tocar
#
#   ArchivosTshark_2/
#     ├── Txt/         ← .txt intermedios (ya existe)
#     └── Csv/Mirai/   ← CSVs finales (ya existe)
#
# Flujo por pcap:
#   1. capinfos  → timestamp de inicio
#   2. editcap   → recortar 40 segundos
#   3. tstat     → logs en ArchivosTstat/<timestamp>.out/
#   4. csv       → convertir logs a CSV en ArchivosTstat/CSV/Mirai/
#   5. tshark    → .txt en ArchivosTshark_2/Txt/
#                  (luego ejecuta feature_extraction_v2.py / txt2csv.ipynb)
# ============================================================

set -e

BASE_PCAP="/home/miguel/Escritorio/TFM/TFM_Miguel/CapturasTrafico"
DIR_TSTAT="/home/miguel/Escritorio/TFM/TFM_Miguel/ArchivosTstat"
DIR_TSTAT_TCP="/home/miguel/Escritorio/TFM/TFM_Miguel/ArchivosTstat/TCP/Mirai"
DIR_TSTAT_UDP="/home/miguel/Escritorio/TFM/TFM_Miguel/ArchivosTstat/UDP/Mirai"
DIR_TSHARK_TXT="/home/miguel/Escritorio/TFM/TFM_Miguel/ArchivosTshark_2/Txt"

# Crea subcarpetas Mirai dentro de TCP/ y UDP/ (igual que existe Benign, etc.)
mkdir -p "$DIR_TSTAT_TCP"
mkdir -p "$DIR_TSTAT_UDP"

# ── Función principal ────────────────────────────────────────
procesar() {
    local PCAP_ORIGINAL="$1"
    local NOMBRE="$2"

    echo ""
    echo "════════════════════════════════════════════════════════"
    echo "  Procesando: $NOMBRE"
    echo "════════════════════════════════════════════════════════"

    local PCAP_40S="${PCAP_ORIGINAL%/*}/${NOMBRE}_40s.pcap"

    # ── PASO 1: capinfos → timestamp de inicio ──────────────
    echo ""
    echo "  [1/5] capinfos → buscando timestamp de inicio..."
    local START_RAW
    START_RAW=$(capinfos -a "$PCAP_ORIGINAL" 2>/dev/null \
        | grep "First packet time" \
        | sed 's/First packet time:\s*//' \
        | tr -d '\r')

    if [ -z "$START_RAW" ]; then
        echo "  ✗ No se pudo obtener el timestamp de $PCAP_ORIGINAL"
        return 1
    fi
    echo "  → Inicio detectado: $START_RAW"

    # Calcular timestamps de inicio y fin (inicio + 40s)
    # capinfos puede devolver coma decimal: 16:37:06,823872 → se normaliza a punto
    local START_FMT END_FMT
    START_FMT=$(python3 -c "
from datetime import datetime
s = '${START_RAW}'.strip().replace(',', '.')
for fmt in ['%Y-%m-%d %H:%M:%S.%f', '%Y-%m-%d %H:%M:%S']:
    try:
        dt = datetime.strptime(s, fmt)
        break
    except:
        continue
print(dt.strftime('%Y-%m-%d %H:%M:%S.') + f'{dt.microsecond:06d}')
")
    END_FMT=$(python3 -c "
from datetime import datetime, timedelta
s = '${START_RAW}'.strip().replace(',', '.')
for fmt in ['%Y-%m-%d %H:%M:%S.%f', '%Y-%m-%d %H:%M:%S']:
    try:
        dt = datetime.strptime(s, fmt)
        break
    except:
        continue
dt2 = dt + timedelta(seconds=40)
print(dt2.strftime('%Y-%m-%d %H:%M:%S.') + f'{dt2.microsecond:06d}')
")
    echo "  → Inicio: $START_FMT"
    echo "  → Fin:    $END_FMT"

    # ── PASO 2: editcap → recortar 40s ──────────────────────
    echo ""
    echo "  [2/5] editcap → recortando a 40 segundos..."
    editcap \
        -A "$START_FMT" \
        -B "$END_FMT" \
        "$PCAP_ORIGINAL" \
        "$PCAP_40S"
    echo "  ✓ → $PCAP_40S"

    # ── PASO 3: tstat ────────────────────────────────────────
    echo ""
    echo "  [3/5] tstat → procesando..."
    tstat -s "$DIR_TSTAT" "$PCAP_40S"

    # El .out más reciente generado por tstat
    local OUT_DIR_NAME
    OUT_DIR_NAME=$(ls -t "$DIR_TSTAT" | grep '\.out$' | head -1)
    echo "  ✓ output dir: $OUT_DIR_NAME"

    # ── PASO 4: convertir logs a CSV ────────────────────────
    echo ""
    echo "  [4/5] Convirtiendo logs a CSV..."

    local LOG_TCP="${DIR_TSTAT}/${OUT_DIR_NAME}/log_tcp_complete"
    local LOG_UDP="${DIR_TSTAT}/${OUT_DIR_NAME}/log_udp_complete"
    local OUT_TCP="${DIR_TSTAT_TCP}/${NOMBRE}_tcp.csv"
    local OUT_UDP="${DIR_TSTAT_UDP}/${NOMBRE}_udp.csv"

    if [ -f "$LOG_TCP" ]; then
        grep -m1 '^#' "$LOG_TCP" \
            | sed 's/^#\([0-9]\+#\)\?//' \
            | sed 's/:[0-9]\+//g' \
            | tr -s ' \t' ',' \
            > "$OUT_TCP"
        grep -v '^#' "$LOG_TCP" \
            | tr -s ' \t' ',' \
            >> "$OUT_TCP"
        echo "  ✓ TCP → $OUT_TCP"
    else
        echo "  ⚠ log_tcp_complete no encontrado"
    fi

    if [ -f "$LOG_UDP" ]; then
        grep -m1 '^#' "$LOG_UDP" \
            | sed 's/^#\([0-9]\+#\)\?//' \
            | sed 's/:[0-9]\+//g' \
            | tr -s ' \t' ',' \
            > "$OUT_UDP"
        grep -v '^#' "$LOG_UDP" \
            | tr -s ' \t' ',' \
            >> "$OUT_UDP"
        echo "  ✓ UDP → $OUT_UDP"
    else
        echo "  ⚠ log_udp_complete no encontrado"
    fi

    # ── PASO 5: tshark TCP + UDP ─────────────────────────────
    echo ""
    echo "  [5/5] tshark → extrayendo TCP y UDP..."

    local TXT_TCP="${DIR_TSHARK_TXT}/${NOMBRE}TCP_v2.txt"
    local TXT_UDP="${DIR_TSHARK_TXT}/${NOMBRE}UDP_v2.txt"

    tshark -r "$PCAP_40S" \
        -Y "tcp" -T fields \
        -E header=y -E separator=$'\t' -E quote=n \
        -e tcp.stream -e ip.src -e ip.dst \
        -e tcp.srcport -e tcp.dstport -e frame.len \
        -e ip.flags.rb -e ip.flags.df -e ip.flags.mf \
        -e tcp.flags.res -e tcp.flags.ns -e tcp.flags.cwr \
        -e tcp.flags.ecn -e tcp.flags.urg \
        -e tcp.flags.ack -e tcp.flags.push \
        -e tcp.flags.reset -e tcp.flags.syn -e tcp.flags.fin \
        -e frame.time_epoch -e ip.ttl \
        -e tcp.checksum.status -e ip.checksum.status \
        -e tcp.seq_raw -e tcp.ack_raw \
        -e tcp.window_size_value -e tcp.len \
        > "$TXT_TCP"
    echo "  ✓ TCP → $TXT_TCP"

    tshark -r "$PCAP_40S" \
        -Y "udp" -T fields \
        -E header=y -E separator=$'\t' -E quote=n \
        -e udp.stream -e ip.src -e ip.dst \
        -e udp.srcport -e udp.dstport -e frame.len \
        -e ip.flags.rb -e ip.flags.df -e ip.flags.mf \
        -e frame.time_epoch -e ip.ttl \
        -e udp.checksum.status -e ip.checksum.status \
        -e tcp.seq_raw -e tcp.ack_raw \
        -e tcp.window_size_value -e udp.length \
        > "$TXT_UDP"
    echo "  ✓ UDP → $TXT_UDP"

    echo ""
    echo "  ✓✓ $NOMBRE completado"
    echo ""
}

# ============================================================
# PCAPS A PROCESAR
# ============================================================

echo "╔══════════════════════════════════════════════════════════╗"
echo "║  MIRAI — greeth_flood 1-5 y udpplain 1-5               ║"
echo "╚══════════════════════════════════════════════════════════╝"

for N in 1 2 3 4 5; do
    PCAP="${BASE_PCAP}/Mirai_greeth_flood/Mirai-greeth_flood${N}.pcap"
    if [ -f "$PCAP" ]; then
        procesar "$PCAP" "Mirai-greeth_flood${N}"
    else
        echo "  ⚠ No encontrado: $PCAP — saltando"
    fi
done

for N in 1 2 3 4 5; do
    PCAP="${BASE_PCAP}/Mirai_udpplain/Mirai-udpplain${N}.pcap"
    if [ -f "$PCAP" ]; then
        procesar "$PCAP" "Mirai-udpplain${N}"
    else
        echo "  ⚠ No encontrado: $PCAP — saltando"
    fi
done

echo "╔══════════════════════════════════════════════════════════╗"
echo "║  Script terminado.                                       ║"
echo "║  Siguientes pasos:                                       ║"
echo "║  1. join_udp_tcp.ipynb → fusiona TCP+UDP de cada pcap   ║"
echo "║     lee de TCP/Mirai/ y UDP/Mirai/                       ║"
echo "║     guarda en CSV/Mirai/                                 ║"
echo "║  2. feature_extraction_v2.py o txt2csv.ipynb             ║"
echo "║     sobre los .txt de ArchivosTshark_2/Txt/             ║"
echo "╚══════════════════════════════════════════════════════════╝"
