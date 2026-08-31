#!/bin/bash
# ============================================================
# procesar_mirai_completo.sh
# Igual que procesar_mirai_nuevos.sh pero ampliado a los 76
# pcaps de Mirai (greeth 0-28, udpplain 0-24, greip 0-21).
#
# Flujo por pcap (idéntico al script original):
#   1. capinfos  → timestamp de inicio
#   2. editcap   → recortar 40 segundos
#   3. tstat     → logs en _tmp_mirai/<timestamp>.out/
#   4. csv       → convertir logs a CSV (TCP/Mirai/ y UDP/Mirai/)
#   5. tshark    → .txt en ArchivosTshark_2/Txt/Mirai/
#
# Lee pcaps de:    /media/miguel/Pen Miguel/Mirai/<subtipo>/
# Salidas a:       /media/miguel/Pen Miguel/Archivos{Tstat,Tshark_2}/
#   (intermedios; los CSVs finales los hacen los dos .py luego)
#
# Sobreescribe los CSVs de Mirai que ya existan (1-5).
# ============================================================

# NO usamos set -e: queremos que un fallo en un pcap no
# detenga el resto del bucle.

# ── CONFIGURACIÓN ────────────────────────────────────────────
BASE_PCAP="/media/miguel/Pen Miguel/Mirai"           # contiene Mirai_greeth_flood/, Mirai_greip/, Mirai_udpplain/
BASE_OUT="/media/miguel/Pen Miguel"

# Pcaps recortados a 40s (intermedios)
DIR_PCAP_40S="$BASE_OUT/Mirai_40s"

# Tstat
DIR_TSTAT_TMP="$BASE_OUT/ArchivosTstat/_tmp_mirai"
DIR_TSTAT_TCP="$BASE_OUT/ArchivosTstat/TCP/Mirai"
DIR_TSTAT_UDP="$BASE_OUT/ArchivosTstat/UDP/Mirai"

# Tshark
DIR_TSHARK_TXT="$BASE_OUT/ArchivosTshark_2/Txt/Mirai"

# ── FLAGS ────────────────────────────────────────────────────
DO_TSTAT=1
DO_TSHARK=1

# ── CREAR CARPETAS ───────────────────────────────────────────
mkdir -p "$DIR_PCAP_40S" "$DIR_TSTAT_TMP" "$DIR_TSTAT_TCP" "$DIR_TSTAT_UDP" "$DIR_TSHARK_TXT"

# ── FUNCIÓN PRINCIPAL — réplica exacta de tu flujo ───────────
procesar() {
    local PCAP_ORIGINAL="$1"
    local NOMBRE="$2"

    echo ""
    echo "════════════════════════════════════════════════════════"
    echo "  Procesando: $NOMBRE"
    echo "════════════════════════════════════════════════════════"

    local PCAP_40S="$DIR_PCAP_40S/${NOMBRE}_40s.pcap"

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
    if [ ! -f "$PCAP_40S" ]; then
        echo "  ✗ editcap no generó $PCAP_40S — saltando"
        return 1
    fi
    echo "  ✓ → $PCAP_40S"

    # ── PASO 3: tstat ────────────────────────────────────────
    if [ $DO_TSTAT -eq 1 ]; then
        echo ""
        echo "  [3/5] tstat → procesando..."

        local RUN_DIR="$DIR_TSTAT_TMP/run_${NOMBRE}"
        mkdir -p "$RUN_DIR"
        tstat -s "$RUN_DIR" "$PCAP_40S" > /dev/null 2>&1

        local OUT_DIR_NAME
        OUT_DIR_NAME=$(ls "$RUN_DIR" 2>/dev/null | grep '\.out$' | head -1)

        if [ -z "$OUT_DIR_NAME" ]; then
            echo "  ✗ tstat no generó salida"
            rm -rf "$RUN_DIR"
        else
            echo "  ✓ output dir: $OUT_DIR_NAME"

            # ── PASO 4: convertir logs a CSV ────────────────
            echo ""
            echo "  [4/5] Convirtiendo logs tstat a CSV..."

            local LOG_TCP="${RUN_DIR}/${OUT_DIR_NAME}/log_tcp_complete"
            local LOG_UDP="${RUN_DIR}/${OUT_DIR_NAME}/log_udp_complete"
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

            rm -rf "$RUN_DIR"
        fi
    fi

    # ── PASO 5: tshark TCP + UDP ─────────────────────────────
    if [ $DO_TSHARK -eq 1 ]; then
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
    fi

    echo ""
    echo "  ✓✓ $NOMBRE completado"
}

# ============================================================
# PCAPS A PROCESAR — 76 en total
# ============================================================

echo "╔══════════════════════════════════════════════════════════╗"
echo "║  MIRAI COMPLETO — 76 pcaps (recortados a 40s)            ║"
echo "║  greeth_flood (0-28) + udpplain (0-24) + greip (0-21)    ║"
echo "╚══════════════════════════════════════════════════════════╝"

ok=0
miss=0
total=0

# ── greeth_flood ─────────────────────────────────────────────
SUBDIR="$BASE_PCAP/Mirai_greeth_flood"

# pcap 0 (sin número)
total=$((total+1))
PCAP="$SUBDIR/Mirai-greeth_flood.pcap"
if [ -f "$PCAP" ]; then
    procesar "$PCAP" "Mirai-greeth_flood" && ok=$((ok+1))
else
    echo "  ⚠ No encontrado: $PCAP — saltando"
    miss=$((miss+1))
fi

# pcaps 1 a 28
for N in $(seq 1 28); do
    total=$((total+1))
    PCAP="$SUBDIR/Mirai-greeth_flood${N}.pcap"
    if [ -f "$PCAP" ]; then
        procesar "$PCAP" "Mirai-greeth_flood${N}" && ok=$((ok+1))
    else
        echo "  ⚠ No encontrado: $PCAP — saltando"
        miss=$((miss+1))
    fi
done

# ── udpplain ─────────────────────────────────────────────────
SUBDIR="$BASE_PCAP/Mirai_udpplain"

total=$((total+1))
PCAP="$SUBDIR/Mirai-udpplain.pcap"
if [ -f "$PCAP" ]; then
    procesar "$PCAP" "Mirai-udpplain" && ok=$((ok+1))
else
    echo "  ⚠ No encontrado: $PCAP — saltando"
    miss=$((miss+1))
fi

for N in $(seq 1 24); do
    total=$((total+1))
    PCAP="$SUBDIR/Mirai-udpplain${N}.pcap"
    if [ -f "$PCAP" ]; then
        procesar "$PCAP" "Mirai-udpplain${N}" && ok=$((ok+1))
    else
        echo "  ⚠ No encontrado: $PCAP — saltando"
        miss=$((miss+1))
    fi
done

# ── greip_flood ──────────────────────────────────────────────
SUBDIR="$BASE_PCAP/Mirai_greip"

total=$((total+1))
PCAP="$SUBDIR/Mirai-greip_flood.pcap"
if [ -f "$PCAP" ]; then
    procesar "$PCAP" "Mirai-greip_flood" && ok=$((ok+1))
else
    echo "  ⚠ No encontrado: $PCAP — saltando"
    miss=$((miss+1))
fi

for N in $(seq 1 21); do
    total=$((total+1))
    PCAP="$SUBDIR/Mirai-greip_flood${N}.pcap"
    if [ -f "$PCAP" ]; then
        procesar "$PCAP" "Mirai-greip_flood${N}" && ok=$((ok+1))
    else
        echo "  ⚠ No encontrado: $PCAP — saltando"
        miss=$((miss+1))
    fi
done

# ── Limpiar carpeta temporal de tstat ────────────────────────
rm -rf "$DIR_TSTAT_TMP" 2>/dev/null

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║  COMPLETADO                                              ║"
echo "║  Procesados:     $ok / $total                                  ║"
echo "║  No encontrados: $miss                                        ║"
echo "╠══════════════════════════════════════════════════════════╣"
echo "║  Siguientes pasos:                                       ║"
echo "║  1. python3 tshark_mirai_txt2csv.py                      ║"
echo "║  2. python3 tstat_mirai_join.py                          ║"
echo "╚══════════════════════════════════════════════════════════╝"
