#!/usr/bin/env bash
# Run on the dedicated lab host after installing Guard and preparing the
# isolated collector namespace. Each stage writes its own evidence files.
set -euo pipefail

mode=$1
id=$2
output=$3
case "$id" in (*[!a-f0-9-]*|'') exit 2 ;; esac
case "$mode" in
  offline) filter='host 198.18.0.2 or host fd42:abcd::2'; marker='GUARD_PROBE complete';;
  broker) filter='tcp port 443 and (host 45.91.11.1 or host 2602:ff16::2)'; marker='GUARD_BROKER replay';;
  *) echo "usage: qualify.sh offline|broker ID OUTPUT_DIR" >&2; exit 2;;
esac
mkdir -p "$output"
tools=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
socket=/run/alethic-guard/operator.sock
request=$(printf '{"id":"%s"}' "$id")
call() { sudo python3 "$tools/guard-operator.py" "$socket" "$1" "$request"; }

sudo timeout 210 tcpdump -n -i guard-observe -U -w "$output/$mode.pcap" "$filter" \
    > "$output/$mode-pcap.log" 2>&1 &
capture=$!
trap 'sudo kill -TERM "$capture" >/dev/null 2>&1 || true' EXIT
sleep .3
if [ "$mode" = offline ]; then
    ping -n -c 1 -W 2 198.18.0.2
    ping -n -6 -c 1 -W 2 fd42:abcd::2
fi
call start > "$output/$mode-start.json"
sudo virsh domiflist "$id" > "$output/$mode-interfaces.txt"
sudo virsh dumpxml "$id" > "$output/$mode-domain.xml"
sudo script -q -f -c "timeout -s INT 190 virsh console $id" "$output/$mode-console.log" \
    < /dev/null > /dev/null &
serial=$!
for tick in $(seq 1 170); do
    if grep -aq "$marker" "$output/$mode-console.log" 2>/dev/null; then break; fi
    sleep 1
done
call contain > "$output/$mode-contain.json"
call terminate > "$output/$mode-terminate.json"
sudo python3 "$tools/guard-operator.py" "$socket" evidence_page "$(printf '{"id":"%s","after":0}' "$id")" > "$output/$mode-events.json"
wait "$serial" || true
grep -a "$marker" "$output/$mode-console.log"
