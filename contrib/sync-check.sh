#!/usr/bin/env bash
# Two stores on this machine sync through the relay, as a phone and a new
# desktop would: "phone" has the store, "desk" none. desk shows an offline
# QR code; phone takes it and dials; the store arrives sealed. Then each
# side's change reaches the other, and what is on disk is checked.
#   contrib/sync-check.sh [DIR]     (Linux: needs script(1); age(1) optional)
set -u
P=${PASA:-pasa}
cd "${1:-$(mktemp -d)}" || exit 1
rm -rf phone desk desk.out desk.fifo; mkdir phone desk
say() { echo "== $(date +%T) $*"; }
# p DIR "LINE..." ARGS: pasa on store DIR, each LINE typed at a prompt.
p() {
  local d=$1 in=$2; shift 2
  { for l in $in; do sleep 1; echo "$l"; done; sleep 2; } |
    PASA_DIR=$PWD/$d script -qec "$P $*" /dev/null | tr -d '\r' |
    grep -av '^\(Password\|Pairing password\|New password\|Again\): *$'
}

say "phone: a store"
p phone 'pw pw' init
p phone 'hunter2 pw' set mail/work
say "desk: no store; it shows a QR code and serves"
mkfifo desk.fifo; exec 3<>desk.fifo
PASA_DIR=$PWD/desk script -qec "$P pair phone --qr" /dev/null <&3 >desk.out 2>&1 &
until grep -q '^password: ' desk.out 2>/dev/null; do sleep 0.2; done
QR=$(grep -ao 'PAIRIR1:[A-Z2-7]*' desk.out | head -1)
PW=$(sed -n 's/^password: //p' desk.out | tr -d '\r')
say "phone: takes it and dials desk"
p phone "$PW pw" join desk "$QR"
echo pw >&3; wait
p desk 'pw' show mail/work | grep -q hunter2 && echo "desk holds the store"
say "desk serves; phone's change reaches it"
PASA_DIR=$PWD/desk $P serve 2>&1 & S=$!; sleep 3
p phone 'phone-secret-1 pw' set a
kill $S; wait $S 2>/dev/null
say "phone serves; desk dials it, having learnt where"
PASA_DIR=$PWD/phone $P serve 2>&1 & S=$!; sleep 3
p desk 'desk-secret-2 pw' set b
kill $S; wait $S 2>/dev/null
for d in phone desk; do
  echo "$d: $(p $d pw ls | tr '\n' ' ')"
done
say "on disk: age files only; no password or store key in the clear"
k=$(p phone pw keys | tail -1)
for d in phone desk; do
  n=$(ls $d/v | wc -l)
  a=$(for f in $d/v/*; do head -n1 "$f"; done | grep -c '^age-encryption.org/v1$')
  c=$(grep -rlaF -e hunter2 -e phone-secret-1 -e desk-secret-2 -e "$k" $d | wc -l)
  echo "$d: $a of $n versions are age files; $c files hold a secret"
done
