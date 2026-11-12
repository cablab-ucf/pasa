#!/usr/bin/env bash
# Stores on this machine pair and sync through the relay, as devices
# would. "phone" holds the store; "desk" takes its keys by QR code (under a
# two-letter password), "lap" by short code, and each syncs the store before
# the store's password is typed anywhere. Then changes go each way, and
# what is on disk is checked.
#   contrib/sync-check.sh [DIR]     (Linux: needs script(1))
set -u
P=${PASA:-pasa}
cd "${1:-$(mktemp -d)}" || exit 1
rm -rf phone desk lap ./*.out ./*.fifo; mkdir phone desk lap
say() { echo "== $(date +%T) $*"; }
# p DIR "LINE..." ARGS: pasa on store DIR, each LINE typed at a prompt.
p() {
  local d=$1 in=$2; shift 2
  { for l in $in; do sleep 1; echo "$l"; done; sleep 2; } |
    PASA_DIR=$PWD/$d script -qec "$P $*" /dev/null | tr -d '\r' |
    grep -av '^QR code password: *$'
}
# until PATTERN FILE: wait for PATTERN in FILE, two minutes at most.
until_in() {
  for _ in $(seq 600); do grep -aq "$1" "$2" 2>/dev/null && return; sleep 0.2; done
  echo "never came: $1"; cat "$2"; exit 1
}
# bg DIR ARGS: pasa on store DIR in the background, typed at through DIR.fifo.
bg() {
  local d=$1; shift
  rm -f "$d.fifo"; mkfifo "$d.fifo"; exec {fd}<>"$d.fifo"
  PASA_DIR=$PWD/$d script -qec "$P $*" /dev/null <&$fd >"$d.out" 2>&1 &
}

say "phone: a store"
p phone 'pw pw' init
p phone 'hunter2 pw' set mail/work
say "phone: a QR code for desk, its password first (ab); then it serves"
bg phone pair desk --qr
sleep 1; echo ab >phone.fifo
until_in 'PAIRIR1:' phone.out
QR=$(grep -ao 'PAIRIR1:[A-Z2-7]*' phone.out | head -1)
grep -aqw ab phone.out && echo "the QR code's password is on the screen" && exit 1
say "desk: takes it (the QR code's password alone), and syncs"
p desk 'ab' join phone "$QR" | tee desk.out
wait
grep -aq 'Password:' phone.out desk.out && echo "pairing asked for the store's password" && exit 1
p desk 'pw' show mail/work | grep -q hunter2 && echo "desk holds the store"
say "phone: a short code for lap; lap takes it, and syncs"
bg phone pair lap
until_in '^there: pasa join' phone.out
CODE=$(sed -n 's/^there: pasa join NAME //p' phone.out | tr -d '\r')
p lap '' join phone "$CODE"
wait
say "desk serves; phone's change reaches it"
PASA_DIR=$PWD/desk $P serve 2>&1 & S=$!; sleep 3
p phone 'phone-secret-1 pw' set a
kill $S; wait $S 2>/dev/null
say "phone serves; desk dials it, having learnt where"
PASA_DIR=$PWD/phone $P serve 2>&1 & S=$!; sleep 3
p desk 'desk-secret-2 pw' set b
kill $S; wait $S 2>/dev/null
for d in phone desk lap; do
  echo "$d: $(p $d pw ls | tr '\n' ' ')"
done
say "what the network side sees (v/, net/): no key file, no store key, no secret"
k=$(p phone pw keys | tail -1)
for d in phone desk lap; do
  n=$(ls $d/v | wc -l)
  a=$(for f in $d/v/*; do head -n1 "$f"; done | grep -c '^age-encryption.org/v1$')
  c=$(grep -rlaF -e hunter2 -e phone-secret-1 -e desk-secret-2 -e "$k" \
    $d/v $d/net | wc -l)
  echo "$d: $a of $n versions are age files; $c files hold a secret"
done
