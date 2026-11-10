#!/bin/sh
# A pasa 0.1 store (age files) into pasa 0.2: needs age 1.3+ (its
# post-quantum keys), and age-plugin-yubikey if a YubiKey opens key.age.
set -eu
old=${PASSWORD_STORE_DIR:-$HOME/.password-store}
tmp=$(mktemp -d "${XDG_RUNTIME_DIR:-/dev/shm}/pasa.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
cfg=$(dirname "${PASA_KEY_FILE:-$HOME/.config/pasa/key.age}")
age -d "${PASA_KEY_FILE:-$cfg/key.age}" > "$tmp/ids"
# Before 0.1.24 key.age held a device key; the store keys sat apart,
# sealed to it (keys.age, or the store's .pasa-keys/).
if grep -q '^# pasa device key' "$tmp/ids"; then
  for k in "$cfg/keys.age" "$old"/.pasa-keys/*.age; do
    [ -f "$k" ] && age -d -i "$tmp/ids" "$k" >> "$tmp/store" 2>/dev/null && break
  done
  mv "$tmp/store" "$tmp/ids"
fi
cd "$old"
find . -name '*.age' ! -path '*/.*' | while read -r f; do
  n=${f#./}; mkdir -p "$tmp/x/$(dirname "$n")"
  age -d -i "$tmp/ids" "$f" > "$tmp/x/${n%.age}"
done
tar -C "$tmp/x" -cf - . | pasa load
