#!/bin/sh
# The hardware-key code reaches no network: neither what the app says to a
# key (Yubikey.kt, Fido.kt) nor Yubico's library (every yubikit artifact
# Gradle resolved for the build) names a class that could open a connection.
# Run after a build; CI does, so a change that breaks this fails there.
set -eu
cd "$(dirname "$0")"
if grep -nE 'java\.net\.|javax\.net\.|okhttp|android\.net\.' \
    app/src/main/java/com/apasa/Yubikey.kt app/src/main/java/com/apasa/Fido.kt; then
    echo "the key code names network classes" >&2; exit 1
fi
net='java/net/(URL|Socket|HttpURLConnection|URLConnection|InetAddress|DatagramSocket)|javax/net/|okhttp|android/net/(http|ConnectivityManager|Network)|SocketChannel'
found=0
for a in $(find "${GRADLE_USER_HOME:-$HOME/.gradle}/caches/modules-2/files-2.1/com.yubico.yubikit" \
    \( -name '*.jar' -o -name '*.aar' \) ! -name '*sources*' ! -name '*javadoc*'); do
    d=$(mktemp -d)
    unzip -q -o "$a" -d "$d"
    if [ -f "$d/classes.jar" ]; then unzip -q -o "$d/classes.jar" -d "$d"; fi
    if grep -rlE "$net" "$d" --include='*.class'; then
        echo "$a names network classes" >&2; exit 1
    fi
    rm -rf "$d"
    found=$((found + 1))
done
[ "$found" -ge 4 ] || { echo "only $found yubikit artifacts found: build first" >&2; exit 1; }
echo "no network in the key code, nor in $found yubikit artifacts"
