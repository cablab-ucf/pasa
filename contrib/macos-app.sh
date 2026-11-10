#!/bin/sh
# pasa.app around the binary $1, in directory $2, at version $3: opening it
# is `pasa gui`. Finder gives an app a bare PATH, so where ykman and git
# usually are is added. Signed ad hoc: no Apple account is involved.
set -eu
a="$2/pasa.app/Contents"
mkdir -p "$a/MacOS"
cp "$1" "$a/MacOS/pasa"
cat > "$a/MacOS/pasa-gui" <<'EOF'
#!/bin/sh
PATH="$PATH:/opt/homebrew/bin:/usr/local/bin:$HOME/.nix-profile/bin:/run/current-system/sw/bin"
exec "$(dirname "$0")/pasa" gui
EOF
chmod +x "$a/MacOS/pasa-gui"
cat > "$a/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>CFBundleName</key><string>pasa</string>
<key>CFBundleIdentifier</key><string>org.pasa</string>
<key>CFBundleExecutable</key><string>pasa-gui</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>$3</string>
<key>NSHighResolutionCapable</key><true/>
</dict></plist>
EOF
ln -s pasa.app/Contents/MacOS/pasa "$2/pasa"
codesign --force --deep -s - "$2/pasa.app"
