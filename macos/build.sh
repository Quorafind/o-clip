#!/bin/zsh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
APP_NAME="O-Clip"
EXECUTABLE_NAME="OClipApp"
APP_DIR="$SCRIPT_DIR/$APP_NAME.app"
CONTENTS_DIR="$APP_DIR/Contents"
MACOS_DIR="$CONTENTS_DIR/MacOS"
RESOURCES_DIR="$CONTENTS_DIR/Resources"
BUILD_DIR="$SCRIPT_DIR/build"

rm -rf "$APP_DIR"
mkdir -p "$MACOS_DIR" "$RESOURCES_DIR" "$BUILD_DIR"

swiftc "$SCRIPT_DIR/OClipApp.swift" \
    -o "$MACOS_DIR/$EXECUTABLE_NAME" \
    -framework AppKit \
    -framework Combine \
    -framework Foundation \
    -framework SwiftUI \
    -lsqlite3

cp "$SCRIPT_DIR/Info.plist" "$CONTENTS_DIR/Info.plist"
chmod +x "$MACOS_DIR/$EXECUTABLE_NAME"

echo "Created $APP_DIR"
echo "Double-click $APP_NAME.app to start the native Swift O-Clip app."
