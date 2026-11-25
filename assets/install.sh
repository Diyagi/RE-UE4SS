#!/usr/bin/env bash
set -e

WORKSHOPMOD_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
DST="$WORKSHOPMOD_DIR/../../../../common/MISERY/MISERY/Binaries/Win64"

cp -v "$WORKSHOPMOD_DIR/dwmapi.dll" "$WORKSHOPMOD_DIR/override.txt" "$WORKSHOPMOD_DIR/UE4SS-settings.ini" "$DST/"

echo "Done!"
