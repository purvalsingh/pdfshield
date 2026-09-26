#!/usr/bin/env bash
# Benchmark PDFShield on real malware inside a locked-down container.
#
#   scripts/benchmark.sh MALICIOUS BENIGN [OUTPUT] [NAME]
#
# MALICIOUS and BENIGN may be folders or .zip archives. Files are picked by
# their %PDF header, so hash-named samples without an extension are included.
# Archives are unpacked
# *inside* the container, into memory (tmpfs), so live samples never touch your
# disk unpacked. Encrypted archives are tried with the conventional malware
# password "infected" (override with ZIP_PASSWORD=...).
#
# The container has no network, a read-only root filesystem, no capabilities,
# capped memory/processes, and sees your data read-only. Only OUTPUT is writable.
set -euo pipefail

MAL=$(realpath "$1"); BEN=$(realpath "$2")
OUT=$(realpath -m "${3:-benchmark-results}"); NAME=${4:-"real-world corpus"}
mkdir -p "$OUT"
cd "$(dirname "$0")/.."

docker build -q ${DOCKER_BUILD_ARGS:-} -t pdfshield . >/dev/null

mount_for() {  # a folder is mounted as-is; an archive's parent folder is mounted
  if [[ -d "$1" ]]; then echo "$1"; else dirname "$1"; fi
}

docker run --rm \
  --network none --read-only --cap-drop ALL --security-opt no-new-privileges \
  --memory 4g --pids-limit 256 \
  --user "$(id -u):$(id -g)" \
  --tmpfs /tmp:rw,size=4g --tmpfs "/unpacked:rw,size=8g,uid=$(id -u)" \
  -v "$(mount_for "$MAL")":/in/mal:ro -v "$(mount_for "$BEN")":/in/ben:ro \
  -v "$OUT":/out:rw \
  -e MAL_NAME="$(basename "$MAL")" -e MAL_IS_DIR="$([[ -d $MAL ]] && echo 1 || echo 0)" \
  -e BEN_NAME="$(basename "$BEN")" -e BEN_IS_DIR="$([[ -d $BEN ]] && echo 1 || echo 0)" \
  -e ZIP_PASSWORD="${ZIP_PASSWORD:-infected}" -e NAME="$NAME" \
  --entrypoint sh pdfshield -c '
set -e
prepare() {  # $1 = in-dir, $2 = name, $3 = is_dir, $4 = target
  if [ "$3" = 1 ]; then echo "$1"; return; fi
  python3 - "$1/$2" "$4" <<PY
import sys, zipfile, os
src, dst = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(src) as z:
    for pwd in (None, os.environ["ZIP_PASSWORD"].encode()):
        try:
            z.extractall(dst, pwd=pwd); break
        except RuntimeError:
            continue
PY
  echo "$4"
}
MALDIR=$(prepare /in/mal "$MAL_NAME" "$MAL_IS_DIR" /unpacked/mal)
BENDIR=$(prepare /in/ben "$BEN_NAME" "$BEN_IS_DIR" /unpacked/ben)
pdfshield benchmark --malicious "$MALDIR" --benign "$BENDIR" \
  --name "$NAME" --output /out --cache /out/features-cache.json
'
echo "Report: $OUT/benchmark.md"
