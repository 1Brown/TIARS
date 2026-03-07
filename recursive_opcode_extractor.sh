#!/usr/bin/env bash
set -euo pipefail

DATASET_ROOT="${1:-}"
OUT_ROOT="${2:-$HOME/opcodes_out}"
ANALYZE_HEADLESS="${3:-/opt/ghidra/support/analyzeHeadless}"
PASSWORD="infected"

MAX_NESTING="${MAX_NESTING:-5}"
MAX_FILES_PER_ARCHIVE="${MAX_FILES_PER_ARCHIVE:-5000}"

if [[ -z "$DATASET_ROOT" || ! -d "$DATASET_ROOT" ]]; then
  echo "Usage: $0 /path/to/dataset_root [/path/to/output_root] [/path/to/analyzeHeadless]"
  exit 1
fi

for cmd in file unzip 7z find mktemp; do
  command -v "$cmd" >/dev/null 2>&1 || {
    echo "Missing dependency: $cmd"
    exit 1
  }
done

if [[ ! -x "$ANALYZE_HEADLESS" ]]; then
  echo "analyzeHeadless not executable: $ANALYZE_HEADLESS"
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GHIDRA_SCRIPTS_DIR="$SCRIPT_DIR/ghidra_scripts"
[[ -f "$GHIDRA_SCRIPTS_DIR/DumpOpcodes.java" ]] || {
  echo "Missing: $GHIDRA_SCRIPTS_DIR/DumpOpcodes.java"
  exit 1
}

mkdir -p "$OUT_ROOT"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

sanitize() {
  echo "$1" | tr ' /' '__' | tr -cd 'A-Za-z0-9._-'
}

group_from_path() {
  local full="$1"
  local rel="${full#$DATASET_ROOT/}"
  local g="${rel%%/*}"
  [[ "$g" == "$rel" ]] && echo "UNKNOWN_GROUP" || echo "$g"
}

extract_archive() {
  local arch="$1"
  local outdir="$2"
  mkdir -p "$outdir"

  if [[ "${arch,,}" == *.zip ]]; then
    unzip -P "$PASSWORD" -qq "$arch" -d "$outdir"
  else
    7z x -p"$PASSWORD" -o"$outdir" "$arch" >/dev/null
  fi
}

should_process_binary() {
  local f="$1"
  [[ -s "$f" ]] || return 1
  local desc
  desc="$(file -b "$f" 2>/dev/null || true)"

  if echo "$desc" | grep -Eqi 'ASCII text|Unicode text|UTF-8 text|script|JSON|XML|HTML'; then
    return 1
  fi

  if echo "$desc" | grep -Eqi 'PE32|PE32\+|ELF|Mach-O|executable|shared object|MS-DOS|COM executable'; then
    return 0
  fi

  return 1
}

run_ghidra() {
  local sample="$1"
  local out="$2"
  mkdir -p "$(dirname "$out")"
  local proj_dir
  proj_dir="$(mktemp -d -p "$WORK_DIR" ghproj_XXXXXX)"

  OPCODE_OUT="$out" \
  "$ANALYZE_HEADLESS" \
    "$proj_dir" proj \
    -import "$sample" \
    -analysisTimeoutPerFile 180 \
    -deleteProject \
    -scriptPath "$GHIDRA_SCRIPTS_DIR" \
    -postScript DumpOpcodes.java \
    >/dev/null 2>&1
}

echo "[*] DATASET_ROOT    : $DATASET_ROOT"
echo "[*] OUT_ROOT        : $OUT_ROOT"
echo "[*] analyzeHeadless : $ANALYZE_HEADLESS"
echo "[*] MAX_NESTING     : $MAX_NESTING"
echo

mapfile -t ARCHIVES < <(find "$DATASET_ROOT" -type f \( -iname "*.zip" -o -iname "*.7z" \) | sort)
[[ ${#ARCHIVES[@]} -eq 0 ]] && { echo "No .zip/.7z found under dataset root."; exit 1; }

archive_count=0
binary_count=0
ok_count=0
fail_count=0

for arch in "${ARCHIVES[@]}"; do
  archive_count=$((archive_count+1))
  rel="${arch#$DATASET_ROOT/}"

  group="$(group_from_path "$arch")"
  group_s="$(sanitize "$group")"

  echo "=== [$archive_count/${#ARCHIVES[@]}] $rel (group: $group) ==="

  stage="$(mktemp -d -p "$WORK_DIR" stage_XXXXXX)"

  # ---------------------------
  # NEW BEHAVIOR: DO NOT STOP ON FAILURE
  # ---------------------------
  if ! extract_archive "$arch" "$stage" 2>/dev/null; then
    echo "[!] Extract failed for $rel — scanning folder anyway"
  fi

  # nested extraction (only if extraction succeeded)
  for ((depth=1; depth<=MAX_NESTING; depth++)); do
    mapfile -t NESTED < <(find "$stage" -type f \( -iname "*.zip" -o -iname "*.7z" \) | sort)
    [[ ${#NESTED[@]} -eq 0 ]] && break

    echo "[*] Nested archives: ${#NESTED[@]} (depth $depth/$MAX_NESTING)"
    for narch in "${NESTED[@]}"; do
      ndir="${narch}.d"
      if extract_archive "$narch" "$ndir" 2>/dev/null; then
        rm -f "$narch"
      else
        echo "[!] Failed nested extract: ${narch#$stage/}"
      fi
    done
  done

  # ---------------------------
  # NEW BEHAVIOR: ALWAYS SCAN FOR BINARIES
  # ---------------------------
  mapfile -t FILES < <(find "$stage" -type f | sort)

  if [[ ${#FILES[@]} -eq 0 ]]; then
    echo "[!] No files found in stage directory"
    echo
    continue
  fi

  for f in "${FILES[@]}"; do
    if ! should_process_binary "$f"; then
      continue
    fi

    binary_count=$((binary_count+1))
    base="$(basename "$f")"
    name="${base%.*}"
    name_s="$(sanitize "$name")"

    out_file="${group_s}__${name_s}.opcode"
    out_path="$OUT_ROOT/$group_s/$out_file"

    echo "[*] BIN: $base -> $out_path"

    if run_ghidra "$f" "$out_path"; then
      if [[ -s "$out_path" ]]; then
        ok_count=$((ok_count+1))
        echo "[+] OK"
      else
        echo "[!] Empty output (kept): $out_path"
      fi
    else
      echo "[-] Ghidra failed: $base"
      fail_count=$((fail_count+1))
    fi
  done

  echo
done

echo "[*] Done."
echo "[*] Archives scanned : $archive_count"
echo "[*] Binaries processed: $binary_count"
echo "[*] Opcode files OK  : $ok_count"
echo "[*] Failures         : $fail_count"
echo "[*] Output root      : $OUT_ROOT"