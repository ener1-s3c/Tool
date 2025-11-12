#!/usr/bin/env bash
# raspi-default-audit.sh
#
# Audit script to check for Raspberry Pi (or other SSH) hosts accepting default/known credentials.
# Output is plain text (one line per attempt).
#
# New: accepts single username (-u) and single password (-w) flags (can be combined with -U/-P lists).
# -c takes precedence if provided (other credential flags will be ignored but warned about).
#
# WARNING: Only run this script on networks and machines you own or are explicitly authorized to test.
#
set -euo pipefail

PROGNAME="$(basename "$0")"
VERSION="1.2"

print_usage() {
  cat <<EOF
$PROGNAME v$VERSION

Usage:
  $PROGNAME [options]

Options:
  -n <network-cidr>    Network to scan (e.g. 192.168.1.0/24). Requires nmap for best results.
  -l <hosts-file>      File with one host/IP per line. Mutually exclusive with -n.
  -c <creds-file>      File with credentials, one "user:password" per line. (Takes precedence)
  -U <user-file>       File with usernames, one per line.
  -P <pass-file>       File with passwords, one per line.
  -u <username>        Single username to try (can be combined with -P)
  -w <password>        Single password to try (can be combined with -U)
  -p <port>            SSH port to check (default: 22)
  -t <timeout>         Connect timeout in seconds (default: 5)
  -o <output.txt>      Output text file (default: audit-results.txt)
  -j <jobs>            Parallel jobs (default: 10)
  -h                   Show this help

Notes:
  - Acceptable credential sources:
      * -c creds-file
      * -U user-file AND -P pass-file
      * -u username AND -w password
      * -u username AND -P pass-file
      * -U user-file AND -w password
  - If -c is provided it will be used and other credential flags will be ignored (with a warning).
  - Make sure you have authorization to scan & attempt logins on the target network.
EOF
}

# Defaults
NETWORK=""
HOSTS_FILE=""
CREDS_FILE=""
USER_FILE=""
PASS_FILE=""
SINGLE_USER=""
SINGLE_PASS=""
SSH_PORT=22
TIMEOUT=5
OUTPUT_FILE="audit-results.txt"
JOBS=10

# Parse args
while getopts ":n:l:c:U:P:u:w:p:t:o:j:h" opt; do
  case $opt in
    n) NETWORK="$OPTARG" ;;
    l) HOSTS_FILE="$OPTARG" ;;
    c) CREDS_FILE="$OPTARG" ;;
    U) USER_FILE="$OPTARG" ;;
    P) PASS_FILE="$OPTARG" ;;
    u) SINGLE_USER="$OPTARG" ;;
    w) SINGLE_PASS="$OPTARG" ;;
    p) SSH_PORT="$OPTARG" ;;
    t) TIMEOUT="$OPTARG" ;;
    o) OUTPUT_FILE="$OPTARG" ;;
    j) JOBS="$OPTARG" ;;
    h) print_usage; exit 0 ;;
    \?) echo "Invalid option: -$OPTARG" >&2; print_usage; exit 2 ;;
    :) echo "Option -$OPTARG requires an argument." >&2; print_usage; exit 2 ;;
  esac
done

# Validate hosts source
if [[ -n "$NETWORK" && -n "$HOSTS_FILE" ]]; then
  echo "Error: Use only one of -n (network) or -l (hosts file)." >&2
  print_usage
  exit 2
fi
if [[ -z "$NETWORK" && -z "$HOSTS_FILE" ]]; then
  echo "Error: Supply either -n (network) or -l (hosts file)." >&2
  print_usage
  exit 2
fi

# Check sshpass
if ! command -v sshpass >/dev/null 2>&1; then
  echo "Error: sshpass is required but not found. Install sshpass and retry." >&2
  echo "On Debian/Ubuntu: sudo apt-get install sshpass" >&2
  exit 3
fi

# Build credentials list
declare -a CREDS=()

if [[ -n "$CREDS_FILE" ]]; then
  # If creds file provided, use it and warn about ignoring other credential flags
  if [[ ! -f "$CREDS_FILE" ]]; then
    echo "Error: credentials file '$CREDS_FILE' not found." >&2
    exit 2
  fi
  if [[ -n "$USER_FILE" || -n "$PASS_FILE" || -n "$SINGLE_USER" || -n "$SINGLE_PASS" ]]; then
    echo "Warning: -c provided; ignoring -U/-P/-u/-w options" >&2
  fi
  while IFS= read -r line || [[ -n "$line" ]]; do
    line_trimmed="$(echo "$line" | tr -d '\r\n' | sed -e 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    [[ -z "$line_trimmed" ]] && continue
    if [[ "$line_trimmed" != *:* ]]; then
      echo "Warning: skipping malformed creds line (no colon): '$line_trimmed'." >&2
      continue
    fi
    CREDS+=("$line_trimmed")
  done < "$CREDS_FILE"
else
  # Build user and pass arrays from provided sources
  declare -a USERS=()
  declare -a PASSES=()

  # Add from files if provided
  if [[ -n "$USER_FILE" ]]; then
    if [[ ! -f "$USER_FILE" ]]; then
      echo "Error: user file '$USER_FILE' not found." >&2
      exit 2
    fi
    while IFS= read -r u || [[ -n "$u" ]]; do
      u="$(echo "$u" | tr -d '\r\n' | sed -e 's/^[[:space:]]*//;s/[[:space:]]*$//')"
      [[ -z "$u" ]] && continue
      USERS+=("$u")
    done < "$USER_FILE"
  fi

  if [[ -n "$PASS_FILE" ]]; then
    if [[ ! -f "$PASS_FILE" ]]; then
      echo "Error: pass file '$PASS_FILE' not found." >&2
      exit 2
    fi
    while IFS= read -r p || [[ -n "$p" ]]; do
      p="$(echo "$p" | tr -d '\r\n' | sed -e 's/^[[:space:]]*//;s/[[:space:]]*$//')"
      [[ -z "$p" ]] && continue
      PASSES+=("$p")
    done < "$PASS_FILE"
  fi

  # Add single username/password if provided
  if [[ -n "$SINGLE_USER" ]]; then
    SINGLE_USER="$(echo "$SINGLE_USER" | tr -d '\r\n' | sed -e 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    USERS+=("$SINGLE_USER")
  fi
  if [[ -n "$SINGLE_PASS" ]]; then
    SINGLE_PASS="$(echo "$SINGLE_PASS" | tr -d '\r\n' | sed -e 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    PASSES+=("$SINGLE_PASS")
  fi

  # Validate that at least one user and one pass exist
  if [[ "${#USERS[@]}" -eq 0 || "${#PASSES[@]}" -eq 0 ]]; then
    echo "Error: No users or passwords defined. Provide -c OR (-U and -P) OR -u and -w OR combinations like -u with -P or -U with -w." >&2
    print_usage
    exit 2
  fi

  # Build cartesian product
  for u in "${USERS[@]}"; do
    for p in "${PASSES[@]}"; do
      CREDS+=("${u}:${p}")
    done
  done
fi

if [[ "${#CREDS[@]}" -eq 0 ]]; then
  echo "Error: no credentials were parsed." >&2
  exit 2
fi

# Build targets list
declare -a TARGETS=()
if [[ -n "$HOSTS_FILE" ]]; then
  if [[ ! -f "$HOSTS_FILE" ]]; then
    echo "Error: hosts file '$HOSTS_FILE' not found." >&2
    exit 2
  fi
  while IFS= read -r host || [[ -n "$host" ]]; do
    host="$(echo "$host" | tr -d '\r\n' | sed -e 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    [[ -z "$host" ]] && continue
    TARGETS+=("$host")
  done < "$HOSTS_FILE"
else
  if command -v nmap >/dev/null 2>&1; then
    echo "Scanning network $NETWORK for hosts with port $SSH_PORT open (using nmap)..." >&2
    mapfile -t nmap_hosts < <(nmap -p "$SSH_PORT" --open -n --host-timeout 30s -oG - "$NETWORK" 2>/dev/null | awk '/Ports:/{print $2}')
    if [[ "${#nmap_hosts[@]}" -eq 0 ]]; then
      echo "No hosts with port $SSH_PORT open found by nmap." >&2
    fi
    for h in "${nmap_hosts[@]}"; do TARGETS+=("$h"); done
  else
    echo "nmap not available. Falling back to probing $NETWORK for hosts with TCP port $SSH_PORT open." >&2
    if [[ "$NETWORK" =~ ^([0-9]+\.[0-9]+\.[0-9]+)\.([0-9]+)\/([0-9]+)$ ]]; then
      base="${BASH_REMATCH[1]}"
      for i in {1..254}; do
        host="${base}.${i}"
        timeout "$TIMEOUT" bash -c "cat < /dev/tcp/$host/$SSH_PORT" >/dev/null 2>&1 && TARGETS+=("$host") || true
      done
    else
      echo "Unsupported NETWORK format for fallback scanning and nmap is missing. Provide hosts file (-l) or install nmap." >&2
      exit 4
    fi
  fi
fi

if [[ "${#TARGETS[@]}" -eq 0 ]]; then
  echo "No targets discovered. Exiting." >&2
  exit 0
fi

echo "Discovered ${#TARGETS[@]} target(s)." >&2
echo "Using ${#CREDS[@]} credential combo(s)." >&2

# Prepare output (clear or create)
: > "$OUTPUT_FILE"

# Worker function: try all credentials against a single target
try_host() {
  local host="$1"
  for cred in "${CREDS[@]}"; do
    user="${cred%%:*}"
    pass="${cred#*:}"
    start_ts=$(date +%s%3N 2>/dev/null || date +%s)
    if sshpass -p "$pass" ssh -o ConnectTimeout="$TIMEOUT" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p "$SSH_PORT" -o BatchMode=no -o PasswordAuthentication=yes "$user@$host" 'echo ok' >/dev/null 2>/dev/null; then
      end_ts=$(date +%s%3N 2>/dev/null || date +%s)
      elapsed_ms=$((end_ts - start_ts))
      elapsed_s=$(awk "BEGIN {print $elapsed_ms/1000}")
      printf '%s:%s user=%s pass=%s status=SUCCESS elapsed=%.3fs\n' "$host" "$SSH_PORT" "$user" "$pass" "$elapsed_s" >> "$OUTPUT_FILE"
      return 0
    else
      end_ts=$(date +%s%3N 2>/dev/null || date +%s)
      elapsed_ms=$((end_ts - start_ts))
      elapsed_s=$(awk "BEGIN {print $elapsed_ms/1000}")
      printf '%s:%s user=%s pass=%s status=FAIL elapsed=%.3fs\n' "$host" "$SSH_PORT" "$user" "$pass" "$elapsed_s" >> "$OUTPUT_FILE"
    fi
  done
  return 1
}

export -f try_host
export TIMEOUT SSH_PORT OUTPUT_FILE

# Persist creds for worker subshells
CREDS_TMP="$(mktemp)"
for c in "${CREDS[@]}"; do printf '%s\n' "$c" >> "$CREDS_TMP"; done

# Run workers
if command -v parallel >/dev/null 2>&1; then
  parallel -j "$JOBS" "CREDS=(); while IFS= read -r L; do CREDS+=(\"\$L\"); done < \"$CREDS_TMP\"; $(declare -f try_host); try_host {1}" ::: "${TARGETS[@]}"
else
  pids=()
  for host in "${TARGETS[@]}"; do
    (
      CREDS=()
      while IFS= read -r L; do CREDS+=("$L"); done < "$CREDS_TMP"
      try_host "$host"
    ) &
    pids+=($!)
    while [[ "$(jobs -rp | wc -l)" -ge "$JOBS" ]]; do sleep 0.2; done
  done

  for pid in "${pids[@]}"; do wait "$pid" || true; done
fi

rm -f "$CREDS_TMP"

echo "Audit complete. Results written to: $OUTPUT_FILE" >&2
