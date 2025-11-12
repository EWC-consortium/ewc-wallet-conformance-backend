#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  ec2jwks.sh [-k KID] [-a SIG_ALG] [--include-enc] [--enc-alg ENC_ALG] [-o OUTFILE] KEY_PEM

Options:
  -k KID            kid for signing key (default: aegean#authentication-key)
  -a SIG_ALG        alg for signing key (default: ES256)
  --include-enc     include a second JWK for encryption/key agreement
  --enc-alg ENC_ALG alg for encryption key (default: ECDH-ES)
  -o OUTFILE        write JWKS to file (default: stdout)
  -h                show this help

Notes:
- Supports NIST P-256 (prime256v1 / secp256r1) EC private keys (PEM).
- The first key is the **private signing key** with "use":"sig" and "alg".
- If --include-enc is used, a second key with "use":"enc" is appended second.
- Requires: openssl, xxd, jq, awk, hexdump (or xxd)
USAGE
}

KID="aegean#authentication-key"
SIG_ALG="ES256"
INCLUDE_ENC=false
ENC_ALG="ECDH-ES"
OUTFILE=""

# Parse args
while [[ $# -gt 0 ]]; do
  case "$1" in
    -k) KID="$2"; shift 2 ;;
    -a) SIG_ALG="$2"; shift 2 ;;
    --include-enc) INCLUDE_ENC=true; shift ;;
    --enc-alg) ENC_ALG="$2"; shift 2 ;;
    -o) OUTFILE="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    --) shift; break ;;
    -*)
      echo "Unknown option: $1" >&2; usage; exit 2 ;;
    *) break ;;
  esac
done

if [ $# -ne 1 ]; then
  usage; exit 2
fi
KEY_PEM="$1"

# Dependencies
for cmd in openssl awk xxd jq hexdump; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "Missing dependency: $cmd" >&2; exit 1; }
done

# Ensure P-256
CURVE_NAME=$(openssl ec -in "$KEY_PEM" -noout -text 2>/dev/null | awk -F': ' '/ASN1 OID:|NIST CURVE:/ {print $2}' | head -n1 || true)
case "$CURVE_NAME" in
  prime256v1|P-256|secp256r1) ;;
  *) echo "Error: Only P-256 keys supported. Detected: ${CURVE_NAME:-unknown}" >&2; exit 1 ;;
esac

# Extract d (private scalar) as hex
priv_hex=$(openssl ec -in "$KEY_PEM" -noout -text 2>/dev/null \
  | awk '
    /priv:/ {inpriv=1; next}
    /pub:/  {inpriv=0}
    inpriv  { gsub(/[: ]/, "", $0); printf "%s", $0 }
    END { print "" }')
[ -n "$priv_hex" ] || { echo "Error: could not extract private scalar d." >&2; exit 1; }

# Extract uncompressed public point (04||X||Y) from SPKI
PUB_DER=$(mktemp)
trap 'rm -f "$PUB_DER"' EXIT
openssl ec -in "$KEY_PEM" -pubout -conv_form uncompressed -outform DER -out "$PUB_DER" >/dev/null 2>&1

pub_hex=$(tail -c 65 "$PUB_DER" | hexdump -v -e '/1 "%02x"')
if [ "${pub_hex:0:2}" != "04" ] || [ ${#pub_hex} -ne 130 ]; then
  echo "Error: unexpected public key encoding." >&2; exit 1
fi
x_hex=${pub_hex:2:64}
y_hex=${pub_hex:66:64}

# hex -> base64url
hex_to_b64url() {
  printf "%s" "$1" | xxd -r -p | openssl base64 -A | tr '+/' '-_' | tr -d '='
}

x_b64=$(hex_to_b64url "$x_hex")
y_b64=$(hex_to_b64url "$y_hex")
d_b64=$(hex_to_b64url "$priv_hex")

# Build JWKS
if $INCLUDE_ENC; then
  JWKS=$(jq -n \
    --arg x "$x_b64" --arg y "$y_b64" --arg d "$d_b64" \
    --arg kid "$KID" --arg sigalg "$SIG_ALG" \
    --arg enkid "${KID}-enc" --arg encalg "$ENC_ALG" \
'{
  keys: [
    {kty:"EC", crv:"P-256", kid:$kid, use:"sig", alg:$sigalg, x:$x, y:$y, d:$d},
    {kty:"EC", crv:"P-256", kid:$enkid, use:"enc", alg:$encalg, x:$x, y:$y, d:$d}
  ]
}')
else
  JWKS=$(jq -n \
    --arg x "$x_b64" --arg y "$y_b64" --arg d "$d_b64" \
    --arg kid "$KID" --arg sigalg "$SIG_ALG" \
'{
  keys: [
    {kty:"EC", crv:"P-256", kid:$kid, use:"sig", alg:$sigalg, x:$x, y:$y, d:$d}
  ]
}')
fi

# Output
if [ -n "$OUTFILE" ]; then
  printf '%s\n' "$JWKS" > "$OUTFILE"
  echo "Wrote JWKS to $OUTFILE"
else
  printf '%s\n' "$JWKS"
fi
