#!/usr/bin/env bash
# Deploys ShieldPipe to the current cluster (kind + Cilium) and proves that each
# runtime security control actually works, not only that the YAML looks right.
set -euo pipefail

NS=shieldpipe
URL="http://shieldpipe.${NS}.svc.cluster.local"
CURL_IMAGE="curlimages/curl:8.23.0@sha256:11e64e28c5f58c8d93ee95fcf22ac055f48b0bc440e0ce7d8013bbb5ad6aa8ac"
SUMMARY="${GITHUB_STEP_SUMMARY:-/dev/null}"
failures=0

result() { # result <ok|fail> <check> <detail>
  local icon="PASS"
  [[ "$1" == ok ]] || { icon="FAIL"; failures=$((failures + 1)); }
  printf '%-4s  %-55s %s\n' "$icon" "$2" "$3"
  echo "| ${icon} | $2 | $3 |" >> "$SUMMARY"
}

expect_eq() { # expect_eq <check> <expected> <actual>
  if [[ "$3" == "$2" ]]; then result ok "$1" "got $3"; else result fail "$1" "expected $2, got $3"; fi
}

client() { # client <pod> <curl args...>  -> prints HTTP code, 000 when the connection is dropped
  kubectl -n clients exec "$1" -- curl -s -o /dev/null -w '%{http_code}' --max-time 5 "${@:2}" || true
}

in_api_pod() {
  kubectl -n "$NS" exec deploy/shieldpipe -- python -c "$1" 2>&1 || true
}

echo "== Deploy"
kubectl apply -f deploy/k8s/namespace.yaml
admin_password="$(openssl rand -base64 30)"
kubectl -n "$NS" create secret generic shieldpipe-secrets \
  --from-literal=jwt-secret="$(openssl rand -hex 32)" \
  --from-literal=admin-password="$admin_password" \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl apply -k deploy/k8s
kubectl -n "$NS" rollout status deploy/shieldpipe --timeout=180s

echo "== Test clients"
kubectl create namespace clients --dry-run=client -o yaml | kubectl apply -f -
kubectl -n clients run allowed --image="$CURL_IMAGE" --labels=access=shieldpipe --restart=Never --command -- sleep 3600
kubectl -n clients run intruder --image="$CURL_IMAGE" --restart=Never --command -- sleep 3600
kubectl -n clients wait --for=condition=Ready pod/allowed pod/intruder --timeout=120s
# Give Cilium a moment to compute identities for the new pods.
sleep 10

{
  echo "### Runtime security controls (kind + Cilium ${CILIUM_VERSION:-})"
  echo "| Result | Control | Detail |"
  echo "|---|---|---|"
} >> "$SUMMARY"
echo "== Checks"

# 1. Authorised path works end to end.
expect_eq "Labelled client reaches /healthz" 200 "$(client allowed "$URL/healthz")"

login_body="{\"username\":\"admin\",\"password\":\"${admin_password}\"}"
login_response="$(kubectl -n clients exec allowed -- curl -s --max-time 5 "$URL/api/v1/auth/login" \
  -H 'Content-Type: application/json' -d "$login_body" || true)"
token="$(sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p' <<<"$login_response")"
if [[ -n "$token" ]]; then result ok "Login through the L7 proxy" "token issued"; else result fail "Login through the L7 proxy" "no token"; fi
expect_eq "Authenticated API call" 200 \
  "$(client allowed "$URL/api/v1/incidents" -H "Authorization: Bearer ${token}")"

# 2. Cilium L7 policy: routes outside the allow-list are refused by Envoy (403),
#    even though the app itself would answer 404 or 405.
expect_eq "L7: undeclared path blocked (GET /openapi.json)" 403 "$(client allowed "$URL/openapi.json")"
expect_eq "L7: undeclared method blocked (PUT /api/v1/users)" 403 "$(client allowed -X PUT "$URL/api/v1/users")"

# 3. Cilium L3/L4: a pod without the access label cannot even open a connection.
expect_eq "L3/L4: unlabelled pod is dropped" 000 "$(client intruder "$URL/healthz")"

# 4. Egress: the API pod cannot call out (exfiltration, reverse shell).
egress="$(in_api_pod "import socket; socket.create_connection(('1.1.1.1', 443), timeout=3); print('connected')")"
if [[ "$egress" == *connected* ]]; then result fail "Egress from API pod denied" "outbound connection succeeded"; else result ok "Egress from API pod denied" "connection blocked"; fi

# 5. Container hardening is effective at runtime.
expect_eq "Process runs as UID 10001" 10001 "$(in_api_pod 'import os; print(os.getuid())' | tr -d '\r')"
write="$(in_api_pod "open('/app/pwned', 'w')")"
if [[ "$write" == *"Read-only file system"* ]]; then result ok "Root filesystem is read-only" "write refused"; else result fail "Root filesystem is read-only" "$write"; fi
expect_eq "No service account token mounted" False \
  "$(in_api_pod "import os; print(os.path.exists('/var/run/secrets/kubernetes.io/serviceaccount/token'))" | tr -d '\r')"

# 6. Pod Security Admission refuses a privileged pod in the namespace.
psa="$(kubectl -n "$NS" run evil --image=busybox:1.37 --dry-run=server \
  --overrides='{"spec":{"containers":[{"name":"evil","image":"busybox:1.37","securityContext":{"privileged":true}}]}}' 2>&1 || true)"
if [[ "$psa" == *"violates PodSecurity"* ]]; then result ok "PSA rejects a privileged pod" "admission denied"; else result fail "PSA rejects a privileged pod" "$psa"; fi

echo
if (( failures > 0 )); then
  echo "${failures} control(s) failed"
  echo "== Debug: verbose request from the allowed client"
  kubectl -n clients exec allowed -- curl -sv --max-time 5 "$URL/healthz" 2>&1 | tail -n 20 || true
  echo "== Debug: Hubble flows (verdicts and drop reasons)"
  kubectl -n kube-system exec ds/cilium -c cilium-agent -- hubble observe --last 60 -o compact 2>&1 | tail -n 60 || true
  echo "== Debug: Cilium endpoints and policy enforcement"
  kubectl -n kube-system exec ds/cilium -c cilium-agent -- cilium-dbg endpoint list 2>&1 || true
  echo "== Debug: Envoy logs"
  kubectl -n kube-system logs ds/cilium-envoy --tail=40 2>&1 || true
  exit 1
fi
echo "All runtime controls verified"
