# Watchman Helm 차트

고객 클러스터에 파수꾼을 `helm install` 한 번으로 설치한다. 운영 중인 개발사 배포
(`agent-system`)와 같은 통제 구성이다: 권한은 get/list 뿐이고 secrets 읽기가 없다.
파드는 non-root·읽기전용 루트FS·capabilities 전부 drop 상태로 돈다. 이그레스는
NetworkPolicy 로 제한하며, 코드는 제안만 하고 스스로 조치하지 않는다.

## 설치

```bash
# 1) 키 없이 설치 확인(mock — 외부 LLM 호출 없음)
helm install watchman ./deploy/helm/watchman -n watchman --create-namespace \
  --set llm.mode=mock \
  --set networkPolicy.apiServerCIDRs='{10.43.0.0/16,<노드망 CIDR>}'

# 2) 실사용 — Secret 을 먼저 만들고 가리킨다(값이 helm 릴리스 기록에 남지 않는다)
kubectl -n watchman create secret generic watchman-secret \
  --from-literal=NVIDIA_API_KEY=... --from-literal=ES_PASS=... --from-literal=TELEGRAM_BOT_TOKEN=...
helm upgrade --install watchman ./deploy/helm/watchman -n watchman -f deploy/helm/examples/values-k3s.yaml
```

### 로그가 ES 가 아니면 (Loki · Datadog)

```bash
# Loki (클러스터 내) — 멀티테넌트면 logs.loki.tenant, 인증은 Secret 의 LOKI_PASS/LOKI_TOKEN
helm upgrade --install watchman ./deploy/helm/watchman -n watchman --reuse-values \
  --set logs.backend=loki \
  --set logs.loki.url=http://loki-gateway.monitoring.svc.cluster.local \
  --set networkPolicy.loki.enabled=true --set networkPolicy.loki.namespace=monitoring --set networkPolicy.loki.port=80

# Datadog — Secret 에 DD_API_KEY·DD_APP_KEY, 사이트가 EU 등이면 logs.datadog.site
helm upgrade --install watchman ./deploy/helm/watchman -n watchman --reuse-values \
  --set logs.backend=datadog --set logs.datadog.site=datadoghq.eu
```

에이전트는 es_search 대신 `log_search` 도구를 쓴다. LLM 은 LogQL·Datadog 쿼리를 쓰지 않는다 —
namespace·포함 문자열·시간창만 넘기고, 코드(`logsrc.py`)가 이스케이프해서 쿼리를 조립한다.

Alertmanager 연결 스니펫은 설치 후 `NOTES` 에 서비스 주소와 함께 출력된다.

## 설계 메모

- **코드 = ConfigMap.** `files/*.py` 는 리포 루트 소스로의 심볼릭 링크다. 원본은 하나이고,
  `helm package` 는 링크를 실파일로 풀어 tgz 에 담는다. 이미지는 공식 `python:3.12-slim`
  그대로 쓴다(stdlib-only). 코드가 바뀌면 `checksum/code` 가 파드를 다시 띄운다.
- **쓰기 Host 허용목록**을 차트가 계산한다. 코드 기본값은 `agent-system` 네임스페이스를
  전제로 하므로, 다른 네임스페이스에 설치하면 Alertmanager 의 POST 가 403 을 받는다.
  차트는 릴리스의 서비스 DNS 전 형태를 `WATCHMAN_WRITE_HOSTS` 로 넣는다.
- **`networkPolicy.apiServerCIDRs` 는 필수다.** 서비스 CIDR 과 apiserver 실주소는
  배포판마다 달라서(K3s 10.43/16, EKS 는 VPC 에 따라 다름) 추측하지 않는다.
  값이 비어 있으면 렌더링을 실패시킨다.
- 감사로그 PVC 에는 `helm.sh/resource-policy: keep` 을 붙였다. uninstall 해도 감사기록은 남는다.

## 알려진 한계

- 외부 443 이그레스는 도메인 단위가 아니라 "사설망 제외 전체 443" 이다(vanilla
  NetworkPolicy 의 한계). 도메인 단위로 막으려면 egress 프록시나 Cilium FQDN 정책을 쓴다.
- K8s API TLS 검증은 꺼져 있다(`kubernetes.verifyTLS=false`). 코드에 CA 번들 경로를
  지정하는 설정이 아직 없다. 트래픽은 클러스터 내부 ClusterIP 경로다.
- **Datadog 연동은 실계정으로 검증하지 않았다.** 요청·응답 모양은 공식 API 문서
  (Logs Search v2, `POST /api/v2/logs/events/search`) 기준 가짜 서버 테스트로만 확인했다.
- 단일 레플리카 전제다. 중복제거·킬체인 상태가 프로세스 메모리에 있다.

## 실측 (2026-09-24, K3s v1.35 홈랩, 임시 네임스페이스 설치 후 삭제)

| 확인 | 결과 |
|---|---|
| mock 설치 → Ready | 통과. 첫 시도는 **감사로그가 없으면 기동 즉시 KeyError** 로 CrashLoop — 코드 버그를 고친 뒤 통과 |
| POST /alert (허용 Host) / 위조 Host | 202 / 403 |
| mock 완주 · kube_read 실조회 | 완료, EventList 수신 |
| RBAC | pods·logs·velero·rolebindings = yes / secrets·configmaps·delete·create·patch = no |
| 이그레스 | K8s API·ES 9200·외부 443 = 열림 / 노드 22·외부 80 = 차단 |
| Loki 백엔드(임시 Loki 3.4.2) | 경보 → log_search 가 해당 네임스페이스 로그 2건 회수. 쿼리 문법을 흉내 낸 입력은 리터럴로 처리돼 0건 |
| Loki 이그레스 규칙 | `networkPolicy.loki.enabled` 켜면 열림 / 끄면 차단 |
| 렌더 결과 vs 운영 매니페스트 | ClusterRole 규칙·securityContext·resources 동일, ConfigMap 코드 5개 원본과 바이트 동일 |
