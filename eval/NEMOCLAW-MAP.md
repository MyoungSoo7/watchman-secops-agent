# NemoClaw / OpenShell 통제 모델 ↔ Watchman 6축 대조 — 2026-09-25

SPEC §6 과 SUBMISSION 정직 고지 5번이 미뤄 둔 "NemoClaw 공식 축과 1:1 매핑" 이다.

**결론 한 줄.** Watchman 은 NemoClaw/OpenShell 런타임 위에서 돌지 않는다. 지정교육(DLI S-FX-43)의
통제 모델을 **K3s 네이티브 통제로 재구현**했다. OpenShell 4개 도메인 중 3개(Filesystem·Network·Process)는
부분~실질 등가이고, **Inference(키 비노출)는 미구현**이다. 과정 스택의 정책 스키마에 없는 2개(도구 허용목록·주입 방어)를
더했다. 그래서 "NemoClaw 적용·준수" 가 아니라 "같은 위협 모델의 재구현" 이라고 쓴다.

## 0. 출처와 등급

| 등급 | 출처 | 쓰임 |
|---|---|---|
| ① 1차·공식 | NVIDIA 문서 — 아래 URL | 축 이름의 기준 |
| ② 수강 노트 | 팀장 블로그 2026-09-20 글(과정 수강 기록) | 과정에서 본 구성·실습 결과. 이미지 표는 과정 원문인지 요약인지 글만으로 가릴 수 없어 **①로 승격하지 않는다** |

① 조회한 URL:
- https://github.com/NVIDIA/OpenShell (README — "four policy domains", Privacy Router, Alpha 고지)
- https://docs.nvidia.com/openshell/security/best-practices.md
- https://docs.nvidia.com/openshell/dev/sandboxes/policies
- https://docs.nvidia.com/openshell/observability/logging · …/ocsf-json-export
- https://docs.nvidia.com/nemoclaw/user-guide/openclaw/security/best-practices ("five layers")
- https://docs.nvidia.com/nemoclaw/user-guide/openclaw/reference/network-policies (Operator Approval)
- https://docs.nvidia.com/nemoclaw/user-guide/openclaw/about/ecosystem (credential custody)
- https://github.com/NVIDIA/NemoClaw/blob/d5b64a72/nemoclaw-blueprint/policies/openclaw-sandbox.yaml

② 수강 노트: `myoungsoo7.github.io/_posts/2026-09-20-harness-instruction-files-and-six-axes-of-freedom.md`(자유도 6축),
`…-inside-the-nemoclaw-dashboard.md`, `…-four-checkmarks-wrong-model-egress-allowlist.md`,
`…-sandbox-policy-lab-two-open-failure-modes.md`, `…-openclaw-openshell-nemoclaw-comparison.md`.

## 1. 공식 축 이름 (원문 표기)

- **OpenShell — 4 policy domains:** `Filesystem` · `Network` · `Process` · `Inference`
  (정책 YAML: 정적 `filesystem_policy`·`landlock`·`process`, 동적 `network_policies`·`network_middlewares`)
- **NemoClaw — "deny-by-default security controls across five layers":** network, filesystem, process, gateway authentication, inference
- 부속: Operator Approval Flow(`openshell term` TUI), OCSF 이벤트 로그(NET·HTTP·SSH·PROC·FINDING·CONFIG·LIFECYCLE), Privacy Router, 자격증명 placeholder 치환
- ② 수강 노트의 "자유도 6축": Filesystem · Network · Process identity · Binary identity · Persistence · Inference routing

## 2. 대조표

| Watchman 통제 (SPEC §6) | 공식 축 | 판정 | 차이 |
|---|---|---|---|
| ① 도구 허용목록 + 스키마 강제 | — | **없음 (Watchman 추가분)** | NemoClaw blueprint 주석: "PolicyFile schema does not support a `tool_policy` section". 가장 가까운 건 Network 의 바이너리·method·path 허용이지만 도구 호출 단위가 아니다 |
| ② 최소 권한 자격증명 | Inference (credential isolation) · Providers | 부분 | 목적 같음, 수단 다름. 공식 스택은 에이전트가 키를 **보지 못하게**, Watchman 은 RBAC(get/list)·ES read-only 로 **범위를 줄인다**. NIM 키는 파드 env 에 있다 |
| ③ 격리 실행 | Process + Filesystem | 부분 (실질 등가) | runAsNonRoot(65534)·allowPrivilegeEscalation false·capabilities drop ALL·seccomp RuntimeDefault·readOnlyRootFilesystem(쓰기는 /data·/tmp). 공식은 Landlock 경로 단위 허용 + 정책 seccomp. 스텝 예산은 공식 대응 항목 없음 |
| ④ 이그레스 통제 | Network (deny-by-default) | 부분~1:1 | 목적지 기본 거부는 같다. 공식은 L7(method·path)·호출 바이너리·SSRF 가드까지, NetworkPolicy 는 L3/L4 |
| ⑤ 프롬프트 주입 방어 | — | **없음 (Watchman 추가분)** | 조회 범위의 공식 문서에 전용 층 없음. 수강 노트도 "샌드박스가 주입을 없애지 않는다". `network_middlewares` regex redact 는 유출 쪽이다 |
| ⑥ 감사 + 인간 승인 | OCSF 로그 + Operator Approval Flow | 부분 | 승인 대상이 다르다 — 공식은 막힌 **네트워크 요청**, Watchman 은 **조치 실행**. OCSF 파일 로그는 "Daily, 3 files max" 순환, Watchman 은 PVC append-only. 스키마는 OCSF 아님 |

## 3. 공식 축인데 Watchman 에 없는 것 (고지)

1. **Inference 키 비노출** — 가장 큰 차이. 파드가 `NVIDIA_API_KEY` 를 env 로 쥔다. 공식 구조는 게이트웨이(`inference.local`)가 키를 쥐고 에이전트는 모른다.
2. **Binary identity** — 실행 파일 경로·조상 프로세스·해시로 신원 판정. Watchman 은 도구 이름 수준.
3. **커널 층 강제의 세분화** — Landlock 경로 단위 쓰기 허용, 정책 기반 seccomp. Watchman 은 RuntimeDefault seccomp + 읽기 전용 루트.
4. **L7 egress 규칙** — method·path, SSRF 가드(loopback·private·link-local).
5. **Gateway authentication 층**(NemoClaw) · **OCSF 표준 이벤트**.

## 4. 수강 실습의 열린 실패 모드 두 개 — Watchman 에 대입

| 실습에서 남은 구멍 (수강 노트) | Watchman | 상태 |
|---|---|---|
| 허용 채널은 양방향 — pip 이 되면 PyPI 로 유출도 된다 | 허용 목적지 4곳(K8s API·ES·NIM·Telegram)도 같다. 특히 NIM(프롬프트에 근거가 실림)·Telegram(카드) | 열려 있음. 완화는 코드층: redact, 카드 출력 스키마, 주입 ⚠·판정 하한. 채널 자체는 닫지 않는다 |
| 에이전트가 쓸 수 있는 지침 파일(persona 변조) | 루트 읽기 전용, LLM 에 파일 쓰기 도구 없음. 쓰기는 코드만 /data 감사로그에 | 해당 없음에 가깝다. 단 감사로그의 옛 판정이 **판정 재사용**(24h)으로 다시 쓰이므로, 오염된 판정이 지속되는 경로는 존재한다 — 주입 감지 run 은 '오탐' 판정 금지(40dd992)로 좁혔다 |

## 5. 제출 문구

> DLI 과정의 NemoClaw/OpenShell 통제 모델(Filesystem·Network·Process·Inference)을 K3s 네이티브 통제로 재구현했다.
> 3개 도메인은 부분~실질 등가이고 Inference 키 격리는 미구현이다(고지). 과정 스택의 정책 스키마에 없는
> 도구 허용목록과 프롬프트 주입 방어를 더했다.

쓰지 않는 표현: "NemoClaw 적용", "OpenShell 준수". OpenShell 은 README 에서 스스로 Alpha("single-player mode"),
Kubernetes 경로는 Experimental 이라고 밝힌다 — 운영 성숙도 비교에 쓸 때는 이 점을 함께 적는다.

## 6. 미검증

- NemoClaw 5층 표의 process 행 세부는 원문을 전부 확인하지 못했다(층 이름 5개는 본문 문장으로 확인).
- "Privacy Router" 명칭은 OpenShell README 에서만 확인.
- "공식 문서에 주입 방어 층이 없다" 는 **조회한 페이지 범위 안에서** 의 관찰이다.
- 수강 노트 내 git/curl 거부 결과가 두 글에서 반대로 적혀 있다(재현 1회) — 이 문서의 결론에는 쓰지 않았다.
