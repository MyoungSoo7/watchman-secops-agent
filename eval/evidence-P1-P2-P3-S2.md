# 실측 증거 — 메인세션 담당 P1·P2·P3·S2 (2026-09-21~22)

ROLE.md §6 공통 규칙 양식: 검사 항목(T-번호) · 입력값 · 예상 · 실제 · run_id · 증거 위치 · 확인자.
확인자: 메인세션(봇 세션 대행). 코드 6aceab5(watchman-agent) / 62c2880(helm-deploy) 기준.

## P1 — NetworkPolicy 이그레스 + 컨테이너 강화

실측 상세는 helm-deploy 커밋 62c2880 본문 참조 (카나리 `app=watchman-canary` + 라이브 파드 적용 전/후 비교, david 노드).

| 검사 | 입력값 | 예상 | 실제 | 증거 위치 |
|---|---|---|---|---|
| T1-1 | netpol 적용 후 허용 5목적지 (DNS·ES 9200·K8s API 443·NIM 443·텔레그램 443) | 전부 연결 OK | 전부 OK | helm-deploy 62c2880 커밋 본문 §3 |
| T1-2 | 외부 80 · 내부망 22(192.168.219.113) · 그 외 ClusterIP 80 | 전부 차단 | 전부 refused | 상동 |
| T1-3 | 파드 내 uid/gid | 65534/65534 (비루트) | 65534/65534 | 상동 §1 |
| T1-4 | `/`·`/app` 쓰기 시도 | 실패(OSError), `/tmp`·`/data` 만 가능 | 예상대로 | 상동 §1 |

주의(정직 기재): ④ 외부 443 레인은 도메인 제한 불가(vanilla netpol) → "사설망 제외 전체 443" 열림.
DNS 레인이 없으면 전멸 — 파드 resolv.conf 가 kube-dns ClusterIP 를 가리켜 kube-system 레인이 유효함을 실측.

## P2 — 주입 ⚠ 표기 (FR-13)

| 검사 | 입력값 | 예상 | 실제 | run_id | 증거 위치 |
|---|---|---|---|---|---|
| T2-1 | fixtures/injection-attempt.json (지문 fx-inj-002) → 라이브 파드 POST /alert | 감사로그 `injection_suspect` + 카드에 ⚠ 줄 | 패턴 2건(ignore-instructions, role-hijack) 감지, 카드에 "⚠ 주입 의심 — 데이터 안 지시문 패턴 2건 감지" 줄. NIM 도 "가짜 또는 조작된 경보" 분류·주입 지시 불이행 | 20260921-150400-003 | 파드 /data/audit.jsonl (card_suppressed — fx- 지문이라 실채팅 발송 억제) |
| T2-2 | 정상 픽스처 2건 (kube-job-failed, velero-partial) | 오탐 0 | detect_injection() == [] | — | test_watchman.py `test_no_false_positive_on_normal_fixtures` |
| T2-3 | `python3 -m unittest test_watchman -v` | 전부 통과 | 51/51 OK | — | 로컬 실행 (누적 51건; 세부 분해는 test_watchman.py 참조) |

## P3 — GET /state (FR-15)

| 검사 | 입력값 | 예상 | 실제 | 증거 위치 |
|---|---|---|---|---|
| T3-1 | `curl GET /state` (port-forward svc/watchman) | 200 JSON, 상태 7값 정의, run 별 llm_calls·토큰·duration | 200. run_states 7값. 실 run 에 llm_calls 2, prompt_tokens 3366, completion_tokens 531 집계 실측 | 본 문서 하단 발췌 |
| T3-2 | POST·DELETE /state | 405 | 둘 다 405 (PUT·PATCH 는 단위 테스트로 405 확인) | test_watchman.py `StateEndpoint` |
| T3-3 | 스냅샷 본문에 시크릿 값 | 0건 | NVIDIA_API_KEY·ES_PASS·TELEGRAM_BOT_TOKEN·K8S_TOKEN 값 미포함 | test_watchman.py `test_snapshot_states_and_no_secrets` |
| T3-4 | 서브에이전트2 10분 폴링 | — | 미실시 (서브에이전트2 착수 후) | — |

상태 전이 실측: 실알림 run 이 NIM 503 재시도 소진으로 죽자 `/state` 에 "실패" 로 잡힘
(20260921-145955-001, handler_errors 집계 +1) — 실패 가시화가 의도대로 동작.
"취소"·"복구 필요" 는 M3 예약값으로 현재 전이 없음(코드 주석 명시).

`/state` 발췌 (2026-09-21T15:04Z, 주입 픽스처 run):
```json
{"run_id": "20260921-150400-003", "alertname": "KubePodCrashLooping",
 "state": "완료", "injection_suspects": 2, "llm_calls": 5, "duration_s": 65.7}
```

## S2 — 감사로그 PVC 영속화

| 검사 | 입력값 | 예상 | 실제 | 증거 위치 |
|---|---|---|---|---|
| 영속 | 파드 삭제 → 재생성 | 감사로그 유지 | 14건 그대로 (emptyDir 는 매번 소실됐음) | helm-deploy 62c2880 §2 |
| 바인딩 | `kubectl get pvc -n agent-system` | Bound | watchman-audit Bound 1Gi local-path | 2026-09-22 00:01 KST 실측 |

트레이드오프(정직 기재): RWO local-path 라 파드가 david 노드에 핀됨. david cordon/drain 시 watchman Pending. Deployment strategy 는 Recreate(RWO 동시 점유 방지).
PVC 이전 감사로그 35건은 `eval/runs-backup-20260921.jsonl` 로 백업(서브에이전트1 P4 라벨링 소재).

## 남은 것 (메인세션 담당 밖)
- T3-4: 서브에이전트2 관제 뷰 폴링 (S1 착수 후)
- NIM 503 과부하: 2026-09-21 15:00~15:03 UTC 사이 실알림·주입 1차 시도 각 1건이 재시도 소진 — ROADMAP §4 리스크 그대로. 데모는 감사로그·사전 확보 자료로 라이브 의존 제거.
