# Watchman(파수꾼)

> **심사용 공개 스냅샷.** 개발 리포(비공개)의 `090fb56` 시점을 히스토리 없이 옮긴 사본이다.
> 변경점: 개인 이메일 1곳 마스킹, 내부 제출 초안(`request.md`) 제외. 코드·테스트·평가 하네스는 원본과 동일(119 tests OK).

Lemuel K3s 클러스터의 Alertmanager 알림을 받아 **로그 조회 → 원인 분류 → 조치 제안**을
수행하는 보안 통제된 SecOps 에이전트. 전 구간 read-only, 자동 실행 없음.
설계·통제 축·마일스톤은 [SPEC.md](SPEC.md), 제출 서사는 [SUBMISSION.md](SUBMISSION.md) 참조.

## 빠른 시작 (키 없이)

```bash
python3 -m unittest test_watchman -v        # 통제 축 단위 테스트
LLM_MODE=mock python3 watchman.py replay fixtures/kube-job-failed.json
python3 eval/run_eval.py                     # 파이프라인 계약 충족(mock, 결정적) — 10/10 (분류 정확도 아님)
python3 eval/run_redteam.py                  # 레드팀 감지 12/12 · 오탐 0 (exit 0 = CI 게이트)
python3 -m unittest test_security_layers    # 킬체인·유출통제·복구·인바리언트 단위 테스트
python3 eval/run_chain.py                    # 킬체인 상관관계 — 2번째 알림에 승격, 오탐 4축 0
python3 eval/run_egress.py                   # 유출 차단 7/7 · 오탐 0 · 마스킹 후 잔존 0
python3 eval/run_recovery.py                 # 복구가능성 판정 5/5 (조회 실패는 UNKNOWN)
python3 eval/run_invariants.py               # 알람 없는 자세 점검 6/6
```

stdlib-only — 설치할 것 없음.

## 실사용

```bash
cp .env.example .env    # NVIDIA_API_KEY(nvapi-)·ES·K8s 토큰 채우기, LLM_MODE=nim
python3 watchman.py serve                   # 127.0.0.1:8687, POST /alert
curl -X POST localhost:8687/alert -d @fixtures/velero-partial.json
```

## 데모 증거 (직접 확인 지점)

리포만 보고 5분 안에 "돌아간다"를 확인할 수 있는 실측 자료:

| 보고 싶은 것 | 어디를 보나 |
|---|---|
| **평가 1회전** — 파이프라인 계약 충족 표(10/10, mock) + 분류 정확도 채점 근거(live) | [eval/REPORT.md](eval/REPORT.md) · 재현 `python3 eval/run_eval.py` |
| **레드팀(입력 축)** — 주입 감지 12/12 + 정상 오탐 0 결과표 | [eval/REDTEAM.md](eval/REDTEAM.md) · 재현 `python3 eval/run_redteam.py` |
| **유출 통제(출력 축)** — 카드·메일·감사로그로 나가는 비밀값 차단 7/7, 오탐 0, 마스킹 후 잔존 0 | `fixtures/egress/` · 재현 `python3 eval/run_egress.py` |
| **킬체인 상관관계** — 개별로는 warning 인 4건이 *순서*로 랜섬웨어가 되는 승격 | `fixtures/chain/` · 재현 `python3 eval/run_chain.py` |
| **복구가능성 조사** — "백업이 있다"와 "복구할 수 있다"를 가르는 판정(velero read-only) | `fixtures/recovery/` · 재현 `python3 eval/run_recovery.py` |
| **알람 없는 자세 점검** — 경보가 울리지 않는 구조적 결함(자격증명 범위·버킷 잠금·기본 암호화 키·RDP·백업 신선도) | `fixtures/invariants/` · 재현 `python3 eval/run_invariants.py` |
| **보안통제 6축 실측** — 403 로그·차단 로그·⚠ 카드·감사 발췌 | [eval/evidence-P1-P2-P3-S2.md](eval/evidence-P1-P2-P3-S2.md) |
| **in-cluster 실관측 run 채점** — 실 NIM 분류 정답률 근거 | [eval/report-20260922.md](eval/report-20260922.md) · [eval/score_cases.py](eval/score_cases.py) |
| **NVIDIA 실행 기록** — run 별 모델 ID·호출 수·토큰·소요 시간 | `GET /state` 집계 (아래) |
| **아키텍처 한눈에** — 알림→조사→분류→카드 + 통제 경계 | [docs/architecture.md](docs/architecture.md) (mermaid) |
| **감사로그 원장** — 매 스텝 append-only 기록 | `audit.jsonl` (gitignore, PVC 영속화). 발췌는 evidence 문서에 마스킹본 |

`GET /state` 예시 (실 run 집계, FR-15):

```bash
curl -s localhost:8687/state | python3 -m json.tool
# → runs[] 각 항목: run_id · alertname · state(관측 7값) · llm_calls · prompt_tokens
#   · completion_tokens · duration_s · injection_suspects
```

## 실 인프라 연결 (이 맥 기준, 2026-09-21 구성)

자격은 전부 read-only 전용 계정이고 파일로 로컬 보관(gitignored):

- **ES**: ECK `logs` 클러스터(ns logging) — 전용 사용자 `watchman`(롤 `watchman_read`,
  로그 인덱스 4패턴 read만). 비밀번호 `.es_watchman_pass`.
  접속: `kubectl -n logging port-forward svc/logs-es-http 19200:9200`
- **K8s**: SA `default/watchman-readonly` + 전용 ClusterRole(19개 리소스 get/list/logs만,
  secrets 없음). 토큰 `.k8s_watchman_token`, API 는 SSH 터널 `127.0.0.1:16443`.
- **재생**: `python3 replay_m0.py` — Alertmanager(`port-forward svc/kps-alertmanager
  19093:9093`)에서 발화 중 실알림을 골라 실 LLM 으로 완주시킨다.

RBAC 경계 실측: jobs list 200 / secrets list 403 / pod delete 403.

## 구조

- `watchman.py` — 전부 (설정·도구·에이전트 루프·감사로그·webhook 서버)
- `test_watchman.py` — 통제 ①③⑤ 검증 (인자 화이트리스트·스텝 예산·출력 스키마·데이터 래핑)
- `fixtures/` — 실알림 모사(cases/·정상) + 레드팀 주입 뱅크(redteam/ 12건)
- `eval/` — 평가·레드팀 하네스와 리포트 (run_eval.py · run_redteam.py · REPORT.md · REDTEAM.md)
- `docs/architecture.md` — 아키텍처 다이어그램
- `audit.jsonl` — append-only 감사 기록 (gitignore 대상)
