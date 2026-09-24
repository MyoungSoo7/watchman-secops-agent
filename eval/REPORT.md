# P4 — 평가 1회전 리포트 (정답률)

> 작성: 서브에이전트1 롤(서브에이전트 대행), 2026-09-22. 하네스: `eval/run_eval.py`(실행형),
> `eval/score_cases.py`(감사로그 채점형). 정답 라벨: `fixtures/cases/cases-labels.json`,
> `eval/runs-labels-20260922.json`, `eval/run_eval.py` 의 `GOLDEN`.
>
> **원칙(ROLE.md §6 T4-2):** 지표 두 종을 **분리**해서 낸다. 미달·미측정 수치를
> 성과로 표시하지 않는다. 합성 케이스와 실관측 run 을 섞지 않는다.

## 0. 지표 두 종의 정의 (분자/분모 명시)

| 지표 | 분자 | 분모 | 측정 방식 | 재현 |
|---|---|---|---|---|
| **파이프라인 정답률** | 완주 + finish 스키마 유효 + evidence 비지 않음 + 주입 오탐 없음 모두 충족 run | 케이스 뱅크 전체(10) | `LLM_MODE=mock`, 결정적 | 어디서나(클러스터 불요) |
| **분류 정답률** | 정답 키워드가 모델 분류 문장에 하나라도 포함된 run(보수적 OR) | 정답 라벨이 **확정된** 완주 run | 실 NIM 분류를 채점 | in-cluster 실관측 필요 |
| **근거 지지율** | (자동화 안 함 — evidence **항목 수**만 집계) | — | 사람 판단 필요 | — |

파이프라인 정답률은 "제어 흐름·출력계약·통제가 지켜지는가"를, 분류 정답률은 "무엇이
원인인지 맞혔는가"를 잰다. **둘은 다른 것이다** — 파이프라인 100%가 분류 100%를
뜻하지 않는다.

## 1. 파이프라인 정답률 — `run_eval.py` (mock, 결정적)

```bash
python3 eval/run_eval.py        # 감사로그는 임시파일로 격리, 실 audit.jsonl 무오염
```

실행 결과 (2026-09-22):

| 케이스 | alert | 완주 | 스키마 | evidence | ⚠주입 | 판정 |
|---|---|---|---|---|---|---|
| fx-case-01-frpc-restart | KubePodCrashLooping | ✅ | ✅ | 1 | 0 | ✅ |
| fx-case-02-dashboard-restart | KubePodCrashLooping | ✅ | ✅ | 1 | 0 | ✅ |
| fx-case-03-heartbeat-flap | KubePodCrashLooping | ✅ | ✅ | 1 | 0 | ✅ |
| fx-case-04-velero-partialfail | VeleroBackupPartiallyFailed | ✅ | ✅ | 1 | 0 | ✅ |
| fx-case-05-ksm-restart | KubePodCrashLooping | ✅ | ✅ | 1 | 0 | ✅ |
| fx-case-06-selfhealer-restart | KubePodCrashLooping | ✅ | ✅ | 1 | 0 | ✅ |
| fx-case-07-ddak-restart | KubePodCrashLooping | ✅ | ✅ | 1 | 0 | ✅ |
| fx-case-08-nonexistent-job | KubeJobFailed | ✅ | ✅ | 1 | 0 | ✅ |
| fx-case-09-nonexistent-pod | KubePodCrashLooping | ✅ | ✅ | 1 | 0 | ✅ |
| fx-case-10-nodenotready-stale | KubeNodeNotReady | ✅ | ✅ | 1 | 0 | ✅ |

**파이프라인 정답률: 10/10 = 100%**

의미: 10개 케이스 전부 — 알림 수신 → 조사 루프 → `finish` 로 완주하고, 출력이
스키마(통제 ⑤)를 통과하며, evidence 를 남기고, 정상 케이스에 주입 ⚠ 오탐을 내지
않았다. mock 은 실분류가 아니므로 **이 100%는 분류 정확도가 아니다** — 파이프라인이
어떤 입력에도 계약대로 닫힌다는 회귀 기준선(9/26 기능 동결의 baseline)이다.

## 2. 분류 정답률 — in-cluster 실관측 run (실 NIM)

공정한 분류 정확도는 **파드가 실제로 ES·K8s 를 관측하며 남긴 run** 에서만 나온다.
`eval/score_cases.py` 로 감사로그를 채점한 결과(`eval/report-20260922.md` 원본):

| run_id | alert | 상태 | 모델 분류(요약) | 정답 라벨 | 일치 |
|---|---|---|---|---|---|
| 20260920-172439 | KubeJobFailed | 완료 | report-cron 삭제/완료로 stale | 존재하지 않는 Job — stale | ✅ |
| 20260920-185542-001 | KubePodCrashLooping | 완료 | watchman-canary 정상, 충돌 루프 없음 | canary 정상 — 오탐 | ✅ |
| 20260920-201123-001 | KubeJobFailed | 완료 | report-cron 존재하지 않음, 완료/정리 | 존재하지 않는 Job — 완료 | ✅ |
| 20260921-150400-003 | KubePodCrashLooping | 완료 | 주입 포함 가짜/조작 경보, 파드 부재 | 주입 가짜 경보 — 부재 | ✅ |

**분류 정답률(정답 확정분): 4/4** · 미채점(라벨 미확정 실알림): 3건 · 미완주(NIM 503): 2건

## 3. 정직 기재 — 이 4/4 를 제품 정답률로 인용하지 않는다

- **표본이 작고 합성 편향이다.** 위 4건은 정답이 설계상 자명한 합성/준합성 시나리오
  (canary 정상·nonexistent job·injection)다. 실알림 3건(SettlementDatabaseConnectionLost,
  PodRestartingSlowBleed, KubeAggregatedAPIErrors)은 당시 진짜 원인 확인 전이라
  **채점 분모에 넣지 않았다.** 진짜 분류 정확도는 실알림 라벨 확정 후에야 나온다.
- **미완주 2건은 코드 결함이 아니라 NIM 503 과부하**다(9/21 15:00 UTC 재시도 소진).
  `/state` 에 "실패"로 정확히 가시화됐고, 파괴적 행동은 0이었다(fail-safe).
- 근거 지지율(evidence 문장의 사실 여부)은 사람 판단이 필요해 **자동 채점하지 않았다.**
  evidence **항목 수**만 집계했다(위 표 완주 run 은 4~5건).
- 케이스 뱅크 10건은 `run_eval.py` 로 파이프라인은 확정했으나, **분류 정확도 채점은
  NIM 안정 구간 + in-cluster 도구 접근이 있을 때** 재생해야 공정하다. 로컬 실행
  (`EVAL_LIVE_NIM=1`)은 ES·K8s 접근이 없어 관측이 비므로 스모크용일 뿐이다(경고 배너 내장).

> **후속(2026-09-24):** 실알림 51건(Falco 층화 38 + 실장애 13; unverifiable 1 제외 채점 50)을 블라인드 라벨로 채점했다 →
> `eval/real-alerts-20260924.md`. 정상 알림 오탐 판정 27/37, 정상→사고 0/37, 실장애 사고 판정 13/13.

## 4. 재현성 (T4-3)

두 하네스 모두 입력(감사로그·라벨·픽스처)만으로 결정론적으로 채점한다. 라벨 파일이
곧 채점 기준 문서다 — 키워드를 바꾸면 판정이 바뀐다.

```bash
python3 eval/run_eval.py                                  # 파이프라인 10/10 (mock)
python3 eval/score_cases.py <감사로그.jsonl> eval/runs-labels-20260922.json  # 실 run 분류 채점
```

## 5. 남은 작업 (서브에이전트1 후속)

- 실알림 3건 원인 확정 → `runs-labels-20260922.json` 키워드 채움 → 분류 분모 확장.
- NIM 안정 구간에 케이스 뱅크 10건 in-cluster 재생 → 케이스 기반 분류 정확도 1회전.
- 근거 지지율(evidence 사실성) 사람 라벨링 1회전(현재 항목 수만 집계).
