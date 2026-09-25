# nat_watchman — Watchman 을 NeMo Agent Toolkit 플러그인으로

운영 에이전트(`watchman.py`, 표준 라이브러리 단일 파일)를 **다시 짜지 않고 감싼다.**
`nat eval` 과 프로파일러가 재는 것이 운영 파드와 같은 코드 경로가 되게 하려는 것이다.

| 등록 이름            | 종류                | 하는 일                                                            |
| -------------------- | ------------------- | ------------------------------------------------------------------ |
| `watchman_triage`    | function (워크플로) | 알림 JSON 1건 → 읽기 전용 조사 → finish 판정 JSON                  |
| `watchman_es_search` | function (도구)     | 허용목록 인덱스만 읽는 로그 검색                                   |
| `watchman_kube_read` | function (도구)     | get/list 만, secrets 무권한                                        |
| `watchman_verdict`   | evaluator           | 판정 vs 블라인드 라벨(benign→오탐, incident→사고). partial 은 오답 |

watchman 의 LLM·도구 호출은 NAT 콜백을 거치지 않는다. 그래서 워커 스레드에서 호출마다 시각과
NIM 응답의 `usage` 를 기록해 두었다가 조사가 끝나면 `LLM_START/END`·`TOOL_START/END` 중간
스텝으로 옮긴다. 프로파일러의 토큰·지연은 추정치가 아니라 실측값이다.
가드 모델 호출은 기록 대상이 아니다(도구·주 LLM 경로만) — 가드 지연은 감사로그 span 에 있다.

## 설치 (Python 3.11–3.13)

```bash
python3.12 -m venv .venv
.venv/bin/pip install 'nvidia-nat[eval,profiling]==1.9.0' nvidia-nat-profiler==1.9.0 langchain-core
.venv/bin/pip install -e nat_watchman
```

## 실행 (리포 루트에서)

```bash
# 키 없이 배선만 확인 — MockLLM 은 verdict 를 내지 않으므로 점수 0 이 정상
.venv/bin/nat eval --config_file nat_watchman/configs/eval_smoke_mock.yml

# 실알림 재생 — 데이터셋은 운영 감사로그에서 만든다(알림 원문이라 커밋하지 않음)
python3 eval/build_nat_dataset.py <prod-audit.jsonl>
# 환경변수(K8S_*·ES_*·NVIDIA_API_KEY)는 eval/run_case_bank.py 머리말과 같다
.venv/bin/nat eval --config_file nat_watchman/configs/eval_real_alerts.yml
python3 eval/nat_kpi.py nat_watchman/.tmp/eval-real > eval/nat-kpi-<날짜>.md
```

평가 중에는 텔레그램 카드·메일을 끈다(`TELEGRAM_BOT_TOKEN`·`SMTP_HOST` 를 빈 값으로 덮어씀).

## 한계

- **재생은 현재 클러스터 상태로 조사한다.** 알림이 난 시점의 파드·로그와 다를 수 있다
  (특히 이미 복구된 incident 는 증거가 사라져 있을 수 있다).
- 라벨은 사람이 블라인드로 단 것이고(`eval/real-labels-20260924.json`), 표본은 50건이다.
