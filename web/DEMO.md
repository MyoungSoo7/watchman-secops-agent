# S1 관제 뷰 — 데모 & 1분 녹화 가이드

파수꾼(Watchman)의 6노드 관제 뷰 프로토(서브에이전트2 S1). Unity 실빌드 대신 **단일 HTML 웹 뷰**로
S1 의 실질 가치("보인다")를 낸다 — 6노드 맵 + `/state` 폴링 + 알림 색 오버레이.
ROADMAP §4 리스크표의 대체안("Unity 뷰가 7일 안에 안 나오면 `/state` JSON 을 문서에 노출")을
한 단계 더 올린 형태.

## 파일

| 파일 | 역할 |
|---|---|
| `web/console-map.html` | 관제 뷰(단일 파일, 외부 의존 없음). 열면 바로 동작 |
| `web/sample-state.json` | 오프라인/녹화용 샘플. `/state` **실제 스키마와 동일** |
| `web/DEMO.md` | 이 문서 |

## 실행

브라우저는 `file://` 페이지에서 로컬 파일 `fetch()` 를 막는다(Chrome 정책).
그래서 **작은 로컬 서버로 서빙**한다 — 이게 녹화에도 가장 안정적이다.

```bash
cd /Users/lms/watchman-agent/web
python3 -m http.server 8899
# 브라우저에서 http://localhost:8899/console-map.html 열기
```

기본은 **샘플 모드**(우상단 배지 `SAMPLE`). 열자마자 6노드 맵에 색이 칠해지고
run 표가 채워진다 — 라이브 클러스터 상태와 무관하게 항상 같은 그림이라 녹화에 안정적.

## 두 데이터 모드

- **샘플**(기본): 같은 폴더의 `sample-state.json` 을 폴링. 네트워크·CORS 무관, 재현 가능.
- **라이브**: 우상단 `라이브` 버튼 → 공개 read-only 엔드포인트 `https://security.lemuel.co.kr/state` 폴링.
  실패(대개 CORS/네트워크)하면 상단에 빨간 배너를 띄우고 샘플로 자동 폴백하되, live 재시도는 계속한다.

폴링 주기 5초. 뷰에는 쓰기 컨트롤이 전혀 없다(FR-15 read-only 계약을 UI 로도 지킴).

## 1분 녹화 시나리오 (권장 순서)

1. **(0:00) 전경** — `http://localhost:8899/console-map.html` 을 연다. 상단 배지 `SAMPLE`,
   그 아래 "클러스터 경보 수준" 바, control-plane 3 / worker 3 노드 맵, run 표가 한 화면에 보인다.
2. **(0:10) 경보 색** — 맵에서 색이 칠해진 노드(주황=부분 결과, 적=실패)와 클러스터 경보 바의
   색이 최악 상태(🔴 실패)를 가리키는 걸 보여준다. run 표의 상태 컬럼 색과 일치한다.
3. **(0:25) ⚠ 주입 배지** — 맵의 알림 칩과 run 표에서 보라색 `⚠` 배지(주입 의심 run)를 짚는다.
   "알림 본문에 지시문 삽입 흔적이 감지되면 배지로 표기" — 파수꾼의 FR-13 통제가 뷰에 드러난다.
4. **(0:40) run 상세** — run 표를 훑는다: run_id, 상태, 알림/네임스페이스, 분류 요약, 신뢰도(%),
   LLM 호출 수, 토큰, 소요 시간. NVIDIA 모델 ID(`nvidia/nemotron-3-super-120b-a12b`)와
   사용량이 상단·표에 함께 보인다(제출 요건: 실행 기록 연결).
5. **(0:50) 라이브 토글**(선택) — `라이브` 버튼을 눌러 공개 `/state` 로 전환. 실 클러스터가
   조용하면 run 0건이 정직하게 그대로 보인다(빈 상태 처리). 다시 `샘플` 로 돌아와 마무리.

## 뷰가 소비하는 `/state` 필드 (FR-15 계약)

`watchman.py` `state_snapshot()` 이 내려주는 그대로만 읽는다(추측 필드 없음):

- 최상위: `service`, `now`, `llm_mode`, `model`, `run_states`, `totals`, `runs_by_state`, `runs`
- `totals`: `alerts_in`, `cards_sent`, `cards_suppressed`, `handler_errors`, `emails_sent`,
  `email_errors`, `injection_suspects`
- `runs[]`: `run_id`, `alertname`, `namespace`, `state`(7값), `duration_s`, `model`,
  `llm_calls`, `prompt_tokens`, `completion_tokens`, `tool_calls`, `injection_suspects`,
  `classification`, `confidence`, `evidence_count`, `proposal_count`

## ⚠ 정직성 메모 (과장 방지)

- `/state` 계약에는 run 을 **클러스터 노드에 매핑하는 필드가 없다.** 6노드 맵은 클러스터
  토폴로지이고, 알림을 노드에 얹는 배치는 `namespace` 해시 기반 **시각화용**이다 —
  "어느 노드에서 떴는지"의 사실이 아니다. 노드 색은 전체 경보 수준을 공유한다.
  **run 표가 사실의 원본이고, 맵은 글랜스용 표현이다.** (뷰 하단 푸터에도 명시)
- 이건 완성품이 아니라 "보인다"를 보여주는 프로토다.

## 메인 세션(메인세션) 할 일 — 서버측

이 뷰 자체는 `watchman.py` 를 건드리지 않는다(서브에이전트2 롤은 뷰 파일만 만든다). 라이브 모드를
**같은 브라우저 origin 문제 없이** 쓰려면 서버측에서 둘 중 하나가 필요하다:

1. **CORS 헤더 추가(권장, 1줄)** — `watchman.py` `do_GET` 의 `/state` 응답에
   `self.send_header("Access-Control-Allow-Origin", "*")` 추가. 그러면 `localhost` 나
   다른 origin 에서 연 뷰가 `https://security.lemuel.co.kr/state` 를 직접 폴링할 수 있다.
   (read-only GET 이라 노출 위험 낮음 — /state 는 이미 시크릿 미포함 스냅샷.)
2. **동일 origin 서빙** — `watchman.py` 에 `GET /console`(또는 `/map`) 라우트를 추가해
   이 HTML 을 그대로 내려주면 CORS 자체가 발생하지 않는다. 기존 `GET /`(대시보드)와 공존.

둘 중 무엇도 없으면 라이브 모드는 CORS 로 막히고 뷰는 샘플로 폴백한다(배너로 안내). **샘플 모드
녹화는 서버 변경 없이 지금 바로 가능하다.**

## 한계 / 미완

- 이 환경에선 Chrome 확장이 연결돼 있지 않아 **자동 스크린샷·GIF 녹화를 뷰에서 직접 뜨지 못했다.**
  파일 서빙(HTTP 200)·JSON 파싱·렌더 로직(운영 대시보드와 동일 팔레트)까지는 검증했으나,
  실제 브라우저 렌더 캡처는 사람이 위 실행 절차로 1회 떠야 한다.
- 노드별 실상태(노드 각각의 Ready/자원)는 `/state` 계약 밖이라 표시하지 않는다(정직성 메모 참조).
