# ROADMAP.md — 9/27(일) 제출 프로토타입 로드맵

> 기간: **2026-09-21(월) ~ 09-27(일), 7일.** 3인 파트타임 전제. 공식 제출은 **9/28 온라인 신청서**
> (P7 확정). 9/27 은 내부 완성 목표다.
> 원칙: **이미 돌아가는 것(E2E)을 깎지 않는다.** 새 기능은 컷라인 아래로만 추가하고,
> 막히면 그 자리에서 Stretch 로 강등한다 — 마감이 스코프를 이긴다.

## 0. 현재 위치 (9/21 실측)

프로토타입의 심장은 **이미 돌아간다**: 실 Alertmanager 알림 → in-cluster 에이전트가
read-only 조사(ES·K8s) → NIM 분류 → 텔레그램 제안 카드. RBAC 경계·화이트리스트
거부·주입 픽스처까지 실측 완료 (SPEC M0·M1·M1.5 ✅). 남은 7일은 이걸
**"제출물"로 포장 + 보안통제 마무리 + 보이게 만들기**에 쓴다.

## 0.1 진행 현황 (2026-09-26 갱신)

| 항목 | 상태 | 증거 |
|---|---|---|
| P1 이그레스·컨테이너 강화 | ✅ | `eval/CONTROL-MATRIX.md` ③⑥, `eval/evidence-P1-P2-P3-S2.md` |
| P2 주입 ⚠ 표기 | ✅ | CONTROL-MATRIX ① (fx-rt-01 라이브, `injection_suspects=2`) |
| P3 `GET /state` | ✅ | evidence-P1-P2-P3-S2 |
| P4 평가 | ✅ (한계 명시) | 파이프라인 `eval/REPORT.md` · **실알림 블라인드 채점** `eval/real-alerts-20260924.md` |
| P5 레드팀 | ✅ 코드층 12/12 · LLM 거부층 라이브 지시 수행 0/12(완주 11) | `eval/REDTEAM.md` §3 |
| P6 제출 패키지 | 문서 ✅ · 데모 영상은 사용자 담당 | `SUBMISSION.md` |
| P7 공식 요건 | ✅ 확정(9/22 팀 브리핑) | §1.1 |
| S1 관제 뷰 | 웹 프로토 ✅ (Unity 대신 단일 HTML) | `web/console-map.html`, `web/DEMO.md` |
| S2 감사로그 PVC | ✅ | helm-deploy `pvc-watchman-audit.yaml`, `AUDIT_PATH=/data/audit.jsonl` |
| S3 카드 카피 | 부분 — 증거 커버리지·동결 지시·신고 기한 추가(fc82272) | — |
| Falco 런타임 탐지 | ✅ **실배포**(STRETCH 에서 승격) — 6노드 DaemonSet + falcosidekick → Alertmanager → watchman | helm-deploy `argocd-applications/falco.yaml` |
| NVIDIA 안전 가드 2차 판정 | ✅ 비차단 판정만 | `eval/guard-20260924.md` |
| NIM 과부하 대응 | ✅ 동시성 제한·백오프(90c5b53) + 모델 폴백 | `SUBMISSION.md` 정직 고지 #7 |
| NAT(NeMo Agent Toolkit) 플러그인 | ✅ 운영 코드 경로 그대로 `nat eval`·프로파일러 | `nat_watchman/`, `eval/nat-kpi-20260925.md` |
| 결정적 게이트 (CI) | ✅ 단위 307건 + eval 6종 exit 0 — 로컬 재현 확인(2026-09-26) | `.github/workflows/ci.yml` |
| 문서 동기화 (SPEC/ROLE/ROADMAP) | ✅ 2026-09-26 — 소스 대조 후 drift 해소 | SPEC.md §12 갱신 이력 |

## 1. 컷라인

### MUST — 이것 없이는 제출 안 됨 (9/26 까지)

| # | 항목 | 담당 | 완료 기준 |
|---|---|---|---|
| P1 | M2 핵심 통제: NetworkPolicy 이그레스 4목적지 + 비루트·readOnlyRootFilesystem | 메인세션 | 차단 실측 로그 (curl 외부 → 실패) |
| P2 | 주입 ⚠ 표기 (FR-13) — 페이로드 감지 시 카드에 배지 | 메인세션 | 레드팀 페이로드 1건이 ⚠ 카드로 도착 |
| P3 | `GET /state` 최소 구현 (FR-15) — 최근 run 목록·카드 요약 JSON + run 상태 7값·사용량 집계(SPEC FR-15) | 메인세션 | curl 로 JSON 실측, 필드는 서브에이전트2 요구 반영 |
| P4 | 평가 1회전: 실제 run ≥10건 라벨링 + 정답률 표 — 지지율 정의는 ROLE.md §6 T4-2 (분자/분모 명시) | 서브에이전트1 | eval/ 에 케이스와 리포트 커밋. **미달 수치를 성과로 표시하지 않는다** |
| P5 | 레드팀 페이로드 ≥10건 뱅크 + 통과/차단 결과표 | 서브에이전트1 | fixtures 확장 + 결과 마크다운 |
| P6 | 제출 패키지: README 데모 GIF·아키텍처 그림·제출 문서(무엇을·어떻게 통제했나) — **심사 4축(기술 활용 심도·실용성/산업가치·완성도·독창성) 구조로 작성** | 서브에이전트1(스토리)+메인세션(실측 자료) | 리포만 보고 5분 안에 이해 가능 |
| P7 | NVIDIA 챌린지 공식 요건 대조 (§1.1) — Build Skill API 필수 여부가 스코프를 바꿀 수 있어 **9/22 중 확인** | 서브에이전트1(공식 안내 접근 가능자) | 확인표에 원문 근거 링크 |

> **P7 진행 (2026-09-22, 공개 1차 출처로 정정):** 앞서 "Build Skill = 로그인 게이트 뒤 미지의 API"로 본 가정을 **정정한다.** "Build Skill"의 실체는 **공개된 NVIDIA Skills 생태계**다 — 로그인 없이 전부 검증 가능한 1차 출처로 확인:
> - **NVIDIA SkillEvaluator** (github.com/NVIDIA/SkillEvaluator, Apache-2.0): Skill 을 검증·채점하는 공식 오픈소스 도구. Tier-1 검증(schema·pii·license·quality·unicode·lint + SkillSpector/Semgrep/Gitleaks 보안)은 **키 없이 결정적으로** 돈다.
> - **SkillSpector**: 프롬프트 주입·데이터 유출·과잉권한·도구 오용 등 **17개 위험 범주 68패턴**(OWASP LLM + MITRE ATLAS 기반).
> - **Skill 사양**: `SKILL.md`(agentskills.io 공개 스펙, 최소 필드 name+description)를 담은 디렉터리. 5개 채점 축(correctness·security·discoverability·effectiveness·efficiency).
>
> **실증(공개·재현 가능):** Watchman 의 read-only 트리아지 계약을 **NVIDIA Skill 로 패키징**해 공식 SkillEvaluator Tier-1 을 **통과**시켰다 — `PASS · exit 0`, 검증기 6개 0 errors, Quality **97.8/100 grade A**. 산출물: `skills/watchman-secops-triage/`(SKILL.md·evals/·references/·`reports/` 원문 JSON), 커밋 7b83cc1.
>
> **여전히 미확정(정직)** *(→ 아래 "P7 확정(2026-09-22)" 으로 해소됨. 기록으로 남긴다)*: 위는 Skills *제품/생태계*가 공개임을 1차로 확인한 것이고, Watchman 이 그 공식 검증기를 통과함도 실증했다. 그러나 **NVIDIA "챌린지" 대회 자체가 "Skill 제출을 필수로 요구하는지", 심사 4축·9/28 제출 양식·마감 시각**은 이 공개 출처들이 말해주지 않는다 — 그 부분은 여전히 2차 정보이며 서브에이전트1의 안내 원문 대조가 남아 있다.
>
> **선제 대비 완료:** `skill_query` 어댑터(동일 NIM `/chat/completions` 호출, 별도 Skill API 제품 아님)를 **기본 OFF 게이트**로 심어둠(watchman 4fb4c45, helm-deploy 061797a). 켠 상태(`NVIDIA_SKILL_ENABLED=1`)에서 **실호출 1건까지 감사로그 `skill_call`(엔드포인트·토큰)로 확보**(`eval/skill-call-20260922.jsonl`, `eval/NVIDIA-USAGE.md` §3). 그 호출은 검증된 NIM 엔드포인트를 향하며, env 3줄로 공식 엔드포인트 교체 가능(코드 무변경).

### 1.1 NVIDIA 챌린지 공식 요건 (2차 정보 — 원문 대조 필요)

팀 공유 계획서(9/21)에서 파악한 요건. **공식 안내 원문과 대조 전까지는 전문(傳聞)이다** — P7 로 확정할 것.

> **P7 원문 탐색 결과(2026-09-22, 공개 웹 조사):** Exa 로 1차·공식 출처를 훑은 결과 —
> **계획서 스펙(9/28 마감 + Build Skill 제출 필수 + 한국어 4축 + NemoClaw/OpenShell 지정교육)을 동시에
> 만족하는 공개 대회 요강은 웹에 없다.** 인접 실재 대회만 확인: 최다 근접은 **Nebius x NVIDIA Global AI
> Hackathon**(NemoClaw/OpenShell + "reusable skills" + 공개 OSS repo 필수, 4축)이나 **마감이 10/30**(≠9/28);
> **UCSC NemoClaw 해커톤**은 "보안통제 시연" 보너스트랙이 Watchman 과 정확히 겹치나 **미국·종료**. 나머지
> (Nemotron Dev Days Seoul·Inception 그랜드챌린지·경기 NGG·AI Champion·LangChain 컨테스트)는 종료/법인·기관
> 대상이라 불일치. → **"그 대회"의 공식 요강은 비공개/초청 또는 한국 로컬 공고로 추정, 공개 인덱스에 없다.**
> 전체 대조표·1차 출처 링크: **[`eval/CHALLENGE-SOURCE-SEARCH.md`](../eval/CHALLENGE-SOURCE-SEARCH.md)**.

> **P7 확정(2026-09-22, 팀 브리핑 + 공식 링크로 해소):** 공개 rules 페이지는 여전히 인덱싱 안 됨(초청/한국 로컬 추정)이나, **팀 브리핑으로 요건이 확정**됐고 교육·플랫폼은 **공식 1차 링크**로 확인됐다:
> - **지정교육 = DLI `S-FX-43` "Securing Agents with NemoClaw and OpenShell"** — 팀 **수료 100% 완료**(learn.nvidia.com/courses/course-detail?course_id=course-v1:DLI+S-FX-43+V1).
> - **온라인 예선 = 자유 주제**, "NVIDIA Skill/API 를 활용한 **실작동 Agent**" 개발, **9/28 온라인 신청서로 데모 제출**. 심사 → **본선 진출 10팀 선정**. "미션 당일 공개"는 **10/7 오프라인 본선**(예선과 무관, 지금 문제 대기 불필요).
> - **"NVIDIA Build 의 Skill/API" = build.nvidia.com.** Watchman 은 이미 정렬 — nemotron-3-super-120b 를 `integrate.api.nvidia.com`(= NVIDIA Build 추론 엔드포인트)로 실호출 + NVIDIA Skill 패키징(SkillEvaluator Tier-1 통과).
> - **제출 계정**: NVIDIA 개발자 ID `iamipro@naver.com`(교육 수료 계정). Skill 메타 author 를 이 계정에 맞출지 확인 중.
> - **결론: 자유 주제이므로 Watchman(SecOps 보안 에이전트) 그대로 적격.** 앞서 검토한 "친구형 AI"는 예시였음. 남은 것은 **빌드가 아니라 제출** — ⓐ 90초 데모 영상 ⓑ 온라인 신청서 작성·제출 ⓒ 팀장과 제출 채널·중복·신청+제출 완료 확인.

| 요건 | Watchman 현황 | 할 일 |
|---|---|---|
| ✅ 공식 제출: **9/28 온라인 신청서**로 실작동 데모(자유 주제) | 본 로드맵은 9/27 완성 기준 | 🟢 확정. 남은 것 = 90초 데모 영상 + 온라인 폼(사용자 직접 제출) + 팀장과 신청·제출 완료 확인 |
| ✅ **NVIDIA Skill/API 활용**(=build.nvidia.com) | 🟢 두 방향 다 충족: (1) Watchman 을 **공개 Skill 로 패키징 → 공식 SkillEvaluator Tier-1 통과**(exit 0, 97.8/100 A, `skills/watchman-secops-triage/`); (2) nemotron-3-super-120b 를 NVIDIA Build 추론 엔드포인트로 실호출 | 🟢 확정 — "Skill/API 활용 Agent" 요건 충족. Skill 필수 여부 논쟁 종결(자유주제) |
| ✅ 지정 교육(DLI S-FX-43, NemoClaw·OpenShell) | 🟢 팀 **수료 100% 완료**(iamipro@naver.com 계정). 주제 "에이전트 보안"과 정합 | 완료 — 확인 불필요 |
| 심사 4축: 기술 활용 심도 / 실용성·산업가치·혁신성 / 완성도 / 커스터마이징·독창성 | 통제 6축·실측 증거가 그대로 소재 | P6 제출 문서 목차를 이 4축으로 |
| NVIDIA 실행 기록 연결 (모델 ID·사용량·실행 번호) | 감사로그에 원재료 있음 | P3 `/state` 집계 + 제출 문서에 run 별 표 |

### SHOULD — 되면 제출물이 눈에 띔

| # | 항목 | 담당 | 비고 |
|---|---|---|---|
| S1 | Unity 데스크톱 관제 뷰 프로토: 6노드 맵 + `/state` 폴링 + 알림 색 오버레이 | 서브에이전트2 | **화면 녹화 1분이 목표** — 완성도보다 "보인다"가 제출 가치. 9/24 까지 착수 판단 |
| S2 | 감사로그 PVC 영속화 | 메인세션 | helm-deploy 1커밋, 30분감 |
| S3 | 카드 카피 다듬기 (3초 판단 기준) | 서브에이전트1 | 프롬프트 수정은 P4 정답률 재확인 후 |

### STRETCH — 9/27 이후로 미뤄도 됨 (제출문서엔 "로드맵"으로 표기)

- recall_similar + ASI06 포이즈닝 방어 (FR-14) — 설계는 SPEC 에 이미 있음
- **인바리언트 미확인 3항목 실측화 (미래 과제, 2026-09-23 결정).** I1 R2 토큰 삭제 권한 분리,
  I2 버킷 보존 잠금 조회용 읽기 전용 토큰, I3 velero-repo-credentials 단일 Secret 한정 읽기(다이제스트만).
  velero·R2 백업 자체 보강과 묶어서 한다. 제출본은 UNKNOWN 을 정직 표기한 상태로 낸다.
- Quest VR 빌드, ESP32 물리 상태등 (FR-17)
- M3 승인 게이트 실행기
- NeMo Guardrails 비교 검토 — *부분:* NVIDIA 안전 가드 모델을 주입 2차 판정으로 붙였다
  (`eval/guard-20260924.md`, 비차단). NeMo Guardrails 프레임워크(레일 정의) 자체와의 비교는 미실시.
- **런타임 위협 트리아지 — 웹셸/RCE 클래스 (Falco 연동).** 2025 롯데카드 사고(온라인
  결제 WAS 침입 → 웹셸 설치, `CVE-2017-10271` 웹로직 RCE)와 동일 유형을 방어 대상으로
  다룬다. Falco 런타임 룰(웹서버 프로세스의 셸 spawn·웹 도큐먼트 루트 하위 쓰기·비정상
  아웃바운드)이 falcosidekick→Alertmanager 경로로 도착하면 Watchman 이 read-only 로
  트리아지하고 **격리·포렌식 보존·패치를 "제안"** 한다(실행 없음, 6축 통제 그대로 유효).
  - **된 것(설계·재현):** 알림 픽스처 `fixtures/scenarios/fx-scn-01-webshell-rce-falco.json`
    + 룰 매핑·근거 문서 [`docs/falco-webshell-rce-triage.md`](docs/falco-webshell-rce-triage.md)
    (1차 출처: 금융위 보도자료·NVD·금융보안원). mock 파이프라인 **완주 실측**(주입 오탐 0,
    finish 스키마 유효, evidence 1).
  - **된 것(운영, 2026-09-22~):** Falco(modern_ebpf, 6노드 DaemonSet) + falcosidekick →
    Alertmanager → Watchman 실배선. 실 Falco 알림을 매일 트리아지 중이고, 그 판정을 블라인드
    라벨로 채점했다(`eval/real-alerts-20260924.md` — 정상 알림 오탐 판정 27/37, '사고' 오판 0/37).
  - **아직 안 된 것:** 실 웹셸 재현 환경에서의 라이브 트리아지. 실알림 표본에 진짜 악성 알림이 0건이라
    탐지(민감도) 쪽은 아직 재지 못했다. → STRETCH.
- **자격증명 탈취·남용 트리아지 — GitHub 마스터키 클래스 (감사로그 연동).** 2026-06
  데이원컴퍼니(패스트캠퍼스) 사고(GitHub 마스터 계정 키 탈취 → 5/9 침입 → 6/8 인지, **약
  30일 미탐지**)와 동일 유형을 방어 대상으로 다룬다. 정직한 경계: **키 유출 자체(예방層:
  Push Protection·OIDC 단명 토큰·KMS·PoLP)는 Watchman 밖**이고, Watchman 은 **탈취 자격증명이
  '사용되는' 이상 신호**(배포 신원의 다수 ns secret 대량 열람·비인가 DB 접근·이상 위치 사용)를
  read-only 로 트리아지하고 **회전·격리·포렌식 보존을 "제안"** 한다(실행 없음, 6축 그대로).
  - **된 것(설계·재현):** 알림 픽스처 `fixtures/scenarios/fx-scn-02-github-key-theft-abuse.json`
    (kube-apiserver audit 평면) + 트리아지 문서
    [`docs/github-key-theft-abuse-triage.md`](docs/github-key-theft-abuse-triage.md)
    (1차 출처: 데이원 공식 통지·ZDNet·뉴스1). mock 파이프라인 **완주 실측**(주입 오탐 0,
    스키마 유효, evidence 1). **부수 성과:** 이 시나리오가 주입 감지층의 substring 오탐
    (`postgres` 의 `post`)을 드러내 `\b` 단어경계로 수정, 회귀 게이트 12/12·10/10 유지 재검증.
  - **아직 안 된 것:** GitHub Audit·GCP Cloud Audit·kube-apiserver audit·DB 감사로그를 ES/SIEM
    으로 수집하고 이상 룰을 세워 Alertmanager 로 라우팅하는 파이프라인. → 이 클래스의 핵심
    통합 작업이자 제출 범위 밖(STRETCH).
- **API 인가 남용 트리아지 — 상담 API/BOLA 클래스 (API 게이트웨이 연동).** 2026-09
  강남언니(힐링페이퍼) 상담내역 조회 API 유출(21만9665명, 시술·상담 등록사진·결제 등 민감정보
  포함)과 동일 유형을 다룬다. 앞의 두 건과 성격이 다르다 — **악성코드·키 탈취가 아니라 정상
  API 의 객체단위 인가 결함(BOLA/IDOR)**이다. 정직한 경계: **예방層(객체단위 인가 수정·레이트
  리밋·응답 최소화·인증 강화)은 Watchman 밖**이고, BOLA 는 개별 요청이 200 이라 **로그만으론
  탐지가 근본적으로 어렵다** — Watchman 은 detector 가 만든 행위 이상 alert 위에서 트리아지하고,
  강남언니의 **"1차 차단 후 다른 경로 재침입"** 공백을 겨냥해 **"형제 엔드포인트 전수 나열 =
  결함 클래스째 닫기"**를 포함한 봉쇄를 **"제안"** 한다(실행 없음, 6축 그대로).
  - **된 것(설계·재현):** 알림 픽스처 `fixtures/scenarios/fx-scn-03-consult-api-bola-abuse.json`
    (api-gateway-audit 평면) + 트리아지 문서
    [`docs/consult-api-bola-abuse-triage.md`](docs/consult-api-bola-abuse-triage.md)
    (1차 출처: 전자신문 단독·뉴시스·플래텀). mock 파이프라인 **완주 실측**(주입 오탐 0,
    스키마 유효, evidence 1).
  - **아직 안 된 것:** API 게이트웨이/인그레스 접근로그를 ES/SIEM 으로 수집하고 '단일 신원
    고fanout 객체 열거·응답 바이트 급증·차단 후 형제 경로 이동' 행위 이상 룰을 세워 Alertmanager
    로 라우팅하는 파이프라인. BOLA 특성상 detector 전제가 앞의 두 클래스보다 무겁다. → 제출
    범위 밖(STRETCH).
- **세션 하이재킹 트리아지 — JWT/세션 토큰 리플레이 클래스 (인증·세션 감사 연동).** CircleCI
  (2022-12 엔지니어 노트북 악성코드가 유효한 2FA-backed SSO 세션 쿠키를 탈취해 원격지에서 직원
  위장·프로덕션 침투)와 Okta(2023 지원 시스템 HAR 파일 세션 토큰으로 1Password·BeyondTrust·
  Cloudflare 등 5개 고객 세션 하이재킹, 14일간 로그 미탐)와 동일 유형을 다룬다. 앞의 세 건과
  또 다르다 — **탈취된 것이 비밀번호나 정적 키가 아니라 이미 인증을 통과한 "세션" 자체**라
  훔친 토큰이 서명·만료·2FA 를 모두 통과한다. 정직한 경계: **예방層(토큰 바인딩/DPoP·네트워크
  위치 바인딩·단명 TTL·쿠키 하드닝·XSS/악성코드 방어)은 Watchman 밖**이고, 개별 요청이 전부
  200 이라 **탐지는 행위·문맥 신호(임파서블 트래블·세션 중 IP/ASN·UA 변경·같은 jti 지리적 동시
  사용)에만 의존**해 근본적으로 어렵다(Okta 의 14일 미탐이 실증). Watchman 은 detector 가 만든
  세션 이상 alert 위에서 트리아지하고, **스테이트리스 JWT 는 개별 폐기가 불가능하다는 구조적
  한계까지 반영해** 봉쇄를 **"제안"** 한다 — **서명키(JWK) 회전(전체 토큰 무효화·대량 재인증)
  vs jti/세션 denylist+단명 TTL 의 트레이드오프 제시**(실행 없음, 6축 그대로).
  - **된 것(설계·재현):** 알림 픽스처 `fixtures/scenarios/fx-scn-05-jwt-session-replay-hijack.json`
    (auth-session-audit 평면) + 트리아지 문서
    [`docs/jwt-session-replay-hijack-triage.md`](docs/jwt-session-replay-hijack-triage.md)
    (1차 출처: CircleCI 공식 리포트·Okta root cause·KrebsOnSecurity·Help Net Security). mock
    파이프라인 **완주 실측**(주입 오탐 0, 스키마 유효, evidence 1).
  - **아직 안 된 것:** 인증·세션 감사 로그를 ES/SIEM 으로 수집하고 '유효 세션의 세션 중 IP/ASN·
    UA 변경·임파서블 트래블·같은 jti 지리적 동시 사용' 이상 룰을 세워 Alertmanager 로 라우팅하는
    파이프라인. 나아가 봉쇄 집행에는 JWK 회전 도구·세션 denylist 저장소 같은 인증 인프라가
    전제된다. → 제출 범위 밖(STRETCH).

## 2. 일자별 계획

| 날짜 | 메인세션 (코어) | 서브에이전트1 (품질·제출) | 서브에이전트2 (뷰) |
|---|---|---|---|
| 9/21 월 | 리포 온보딩 정리 · `/state` 필드 초안 | 리포 읽기 · 감사로그 run 훑기 | 리포 읽기 · `/state` 필요 필드 이슈 |
| 9/22 화 | P3 `/state` 구현 | P4 라벨링 시작 (기존 run 6건부터) | Unity 프로젝트 뼈대 · 폴링 확인 |
| 9/23 수 | P1 NetworkPolicy + 컨테이너 강화 | P5 페이로드 뱅크 설계 (Codex 병렬 생성) | 노드 맵 렌더 |
| 9/24 목 | P2 주입 ⚠ 표기 | P5 페이로드 실주입 테스트 (메인세션와) | 알림 오버레이 · **S1 계속/중단 판단** |
| 9/25 금 | P1·P2 실측 증거 수집 · S2 | P4 정답률 표 완성 · P6 제출 문서 초안 | 화면 녹화용 다듬기 |
| 9/26 토 | **기능 동결.** 버그만 수정 | P6 데모 GIF·아키텍처 그림·문서 완성 | 녹화 1분 제출용 |
| 9/27 일 | 최종 리허설(실알림 E2E 1회) · 제출 | 제출물 최종 검수 | — |

## 3. 제출 체크리스트 (9/27)

- [x] 랜섬웨어 대응 4층 추가 (2026-09-23) — 킬체인 상관관계(FR-21)·출력 유출 통제(FR-22)·
      복구가능성 조사(FR-23)·주기 인바리언트(FR-24). 각 층마다 픽스처 뱅크 + exit 코드 게이트
      하네스(`run_chain`/`run_egress`/`run_recovery`/`run_invariants`) + 단위테스트 17개.
      **자동 격리·자동 실행은 넣지 않았다** — 전 구간 read-only 계약을 깨지 않는다.
- [ ] 실알림 E2E 데모 증거 (GIF 또는 감사로그+카드 스크린샷)
- [x] 보안통제 6축 각각의 **실측 증거** (403 로그, 차단 로그, ⚠ 카드, 감사로그 발췌) — `eval/CONTROL-MATRIX.md`
- [x] 평가 리포트 (정답률 표 + 레드팀 결과표) — REPORT·real-alerts-20260924·REDTEAM
- [x] SPEC.md / ROLE.md / ROADMAP.md 최신화 (2026-09-26) — 소스 대조로 확인한 drift 를 해소했다:
      기본 등록 도구에 `container_lookup` 이 빠져 있던 것(허용목록이 이 프로젝트의 핵심 주장이라 가장 컸다),
      §3 스텝 예산이 FR-4 와 자기모순, ES 허용목록 4개→실제 기본값 1개, 리소스 19종→21종,
      FR-11 이 "PVC 미결" 인데 ROADMAP S2 는 ✅ 라 두 문서가 반박하던 것. 또 SPEC 에 아예 없던 구현물
      (Falco 수신·판정 재사용·안전 가드·감사 해시 체인·이메일 이중화·내장 콘솔·NAT 플러그인·스냅샷 재생)을
      FR-25~FR-36 으로 명세화했다. **코드 변경 없음** — 9/26 기능 동결을 지켰다.
- [ ] (S1 성공 시) 관제 뷰 녹화 — 뷰는 있음(`web/DEMO.md` 녹화 가이드), 녹화는 사용자 담당
- [x] Skills 생태계 실체 확인 + Watchman 을 공식 SkillEvaluator 로 검증(P7 부분완료, 7b83cc1)
- [x] §1.1 공식 요건 확인표 완료 (P7) — 9/22 팀 브리핑으로 확정: 자유 주제, 9/28 온라인 신청서, 지정교육 수료
- [x] NVIDIA 실행 기록 표 (run 별 모델 ID·호출 수·토큰·소요 시간 — `/state` 집계 발췌) — `eval/NVIDIA-USAGE.md`
- [x] 공개 전환 + 노출 점검 (2026-09-26) — 이 스냅샷 리포는 이미 **PUBLIC**. 유출 스윕 결과:
      홈 LAN 대역(192.168.219.x) 전량 `[REDACTED-IP]` 처리 완료(e482b3c), 남은 10.42.x.x 는 수명 짧은
      k3s 파드 CIDR 이라 의도적 잔존. 실 키·토큰 0건(검출된 nvapi-/AKIA/PEM 은 전부 유출 통제 게이트용
      픽스처). `iamipro@naver.com` 은 Skill 스펙 `author` 필드 겸 NVIDIA 제출 계정이라 의도적 보존.
      ※ 제출처가 공개 리포를 **요구**하는지 자체는 여전히 팀장 확인 사항

## 4. 리스크

| 리스크 | 완화 |
|---|---|
| NIM 503 과부하가 데모 중 발생 | 재시도 내장 + 데모는 감사로그·GIF 사전 확보로 라이브 의존 제거 |
| 3인 가용 시간 미확정 | 컷라인 MUST 는 메인세션+서브에이전트1만으로 닫힘. S1 은 9/24 판단점 |
| Unity 뷰가 7일 안에 안 나옴 | S1 은 SHOULD — 없어도 제출 성립. 대신 `/state` JSON 을 문서에 노출 |
| 프롬프트 수정이 분류 품질을 깨뜨림 | 9/26 기능 동결 + P4 정답률 표가 회귀 기준선 |
