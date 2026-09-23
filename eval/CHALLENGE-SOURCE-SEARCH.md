# 대회요강 원문 탐색 결과 (P7 — 공개 웹 조사)

> 작성: 메인세션, 2026-09-22. 사용자 지시 "대회요강 원문찾아봐" 이행.
> 방법: Exa MCP 웹검색(1차·공식 출처 우선, CLAUDE.md 규칙). 아래 후보는 전부 실제 공개 페이지다.
> **결론(정직):** 팀 공유 계획서가 기술한 스펙 —
> **① 9/28 마감 · ② Build Skill 제출 필수 · ③ 한국어 4축(기술활용심도/실용성·산업가치/완성도/독창성) · ④ NemoClaw·OpenShell 지정교육** —
> 을 **동시에** 만족하는 공개 대회 요강은 웹에서 확인되지 않는다. 인접한 실제 대회들의 요강만 존재한다.

## 0. 해소(2026-09-22, 팀 브리핑 + 공식 링크) — 이 조사의 후속

이 문서의 §3 결론("공개 요강 부재")은 맞았고, 그 미싱 링크는 **같은 날 팀 브리핑으로 채워졌다.** 확정 요건:

- **지정교육 = DLI `S-FX-43` "Securing Agents with NemoClaw and OpenShell"** (수료 완료) — 공식: `learn.nvidia.com/courses/course-detail?course_id=course-v1:DLI+S-FX-43+V1`
- **온라인 예선 = 자유 주제.** "NVIDIA Skill/API 활용 **실작동 Agent**" 개발 → **9/28 온라인 신청서로 데모 제출** → 심사 후 **본선 진출 10팀 선정**. "미션 당일 공개"는 **10/7 오프라인 본선**(예선 무관).
- **"NVIDIA Build" = `build.nvidia.com`.** Watchman 은 이미 정렬(nemotron-3-super-120b @ `integrate.api.nvidia.com` 실호출 + NVIDIA Skill 패키징 SkillEvaluator 통과).
- **결론: 자유 주제이므로 Watchman(SecOps) 그대로 적격** — "친구형 AI"는 예시였다. 남은 것은 **제출**(90초 데모 영상 + 온라인 폼 + 팀장과 신청·제출 완료 확인). 제출 폼은 **사용자 본인이 직접 제출**(이 리포는 폼 URL 미보관).
- **여전히 참인 것:** 대회의 **공개 rules 페이지는 웹에 인덱싱돼 있지 않다**(§3 추정과 정합 — 초청/한국 로컬). 즉 요건 텍스트의 출처는 "팀 브리핑(내부 공식)"이며, 아래 §1 의 공개 대회들은 그와 **별개의 인접 대회들**이다.

---

## 1. 공개 웹에서 확인된 실제 NVIDIA 관련 대회 (1차 출처)

| 대회 | 주최/성격 | 마감·시기 | 심사축(원문) | Skill/NemoClaw | 프로필 일치 |
|---|---|---|---|---|---|
| **Nebius x NVIDIA Global AI Hackathon** (`nebiusglobalaihackathon.devpost.com/rules`) | Nebius+NVIDIA, 글로벌·개인/팀 | **2026-08-26 ~ 10-30** | Technological Implementation · Design · Potential Impact · Quality of Idea (4축) | Personal AI Track = NemoClaw/OpenShell/Hermes + "reusable skills" + 공개 OSS repo 필수 | **마감 불일치(10/30≠9/28)**, 축 명칭 다름. 그 외 최다 근접 |
| **NemoClaw NVIDIA x ASUS Hackathon @ UCSC** (`nemoclaw.devpost.com`) | NVIDIA+ASUS, **US only·invite only** | 2026-05-16 (**종료**) | Presentation · Use of NVIDIA tools · Use of Nemotron · Use of Brev (+ Best Use of NemoClaw 보너스트랙 = "demonstrate its security controls") | 보너스트랙이 **보안통제 시연**을 별도 심사 | 미국·종료. 단 "보안통제 시연" 축은 Watchman 과 정확히 겹침 |
| **NVIDIA Nemotron Developer Days Seoul 2026 해커톤 / Build-a-Claw** (`blogs.nvidia.co.kr/blog/nvidia-build-a-claw-korea`) | NVIDIA Korea, 서울 | 2026-04-21~22 (**종료**) | 3 트랙(빌더 에이전트·유스케이스·파인튜닝/데이터셋), 노타 AI 우승 | OpenClaw/NemoClaw 현장 구현(Build-a-Claw) | 한국·종료. 개인 Skill 제출 대회 아님 |
| **NVIDIA Inception 그랜드 챌린지 2026** (`blogs.nvidia.co.kr/blog/inception-grand-challenge-semifinal-2026`) | NVIDIA APAC, **스타트업(법인)** | 한국 준결승 8/27 | 산업 실증(피지컬AI·에이전틱·AI보안 등) | — | 개인 프로젝트 아님(법인 대상) |
| **경기도 AI 글로벌 챌린지 / NGG(NVIDIA Gyeonggi Growth)** (`bizinfo.go.kr` PBLN_000000000121618) | 경기도경제과학진흥원+NVIDIA, **도내 중소기업** | 모집 공고 | NVIDIA 교육·글로벌프로그램·인셉션 등록 지원 | — | 기업 대상 육성사업, 심사 4축·Skill 제출 무관 |
| **인공지능 챔피언(AI Champion) 2026** (`tta.or.kr` 공고 PDF, ai-champion.or.kr) | 과기정통부/TTA, **연구팀** | 설명회 4/1 | 추후 홈페이지 공지(국내 AI 트랙: KT·LG·NC·SKT·업스테이지) | — | 국산모델 트랙, NVIDIA 전용 아님 |
| **NVIDIA x LangChain 생성형 AI 에이전트 컨테스트** (`nvidia.com/ko-kr/.../developer-contest-with-langchain`) | NVIDIA+LangChain | 2024-05-15~06-17 (**종료**) | 실제 적용 · 기술 통합 · 제출물 품질(3축) | LangChain/NIM | 종료. 축이 3개(계획서 4축의 원형에 가장 근접) |

## 2. 무엇이 일치하고, 무엇이 안 맞나 (정직 대조)

- **일치하는 조각들(실재 확인):**
  - "NemoClaw/OpenShell + reusable skills + 공개 OSS repo" 요구 → **Nebius** Personal AI Track 에 실제로 있다.
  - "보안통제를 시연하면 별도 심사" → **UCSC** NemoClaw 보너스트랙에 실제로 있다. Watchman 의 통제 6축이 그대로 겨냥하는 지점.
  - "실용성·기술통합·완성도" 계열 축 → NVIDIA 대회 다수에 반복 등장(LangChain 3축 등).
- **어느 공개 요강에서도 확인 안 되는 것:**
  - **9/28 마감** — 근접 후보 Nebius 는 10/30. 나머지는 이미 종료 또는 무관.
  - **"Build Skill 제출을 필수 요건으로" 명문화** — 어느 요강도 특정 "Build Skill API 호출/제출"을 강제하지 않는다. Nebius 는 "reusable skills"를 **권장·트랙 성격**으로 언급할 뿐.
  - **한국어 4축(기술활용심도/실용성·산업가치/완성도/독창성) 그대로** — 이 정확한 4축 조합은 공개 요강에 없다.

## 3. 결론과 함의 (P7 잔여의 처리)

1. **팀 계획서가 가리키는 "그 대회"의 공식 요강은 공개 웹에 인덱싱돼 있지 않다.** 정황상
   (a) 초청/비공개(invite-only) 또는 (b) 한국 로컬·기관 연계(예: NGG·AI Champion 류) 공고이거나
   (c) 계획서가 여러 공개 대회의 조각을 합성했을 가능성이 높다.
2. 따라서 **"Build Skill 제출 필수 / 심사 4축 / 9/28 마감"을 사실로 주장하지 않는다**(P7·P4 원칙 유지).
   이 세 항목은 **팀이 보유한 공식 안내 원문(2차→1차 승격)**으로만 확정된다 — 그 원문이 이 조사의 마지막 미싱 링크다.
3. **다만 준비 상태는 견고하다(정직한 긍정):** 근접 공개 대회 두 곳이 실제로 요구·가점하는 것 —
   "공개 OSS repo + 재사용 가능한 Skill"(Nebius), "보안통제 시연"(UCSC) — 을 Watchman 은 **이미 충족**한다:
   공식 SkillEvaluator Tier-1 통과(`skills/watchman-secops-triage/`, `PASS exit 0`),
   통제 6축 라이브 실측(`eval/CONTROL-MATRIX.md`), stdlib-only 공개 리포. 어떤 대회로 확정되든 손해 없는 산출물이다.

## References (1차·공식)

- Nebius x NVIDIA Global AI Hackathon 규정: https://nebiusglobalaihackathon.devpost.com/rules
- NemoClaw x ASUS Hackathon @ UCSC: https://nemoclaw.devpost.com/
- NVIDIA Build-a-Claw 한국(공식 블로그): https://blogs.nvidia.co.kr/blog/nvidia-build-a-claw-korea/
- Nemotron Dev Days Seoul 2026 리캡: https://blogs.nvidia.co.kr/blog/nvidia-build-a-claw-korea-2026-recap/
- NVIDIA Inception 그랜드 챌린지 한국 준결승: https://blogs.nvidia.co.kr/blog/inception-grand-challenge-semifinal-2026/
- NVIDIA NemoClaw 발표(뉴스룸): http://nvidianews.nvidia.com/news/nvidia-announces-nemoclaw
- NVIDIA NemoClaw 문서(Overview): https://docs.nvidia.com/nemoclaw/user-guide/openclaw/about/overview
- NVIDIA x LangChain 개발자 컨테스트(심사기준): https://www.nvidia.com/ko-kr/ai-data-science/generative-ai/developer-contest-with-langchain/
- 경기 NGG(NVIDIA Gyeonggi Growth) 공고: https://www.bizinfo.go.kr/sii/siia/selectSIIA200Detail.do?pblancId=PBLN_000000000121618
- 인공지능 챔피언 2026 공고(TTA): https://www.tta.or.kr/bbs/notice/20260328114050839_I9Pl.pdf
- DLI S-FX-43 "Securing Agents with NemoClaw and OpenShell": https://learn.nvidia.com/ (코스 카탈로그 검색)

관련: [ROADMAP.md](../ROADMAP.md) §1.1 P7 · [SUBMISSION.md](../SUBMISSION.md) 정직고지 3 · [eval/NVIDIA-USAGE.md](NVIDIA-USAGE.md) §3
