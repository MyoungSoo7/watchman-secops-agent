# viewer/ — 서브에이전트2 관제 뷰 (S1)

`GET /state` 를 소비하는 관제 뷰 영역. Unity 3D/VR 뷰가 최종 목표지만, 그 전까지의
**소비자 검증 도구**로 stdlib 폴링 클라이언트를 둔다. 경계 계약(ROLE.md §4-2): 뷰는
클러스터·ES 를 직접 찌르지 않고 **오직 `/state` 만** 폴링한다.

## poll_state.py — 폴링 클라이언트 (S1 / T3-4)

```bash
# port-forward 전제
KUBECONFIG=~/.kube/config-tunnel kubectl port-forward -n agent-system svc/watchman 8687:8687 &
python3 viewer/poll_state.py                       # 30초 간격 10분(TS1-1 기본)
python3 viewer/poll_state.py --interval 5 --duration 60 --quiet
```

콘솔에 노드·run 상태를 심각도 마크(🔴실패 🟡부분 🔵실행중 🟢완료)로 그리고,
주입 의심 run 엔 ⚠ 를 붙인다. 매 폴 계약 필드(FR-15) 존재를 검사해 **부족하면
이슈로 회송**하라고 stderr 로 알린다.

### 소비하는 계약 필드
`service · now · llm_mode · model · run_states[] · totals{} · runs_by_state{} · runs[]{run_id, alertname, state, llm_calls, injection_suspects, ...}`

## 실측 (2026-09-22, T3-4)

- 12폴(5초 간격 62초) 연속: **파싱 에러 0 · 부족 필드 0 · 크래시 없음** → 통과
- 쓰기 메서드(POST/DELETE) → 405 확인 (read-only 계약)
- 렌더 샘플: 완료 2·실패 2 run, 주입 run 2건에 ⚠ 정상 표기

Unity 뷰는 이 계약을 그대로 폴링하면 된다 — 필드가 부족하면 poll_state.py 가 먼저 잡아
메인세션에게 `/state` 필드 추가 이슈로 올린다(§4-2 경계 계약).
