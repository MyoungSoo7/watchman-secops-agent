#!/usr/bin/env python3
"""서브에이전트2 관제 뷰 소비자 (S1 / T3-4) — Unity 대신 stdlib 폴링 클라이언트.

`GET /state` 를 주기 폴링해 노드·run 상태를 콘솔에 텍스트 맵으로 그린다.
Unity 3D 뷰가 붙기 전까지의 소비자 검증 도구 — 파싱 에러 0·필드 무결성을
실측하는 게 목적이다(ROLE.md T3-4: "Unity 또는 curl 폴링 스크립트로 10분 폴링,
파싱 에러 0, 필드 부족하면 이슈로 회송").

사용:
  python3 viewer/poll_state.py [--url URL] [--interval 30] [--duration 600]
기본 URL = http://127.0.0.1:8687/state (port-forward svc/watchman 8687:8687 전제)

계약(소비하는 필드, FR-15): service, now, llm_mode, model, run_states[],
totals{}, runs_by_state{}, runs[]{run_id,alertname,state,...}
"""
import argparse
import json
import sys
import time
import urllib.request

REQUIRED_TOP = ["service", "now", "run_states", "totals", "runs_by_state", "runs"]
SEVERITY_MARK = {"실패": "🔴", "복구 필요": "🟠", "부분 결과": "🟡",
                 "실행 중": "🔵", "대기": "⚪", "완료": "🟢", "취소": "⚫"}


def fetch(url, timeout=10):
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        if resp.status != 200:
            raise ValueError(f"HTTP {resp.status}")
        return json.loads(resp.read())


def validate(state):
    """계약 필드 존재 확인 → 부족 필드 목록."""
    return [f for f in REQUIRED_TOP if f not in state]


def render(state):
    lines = [f"[{state.get('now','?')}] {state.get('service','?')} "
             f"model={state.get('model','?')} llm={state.get('llm_mode','?')}"]
    rbs = state.get("runs_by_state", {})
    lines.append("  상태: " + "  ".join(
        f"{SEVERITY_MARK.get(k,'·')}{k}={v}" for k, v in rbs.items() if v))
    for r in state.get("runs", [])[:5]:
        mark = SEVERITY_MARK.get(r.get("state"), "·")
        inj = " ⚠" if r.get("injection_suspects") else ""
        lines.append(f"  {mark} {r.get('run_id')} {r.get('alertname','?')} "
                     f"[{r.get('state')}]{inj} calls={r.get('llm_calls','-')}")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:8687/state")
    ap.add_argument("--interval", type=float, default=30)
    ap.add_argument("--duration", type=float, default=600)
    ap.add_argument("--quiet", action="store_true", help="맵 렌더 생략, 요약만")
    args = ap.parse_args()

    polls, errors, missing_fields = 0, 0, set()
    t0 = time.time()
    while time.time() - t0 < args.duration:
        polls += 1
        try:
            state = fetch(args.url)
            miss = validate(state)
            if miss:
                missing_fields.update(miss)
                errors += 1
                print(f"[{polls}] 필드 부족: {miss}  → 이슈로 회송", file=sys.stderr)
            elif not args.quiet:
                print(f"--- poll {polls} ---")
                print(render(state))
        except Exception as e:
            errors += 1
            print(f"[{polls}] 파싱/연결 에러: {type(e).__name__}: {e}", file=sys.stderr)
        time.sleep(args.interval)

    elapsed = int(time.time() - t0)
    print(f"\n=== 폴링 요약 (TS1-1 / T3-4) ===")
    print(f"기간 {elapsed}s · 폴 {polls}회 · 에러 {errors}회 · "
          f"부족 필드 {sorted(missing_fields) or '없음'}")
    print("통과" if errors == 0 else "미통과(위 에러 확인)")
    sys.exit(0 if errors == 0 else 1)


if __name__ == "__main__":
    main()
