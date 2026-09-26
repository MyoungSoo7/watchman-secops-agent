#!/usr/bin/env python3
"""`nat eval` 출력 → KPI 표(markdown).

입력은 nat eval output_dir 의 workflow_output.json 하나다. 각 항목의 generated_answer 가
watchman_triage 가 돌려준 JSON(verdict·seconds·토큰)이고, answer 가 블라인드 라벨이다.
토큰은 NIM 응답 usage 필드 합, 시간은 알림 1건 조사 벽시계다 — 추정치는 없다.

사용: python3 eval/nat_kpi.py nat_watchman/.tmp/eval-real [> report.md]
"""
import json
import os
import statistics
import sys


def pct(n, d):
    return f"{n}/{d} ({100 * n / d:.0f}%)" if d else "0/0"


def q(xs, p):
    xs = sorted(xs)
    if not xs:
        return 0
    k = (len(xs) - 1) * p
    lo, hi = int(k), min(int(k) + 1, len(xs) - 1)
    return xs[lo] + (xs[hi] - xs[lo]) * (k - lo)


def main():
    out_dir = sys.argv[1] if len(sys.argv) > 1 else "nat_watchman/.tmp/eval-real"
    rows = json.load(open(os.path.join(out_dir, "workflow_output.json"), encoding="utf-8"))
    recs = []
    for r in rows:
        try:
            g = json.loads(r.get("generated_answer") or "{}")
        except ValueError:
            g = {}
        recs.append({"id": r["id"], "gt": r["answer"], "set": r.get("set"), **g})

    benign = [r for r in recs if r["gt"] == "benign"]
    incident = [r for r in recs if r["gt"] == "incident"]
    ok = [r for r in recs if not r.get("partial") and r.get("verdict")]

    def cnt(rs, v):
        return sum(1 for r in rs if r.get("verdict") == v)

    secs = [r["seconds"] for r in recs if r.get("seconds") is not None]
    ptok = [r.get("prompt_tokens", 0) for r in recs]
    ctok = [r.get("completion_tokens", 0) for r in recs]
    calls = [r.get("llm_calls", 0) for r in recs]
    tools = [r.get("tool_calls", 0) for r in recs]
    models = {}
    for r in recs:
        for m in r.get("models") or []:
            models[m] = models.get(m, 0) + 1

    print(f"# Watchman NAT eval KPI — {os.path.basename(out_dir.rstrip('/'))}\n")
    print(f"알림 {len(recs)}건 (benign {len(benign)} · incident {len(incident)}), "
          f"완주 {len(ok)} · 부분결과 {sum(1 for r in recs if r.get('partial'))} · "
          f"판정없음 {sum(1 for r in recs if not r.get('verdict'))}\n")
    print("## 판정\n")
    print("| 지표 | 값 | 뜻 |\n|---|---|---|")
    print(f"| 정상 알림 자동 종결(오탐) | {pct(cnt(benign, '오탐'), len(benign))} | 사람이 안 봐도 되는 비율 |")
    print(f"| 정상 알림 → 의심 | {pct(cnt(benign, '의심'), len(benign))} | 사람에게 넘김(안전 방향) |")
    print(f"| **정상 알림 → 사고 격상** | {pct(cnt(benign, '사고'), len(benign))} | 치명적 과잉(0 이 목표) |")
    print(f"| 사고 알림 → 사고 | {pct(cnt(incident, '사고'), len(incident))} | 정확 탐지 |")
    print(f"| 사고 알림 → 의심 | {pct(cnt(incident, '의심'), len(incident))} | 사람에게 넘김(놓치진 않음) |")
    print(f"| **사고 알림 → 오탐 종결** | {pct(cnt(incident, '오탐'), len(incident))} | 치명적 누락(0 이 목표) |")
    print()
    print("## 비용·속도 (알림 1건당)\n")
    print("| 지표 | p50 | p95 | 평균 |\n|---|---|---|---|")
    for name, xs in (("조사 시간(초)", secs), ("LLM 호출", calls), ("도구 호출", tools),
                     ("prompt 토큰", ptok), ("completion 토큰", ctok)):
        if xs:
            print(f"| {name} | {q(xs, .5):.0f} | {q(xs, .95):.0f} | {statistics.mean(xs):.0f} |")
    print(f"\n토큰 합계: prompt {sum(ptok):,} · completion {sum(ctok):,}")
    print("\n응답을 낸 모델(알림 수): " + ", ".join(f"`{m}` {n}" for m, n in sorted(models.items())))
    snaps = [r["snapshot"] for r in recs if isinstance(r.get("snapshot"), dict)]
    if snaps:
        tot = {k: sum(x.get(k, 0) for x in snaps) for k in ("hit", "digest", "miss")}
        n = sum(tot.values())
        print("\n## 알림 시점 증거 재생\n")
        print(f"도구 호출 {n}건 중 원문 {tot['hit']} · 요약(앞 1,500자) {tot['digest']} · "
              f"기록 없음(miss) {tot['miss']}. 기록 없는 run {sum(1 for x in snaps if x.get('missing_run'))}건.")
        print("miss 는 현재 클러스터로 대체하지 않았다 — 운영과 다른 조회를 하면 결과를 못 받는다.")
    print("\n## 항목별\n")
    print("| id | 라벨 | 판정 | 신뢰도 | 초 | 토큰(p/c) |\n|---|---|---|---|---|---|")
    for r in recs:
        print(f"| {r['id']} | {r['gt']} | {r.get('verdict')}{' (partial)' if r.get('partial') else ''} "
              f"| {r.get('confidence')} | {r.get('seconds')} | {r.get('prompt_tokens')}/{r.get('completion_tokens')} |")


if __name__ == "__main__":
    main()
