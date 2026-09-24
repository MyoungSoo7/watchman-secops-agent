#!/usr/bin/env python3
"""실알림 분류 정답률 채점 — 라벨(real-labels-*.json) × 감사로그(audit.jsonl) 의 finish.verdict.

정답 라벨은 모델 판정을 보기 전에 알림 원본 필드만 보고 매겼다(블라인드).
benign 은 '오탐' 을 정답으로, incident 는 '사고' 를 정답으로 본다. unverifiable 은 채점 제외.

usage: score_real_alerts.py <audit.jsonl> [labels.json]
"""
import collections, json, sys

audit = sys.argv[1]
labels = json.load(open(sys.argv[2] if len(sys.argv) > 2 else "eval/real-labels-20260924.json"))
labels.pop("_meta", None)

verdict = {}
for line in open(audit):
    try:
        r = json.loads(line)
    except ValueError:
        continue
    if r.get("kind") == "finish" and r.get("run") in labels:
        verdict[r["run"]] = (r.get("payload") or {}).get("verdict")

EXPECT = {"benign": "오탐", "incident": "사고"}
for s in ("falco-stratified", "incident-window"):
    rows = [(k, v) for k, v in labels.items() if v["set"] == s and v["gt"] in EXPECT]
    skipped = sum(1 for v in labels.values() if v["set"] == s and v["gt"] not in EXPECT)
    dist = collections.Counter(verdict.get(k) for k, _ in rows)
    ok = sum(1 for k, v in rows if verdict.get(k) == EXPECT[v["gt"]])
    print(f"[{s}] 채점 {len(rows)}건 (제외 {skipped}) 정답 {ok}/{len(rows)} 판정분포 {dict(dist)}")
    if s == "falco-stratified":
        # 반대 방향 치명 오류: 정상 알림을 '사고' 로 부른 건수
        print(f"  benign→사고 {dist.get('사고', 0)}/{len(rows)}")
        by = collections.defaultdict(collections.Counter)
        for k, v in rows:
            by[v["rule"]][verdict.get(k)] += 1
        for rule, c in sorted(by.items(), key=lambda x: -sum(x[1].values())):
            print(f"  {rule}: 오탐 {c.get('오탐', 0)}/{sum(c.values())}  {dict(c)}")
