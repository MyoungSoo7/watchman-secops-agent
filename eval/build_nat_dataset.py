#!/usr/bin/env python3
"""NAT 평가 데이터셋 생성 — 블라인드 라벨(real-labels-*.json) × 감사로그의 alert_in 원본.

라벨은 run id 로 매겨져 있고 알림 원본은 감사로그에만 있다. 감사로그는 git 밖(.gitignore)이므로
데이터셋도 git 에 넣지 않고 eval/nat-data/ 에 만든다(같이 .gitignore).
unverifiable 라벨은 채점 제외 규칙(score_real_alerts.py)과 같게 뺀다.

usage: build_nat_dataset.py [audit.jsonl] [labels.json] [out.json]
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
audit = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "audit.jsonl")
labels = json.load(open(sys.argv[2] if len(sys.argv) > 2 else os.path.join(HERE, "real-labels-20260924.json")))
out = sys.argv[3] if len(sys.argv) > 3 else os.path.join(HERE, "nat-data", "real-alerts-20260924.json")
labels.pop("_meta", None)

alerts = {}
for line in open(audit, encoding="utf-8"):
    try:
        r = json.loads(line)
    except ValueError:
        continue
    if r.get("kind") == "alert_in" and r.get("run") in labels and r["run"] not in alerts:
        alerts[r["run"]] = r.get("payload")

rows, missing = [], []
for rid, v in labels.items():
    if v["gt"] not in ("benign", "incident"):
        continue
    if rid not in alerts:
        missing.append(rid)
        continue
    rows.append({"id": rid, "question": json.dumps(alerts[rid], ensure_ascii=False),
                 "answer": v["gt"], "set": v["set"], "rule": v.get("rule", "")})
os.makedirs(os.path.dirname(out), exist_ok=True)
json.dump(rows, open(out, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
print(f"{len(rows)}건 → {out} (원본 없음 {len(missing)}: {missing[:5]})")
