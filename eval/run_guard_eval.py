#!/usr/bin/env python3
"""NVIDIA 안전 가드(2차 주입 판정) 실측 — 프로덕션과 같은 경로(watchman.guard_check)로 판정한다.

키가 있는 곳(watchman 파드)에서 돌린다:  python3 eval/run_guard_eval.py
두 뱅크를 잰다:
  1. 기존 뱅크 — fixtures/redteam(공격 12) + fixtures/cases·정상 픽스처(정상 13). 표면은 알림 주석 값.
  2. 우회 뱅크 — eval/guard_heldout.json: 정규식이 못 잡게 우리가 직접 쓴 공격 10 + 보안
     사건을 *보고*하는 정상 알림 10(하드네거티브). 직접 쓴 문장이라 일반화 성능 근거가 아니다.
정규식 판정(detect_injection)을 나란히 적어 두 층이 서로 무엇을 메우는지 보인다.
"""
import glob
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
import watchman  # noqa: E402

watchman.audit = lambda *a, **k: None  # 측정은 감사로그를 더럽히지 않는다


def bank_existing():
    rows = []
    paths = (sorted(glob.glob(os.path.join(ROOT, "fixtures", "redteam", "*.json")))
             + sorted(glob.glob(os.path.join(ROOT, "fixtures", "cases", "fx-*.json")))
             + [os.path.join(ROOT, "fixtures", n) for n in
                ("kube-job-failed.json", "velero-partial.json", "sa-reach.json")])
    for p in paths:
        env = json.load(open(p, encoding="utf-8"))
        rows.append({"name": os.path.basename(p)[:-5], "attack": "redteam" in p,
                     "text": watchman._alert_free_text(env)})
    return rows


def run(title, rows):
    print(f"## {title}\n\n| 샘플 | 공격 | 정규식 | 가드 |\n|---|---|---|---|")
    c = {"tp": 0, "fp": 0, "rtp": 0, "rfp": 0, "err": 0, "atk": 0, "ben": 0}
    for r in rows:
        g = watchman.guard_check("guard-eval", r["text"])
        rx = bool(watchman.detect_injection(r["text"]))
        c["atk" if r["attack"] else "ben"] += 1
        if g is None:
            c["err"] += 1
        elif g:
            c["tp" if r["attack"] else "fp"] += 1
        if rx:
            c["rtp" if r["attack"] else "rfp"] += 1
        gs = "오류" if g is None else ("unsafe" if g else "safe")
        print(f"| {r['name']} | {'Y' if r['attack'] else '-'} | {'⚠' if rx else '-'} | {gs} |")
    print(f"\n가드: 감지 {c['tp']}/{c['atk']} · 오탐 {c['fp']}/{c['ben']} · 오류 {c['err']}  "
          f"| 정규식: 감지 {c['rtp']}/{c['atk']} · 오탐 {c['rfp']}/{c['ben']}\n")
    return c


if __name__ == "__main__":
    if not (watchman.GUARD_ENABLED and watchman.NVIDIA_API_KEY and watchman.LLM_MODE == "nim"):
        sys.exit("가드 비활성(키·LLM_MODE=nim·GUARD_ENABLED 필요) — 파드 안에서 돌릴 것")
    print(f"# NVIDIA 안전 가드 실측 — 모델 {watchman.GUARD_MODEL}\n")
    run("1. 기존 뱅크 (레드팀 12 + 정상 13)", bank_existing())
    held = json.load(open(os.path.join(HERE, "guard_heldout.json"), encoding="utf-8"))
    run("2. 우회 뱅크 (직접 작성 공격 10 + 하드네거티브 10)", held)
