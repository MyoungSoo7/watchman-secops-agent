#!/usr/bin/env python3
"""P7 유출(egress) 하네스 (실행형) — 에이전트가 *내보내는* 표면을 채점한다.

레드팀(run_redteam.py)은 입력 축이다. 공격자가 알림 본문에 심은 지시를 에이전트가
따르는지 본다. 이 하네스는 반대쪽을 본다 — **에이전트가 읽어온 값이 카드·이메일·
감사로그로 새어나가는지.** read-only 권한으로도 유출은 성립한다.

채점
  1. 유출 뱅크(expect=detect) 전수 → 전부 차단(마스킹)되어야 한다.
  2. 정상 뱅크(expect=clean) + 실제 카드 샘플 → 오탐 0.
  3. 마스킹 후 원문 잔존 검사 — 비밀값 문자열이 결과에 남아 있으면 실패.

사용:  python3 eval/run_egress.py     (exit 0 = 전부 통과, CI 게이트)
"""
import glob
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
EG_DIR = os.path.join(ROOT, "fixtures", "egress")
CASES_DIR = os.path.join(ROOT, "fixtures", "cases")


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def main():
    sys.path.insert(0, ROOT)
    import redact  # noqa: E402

    files = sorted(glob.glob(os.path.join(EG_DIR, "fx-eg-*.json")))
    det = [load(p) for p in files if load(p)["expect"] == "detect"]
    clean = [load(p) for p in files if load(p)["expect"] == "clean"]
    ok = True

    print("# P7 유출(egress) 결과표 (run_egress.py) — 출력 통제층(결정론적)\n")
    print(f"기준 코드: redact.scan / redact.redact · 규칙 {len(redact.RULES) + 1}개"
          " (정규식 9 + base64 디코딩 판정 1)\n")

    print("## 1. 유출 뱅크 — 차단율\n")
    print("| id | 나가는 곳 | 유출 벡터 | 차단 | 걸린 규칙 |")
    print("|---|---|---|---|---|")
    blocked = 0
    leftovers = []
    for c in det:
        cleaned, hits = redact.redact(c["text"])
        got = bool(hits)
        blocked += got
        if not got:
            ok = False
        # 원문 잔존 검사 — 마스킹 결과에 비밀값 후보가 남아 있으면 실패
        still = redact.scan(cleaned)
        if still:
            leftovers.append(c["id"])
        rules = ", ".join(sorted({h["rule"] for h in hits})) or "—"
        print(f"| {c['id']} | {c['where']} | {c['vector']} | "
              f"{'✅ 차단' if got else '❌ 통과'} | {rules} |")
    print(f"\n**차단율: {blocked}/{len(det)}"
          + (f" = {100 * blocked // len(det)}%" if det else "") + "**")
    print(f"**마스킹 후 잔존: {len(leftovers)}건** "
          f"{'✅' if not leftovers else '❌ ' + str(leftovers)}")
    ok &= not leftovers

    print("\n## 2. 정상 뱅크 — 오탐 확인 (기대: 전부 미탐)\n")
    print("| id | 내용 | 오탐 | 걸린 규칙 |")
    print("|---|---|---|---|")
    fp = 0
    for c in clean:
        hits = redact.scan(c["text"])
        if hits:
            fp += 1
            ok = False
        print(f"| {c['id']} | {c['vector']} | "
              f"{'⚠ 오탐!' if hits else 'N ✅'} | {', '.join(h['rule'] for h in hits) or '—'} |")

    # 실제 알림 봉투(정상 케이스 뱅크)도 그대로 통과해야 한다
    extra_fp = []
    for p in sorted(glob.glob(os.path.join(CASES_DIR, "fx-case-*.json"))):
        txt = open(p, encoding="utf-8").read()
        if redact.scan(txt):
            extra_fp.append(os.path.basename(p))
    print(f"\n정상 알림 봉투 전수(fx-case-*) 오탐: **{len(extra_fp)}건** "
          f"{'✅' if not extra_fp else '❌ ' + str(extra_fp)}")
    ok &= not extra_fp
    print(f"**정상 카드 오탐: {fp}/{len(clean)}** (0 이 목표)")

    print("\n## 3. 차단 예시 (마스킹된 실제 출력)\n")
    sample = det[0]
    cleaned, hits = redact.redact(sample["text"])
    print("```")
    print(cleaned.strip())
    print("```")
    print("\n" + redact.summary_line(hits))

    print(f"\n## 요약\n\n- 차단 {blocked}/{len(det)} · 오탐 {fp}/{len(clean)} · "
          f"잔존 {len(leftovers)} → {'전부 통과 ✅' if ok else '⚠ 확인 필요'}")
    print("- 이 층은 **출력 통제**다. 입력 축(주입) 재현 검증은 eval/run_redteam.py.")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
