#!/usr/bin/env python3
"""P9 인바리언트 하네스 (실행형) — 알람이 없을 때의 자세를 채점한다.

알람 구동 에이전트는 *평시의 구조적 결함*을 영원히 못 본다. 백업 자격증명이
클러스터 안에 있다는 사실은 경보가 아니라 설정이기 때문이다. 이 하네스는
그 질문들의 판정이 회귀 없이 유지되는지 본다.

두 가지를 특히 지킨다.
  * **'없다'와 '모른다'를 가른다** — 조회 권한이 없으면 FAIL 이 아니라 UNKNOWN.
  * **비밀값이 출력에 안 섞인다** — 전 케이스의 카드·판정문을 redact 로 재검사한다.

사용:  python3 eval/run_invariants.py     (exit 0 = 전부 통과, CI 게이트)
"""
import glob
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
INV_DIR = os.path.join(ROOT, "fixtures", "invariants")
IDS = ["I1", "I2", "I3", "I4", "I5"]


def make_probe(spec):
    def probe(key):
        if "__error__" in spec:
            raise RuntimeError(spec["__error__"])
        if key not in spec:
            raise RuntimeError(f"{key} 미제공")
        return spec[key]
    return probe


def main():
    sys.path.insert(0, ROOT)
    import invariants  # noqa: E402
    import redact  # noqa: E402

    print("# P9 인바리언트 결과표 (run_invariants.py) — 알람 없는 정기 점검\n")
    print("| id | 상황 | 기대 판정 | 실제 | " + " | ".join(IDS) + " | 일치 |")
    print("|---|---|---|---|" + "---|" * (len(IDS) + 1))
    ok = True
    cards = {}
    for p in sorted(glob.glob(os.path.join(INV_DIR, "fx-inv-*.json"))):
        c = json.load(open(p, encoding="utf-8"))
        res = invariants.run(make_probe(c["probe"]))
        cards[c["id"]] = res
        got = {r["id"]: r["status"] for r in res["results"]}
        exp = c["expect"]
        hit = res["verdict"] == exp["verdict"] and all(got[i] == exp[i] for i in IDS)
        ok &= hit
        marks = " | ".join(f"{got[i]}{'' if got[i] == exp[i] else '≠' + exp[i]}" for i in IDS)
        print(f"| {c['id']} | {c['vector']} | {exp['verdict']} | {res['verdict']} | "
              f"{marks} | {'✅' if hit else '❌'} |")

    print("\n## 카드 출력 — 오늘 실측 자세\n")
    print("```")
    for line in invariants.card_lines(cards["fx-inv-01-measured-tonight"]):
        print(line)
    print("```")

    print("\n## 유출 재검사 — 판정 출력에 비밀값이 섞이지 않는가\n")
    leaked = 0
    for cid, res in cards.items():
        blob = "\n".join(invariants.card_lines(res)) + json.dumps(res, ensure_ascii=False)
        hits = redact.scan(blob)
        if hits:
            leaked += 1
            print(f"- ❌ {cid}: {[h['rule'] for h in hits]}")
    ok &= leaked == 0
    print(f"전 {len(cards)}케이스 카드·판정 JSON 스캔 → 검출 {leaked}건 {'✅' if not leaked else '❌'}")
    print("(I3 은 키를 비교만 하고 다이제스트도 카드에 싣지 않는다)")

    print("\n## '모른다'를 'FAIL' 로 읽지 않는가\n")
    nq = cards["fx-inv-04-not-queryable"]
    i2 = [r for r in nq["results"] if r["id"] == "I2"][0]
    good = i2["status"] == "UNKNOWN"
    ok &= good
    print(f"잠금 조회 권한 없음 → I2 **{i2['status']}** (FAIL 아님) {'✅' if good else '❌'}")
    print(f"\n## 요약\n\n- 전체 {'통과 ✅' if ok else '⚠ 확인 필요'}")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
