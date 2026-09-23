#!/usr/bin/env python3
"""P8 복구가능성 하네스 (실행형) — "복구할 수 있는가"의 판정을 채점한다.

recovery.assess 는 의존성 주입(fetch)이라 클러스터 없이 픽스처로 그대로 돈다.
채점 기준 시각은 픽스처에 박아 결정론을 지킨다.

특히 5번(조회 실패)은 이 하네스의 존재 이유다 — **에러를 빈 목록으로 읽으면
'백업 0건'이 아니라 '정상'처럼 보인다.** 그 오독을 회귀로 막는다.

사용:  python3 eval/run_recovery.py     (exit 0 = 전부 통과, CI 게이트)
"""
import glob
import json
import os
import sys
from datetime import datetime

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
RC_DIR = os.path.join(ROOT, "fixtures", "recovery")


def make_fetch(data):
    def fetch(kind):
        resp = data.get(kind)
        if resp is None:
            raise RuntimeError(f"{kind} 미제공")
        if isinstance(resp, dict) and "__error__" in resp:
            raise RuntimeError(resp["__error__"])
        return resp
    return fetch


def main():
    sys.path.insert(0, ROOT)
    import recovery  # noqa: E402

    print("# P8 복구가능성 결과표 (run_recovery.py) — 조사층(결정론적, read-only)\n")
    print("| id | 상황 | 기대 판정 | 실제 판정 | R1 | R2 | R3 | 일치 |")
    print("|---|---|---|---|---|---|---|---|")
    ok = True
    results = {}
    for p in sorted(glob.glob(os.path.join(RC_DIR, "fx-rc-*.json"))):
        c = json.load(open(p, encoding="utf-8"))
        now = datetime.fromisoformat(c["now"].replace("Z", "+00:00"))
        res = recovery.assess(make_fetch(c["data"]), now=now)
        results[c["id"]] = res
        st = {f["id"]: f["status"] for f in res["findings"]}
        hit = res["verdict"] == c["expect"]
        ok &= hit
        print(f"| {c['id']} | {c['vector']} | {c['expect']} | {res['verdict']} | "
              f"{st['R1']} | {st['R2']} | {st['R3']} | {'✅' if hit else '❌'} |")

    print("\n## 카드 출력 예시 — 정상\n")
    print("```")
    for line in recovery.card_lines(results["fx-rc-01-healthy"]):
        print(line)
    print("```")
    print("\n## 카드 출력 예시 — 백업 파괴 직후 (킬체인 S2)\n")
    print("```")
    for line in recovery.card_lines(results["fx-rc-02-backups-deleted"]):
        print(line)
    print("```")
    print("\n## 오독 방지 — 조회 실패를 '정상'으로 읽지 않는가\n")
    unk = results["fx-rc-05-unknown"]
    good = unk["verdict"] == "미확인" and unk["notes"]
    ok &= bool(good)
    print(f"403 전수 실패 → 판정 **{unk['verdict']}** · 사유 {len(unk['notes'])}건 기록 "
          f"{'✅' if good else '❌'}")
    print(f"\n## 요약\n\n- 전체 {'통과 ✅' if ok else '⚠ 확인 필요'}")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
