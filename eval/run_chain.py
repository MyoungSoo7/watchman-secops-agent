#!/usr/bin/env python3
"""P6 킬체인 하네스 (실행형) — 알림을 *순서대로* 넣으며 승격 시점을 채점한다.

기존 eval/run_eval.py 는 알림 1건 = 1 run 의 분류를 본다. 이 하네스는 그걸로는
보이지 않는 것을 본다: **단발로는 중간 심각도인 알림들이 이어질 때 언제 최고 심각도로
올라가는가.** 승격은 chain.assess() 가 결정론적으로 판정하므로 클러스터·LLM 없이
어디서나 같은 표가 나온다.

채점 항목
  1. 진행 — 4단계를 순서대로 투입하며 누적 판정. 2단계에서 승격돼야 한다.
  2. 오탐 A — 정상 케이스 뱅크(fx-case-*) 전수를 넣어도 승격 0.
  3. 오탐 B — 같은 단계만 반복(단계 1개)하면 승격 없음.
  4. 오탐 C — 서로 다른 단계라도 상관 창(180분) 밖이면 승격 없음.
  5. 오탐 D — 레드팀 주입 페이로드(공격자가 본문에 심은 어휘)로는 승격 없음.
  6. 오탐 E — 어휘로만 잡힌 단계들(공격자가 쓴 cmdline)로는 승격 없이 '의심'.

사용:  python3 eval/run_chain.py     (exit 0 = 전부 통과, CI 게이트)
watchman.py 는 건드리지 않는다.
"""
import glob
import json
import os
import sys
from datetime import datetime, timedelta, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CHAIN_DIR = os.path.join(ROOT, "fixtures", "chain")
CASES_DIR = os.path.join(ROOT, "fixtures", "cases")
RT_DIR = os.path.join(ROOT, "fixtures", "redteam")

ORDER = [
    "fx-chain-01-secret-access",
    "fx-chain-02-backup-destroy",
    "fx-chain-03-mass-encrypt",
    "fx-chain-04-node-login",
]


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)["alerts"][0]


def ts_of(alert):
    return datetime.fromisoformat(str(alert["startsAt"]).replace("Z", "+00:00"))


def main():
    sys.path.insert(0, ROOT)
    import chain  # noqa: E402

    ok = True
    print("# P6 킬체인 결과표 (run_chain.py) — 상관관계층(결정론적)\n")
    print(f"체인: **{chain.CHAIN['title']}** · 상관 창 {chain.CHAIN['window_minutes']}분 · "
          f"승격 기준 서로 다른 단계 {chain.CHAIN['escalate_at']}개\n")

    # 1) 진행 — 순서대로 투입
    print("## 1. 진행 — 알림을 순서대로 투입\n")
    print("| # | 투입 알림 | 단일 severity | 누적 단계 | 체인 판정 | 승격 |")
    print("|---|---|---|---|---|---|")
    chain.reset()
    info = None
    first_escalate_at = None
    for i, fid in enumerate(ORDER, 1):
        alert = load(os.path.join(CHAIN_DIR, fid + ".json"))
        sev = (alert.get("labels") or {}).get("severity", "?")
        info = chain.observe(alert)
        stages = "→".join(s["stage"].split("-")[0] for s in info["stages"])
        verdict = info["severity"]
        esc = "🔴 예" if info["escalated"] else "아니오"
        if info["escalated"] and first_escalate_at is None:
            first_escalate_at = i
        print(f"| {i} | {fid} | {sev} | {info['stage_count']} ({stages}) | {verdict} | {esc} |")
    exp = chain.CHAIN["escalate_at"]
    hit = first_escalate_at == exp
    ok &= hit
    print(f"\n**최초 승격 시점: {first_escalate_at}번째 알림** (기대 {exp}) "
          f"{'✅' if hit else '❌'}")
    full = info["stage_count"] == len(chain.STAGES)
    ok &= full
    print(f"**최종 단계 커버리지: {info['stage_count']}/{len(chain.STAGES)}** "
          f"{'✅' if full else '❌'}")
    print("\n카드에 붙는 줄:\n")
    print("```")
    for line in chain.card_lines(info):
        print(line)
    print("```")
    print(f"\n복구가능성 조사 필요 플래그: **{info['needs_recovery_check']}** "
          f"(백업 파괴 단계 포함 시 True) {'✅' if info['needs_recovery_check'] else '❌'}")
    ok &= bool(info["needs_recovery_check"])

    # 2) 오탐 A — 정상 케이스 뱅크
    print("\n## 2. 오탐 A — 정상 케이스 뱅크 전수\n")
    chain.reset()
    hits = []
    normals = sorted(glob.glob(os.path.join(CASES_DIR, "fx-case-*.json")))
    for p in normals:
        alert = load(p)
        st = chain.stage_of(alert)
        r = chain.observe(alert)
        if st:
            hits.append((os.path.basename(p), st))
        if r and r["escalated"]:
            hits.append((os.path.basename(p), "ESCALATED"))
    print(f"정상 {len(normals)}건 투입 → 단계 매칭 **{len(hits)}건** "
          f"{'✅' if not hits else '❌ ' + str(hits)}")
    ok &= not hits

    # 3) 오탐 B — 같은 단계만 반복
    print("\n## 3. 오탐 B — 같은 단계만 반복 (단계 1개)\n")
    chain.reset()
    a = load(os.path.join(CHAIN_DIR, "fx-chain-01-secret-access.json"))
    r = None
    for k in range(5):
        dup = json.loads(json.dumps(a))
        dup["fingerprint"] = f"{a['fingerprint']}-dup{k}"
        dup["startsAt"] = (ts_of(a) + timedelta(minutes=5 * k)).isoformat().replace("+00:00", "Z")
        r = chain.observe(dup)
    print(f"같은 단계 5건 → 누적 단계 {r['stage_count']} · 승격 {r['escalated']} "
          f"{'✅' if not r['escalated'] else '❌'}")
    ok &= not r["escalated"]

    # 4) 오탐 C — 상관 창 밖
    print("\n## 4. 오탐 C — 서로 다른 단계지만 상관 창 밖\n")
    chain.reset()
    a1 = load(os.path.join(CHAIN_DIR, "fx-chain-01-secret-access.json"))
    a2 = load(os.path.join(CHAIN_DIR, "fx-chain-03-mass-encrypt.json"))
    far = json.loads(json.dumps(a2))
    far["startsAt"] = (ts_of(a1) + timedelta(minutes=chain.CHAIN["window_minutes"] + 30)) \
        .isoformat().replace("+00:00", "Z")
    chain.observe(a1)
    r = chain.observe(far)
    gap = chain.CHAIN["window_minutes"] + 30
    print(f"{gap}분 간격 2단계 → 누적 단계 {r['stage_count']} · 승격 {r['escalated']} "
          f"{'✅' if not r['escalated'] else '❌'}")
    ok &= not r["escalated"]

    # 5) 오탐 D — 레드팀 주입 페이로드
    print("\n## 5. 오탐 D — 레드팀 주입 페이로드로 승격 유도\n")
    chain.reset()
    rt = sorted(glob.glob(os.path.join(RT_DIR, "fx-rt-*.json")))
    rt_hits = []
    for p in rt:
        alert = load(p)
        r = chain.observe(alert)
        if r and r["escalated"]:
            rt_hits.append(os.path.basename(p))
    print(f"주입 {len(rt)}건 투입 → 승격 **{len(rt_hits)}건** "
          f"{'✅' if not rt_hits else '❌ ' + str(rt_hits)}")
    ok &= not rt_hits
    print("\n> 주의: 승격은 *관측된 알림의 조합*으로만 결정된다. 알림 본문에 공격자가 써넣은 "
          "문장은 단계 판정의 근거가 될 수 있으므로(어휘 보조 판정), 주입 뱅크에서 승격이 "
          "일어나지 않는지는 회귀로 계속 본다.")

    # 6) 어휘만으로 만든 체인 — Falco 출력의 cmdline 은 컨테이너 안 공격자가 쓰는 텍스트다
    print("\n## 6. 오탐 E — 공격자가 쓴 명령줄만으로 2단계 체인 조립\n")
    chain.reset()
    base = datetime(2026, 9, 22, 18, 0, tzinfo=timezone.utc)
    forged = [f"sh -c 'echo delete backup'", "sh -c 'echo ransom'", "sh -c 'echo rdp 3389'"]
    r = None
    for i, cmd in enumerate(forged):
        r = chain.observe({"fingerprint": f"fx-forged-{i}",
                           "labels": {"rule": "Terminal shell in container", "source": "falco"},
                           "annotations": {"description": f"cmdline={cmd}"},
                           "startsAt": (base + timedelta(minutes=i)).isoformat()})
    e_ok = bool(r) and r["stage_count"] >= 2 and not r["escalated"] and r["suspected"]
    print(f"위조 {len(forged)}건 → 어휘 단계 {r['stage_count'] if r else 0}개 · 승격 {r and r['escalated']} · "
          f"의심 {r and r['suspected']} {'✅' if e_ok else '❌'}")
    print("\n> 룰 이름으로 잡힌 단계가 하나도 없으면 critical 로 올리지 않고 의심(warning)으로 둔다. "
          "룰 이름은 탐지기가 붙이지만 본문은 공격자가 쓸 수 있다.")
    ok &= e_ok

    print(f"\n## 요약\n\n- 전체 {'통과 ✅' if ok else '⚠ 확인 필요'}")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
