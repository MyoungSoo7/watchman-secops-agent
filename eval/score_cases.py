#!/usr/bin/env python3
"""P4 평가 하네스 (FR-18) — 감사로그의 완주 run 을 정답 라벨과 대조해 채점.

재현 가능·투명한 채점기. 두 지표(ROLE.md T4-2):
  분류 정답률 = 정답 라벨 키워드와 일치한 run ÷ 라벨 있는 전체 run
  근거 지지율 = finish.evidence 항목 수(원문 인용 흔적) — 리소스명 조작 여부는
                별도 플래그. 자동 채점이 애매하면 사람 확인 대상으로 남긴다.

사용:
  python3 eval/score_cases.py <audit.jsonl> [labels.json]
labels.json 형식: { "<run_id 또는 fingerprint>": {"cause": "...", "keywords": ["...","..."]} }
없으면 eval/cases/cases-labels.json 의 fingerprint 라벨을 쓴다(케이스 뱅크 재생 채점용).
"""
import json
import sys
import os

HERE = os.path.dirname(os.path.abspath(__file__))


def load_runs(audit_path):
    """audit.jsonl → {run_id: {alertname, fingerprint, classification, evidence, state}}"""
    runs = {}
    for line in open(audit_path, encoding="utf-8"):
        line = line.strip()
        if not line:
            continue
        e = json.loads(line)
        rid = e.get("run") or e.get("run_id")
        if not rid or rid == "server":
            continue
        r = runs.setdefault(rid, {"run_id": rid, "evidence": [], "classification": None,
                                  "fingerprint": None, "alertname": None, "state": None,
                                  "human_label": None})
        kind = e.get("kind")
        p = e.get("payload", {})
        if kind == "alert_in":
            a = (p.get("alerts") or [{}])[0]
            r["fingerprint"] = a.get("fingerprint")
            r["alertname"] = a.get("labels", {}).get("alertname")
        elif kind == "finish":
            r["classification"] = p.get("classification")
            r["evidence"] = p.get("evidence", []) or []
            r["state"] = "완료"
        elif kind in ("card_suppressed", "card_sent"):
            r["state"] = r["state"] or "완료"
        elif kind == "error":
            r["state"] = "실패"
        elif kind == "human_label":
            r["human_label"] = p.get("label")   # 여러 번 눌렀으면 마지막 것
    return runs


def human_label_rate(runs):
    """카드 👍/👎 로 사람이 단 라벨의 정답률. fx- 픽스처(테스트 알림)는 뺀다.
    반환: (맞음, 라벨 단 run 수, [(run_id, alertname, label)])"""
    rows = [(rid, r["alertname"], r["human_label"]) for rid, r in sorted(runs.items())
            if r["human_label"] in ("correct", "wrong")
            and not str(r["fingerprint"] or "").startswith("fx-")]
    return sum(1 for _, _, lb in rows if lb == "correct"), len(rows), rows


def match(classification, keywords):
    """정답 키워드가 분류 문장에 하나라도 포함되면 일치로 본다(보수적 OR)."""
    if not classification or not keywords:
        return None
    text = classification.lower()
    hit = [k for k in keywords if k.lower() in text]
    return bool(hit), hit


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    audit = sys.argv[1]
    labels_path = sys.argv[2] if len(sys.argv) > 2 else os.path.join(HERE, "cases", "cases-labels.json")
    labels_raw = json.load(open(labels_path, encoding="utf-8")) if os.path.exists(labels_path) else {}

    # cases-labels.json 은 {fp: "문장"} 형식 — keywords 자동 추출(명사 몇 개)
    def normalize(v):
        if isinstance(v, dict):
            return v.get("cause", ""), v.get("keywords", [])
        return v, [w for w in v.replace(",", " ").split() if len(w) >= 2][:6]

    runs = load_runs(audit)
    scored, matched, pending = 0, 0, []
    print(f"# P4 채점 — {os.path.basename(audit)}  ({len(runs)} run)\n")
    print("| run_id | alert | 상태 | 모델 분류(요약) | 정답 라벨 | 일치 | evidence |")
    print("|---|---|---|---|---|---|---|")
    for rid, r in sorted(runs.items()):
        key = r["fingerprint"] if r["fingerprint"] in labels_raw else rid
        cls = (r["classification"] or "")[:40]
        ev = len(r["evidence"])
        cause_kws = normalize(labels_raw[key]) if key in labels_raw else (None, [])
        if key in labels_raw and cause_kws[1]:  # 키워드 없는 라벨은 아직 미확정 → pending
            cause, kws = cause_kws
            m = match(r["classification"], kws)
            scored += 1
            if m and m[0]:
                matched += 1
                verdict = "✅"
            elif m is None:
                verdict = "—(미완주)"
            else:
                verdict = "❌"
            print(f"| {rid} | {r['alertname']} | {r['state']} | {cls} | {cause[:30]} | {verdict} | {ev} |")
        else:
            pending.append(rid)
            print(f"| {rid} | {r['alertname']} | {r['state']} | {cls} | (라벨 필요) | ⏳ | {ev} |")
    print()
    rate = f"{matched}/{scored}" + (f" = {100*matched//scored}%" if scored else "")
    print(f"**분류 정답률(자동, 키워드 OR): {rate}**  ·  라벨 필요(서브에이전트1): {len(pending)}건")
    print("\n> 자동 채점은 키워드 포함 여부다. 최종 정답률은 서브에이전트1의 사람 라벨링(T4-3 교차 확인) 후 확정한다.")
    print("> 미달 수치를 성과로 표시하지 않는다(ROLE.md T4-2).")

    ok, n, rows = human_label_rate(runs)
    print("\n## 실알림 정답률 — 카드 👍/👎 사람 라벨\n")
    if not n:
        print("라벨 0건 — 아직 측정값 없음(수치를 만들지 않는다).")
        return
    print("| run_id | alert | 라벨 |")
    print("|---|---|---|")
    for rid, an, lb in rows:
        print(f"| {rid} | {an} | {'👍 맞음' if lb == 'correct' else '👎 틀림'} |")
    print(f"\n**실알림 정답률(사람 라벨): {ok}/{n} = {100 * ok // n}%**")
    print("> 표본은 사람이 버튼을 누른 카드뿐이다 — 누르지 않은 카드는 분모에 없다(선택 편향 가능).")


if __name__ == "__main__":
    main()
