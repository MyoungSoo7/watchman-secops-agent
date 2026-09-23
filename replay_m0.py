"""M0 완료 기준 재생 — Alertmanager 에서 지금 발화 중인 실알림 3건을 골라
실 NIM + 실 ES/K8s(read-only) 로 에이전트를 완주시킨다.

실행: python3 replay_m0.py   (사전조건: ES 19200·AM 19093 포트포워드, config-tunnel)
"""

import json
import time
import urllib.request

import watchman as w

AM = "http://127.0.0.1:19093/api/v2/alerts?active=true&silenced=false"

WANTED = [  # (alertname, namespace) — 실제 문제가 있는 순
    ("PodRestartingSlowBleed", "ai-ocr"),
    ("PodRestartingSlowBleed", "elastic-system"),
    ("CPUThrottlingHigh", "lemuel-monitor"),
]


def fetch_alerts():
    with urllib.request.urlopen(AM, timeout=10) as r:
        return json.load(r)


def to_webhook(a):
    return {"alerts": [{
        "status": "firing",
        "labels": a["labels"],
        "annotations": a["annotations"],
        "startsAt": a.get("startsAt", ""),
    }]}


def main():
    alerts = fetch_alerts()
    picked = []
    for name, ns in WANTED:
        for a in alerts:
            l = a["labels"]
            if l.get("alertname") == name and l.get("namespace") == ns:
                picked.append(a)
                break
    print(f"selected {len(picked)}/3 alerts")

    results = []
    for i, a in enumerate(picked):
        rid = f"m0-{i+1}-{a['labels']['alertname']}"
        print(f"\n=== run {rid} ===", flush=True)
        for attempt in range(4):  # NIM 503 폭주 대비 상위 재시도
            try:
                res = w.run_agent(to_webhook(a), run_id=rid)
                results.append((rid, res))
                break
            except Exception as e:
                print(f"  attempt {attempt+1} failed: {e}", flush=True)
                if attempt == 3:
                    results.append((rid, {"error": str(e)}))
                else:
                    time.sleep(45)

    print("\n\n========== SUMMARY ==========")
    for rid, res in results:
        print(f"\n--- {rid} ---")
        print(json.dumps(res, ensure_ascii=False, indent=1)[:1500])


if __name__ == "__main__":
    main()
