#!/usr/bin/env python3
"""케이스 뱅크 실재생 — fixtures/cases/ 10건을 실 클러스터·실 NIM 으로 완주시키고 결과를 남긴다.

run_eval.py(mock, 결정적)와 달리 도구는 전부 실제로 나간다(읽기 전용 계정):
  - K8s API: SA watchman-readonly 토큰, SSH 터널
  - ES: 전용 사용자 watchman(로그 인덱스 read 만), port-forward
  - LLM: 운영과 같은 NIM 설정(주 모델 + 폴백 체인, 가드 켬)
텔레그램·메일은 끈다(환경에서 토큰 제거) — 카드는 나가지 않는다.

채점은 이 스크립트가 하지 않는다. 라벨(cases-labels.json)이 자유 서술이라 키워드 자동 채점이
오판하기 쉽다. 결과 JSON 에 분류·판정·근거를 그대로 남기고, 사람이 루브릭으로 채점한 표를
보고서에 싣는다(채점 근거를 누구나 대조할 수 있게).

사용 (값은 출력하지 않는다):
  export NVIDIA_API_KEY=... ES_PASS=$(cat .es_watchman_pass)
  K8S_API=https://127.0.0.1:16443 K8S_TOKEN_FILE=.k8s_watchman_token K8S_CA_FILE=<클러스터 CA> \
  ES_URL=https://logs-es-http.logging.svc:19200 LOCAL_RESOLVE=logs-es-http.logging.svc=127.0.0.1 \
  ES_USER=watchman ES_CA_FILE=<ES CA> \
  python3 eval/run_case_bank.py out.json
"""
import glob
import json
import os
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

tmp = tempfile.NamedTemporaryFile(prefix="casebank-audit-", suffix=".jsonl", delete=False)
tmp.close()
os.environ.update({"LLM_MODE": "nim", "AUDIT_PATH": tmp.name})
for k in ("TELEGRAM_BOT_TOKEN", "SMTP_HOST"):
    os.environ.pop(k, None)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)
import localnet  # noqa: E402

localnet.install()
import watchman  # noqa: E402

EVENTS = {}
_real_audit = watchman.audit


def audit(run_id, kind, payload):
    EVENTS.setdefault(run_id, []).append((kind, payload))
    return _real_audit(run_id, kind, payload)


watchman.audit = audit


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "casebank.json"
    labels = json.load(open(os.path.join(ROOT, "fixtures", "cases", "cases-labels.json"),
                            encoding="utf-8"))
    only = os.environ.get("CASES", "")
    rows = []
    for p in sorted(glob.glob(os.path.join(ROOT, "fixtures", "cases", "fx-case-*.json"))):
        name = os.path.basename(p)[:-5]
        if only and not any(o and o in name for o in only.split(",")):
            continue
        rid = f"casebank-{name}"
        t0 = time.time()
        try:
            res = watchman.run_agent(json.load(open(p, encoding="utf-8")), run_id=rid)
        except Exception as e:  # 루프 밖 예외도 남기고 다음 케이스로
            res = {"classification": f"예외: {e}", "partial": True}
        ev = EVENTS.get(rid, [])
        fin = next((pl for k, pl in reversed(ev) if k == "finish"), {}) or {}
        row = {
            "case": name,
            "label": labels.get(name),
            "seconds": round(time.time() - t0, 1),
            "partial": bool(res.get("partial")),
            "classification": res.get("classification") or fin.get("classification"),
            "verdict": res.get("verdict") or fin.get("verdict"),
            "confidence": res.get("confidence") or fin.get("confidence"),
            "evidence": res.get("evidence") or fin.get("evidence") or [],
            "tools": [(pl.get("tool"), (pl.get("args") or {})) for k, pl in ev if k == "tool"],
            "llm_errors": [str(pl.get("error"))[:120] for k, pl in ev if k == "llm_error"],
            "fallback_steps": sum(1 for k, _ in ev if k == "llm_fallback"),
        }
        rows.append(row)
        print(f"{name}: {row['verdict']} / {row['confidence']} / partial={row['partial']} "
              f"{row['seconds']}s — {str(row['classification'])[:90]}", file=sys.stderr)
    with open(out, "w", encoding="utf-8") as f:
        json.dump({"model": watchman.NIM_MODEL, "fallback": watchman.NIM_FALLBACK_MODELS,
                   "ran_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "rows": rows},
                  f, ensure_ascii=False, indent=1)
    os.unlink(tmp.name)


if __name__ == "__main__":
    main()
