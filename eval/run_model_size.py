#!/usr/bin/env python3
"""모델 크기별 도구 호출 성공률 — 같은 에이전트 루프(watchman.run_agent)를 모델만 바꿔 돌린다.

재는 것은 **분류 정확도가 아니라 도구 호출 규약 준수**다:
  - 형식 준수   LLM 출력에서 JSON 도구 호출이 나왔는가(형식 오류 step_error 건수)
  - 인자 통과   도구 인자가 코드 검증(허용목록·이름 규칙·범위)을 통과했는가(arg_rejected)
  - 완주       스텝 예산(6 + 유예 2) 안에 유효한 finish 로 끝났는가
  - 도구 사용   finish 전에 도구를 한 번이라도 불렀는가(아무것도 안 보고 결론 내는 것 방지)

공정성 장치:
  - 클러스터 도구 응답은 **고정 스텁**이다(_http_json·urlopen 을 가로챈다). 모델마다 같은
    관측을 받으므로 차이는 모델에서만 나온다. 인자 검증은 실제 코드 그대로다 — 스텁은
    검증을 통과한 뒤의 네트워크 호출만 대신한다.
  - 폴백 모델을 끈다(NIM_FALLBACK_MODELS 비움). 켜 두면 작은 모델의 실패를 큰 모델이 메운다.
  - 가드·skill·recovery 게이트를 끈다. 프롬프트는 운영 es 모드와 같다.
  - NIM 호출 자체가 실패한 run(429·503 소진)은 모델 능력이 아니므로 분모에서 빼고 따로 센다.

사용 (키가 환경에 있어야 한다 — 값은 출력하지 않는다):
  NIM_MODEL=meta/llama-3.1-8b-instruct python3 eval/run_model_size.py [반복수] [결과.json]
"""
import glob
import io
import json
import os
import sys
import tempfile
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
STUB = "http://stub.invalid"

tmp = tempfile.NamedTemporaryFile(prefix="msize-audit-", suffix=".jsonl", delete=False)
tmp.close()
os.environ.update({
    "LLM_MODE": "nim", "AUDIT_PATH": tmp.name, "NIM_FALLBACK_MODELS": "",
    "GUARD_ENABLED": "0", "NVIDIA_SKILL_ENABLED": "0", "RECOVERY_ENABLED": "0",
    "LOG_BACKEND": "es", "ES_URL": STUB, "ES_USER": "", "K8S_API": STUB, "K8S_TOKEN": "stub",
})
os.environ.pop("TELEGRAM_BOT_TOKEN", None)
sys.path.insert(0, ROOT)
import watchman  # noqa: E402

# ---------------------------------------------------------------- 고정 스텁

_T = "2026-09-24T01:00:00Z"
_POD = {"kind": "Pod", "metadata": {"name": "app-0", "namespace": "default",
                                    "creationTimestamp": _T, "ownerReferences": [
                                        {"kind": "ReplicaSet", "name": "app-6d9f"}]},
        "spec": {"nodeName": "node-a", "containers": [{"name": "app", "image": "app:1.4.2"}]},
        "status": {"phase": "Running", "containerStatuses": [
            {"name": "app", "ready": True, "restartCount": 3,
             "lastState": {"terminated": {"reason": "Error", "exitCode": 1, "finishedAt": _T}}}]}}
_EVENT = {"kind": "Event", "metadata": {"name": "app-0.1", "namespace": "default"},
          "reason": "BackOff", "type": "Warning", "count": 4, "lastTimestamp": _T,
          "message": "Back-off restarting failed container app",
          "involvedObject": {"kind": "Pod", "name": "app-0"}}
_NODE = {"kind": "Node", "metadata": {"name": "node-a"},
         "status": {"conditions": [{"type": "Ready", "status": "True", "lastTransitionTime": _T}]}}
_BY_RES = {"pods": _POD, "events": _EVENT, "nodes": _NODE}
_LOG = ("2026-09-24T00:58:10Z ERROR upstream connect error: connection reset by peer\n"
        "2026-09-24T00:58:11Z INFO retrying (attempt 2/3)\n"
        "2026-09-24T00:58:14Z INFO recovered, serving\n")


def _stub_json(url):
    if "/_search" in url:
        return {"hits": {"total": {"value": 2, "relation": "eq"}, "hits": [
            {"_source": {"@timestamp": _T, "log": line,
                         "kubernetes.namespace_name": "default", "kubernetes.pod_name": "app-0"}}
            for line in _LOG.splitlines()[:2]]}}
    seg = url.split("?")[0].rstrip("/").split("/")
    for i in range(len(seg) - 1, -1, -1):  # .../<resource>[/<name>]
        if seg[i] in _BY_RES or seg[i].endswith("s") and i >= len(seg) - 2:
            res = seg[i]
            obj = _BY_RES.get(res, {"kind": res.rstrip("s").capitalize(),
                                    "metadata": {"name": "x", "namespace": "default"}})
            if i == len(seg) - 1:
                return {"kind": obj["kind"] + "List", "items": [obj]}
            return dict(obj, metadata=dict(obj["metadata"], name=seg[i + 1]))
    return {"kind": "List", "items": []}


_real_http_json = watchman._http_json
_real_urlopen = urllib.request.urlopen


def fake_http_json(url, *a, **kw):
    if url.startswith(STUB):
        return _stub_json(url)
    return _real_http_json(url, *a, **kw)


class _Resp(io.BytesIO):
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def fake_urlopen(req, *a, **kw):
    url = req.full_url if hasattr(req, "full_url") else str(req)
    if url.startswith(STUB):
        return _Resp(_LOG.encode())
    return _real_urlopen(req, *a, **kw)


watchman._http_json = fake_http_json
urllib.request.urlopen = fake_urlopen

# 감사 이벤트를 run 별로 메모리에 모은다
EVENTS = {}
_real_audit = watchman.audit


def audit(run_id, kind, payload):
    EVENTS.setdefault(run_id, []).append((kind, payload))
    return _real_audit(run_id, kind, payload)


watchman.audit = audit

# ---------------------------------------------------------------- 실행


def load_cases():
    paths = (sorted(glob.glob(os.path.join(ROOT, "fixtures", "cases", "fx-case-*.json")))
             + sorted(glob.glob(os.path.join(ROOT, "fixtures", "scenarios", "fx-scn-*.json"))))
    only = os.environ.get("MSIZE_CASES", "")  # 스모크용 부분 선택(쉼표 구분 부분일치)
    if only:
        paths = [p for p in paths if any(o and o in p for o in only.split(","))]
    return [(os.path.basename(p)[:-5], json.load(open(p, encoding="utf-8"))) for p in paths]


def score(run_id, res):
    ev = EVENTS.get(run_id, [])
    kinds = [k for k, _ in ev]
    llm_err = next((p.get("error") for k, p in ev if k == "llm_error"), None)
    return {
        "llm_calls": kinds.count("llm_out"),
        "tool_ok": kinds.count("tool"),
        "arg_rejected": kinds.count("arg_rejected"),
        "format_error": sum(1 for k, p in ev if k == "step_error"
                            and "유예" not in str(p.get("error"))),
        "grace_violation": sum(1 for k, p in ev if k == "step_error"
                               and "유예" in str(p.get("error"))),
        "infra_error": kinds.count("infra_error"),
        "finished": "finish" in kinds,
        "normalized": "finish_normalized" in kinds,
        "llm_error": (llm_err or "")[:160] or None,
        "first_ok": bool(ev) and _first_ok(ev),
        "tools_used": sorted({p.get("tool") for k, p in ev if k == "tool"}),
        "rejections": [str(p.get("error"))[:120] for k, p in ev if k == "arg_rejected"],
        "classification": (res.get("classification") or "")[:160],
    }


def _first_ok(ev):
    """첫 LLM 응답이 곧바로 유효한 도구 호출(검증 통과)이었는가."""
    for k, p in ev:
        if k == "tool" and p.get("step") == 1:
            return True
        if k in ("arg_rejected", "step_error", "finish") and p.get("step", 1) == 1:
            return k == "finish"
    return False


def main():
    reps = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    model = watchman.NIM_MODEL
    rows = []
    for rep in range(reps):
        for name, env in load_cases():
            rid = f"msize-{rep}-{name}"
            t0 = time.time()
            try:
                res = watchman.run_agent(env, run_id=rid)
            except Exception as e:  # 루프 밖 예외도 기록하고 다음 케이스로
                res = {"classification": f"예외: {e}", "partial": True}
                EVENTS.setdefault(rid, []).append(("harness_error", {"error": str(e)}))
            row = {"case": name, "rep": rep, "seconds": round(time.time() - t0, 1)}
            row.update(score(rid, res))
            rows.append(row)
            print(f"[{model}] {name} r{rep}: fin={row['finished']} tool={row['tool_ok']} "
                  f"rej={row['arg_rejected']} fmt={row['format_error']} "
                  f"llmerr={bool(row['llm_error'])} {row['seconds']}s", file=sys.stderr)
    # 본체가 stdout 에 로그를 찍으므로 결과는 파일로만 쓴다
    out = sys.argv[2] if len(sys.argv) > 2 else f"msize-{model.split('/')[-1]}.json"
    with open(out, "w", encoding="utf-8") as f:
        json.dump({"model": model, "reps": reps, "rows": rows}, f, ensure_ascii=False, indent=1)
    os.unlink(tmp.name)


if __name__ == "__main__":
    main()
