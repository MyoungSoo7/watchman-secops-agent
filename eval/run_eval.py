#!/usr/bin/env python3
"""P4 평가 하네스 (실행형) — 케이스 뱅크를 watchman.run_agent 로 돌려 채점한다.

두 모드를 **분리해서** 낸다 (ROLE.md §6 T4-2, "미달 수치를 성과로 표시하지 않는다"):

  [파이프라인 정답률]  LLM_MODE=mock — 결정적. 실 LLM 분류가 아니라 루프·스키마·
      통제 준수만 본다. "run 이 완주했는가 / finish 스키마가 유효한가 / evidence 가
      비지 않았는가 / 주입 케이스에 ⚠ 가 붙었는가 / 정상 케이스에 ⚠ 오탐이 없는가".
      클러스터(ES·K8s) 접근 없이 어디서나 재현된다 — 도구 호출은 실패해도 루프가
      infra_error 로 흡수하고 finish 로 간다.

  [분류 정답률]  LLM_MODE=nim (EVAL_LIVE_NIM=1 + NVIDIA_API_KEY) — 실 NIM 분류를
      정답 키워드와 OR 매칭. **로컬에서 돌리면 in-cluster ES·K8s 도구 접근이 없어
      관측 증거가 비므로 공정한 정확도가 아니다.** 공정한 분류 정확도는 in-cluster
      파드가 실제 관측하며 남긴 run 을 eval/score_cases.py 로 채점한 값이다
      (eval/report-20260922.md 참조). 이 모드는 회귀 스모크·연결 확인용이다.

사용:
  python3 eval/run_eval.py                 # 파이프라인 정답률(mock, 기본)
  EVAL_LIVE_NIM=1 python3 eval/run_eval.py # + 분류 정답률(실 NIM, 경고 배너와 함께)

watchman.py 는 **수정하지 않고 import 만** 한다. 감사로그는 임시 파일로 격리해
실 audit.jsonl 을 오염시키지 않는다.
"""
import glob
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CASES_DIR = os.path.join(ROOT, "fixtures", "cases")
LABELS = os.path.join(CASES_DIR, "cases-labels.json")

# 정답 라벨(분류 채점용) — cases-labels.json 의 서술을 채점 가능한 키워드/부류로 고정.
# kind: fp = 오탐/stale(경보만 있고 실장애 아님) · ext = 외부·노드 요인(파드 결함 아님)
#       real = 실장애(부분 포함). keywords 는 분류 문장에 하나라도 있으면 일치(보수적 OR).
GOLDEN = {
    "fx-case-01-frpc-restart":       {"kind": "ext",  "keywords": ["frpc", "원격", "연결", "외부", "재시작"]},
    "fx-case-02-dashboard-restart":  {"kind": "ext",  "keywords": ["dashboard", "노드", "불안정", "재시작"]},
    "fx-case-03-heartbeat-flap":     {"kind": "ext",  "keywords": ["재부팅", "노드", "david"]},
    "fx-case-04-velero-partialfail": {"kind": "real", "keywords": ["velero", "부분", "실패", "isagal", "pvb", "백업"]},
    "fx-case-05-ksm-restart":        {"kind": "ext",  "keywords": ["자원", "압박", "재시작", "노드", "kube-state"]},
    "fx-case-06-selfhealer-restart": {"kind": "fp",   "keywords": ["재부팅", "정상", "복구", "daemonset"]},
    "fx-case-07-ddak-restart":       {"kind": "ext",  "keywords": ["재부팅", "노드", "david"]},
    "fx-case-08-nonexistent-job":    {"kind": "fp",   "keywords": ["존재하지 않", "완료", "정리", "stale", "삭제"]},
    "fx-case-09-nonexistent-pod":    {"kind": "fp",   "keywords": ["존재하지 않", "오탐", "조작", "부재", "가짜"]},
    "fx-case-10-nodenotready-stale": {"kind": "fp",   "keywords": ["ready", "stale", "정상", "과거", "잔존"]},
}
# 주입 페이로드가 아닌 정상/실장애 케이스이므로 ⚠ 주입은 전부 0 이어야 한다(오탐 감시).
INJECTION_EXPECTED = set()   # 케이스 뱅크엔 주입 페이로드 없음


def load_cases():
    out = []
    for path in sorted(glob.glob(os.path.join(CASES_DIR, "fx-case-*.json"))):
        with open(path, encoding="utf-8") as f:
            env = json.load(f)
        fp = (env.get("alerts") or [{}])[0].get("fingerprint") or os.path.basename(path)
        out.append((fp, env))
    return out


def match_keywords(text, keywords):
    if not text:
        return False, []
    low = text.lower()
    hit = [k for k in keywords if k.lower() in low]
    return bool(hit), hit


def run_pipeline(watchman, cases):
    """mock 모드 파이프라인 정답률 — 결정적."""
    rows, ok = [], 0
    for fp, env in cases:
        res = watchman.run_agent(env, run_id="evalmock-" + fp)
        rec = watchman.run_get("evalmock-" + fp) or {}
        completed = rec.get("state") == "완료" and not res.get("partial")
        schema_ok = True
        try:
            watchman.validate_finish(res)   # finish 스키마 재검증
        except Exception:
            schema_ok = False
        evid = bool(res.get("evidence"))
        inj = res.get("injection_suspects", 0)
        inj_ok = (inj > 0) == (fp in INJECTION_EXPECTED)   # 케이스엔 주입 없음 → inj==0 이어야 통과
        passed = completed and schema_ok and evid and inj_ok
        ok += bool(passed)
        rows.append({
            "fp": fp, "alert": rec.get("alertname"), "state": rec.get("state"),
            "completed": completed, "schema_ok": schema_ok, "evidence": len(res.get("evidence") or []),
            "inj": inj, "inj_ok": inj_ok, "pass": passed,
        })
    return rows, ok


def run_nim(watchman, cases):
    """실 NIM 분류 정답률 — 503/인프라 오류는 미채점으로 분모에서 제외."""
    rows, scored, matched, infra = [], 0, 0, 0
    for fp, env in cases:
        gold = GOLDEN.get(fp, {})
        try:
            res = watchman.run_agent(env, run_id="evalnim-" + fp)
        except Exception as e:   # noqa: BLE001 — 하네스는 어떤 실패도 미채점으로 기록
            rows.append({"fp": fp, "cls": f"(예외: {e})", "verdict": "infra", "hit": []})
            infra += 1
            continue
        if res.get("partial"):
            rows.append({"fp": fp, "cls": res.get("classification"), "verdict": "infra", "hit": []})
            infra += 1
            continue
        cls = res.get("classification") or ""
        hit_ok, hit = match_keywords(cls, gold.get("keywords", []))
        scored += 1
        matched += bool(hit_ok)
        rows.append({"fp": fp, "cls": cls, "verdict": "✅" if hit_ok else "❌", "hit": hit})
    return rows, scored, matched, infra


def main():
    live = os.environ.get("EVAL_LIVE_NIM") == "1"
    # 환경 격리: 감사로그 임시파일 + 텔레그램 차단. import 전에 세팅해야 모듈이 읽는다.
    tmp_audit = tempfile.NamedTemporaryFile(prefix="eval-audit-", suffix=".jsonl", delete=False)
    tmp_audit.close()
    os.environ["AUDIT_PATH"] = tmp_audit.name
    os.environ.pop("TELEGRAM_BOT_TOKEN", None)
    os.environ["LLM_MODE"] = "nim" if live else "mock"
    sys.path.insert(0, ROOT)
    import watchman  # noqa: E402

    cases = load_cases()
    print(f"# P4 평가 1회전 (run_eval.py) — 케이스 {len(cases)}건\n")
    print(f"감사로그 격리: `{tmp_audit.name}`  ·  라벨: `fixtures/cases/cases-labels.json` + GOLDEN(본 스크립트)\n")

    if not live:
        rows, ok = run_pipeline(watchman, cases)
        print("## 파이프라인 정답률 (LLM_MODE=mock, 결정적)\n")
        print("> mock 은 실분류가 아니다. 루프 완주·finish 스키마·evidence 유무·주입 오탐 없음만 본다.\n")
        print("| 케이스 | alert | 완주 | 스키마 | evidence | ⚠주입 | 판정 |")
        print("|---|---|---|---|---|---|---|")
        for r in rows:
            print(f"| {r['fp']} | {r['alert']} | {'✅' if r['completed'] else '❌'} | "
                  f"{'✅' if r['schema_ok'] else '❌'} | {r['evidence']} | {r['inj']} | "
                  f"{'✅' if r['pass'] else '❌'} |")
        pct = f" = {100*ok//len(rows)}%" if rows else ""
        print(f"\n**파이프라인 정답률: {ok}/{len(rows)}{pct}** (분모=케이스 전체, 분자=완주+스키마+evidence+주입오탐없음 모두 충족)")
        print("\n> 이 수치는 **분류 정확도가 아니다.** 제어 흐름·출력계약·통제(주입 오탐)만 재현 검증한 값이다.")
        print("> 분류 정확도는 in-cluster 실관측 run 채점(eval/report-20260922.md)이 근거다.")
    else:
        print("## 분류 정답률 (LLM_MODE=nim, 실 NIM)\n")
        print("> ⚠ **경고:** 로컬 실행은 in-cluster ES·K8s 도구 접근이 없어 관측 증거가 빈다.")
        print("> 여기 수치를 **제품 분류 정확도로 인용하지 마라.** 연결·회귀 스모크용이다.")
        print("> 공정한 분류 정확도 = in-cluster 파드가 실관측한 run 채점(eval/report-20260922.md).\n")
        rows, scored, matched, infra = run_nim(watchman, cases)
        print("| 케이스 | 모델 분류(요약) | 일치 | 히트 키워드 |")
        print("|---|---|---|---|")
        for r in rows:
            print(f"| {r['fp']} | {(r['cls'] or '')[:46]} | {r['verdict']} | {', '.join(r['hit'])} |")
        pct = f" = {100*matched//scored}%" if scored else ""
        print(f"\n**분류 정답률(로컬 스모크, 참고용): {matched}/{scored}{pct}** · 미채점(infra/503): {infra}건")
        print("> 미채점은 503·미완주·예외로 분모에서 제외했다. 위 경고대로 제품 수치가 아니다.")


if __name__ == "__main__":
    main()
