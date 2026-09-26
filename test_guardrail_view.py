"""관제 뷰 보안 표시 4종 — 툴 거부 사유·가드레일 지표·코드 심각도·마스킹 기록 (2026-09-25).

실행: python3 -m unittest test_guardrail_view -v   (외부 의존성·네트워크 불필요)
"""
import json
import os
import shutil
import tempfile
import unittest

os.environ.setdefault("LLM_MODE", "mock")
os.environ.setdefault("SNAPSHOT_PATH", "")

import redact
import watchman as w


class _Isolated(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self._saved = (dict(w._totals), dict(w._runs), list(w._runs_order), w._audit_seq)
        w._totals.update(dict.fromkeys(w._totals, 0))
        w._runs.clear()
        del w._runs_order[:]

    def tearDown(self):
        t, r, o, seq = self._saved
        w._totals.clear(); w._totals.update(t)
        w._runs.clear(); w._runs.update(r)
        del w._runs_order[:]; w._runs_order.extend(o)
        w._audit_seq = seq
        shutil.rmtree(self.tmp, ignore_errors=True)


def _script(*steps):
    """LLM 대본 — 차례로 JSON 을 내고, 끝나면 finish."""
    it = iter(steps)

    def llm(messages):
        try:
            return json.dumps(next(it))
        except StopIteration:
            return json.dumps({"tool": "finish", "args": {
                "classification": "테스트", "confidence": "낮음",
                "evidence": ["테스트 근거"], "proposals": []}})
    return llm


class RejectReason(unittest.TestCase):
    # logs 형식 검사는 K8S_API 확인 뒤에 있다 — 환경변수가 없는 맥에선 RuntimeError 로 새서
    # 단독 실행만 실패했다. 네트워크는 타지 않는다(전부 ToolError 로 먼저 끝난다).
    def setUp(self):
        self._api = w.K8S_API
        w.K8S_API = "https://k8s.invalid"

    def tearDown(self):
        w.K8S_API = self._api

    def test_real_messages_classified(self):
        # 실제 ToolError 문구 — 바뀌면 분류가 조용히 format 으로 새므로 여기서 잡는다.
        for fn, args, want in (
            (w.tool_kube_read, {"verb": "get", "resource": "secrets"}, "scope"),
            (w.tool_kube_read, {"verb": "delete", "resource": "pods"}, "scope"),
            (w.tool_es_search, {"index_pattern": "nope-*", "query": "x"}, "scope"),
            (w.tool_kube_read, {"verb": "logs", "resource": "pods"}, "format"),
        ):
            with self.assertRaises(w.ToolError) as cm:
                fn(args)
            self.assertEqual(w.reject_reason(cm.exception), want, str(cm.exception))
        self.assertEqual(w.reject_reason("알 수 없는 도구: rm"), "scope")
        self.assertEqual(w.reject_reason("size 는 1~50"), "format")
        self.assertEqual(w.reject_reason("NVIDIA_API_KEY 미설정"), "unavailable")


class ToolRejectsInRun(_Isolated):
    def test_scope_attempt_marked_and_counted(self):
        llm = _script({"tool": "kube_read", "args": {"verb": "get", "resource": "secrets"}},
                      {"tool": "es_search", "args": {"index_pattern": "x", "size": "많이"}})
        alert = {"alerts": [{"labels": {"alertname": "R", "namespace": "default"}}]}
        w.run_agent(alert, llm=llm, run_id="t-rej")
        rec = w.run_get("t-rej")
        self.assertEqual(rec["tool_rejects"].get("scope"), 1)
        self.assertEqual(w._totals["tool_rejects_scope"], 1)
        snap = w.state_snapshot(public=True)
        row = [r for r in snap["runs"] if r["run_id"] == "t-rej"][0]
        self.assertIn("tool_scope", row["signals"])
        self.assertIn("tool_rejects_scope", snap["totals"])
        # 공개 스냅샷엔 사유 분류·건수만 — 어떤 리소스를 노렸는지는 없다.
        self.assertNotIn("secrets", json.dumps(row, ensure_ascii=False))
        trace = w.trace_snapshot("t-rej")
        self.assertEqual(trace["tool_rejects"].get("scope"), 1)

    def test_unknown_tool_gets_rejected_span(self):
        llm = _script({"tool": "shell_exec", "args": {"cmd": "id"}})
        w.run_agent({"alerts": [{"labels": {"alertname": "U"}}]}, llm=llm, run_id="t-unk")
        spans = w.run_get("t-unk").get("spans") or []
        self.assertTrue(any(s["name"] == "tool:?" and s["status"] == "rejected" for s in spans))
        self.assertNotIn("shell_exec", json.dumps(spans))


class RestoreCounts(_Isolated):
    def _write(self, rows):
        path = os.path.join(self.tmp, "audit.jsonl")
        with open(path, "w", encoding="utf-8") as f:
            for i, (run, kind, payload) in enumerate(rows, 1):
                f.write(json.dumps({"ts": "2026-09-25T10:00:00+0900", "run": run, "seq": i,
                                    "kind": kind, "payload": payload}, ensure_ascii=False) + "\n")
        return path

    def test_old_records_without_reason_and_new_events(self):
        alert = {"alerts": [{"labels": {"alertname": "Falco", "priority": "Critical",
                                        "namespace": "a"}}]}
        path = self._write([
            ("r1", "alert_in", alert),
            ("r1", "arg_rejected", {"step": 1, "error": "resource 는 ['pods'] 만 허용"}),
            ("r1", "arg_rejected", {"step": 2, "error": "size 는 1~50"}),
            ("r1", "injection_suspect", {"source": "alert", "patterns": ["a", "b"]}),
            ("r1", "redaction", {"gate": "run", "rules": {"email": 2, "jwt": 1}}),
            ("r1", "finish", {"classification": "x", "confidence": "높음", "verdict": "사고"}),
        ])
        w.restore_from_audit(path)
        r = w.run_get("r1")
        self.assertEqual(r["tool_rejects"], {"scope": 1, "format": 1})
        self.assertEqual(r["redactions"], {"email": 2, "jwt": 1})
        self.assertTrue(r["redaction_checked"])
        self.assertEqual(r["src_severity"], "critical")
        self.assertEqual(w._totals["injection_suspects"], 2)
        self.assertEqual(w._totals["redactions"], 3)
        self.assertEqual(w.severity_of(r), "Critical")

    def test_injection_total_is_cumulative_not_last_50(self):
        # 예전엔 /state 가 최근 50 run 합으로 덮어써서 누적이 줄어들 수 있었다.
        w._totals["injection_suspects"] = 7
        self.assertEqual(w.state_snapshot()["totals"]["injection_suspects"], 7)


class Severity(unittest.TestCase):
    def test_matrix(self):
        S = w.severity_of
        self.assertEqual(S({"verdict": "사고", "src_severity": "critical"}), "Critical")
        self.assertEqual(S({"verdict": "사고", "src_severity": "warning"}), "High")
        self.assertEqual(S({"verdict": "사고"}), "High")
        self.assertEqual(S({"verdict": "의심"}), "Medium")
        self.assertEqual(S({"verdict": "오탐"}), "Info")
        self.assertEqual(S({"verdict": "불명"}), "Unknown")
        self.assertEqual(S({"verdict": None, "state": "부분 결과"}), "Unknown")
        self.assertIsNone(S({"verdict": None, "state": "실행 중"}))
        # 보안 신호가 있으면 Medium 밑으로 안 내려간다
        self.assertEqual(S({"verdict": "불명", "guard_flags": 1}), "Medium")
        self.assertEqual(S({"verdict": "오탐", "injection_suspects": 2}), "Medium")
        self.assertNotIn("Low", w.SEVERITIES)


class GuardrailCards(_Isolated):
    def test_rates_carry_denominators(self):
        w._totals.update(guard_checks=657, guard_flags=29, guard_errors=143)
        g = w.state_snapshot(public=True)["guardrail"]
        self.assertEqual(g["guard_flag_rate"], {"num": 29, "den": 657})
        # 실패는 모델 시도마다 센다 — 분모는 성공 검사 + 실패 시도
        self.assertEqual(g["guard_fail_rate"], {"num": 143, "den": 800})

    def test_latency_from_guard_spans(self):
        w.run_register("L1")
        w.run_update("L1", duration_s=10.0,
                     spans=[{"name": "guard", "dur_ms": 1000}, {"name": "guard", "dur_ms": 3000},
                            {"name": "llm", "dur_ms": 5000}])
        L = w.state_snapshot()["guardrail"]["guard_latency"]
        self.assertEqual((L["calls"], L["runs"], L["share_pct"]), (2, 1, 40.0))
        self.assertEqual(L["p50_ms"], 2000)


class EgressMasking(_Isolated):
    def test_pii_pseudonymized_before_llm_and_recorded(self):
        seen = {}

        def spy(messages):
            seen["user"] = messages[1]["content"]
            return json.dumps({"tool": "finish", "args": {
                "classification": "테스트", "confidence": "낮음",
                "evidence": ["근거"], "proposals": []}})

        alert = {"alerts": [{"labels": {"alertname": "M"},
                             "annotations": {"description": "user kim@example.com 010-1234-5678"}}]}
        w.run_agent(alert, llm=spy, run_id="t-pii")
        self.assertNotIn("kim@example.com", seen["user"])
        self.assertNotIn("010-1234-5678", seen["user"])
        self.assertIn("[PII:email:", seen["user"])
        rec = w.run_get("t-pii")
        self.assertEqual(rec["redactions"], {"email": 1, "kr_mobile": 1})
        self.assertTrue(rec["redaction_checked"])
        pub = json.dumps(w.state_snapshot(public=True), ensure_ascii=False)
        self.assertNotIn("kim@example.com", pub)

    def test_checked_zero_is_distinguished(self):
        w.run_agent({"alerts": [{"labels": {"alertname": "Z"}}]}, llm=_script(), run_id="t-z")
        rec = w.run_get("t-z")
        self.assertTrue(rec["redaction_checked"])
        self.assertEqual(rec["redactions"], {})


class PiiRedact(unittest.TestCase):
    def test_pseudonym_stable_and_rrn_removed(self):
        a, _ = redact.redact("a Kim@Example.com", pii=True)
        b, _ = redact.redact("b kim@example.com", pii=True)
        self.assertEqual(a.split()[1], b.split()[1])
        t, hits = redact.redact("주민 900101-1234567", pii=True)
        self.assertEqual(t, "주민 [REDACTED:kr_rrn]")
        self.assertEqual(hits[0]["rule"], "kr_rrn")

    def test_off_by_default_and_idempotent(self):
        self.assertEqual(redact.redact("x a@b.com")[1], [])
        once, _ = redact.redact("x a@b.com 010-9999-8888", pii=True)
        self.assertEqual(redact.redact(once, pii=True), (once, []))

    def test_no_false_hits_on_ops_text(self):
        for s in ("run 20260925-101010-001", "ts 2026-09-25T10:00:00+0900", "ip 10.0.0.1",
                  "image nginx@sha256:abcd", "port 8080 1234 5678"):
            self.assertEqual(redact.redact(s, pii=True)[1], [], s)

    def test_url_password_stays_secret_rule(self):
        t, hits = redact.redact("postgres://u:hunter2pass@db.example.com/x", pii=True)
        self.assertEqual([h["rule"] for h in hits], ["url_userinfo"])


if __name__ == "__main__":
    unittest.main()
