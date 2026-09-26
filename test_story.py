"""run 상세 서사 — 스텝별 의도(why)·발견(find)·노드사건 대조(corr) (2026-09-25).

실행: python3 -m unittest test_story -v   (외부 의존성·네트워크 불필요)
"""
import json
import os
import unittest

os.environ.setdefault("LLM_MODE", "mock")
os.environ.setdefault("SNAPSHOT_PATH", "")

import watchman as w
from test_guardrail_view import _Isolated, _script


POD = {"kind": "Pod", "metadata": {"name": "secret-pod-abc", "namespace": "a"},
       "spec": {"nodeName": "worker-zeta"},
       "status": {"phase": "Running", "containerStatuses": [{"restartCount": 3}, {"restartCount": 1}]},
       "node_event_correlation": {"window_seconds": 300, "containers": [
           {"node": "worker-zeta", "gap_seconds": -40, "coincides_with_node_event": True},
           {"node": "worker-zeta", "gap_seconds": 900, "coincides_with_node_event": False}]}}


class FindingOf(unittest.TestCase):
    def test_counts_only(self):
        f = w.finding_of
        self.assertEqual(f("es_search", {"total": {"value": 12, "relation": "gte"},
                                         "hits": [{}, {}]})[0], "매칭 로그 12+건 · 표본 2건")
        self.assertEqual(f("log_search", {"total": 0, "hits": []})[0], "매칭 로그 0건")
        self.assertEqual(f("kube_read", {"not_found": True})[0], "대상 없음 (not found)")
        self.assertEqual(f("kube_read", {"kind": "PodList", "items": [
            {"status": {"phase": "Running"}}, {"status": {"phase": "Running"}},
            {"status": {"phase": "Failed"}}]})[0], "Pod 3개 (Running 2 · Failed 1)")
        self.assertEqual(f("container_lookup", {"found": False, "checked_pods": 40,
                                                "dind_pods": ["x"]})[0],
                         "kubelet 관리 파드 40개에 없음 · dind 파드 1개 후보")
        self.assertEqual(f("nope", {"a": 1}), (None, None))
        self.assertEqual(f("kube_read", "not a dict"), (None, None))

    def test_pod_and_correlation_without_names(self):
        find, corr = w.finding_of("kube_read", POD)
        self.assertEqual(find, "Pod · Running · 재시작 4회")
        self.assertEqual(corr, {"coincides": True, "gap_s": 40, "window_s": 300})
        blob = json.dumps([find, corr], ensure_ascii=False)
        self.assertNotIn("worker-zeta", blob)
        self.assertNotIn("secret-pod-abc", blob)


class StoryInRun(_Isolated):
    def setUp(self):
        super().setUp()
        self._tools = dict(w.TOOLS)
        w.TOOLS["kube_read"] = lambda args: POD

    def tearDown(self):
        w.TOOLS.clear(); w.TOOLS.update(self._tools)
        super().tearDown()

    def test_why_find_corr_recorded_and_public(self):
        llm = _script(
            {"tool": "kube_read", "why": "파드가 노드 재부팅과 같이 재시작했는지 확인  10.0.0.7",
             "args": {"verb": "get", "resource": "pods", "namespace": "a", "name": "secret-pod-abc"}},
            {"tool": "shell_exec", "why": "셸로 확인", "args": {"cmd": "id"}},
            {"tool": "finish", "why": "판정에 섞이면 안 됨", "args": {
                "classification": "노드 재부팅 동반 재기동", "confidence": "중간",
                "evidence": ["재시작 4회"], "proposals": []}})
        alert = {"alerts": [{"labels": {"alertname": "Falco", "source": "syscall", "namespace": "a"}}]}
        w.run_agent(alert, llm=llm, run_id="t-story")
        tr = w.trace_snapshot("t-story")
        st = tr["story"]
        self.assertEqual(tr["alert_source"], "syscall")
        ok = [x for x in st if x.get("status") == "ok"][0]
        self.assertEqual(ok["tool"], "kube_read")
        self.assertEqual(ok["find"], "Pod · Running · 재시작 4회")
        self.assertEqual(ok["corr"]["gap_s"], 40)
        self.assertNotIn("10.0.0.7", ok["why"])  # 공개 관문(IP 가림)을 거친다
        self.assertNotIn("  ", ok["why"])
        rej = [x for x in st if x.get("status") == "rejected"][0]
        self.assertEqual(rej["tool"], "?")  # LLM 이 지어낸 도구 이름은 싣지 않는다
        self.assertEqual(rej["why"], "셸로 확인")
        blob = json.dumps(tr, ensure_ascii=False)
        for leak in ("shell_exec", "worker-zeta", "secret-pod-abc", "판정에 섞이면"):
            self.assertNotIn(leak, blob)
        self.assertNotIn("why", json.dumps(w.run_get("t-story").get("findings") or {}, ensure_ascii=False))

    def test_story_not_in_public_state(self):
        w.run_agent({"alerts": [{"labels": {"alertname": "S"}}]},
                    llm=_script({"tool": "kube_read", "why": "확인",
                                 "args": {"verb": "get", "resource": "pods", "namespace": "a"}}),
                    run_id="t-st2")
        snap = w.state_snapshot(public=True)
        self.assertNotIn("story", json.dumps(snap["runs"], ensure_ascii=False))


class StoryRestore(_Isolated):
    def _write(self, rows):
        path = os.path.join(self.tmp, "audit.jsonl")
        with open(path, "w", encoding="utf-8") as f:
            for i, (run, kind, payload) in enumerate(rows, 1):
                f.write(json.dumps({"ts": "2026-09-25T10:00:00+0900", "run": run, "seq": i,
                                    "kind": kind, "payload": payload}, ensure_ascii=False) + "\n")
        return path

    def test_new_and_legacy_records(self):
        alert = {"alerts": [{"labels": {"alertname": "Falco", "source": "syscall"}}]}
        path = self._write([
            ("r1", "alert_in", alert),
            ("r1", "container_resolved", {"found": True, "namespace": "a"}),
            ("r1", "tool", {"step": 1, "tool": "kube_read",
                            "args": {"verb": "get", "resource": "pods", "name": "secret-pod-abc"},
                            "result_digest": "x", "why": "재시작 확인",
                            "find": "Pod · Running", "corr": {"coincides": False, "gap_s": 900}}),
            ("r1", "arg_rejected", {"step": 2, "tool": "rm", "reason": "scope", "error": "알 수 없는 도구: rm"}),
            ("r2", "alert_in", alert),
            ("r2", "tool", {"step": 1, "tool": "es_search", "args": {"index_pattern": "logstash-k8s-*"},
                            "result_digest": str({"total": {"value": 5}, "hits": [{}]})}),
            ("r2", "tool", {"step": 2, "tool": "es_search", "args": {},
                            "result_digest": "{" + "x" * 1600}),
        ])
        w.restore_from_audit(path)
        s1 = w.trace_snapshot("r1")["story"]
        self.assertEqual([x.get("by") for x in s1], ["server", None, None])
        self.assertEqual(s1[0]["find"], "컨테이너 → 파드 확인 (ns a)")
        self.assertEqual((s1[1]["why"], s1[1]["corr"]["gap_s"]), ("재시작 확인", 900))
        self.assertNotIn("name", s1[1]["args"])  # 공개 화이트리스트(verb·resource·ns…)만
        self.assertEqual((s1[2]["tool"], s1[2]["status"]), ("?", "rejected"))
        s2 = w.trace_snapshot("r2")["story"]
        self.assertTrue(all(x["legacy"] for x in s2))
        self.assertEqual(s2[0]["find"], "매칭 로그 5건 · 표본 1건")
        self.assertNotIn("find", s2[1])  # 잘린 요약은 되살리지 않는다
        self.assertNotIn("why", s2[0])

    def test_story_capped(self):
        rows = [("r3", "alert_in", {"alerts": [{"labels": {"alertname": "C"}}]})]
        rows += [("r3", "tool", {"step": i, "tool": "kube_read", "args": {}, "result_digest": "x",
                                 "find": "f"}) for i in range(1, 30)]
        w.restore_from_audit(self._write(rows))
        self.assertEqual(len(w.trace_snapshot("r3")["story"]), w.STORY_KEEP)


class Dashboard(unittest.TestCase):
    def test_story_view_wired(self):
        h = w.DASHBOARD_HTML
        for s in ("function storyHtml", "INVESTIGATION", "details class=\"perf\"", "tag:'WHY'",
                  "tag:'CORRELATE'", "id=\"tl\""):
            self.assertIn(s, h)


if __name__ == "__main__":
    unittest.main()
