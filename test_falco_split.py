"""Falco 기록자(sensor) ≠ 사건 대상(subject) 분리 (2026-09-25).

로그 수집기가 Falco 출력에 Falco 파드 자신의 kubernetes.* 를 붙여, 모델이 센서를 실행 주체로
적었다(011·005·006 run). es_search 가 둘을 다른 이름으로 갈라 주는지 본다.
실행: python3 -m unittest test_falco_split -v
"""
import json
import os
import unittest

os.environ.setdefault("LLM_MODE", "mock")
os.environ.setdefault("SNAPSHOT_PATH", "")

import watchman as w

FALCO_HIT = {"_source": {
    "@timestamp": "2026-09-25T01:41:17Z", "rule": "Drop and execute new binary in container",
    "priority": "Critical",
    "kubernetes": {"namespace_name": "falco", "pod_name": "falco-w6r7t", "container_name": "falco"},
    "output_fields": {"proc.cmdline": "python -m pip install", "k8s.ns.name": "arc-runners",
                      "k8s.pod.name": "runner-abc", "container.id": "d9fa947cb1dc",
                      "container.name": "<NA>"}}}
APP_HIT = {"_source": {"@timestamp": "2026-09-25T01:40:00Z", "log": "GET /health 200",
                       "kubernetes": {"namespace_name": "shop", "pod_name": "api-1"}}}


class FalcoSplit(unittest.TestCase):
    def setUp(self):
        self._saved = (w._http_json, w.ES_URL)
        self.bodies = []

        def fake(url, data=None, **kw):
            self.bodies.append(data)
            return {"hits": {"total": {"value": 475, "relation": "eq"},
                             "hits": [json.loads(json.dumps(FALCO_HIT)),
                                      json.loads(json.dumps(APP_HIT))]}}
        w._http_json, w.ES_URL = fake, "https://es.invalid"

    def tearDown(self):
        w._http_json, w.ES_URL = self._saved

    def _run(self):
        return w.tool_es_search({"index_pattern": "logstash-*", "query_string": "rule:x"})

    def test_sensor_and_subject_are_separate(self):
        out = self._run()
        h = out["hits"][0]
        self.assertNotIn("kubernetes", h)  # 모호한 "파드" 필드는 남기지 않는다
        self.assertEqual(h["sensor"]["pod"], "falco-w6r7t")
        self.assertIn("실행 주체 아님", h["sensor"]["role"])
        self.assertEqual(h["subject"]["namespace"], "arc-runners")
        self.assertEqual(h["subject"]["pod"], "runner-abc")
        self.assertEqual(h["subject"]["container_id"], "d9fa947cb1dc")
        self.assertNotIn("container_name", h["subject"])  # <NA> 는 버린다
        self.assertEqual(h["output_fields"], {"proc.cmdline": "python -m pip install"})
        self.assertEqual(out["falco_subjects"]["sample_by_namespace"], {"arc-runners": 1})

    def test_non_falco_hit_untouched(self):
        h = self._run()["hits"][1]
        self.assertEqual(h["kubernetes"]["pod_name"], "api-1")
        self.assertNotIn("sensor", h)

    def test_subject_fields_requested(self):
        self._run()
        src = self.bodies[0]["_source"]
        for f in ("output_fields.k8s.ns.name", "output_fields.k8s.pod.name",
                  "output_fields.container.id"):
            self.assertIn(f, src)

    def test_nested_output_fields(self):
        h = w._split_falco_hit({"rule": "r", "kubernetes": {"namespace_name": "falco"},
                                "output_fields": {"k8s": {"ns": {"name": "arc-runners"}}}})
        self.assertEqual(h["subject"]["namespace"], "arc-runners")

    def test_finding_mentions_subject_count_not_names(self):
        find, _ = w.finding_of("es_search", self._run())
        self.assertEqual(find, "매칭 로그 475건 · 표본 2건 · Falco 기록 1건 대상 ns 1곳")
        self.assertNotIn("arc-runners", find)

    def test_prompt_rule(self):
        self.assertIn("sensor", w.SYSTEM_PROMPT)
        self.assertIn("subject 로만", w.SYSTEM_PROMPT)


if __name__ == "__main__":
    unittest.main()
