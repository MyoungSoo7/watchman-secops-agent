#!/usr/bin/env python3
"""logsrc(Loki·Datadog 어댑터) 단위 테스트 — 네트워크 없이 가짜 http 로 돈다.

핵심은 통제 ①: LLM 이 준 문자열이 따옴표 리터럴 밖으로 나가 쿼리 구조를 바꿀 수 없어야 한다.
"""
import json
import os
import subprocess
import sys
import unittest
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import logsrc  # noqa: E402

NOW_NS = 1_780_000_000_000_000_000


class FakeHTTP:
    def __init__(self, resp):
        self.resp = resp
        self.calls = []

    def __call__(self, url, data=None, headers=None, method=None, verify=True):
        self.calls.append({"url": url, "data": data, "headers": headers or {},
                           "method": method, "verify": verify})
        return self.resp


def loki_cfg(**over):
    env = {"LOG_BACKEND": "loki", "LOKI_URL": "http://loki.logging:3100/"}
    env.update(over)
    return logsrc.config_from_env(env)


def dd_cfg(**over):
    env = {"LOG_BACKEND": "datadog", "DD_API_KEY": "k", "DD_APP_KEY": "a"}
    env.update(over)
    return logsrc.config_from_env(env)


LOKI_RESP = {"status": "success", "data": {"resultType": "streams", "result": [
    {"stream": {"namespace": "shop", "pod": "api-1", "container": "api"},
     "values": [[str(NOW_NS - 3_000_000_000), "older"], [str(NOW_NS - 1_000_000_000), "newest"]]},
    {"stream": {"namespace": "shop", "pod": "api-2", "container": "api"},
     "values": [[str(NOW_NS - 2_000_000_000), "middle"]]},
]}}


class TestConfig(unittest.TestCase):
    def test_default_is_es(self):
        self.assertEqual(logsrc.config_from_env({})["backend"], "es")

    def test_unknown_backend_fails_at_startup(self):
        with self.assertRaises(ValueError):
            logsrc.config_from_env({"LOG_BACKEND": "splunk"})

    def test_bad_label_and_site_rejected(self):
        with self.assertRaises(ValueError):
            logsrc.config_from_env({"LOKI_NAMESPACE_LABEL": 'ns"} |= "x'})
        with self.assertRaises(ValueError):
            logsrc.config_from_env({"DD_SITE": "evil.com/x?"})


class TestValidate(unittest.TestCase):
    def test_namespace_must_be_k8s_name(self):
        for bad in ['shop"}', "Shop", "a b", "x" * 64, "-a"]:
            with self.assertRaises(logsrc.ArgError, msg=bad):
                logsrc.validate({"namespace": bad})

    def test_ranges(self):
        with self.assertRaises(logsrc.ArgError):
            logsrc.validate({"minutes_back": 241})
        with self.assertRaises(logsrc.ArgError):
            logsrc.validate({"limit": 0})
        with self.assertRaises(logsrc.ArgError):
            logsrc.validate({"limit": "many"})
        # 상한 초과 limit 은 거부 대신 50 으로 자른다(es_search 와 같은 규칙)
        self.assertEqual(logsrc.validate({"limit": 500})[3], 50)

    def test_newlines_and_control_chars_removed(self):
        _, contains, _, _ = logsrc.validate({"contains": "a\n} | line_format\r\x00b"})
        self.assertNotIn("\n", contains)
        self.assertNotIn("\x00", contains)


class TestLokiQuery(unittest.TestCase):
    def test_injection_stays_inside_literal(self):
        evil = 'x" } |~ ".*" or {job=~".+'
        _, contains, _, _ = logsrc.validate({"contains": evil})
        q = logsrc.loki_query("shop", contains)
        self.assertEqual(q, '{namespace="shop"} |= "x\\" } |~ \\".*\\" or {job=~\\".+"')
        # 이스케이프 안 된 따옴표는 리터럴 경계 4개(ns 2 + contains 2)뿐이어야 한다
        unescaped = sum(1 for i, c in enumerate(q) if c == '"' and q[i - 1] != "\\")
        self.assertEqual(unescaped, 4)

    def test_backslash_cannot_eat_closing_quote(self):
        self.assertEqual(logsrc.loki_query("", "a\\"), '{namespace=~".+"} |= "a\\\\"')

    def test_no_namespace_no_text(self):
        self.assertEqual(logsrc.loki_query("", ""), '{namespace=~".+"}')


class TestLokiSearch(unittest.TestCase):
    def test_request_and_flatten(self):
        http = FakeHTTP(LOKI_RESP)
        out = logsrc.search(loki_cfg(), {"namespace": "shop", "contains": "err",
                                         "minutes_back": 10, "limit": 2}, http, now_ns=NOW_NS)
        call = http.calls[0]
        u = urllib.parse.urlparse(call["url"])
        self.assertEqual(u.path, "/loki/api/v1/query_range")
        qs = dict(urllib.parse.parse_qsl(u.query))
        self.assertEqual(qs["query"], '{namespace="shop"} |= "err"')
        self.assertEqual(int(qs["end"]) - int(qs["start"]), 10 * 60 * 10**9)
        self.assertEqual(qs["limit"], "2")
        self.assertEqual(qs["direction"], "backward")
        self.assertEqual(call["method"], "GET")
        # 스트림 경계를 넘어 최신순으로 합치고 limit 에서 자른다
        self.assertEqual([h["log"] for h in out["hits"]], ["newest", "middle"])
        self.assertEqual(out["hits"][0]["kubernetes.pod_name"], "api-1")
        self.assertEqual(out["hits"][1]["kubernetes.container_name"], "api")
        self.assertTrue(out["hits"][0]["@timestamp"].endswith("Z"))
        self.assertEqual(out["total"]["relation"], "gte")

    def test_auth_headers(self):
        http = FakeHTTP(LOKI_RESP)
        logsrc.search(loki_cfg(LOKI_TOKEN="t", LOKI_TENANT="acme"), {}, http, now_ns=NOW_NS)
        h = http.calls[0]["headers"]
        self.assertEqual(h["Authorization"], "Bearer t")
        self.assertEqual(h["X-Scope-OrgID"], "acme")
        http = FakeHTTP(LOKI_RESP)
        logsrc.search(loki_cfg(LOKI_USER="u", LOKI_PASS="p"), {}, http, now_ns=NOW_NS)
        self.assertTrue(http.calls[0]["headers"]["Authorization"].startswith("Basic "))

    def test_custom_namespace_label(self):
        http = FakeHTTP({"status": "success", "data": {"result": []}})
        logsrc.search(loki_cfg(LOKI_NAMESPACE_LABEL="k8s_namespace_name"),
                      {"namespace": "shop"}, http, now_ns=NOW_NS)
        qs = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(http.calls[0]["url"]).query))
        self.assertEqual(qs["query"], '{k8s_namespace_name="shop"}')

    def test_unset_url_and_failed_status(self):
        with self.assertRaises(RuntimeError):
            logsrc.search(logsrc.config_from_env({"LOG_BACKEND": "loki"}), {}, FakeHTTP({}))
        with self.assertRaises(RuntimeError):
            logsrc.search(loki_cfg(), {}, FakeHTTP({"status": "error"}), now_ns=NOW_NS)

    def test_long_line_truncated(self):
        resp = {"status": "success", "data": {"result": [
            {"stream": {}, "values": [[str(NOW_NS), "x" * 10000]]}]}}
        out = logsrc.search(loki_cfg(), {}, FakeHTTP(resp), now_ns=NOW_NS)
        self.assertEqual(len(out["hits"][0]["log"]), logsrc.MAX_LINE)


class TestDatadog(unittest.TestCase):
    RESP = {"data": [{"id": "1", "attributes": {
        "timestamp": "2026-09-24T01:00:00Z", "message": "boom", "service": "api",
        "status": "error", "tags": ["kube_namespace:shop", "pod_name:api-1",
                                    "kube_container_name:api", "env:prod"]}}],
        "meta": {"page": {"after": "cursor"}}}

    def test_request_and_flatten(self):
        http = FakeHTTP(self.RESP)
        out = logsrc.search(dd_cfg(DD_SITE="datadoghq.eu"),
                            {"namespace": "shop", "contains": 'say "hi"', "minutes_back": 30,
                             "limit": 99}, http)
        call = http.calls[0]
        self.assertEqual(call["url"], "https://api.datadoghq.eu/api/v2/logs/events/search")
        self.assertEqual(call["method"], "POST")
        self.assertEqual(call["headers"]["DD-API-KEY"], "k")
        self.assertEqual(call["headers"]["DD-APPLICATION-KEY"], "a")
        self.assertEqual(call["data"], {
            "filter": {"query": 'kube_namespace:shop "say \\"hi\\""',
                       "from": "now-30m", "to": "now"},
            "sort": "-timestamp", "page": {"limit": 50}})
        h = out["hits"][0]
        self.assertEqual((h["log"], h["kubernetes.namespace_name"], h["kubernetes.pod_name"],
                          h["kubernetes.container_name"]), ("boom", "shop", "api-1", "api"))
        self.assertEqual(out["total"]["relation"], "gte")

    def test_empty_query_is_wildcard_and_keys_required(self):
        self.assertEqual(logsrc.datadog_query("", ""), "*")
        with self.assertRaises(RuntimeError):
            logsrc.search(logsrc.config_from_env({"LOG_BACKEND": "datadog"}), {}, FakeHTTP({}))


class TestWatchmanWiring(unittest.TestCase):
    """본체 연결 — 별도 프로세스로 import 해서 환경변수별 모듈 상수를 본다."""

    def probe(self, env):
        code = ("import json,watchman as w;print(json.dumps({'tools':sorted(w.TOOLS),"
                "'plan':w.evidence_plan({})[-1],'cov':w.coverage_key('log_search',{}),"
                "'prompt_has_log':'log_search' in w.SYSTEM_PROMPT,"
                "'prompt_has_es':'es_search' in w.SYSTEM_PROMPT}))")
        e = {k: v for k, v in os.environ.items() if not k.startswith(("LOG_", "LOKI_", "DD_"))}
        e.update(env)
        out = subprocess.run([sys.executable, "-c", code], cwd=HERE, env=e,
                             capture_output=True, text=True, check=True).stdout
        return json.loads(out.strip().splitlines()[-1])

    def test_es_default_unchanged(self):
        r = self.probe({})
        self.assertIn("es_search", r["tools"])
        self.assertNotIn("log_search", r["tools"])
        self.assertEqual(r["plan"], ["es", "ES 로그 색인"])
        self.assertFalse(r["prompt_has_log"])

    def test_loki_swaps_tool(self):
        r = self.probe({"LOG_BACKEND": "loki", "LOKI_URL": "http://x:3100"})
        self.assertIn("log_search", r["tools"])
        self.assertNotIn("es_search", r["tools"])
        self.assertEqual(r["plan"], ["es", "로그 색인(Loki)"])
        self.assertEqual(r["cov"], "es")
        self.assertTrue(r["prompt_has_log"])
        self.assertFalse(r["prompt_has_es"])


if __name__ == "__main__":
    unittest.main()
