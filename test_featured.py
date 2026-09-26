"""대표 run 고정 — 밀어냄·복원 창·/state 50건 상한에서 빠진다 (2026-09-25).

실행: python3 -m unittest test_featured -v
"""
import json
import os
import shutil
import tempfile
import unittest

os.environ.setdefault("LLM_MODE", "mock")
os.environ.setdefault("SNAPSHOT_PATH", "")

import watchman as w

FEAT = "20260925-122437-025"
BEFORE = "20260925-104117-011"


class Featured(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self._saved = (dict(w._totals), dict(w._runs), list(w._runs_order), w._audit_seq,
                       w.FEATURED_RUNS, w.FEATURED)
        w.FEATURED = ((FEAT, "대표"), (BEFORE, "수정 전"))
        w.FEATURED_RUNS = (FEAT, BEFORE)
        w._runs.clear()
        del w._runs_order[:]

    def tearDown(self):
        t, r, o, seq, f, ff = self._saved
        w._totals.clear(); w._totals.update(t)
        w._runs.clear(); w._runs.update(r)
        del w._runs_order[:]; w._runs_order.extend(o)
        w._audit_seq, w.FEATURED_RUNS, w.FEATURED = seq, f, ff
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_default_is_the_chosen_pair(self):
        self.assertEqual(self._saved[5], ((FEAT, "대표"), (BEFORE, "수정 전")))
        self.assertEqual(w._parse_featured(" a:대표 , b ,, c:수정 전"),
                         (("a", "대표"), ("b", "대표"), ("c", "수정 전")))
        self.assertEqual(w._parse_featured(""), ())

    def test_pair_labels_and_rank_survive(self):
        w.run_register(BEFORE)
        w.run_register(FEAT)
        for i in range(120):
            w.run_register(f"n-{i:03d}")
        runs = {r["run_id"]: r for r in w.state_snapshot(public=True)["runs"]}
        self.assertEqual((runs[FEAT]["featured"], runs[FEAT]["featured_rank"]), ("대표", 0))
        self.assertEqual((runs[BEFORE]["featured"], runs[BEFORE]["featured_rank"]), ("수정 전", 1))

    def test_survives_eviction_and_state_cap(self):
        w.run_register(FEAT)
        w.run_update(FEAT, state="완료")
        for i in range(250):
            w.run_register(f"n-{i:03d}")
        self.assertIn(FEAT, w._runs)
        self.assertEqual(len(w._runs_order), w.RUNS_KEEP + 1)
        self.assertNotIn("n-149", w._runs)  # 비고정은 여전히 밀린다
        for public in (False, True):
            runs = w.state_snapshot(public=public)["runs"]
            row = [r for r in runs if r["run_id"] == FEAT]
            self.assertEqual(len(row), 1)
            self.assertEqual(row[0]["featured"], "대표")
            self.assertEqual(sum(1 for r in runs if r.get("featured")), 1)
            self.assertEqual(len(runs), 51)
        self.assertIsNotNone(w.trace_snapshot(FEAT))

    def test_not_duplicated_when_recent(self):
        w.run_register(FEAT)
        runs = w.state_snapshot()["runs"]
        self.assertEqual([r["run_id"] for r in runs], [FEAT])

    def test_restore_keeps_featured_outside_window(self):
        path = os.path.join(self.tmp, "audit.jsonl")
        alert = {"alerts": [{"labels": {"alertname": "Falco", "namespace": "a"}}]}
        with open(path, "w", encoding="utf-8") as f:
            seq = 0
            for rid in [FEAT] + [f"r-{i:03d}" for i in range(150)]:
                for kind, pl in (("alert_in", alert),
                                 ("finish", {"classification": "x", "confidence": "높음",
                                             "verdict": "오탐"})):
                    seq += 1
                    f.write(json.dumps({"ts": "2026-09-25T10:41:17+0900", "run": rid, "seq": seq,
                                        "kind": kind, "payload": pl}, ensure_ascii=False) + "\n")
        w.restore_from_audit(path)
        self.assertIn(FEAT, w._runs)
        self.assertIn("r-149", w._runs)
        self.assertNotIn("r-049", w._runs)
        self.assertEqual(w._runs[FEAT]["verdict"], "오탐")

    def test_picker_wiring(self):
        self.assertIn("'★ '+esc(String(r.featured))", w.DASHBOARD_HTML)
        self.assertIn("fr(a.r)-fr(b.r)", w.DASHBOARD_HTML)


if __name__ == "__main__":
    unittest.main()
