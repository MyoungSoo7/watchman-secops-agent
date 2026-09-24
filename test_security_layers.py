#!/usr/bin/env python3
"""chain·redact·recovery·invariants 단위테스트.

test_watchman.py 와 파일을 나눈 이유는 하나다 — 이 리포는 여러 세션이 동시에
고치고 있어서, 새 층을 기존 테스트 파일 안에 끼워 넣으면 같은 앵커 뒤 삽입으로
조용히 섞인다. 층이 다르면 파일도 나눈다.

실행: python3 -m unittest test_security_layers
"""
import datetime
import unittest

import chain
import invariants
import recovery
import redact


def alert(name, ts):
    return {"labels": {"alertname": name, "namespace": "velero"},
            "startsAt": ts, "annotations": {}}


class ChainTest(unittest.TestCase):
    def setUp(self):
        chain.reset()

    def test_single_alert_does_not_escalate(self):
        info = chain.observe(alert("VeleroBackupDeleted", "2026-09-22T18:41:00Z"))
        self.assertIsNotNone(info)
        self.assertFalse(info["escalated"])
        self.assertEqual([], chain.card_lines(info))

    def test_two_distinct_stages_escalate(self):
        chain.observe(alert("AnomalousServiceAccountSecretAccess", "2026-09-22T18:12:00Z"))
        info = chain.observe(alert("VeleroBackupDeleted", "2026-09-22T18:41:00Z"))
        self.assertTrue(info["escalated"])
        self.assertTrue(info["needs_recovery_check"])
        self.assertTrue(chain.card_lines(info))

    def test_same_stage_repeated_does_not_escalate(self):
        for i in range(5):
            info = chain.observe(alert("VeleroBackupDeleted", f"2026-09-22T18:0{i}:00Z"))
        self.assertFalse(info["escalated"])

    def test_outside_window_does_not_escalate(self):
        chain.observe(alert("AnomalousServiceAccountSecretAccess", "2026-09-22T10:00:00Z"))
        info = chain.observe(alert("VeleroBackupDeleted", "2026-09-22T18:41:00Z"))
        self.assertFalse(info["escalated"])

    def test_unrelated_alert_matches_no_stage(self):
        self.assertIsNone(chain.observe(alert("KubePodCrashLooping", "2026-09-22T18:00:00Z")))

    def _falco(self, cmd, ts):
        # Falco 출력엔 proc.cmdline 이 그대로 실린다 = 컨테이너 안 공격자가 쓰는 텍스트
        return {"fingerprint": "fp-" + ts,  # Alertmanager 가 붙이는 값. 없으면 observe 가 같은 건으로 합친다
                "labels": {"rule": "Terminal shell in container", "source": "falco",
                           "k8s_ns_name": "default"},
                "annotations": {"description": f"A shell was spawned ... cmdline={cmd}"},
                "startsAt": ts}

    def test_attacker_text_alone_is_suspected_not_escalated(self):
        chain.observe(self._falco("sh -c 'echo delete backup'", "2026-09-22T18:00:00Z"))
        info = chain.observe(self._falco("sh -c 'echo ransom'", "2026-09-22T18:01:00Z"))
        self.assertEqual(info["stage_count"], 2)
        self.assertFalse(info["escalated"])
        self.assertTrue(info["suspected"])
        self.assertEqual(info["severity"], "warning")
        lines = chain.card_lines(info)
        self.assertTrue(lines and "의심" in lines[0] and "승격" in lines[0])

    def test_one_named_stage_plus_keyword_escalates(self):
        chain.observe(alert("VeleroBackupDeleted", "2026-09-22T18:00:00Z"))
        info = chain.observe(self._falco("openssl enc -in db.dump -out db.dump.locked", "2026-09-22T18:05:00Z"))
        self.assertTrue(info["escalated"])
        self.assertEqual({s["stage"]: s["basis"] for s in info["stages"]},
                         {"S2-backup-destroy": "name", "S3-mass-encrypt": "keyword"})

    def test_fixture_alerts_never_enter_real_chain(self):
        # 2026-09-24: 데모 fx- 알림 2건이 실제 Falco 카드에 "3/4단계"로 붙어 발송됐다
        chain.observe(alert("AnomalousServiceAccountSecretAccess", "2026-09-22T18:00:00Z"), fixture=True)
        chain.observe(alert("VeleroBackupDeleted", "2026-09-22T18:05:00Z"), fixture=True)
        real = chain.observe(self._falco("openssl enc -in db.dump -out db.dump.locked", "2026-09-22T18:06:00Z"))
        self.assertEqual(real["stage_count"], 1)
        self.assertEqual([], chain.card_lines(real))

    def test_fixtures_still_chain_among_themselves(self):
        chain.observe(alert("VeleroBackupDeleted", "2026-09-22T18:00:00Z"))  # 실제 알림은 섞이지 않는다
        info = chain.observe(alert("AnomalousServiceAccountSecretAccess", "2026-09-22T18:05:00Z"), fixture=True)
        self.assertEqual(info["stage_count"], 1)
        info = chain.observe({**alert("VeleroBackupDeleted", "2026-09-22T18:06:00Z"), "fingerprint": "fx-2"}, fixture=True)
        self.assertTrue(info["escalated"])

    def test_unrelated_alert_during_chain_gets_no_banner(self):
        # 2026-09-24: 체인 창 안에 들어온 lynis 오탐 Falco 카드에 "랜섬웨어 3/4단계"가 붙어 발송됐다
        chain.observe(alert("AnomalousServiceAccountSecretAccess", "2026-09-22T18:00:00Z"))
        self.assertTrue(chain.observe(alert("VeleroBackupDeleted", "2026-09-22T18:05:00Z"))["escalated"])
        lynis = {"fingerprint": "fp-lynis", "startsAt": "2026-09-22T18:06:00Z",
                 "labels": {"rule": "Clear Log Activities", "source": "falco"},
                 "annotations": {"description": "lynis touched /var/log/lynis-report.dat"}}
        self.assertIsNone(chain.observe(lynis))
        self.assertEqual([], chain.card_lines(chain.observe(lynis)))

    def test_chain_still_seen_by_next_stage_after_unrelated_alert(self):
        chain.observe(alert("AnomalousServiceAccountSecretAccess", "2026-09-22T18:00:00Z"))
        chain.observe(alert("KubePodCrashLooping", "2026-09-22T18:02:00Z"))  # 무관 알림이 끼어도
        info = chain.observe(alert("VeleroBackupDeleted", "2026-09-22T18:05:00Z"))
        self.assertTrue(info["escalated"])
        self.assertEqual(info["stage_count"], 2)


class RedactTest(unittest.TestCase):
    def test_masks_value_not_key(self):
        out, hits = redact.redact("R2_SECRET_ACCESS_KEY=wJalrXUtnFEMIK7MDENGbPxRfiCY")
        self.assertIn("R2_SECRET_ACCESS_KEY=", out)
        self.assertNotIn("wJalrXUtnFEMIK7MDENGbPxRfiCY", out)
        self.assertTrue(hits)

    def test_idempotent(self):
        once, _ = redact.redact("token: abcd1234abcd1234abcd1234")
        twice, hits = redact.redact(once)
        self.assertEqual(once, twice)
        self.assertEqual([], redact.scan(twice))

    def test_scan_never_returns_the_value(self):
        secret = "nvapi-0123456789abcdefghijklmnop"
        for hit in redact.scan(f"key={secret}"):
            self.assertNotIn(secret, repr(hit))

    def test_digest_and_image_tag_are_not_secrets(self):
        clean = ("image: ghcr.io/myoungsoo7/watchman@sha256:"
                 "3b1f0c7d9a5e4c2b8f6a0d1e7c4b9a2f5e8d3c6b1a4f7e0d9c2b5a8f3e6d1c4b")
        self.assertEqual([], redact.scan(clean))

    def test_guard_walks_nested_structures(self):
        out = redact.guard({"a": [{"b": "password=hunter2hunter2hunter2"}]})
        self.assertNotIn("hunter2hunter2hunter2", str(out))

    # 2026-09-24 보안 리뷰: redact 는 json.dumps 결과에 적용되는데, 키 뒤에 닫는 따옴표가
    # 끼는 JSON·repr 꼴을 kv_secret 이 못 잡았다. 앱이 설정을 JSON 으로 로그에 찍으면
    # 그 값이 그대로 NIM·감사로그·카드로 나갔다.
    def test_json_and_repr_shaped_secrets_are_masked(self):
        for text in ('{"password": "SuperSecretValue123"}',
                     "{'db_password': 'SuperSecretValue123'}",
                     '"apiKey":"SuperSecretValue123"',
                     "password=hunter2x"):
            out, hits = redact.redact(text)
            self.assertNotIn("SuperSecretValue123", out, text)
            self.assertNotIn("hunter2x", out, text)
            self.assertTrue(hits, text)

    def test_url_userinfo_password_is_masked(self):
        out, _ = redact.redact("jdbc url postgres://settle:pw12345@jen-postgres:5432/db")
        self.assertNotIn("pw12345", out)
        self.assertIn("postgres://settle:", out)   # 어떤 계정인지는 읽혀야 한다
        self.assertIn("@jen-postgres", out)

    def test_vendor_api_keys_are_masked(self):
        for secret in ("sk-ant-api03-" + "A1b2C3d4" * 5,
                       "sk-proj-" + "A1b2C3d4" * 5,
                       "AIzaSy" + "A1b2C3d4E5" * 3 + "abcde"):
            out, _ = redact.redact(f"found {secret} in env")
            self.assertNotIn(secret, out)

    def test_guard_masks_values_under_sensitive_keys(self):
        # 값이 짧거나 무늬가 없어도 키 이름이 비밀이면 통째로 가린다.
        out, hits = redact.guard({"password": "abc", "DB_PASSWORD": "x1",
                                  "prompt_tokens": 18768, "token_count": "12"})
        self.assertNotIn("abc", str(out["password"]))
        self.assertNotIn("x1", str(out["DB_PASSWORD"]))
        self.assertEqual(18768, out["prompt_tokens"])   # 수치 필드는 건드리지 않는다
        self.assertEqual("12", out["token_count"])
        self.assertTrue(hits)

    def test_ordinary_log_lines_stay_clean(self):
        for clean in ('{"level":"info","msg":"token refreshed","user":"lms"}',
                      "password policy updated for 3 users",
                      "https://security.lemuel.co.kr/view"):
            self.assertEqual([], redact.scan(clean), clean)


def _velero(backups=(), schedules=(), bsls=()):
    def fetch(kind):
        return {"backups": {"items": list(backups)},
                "schedules": {"items": list(schedules)},
                "backupstoragelocations": {"items": list(bsls)}}[kind]
    return fetch


NOW = datetime.datetime(2026, 9, 22, 16, 0, tzinfo=datetime.timezone.utc)


class RecoveryTest(unittest.TestCase):
    def test_cron_interval(self):
        self.assertEqual(4, recovery.cron_interval_hours("0 */4 * * *"))
        self.assertEqual(24, recovery.cron_interval_hours("0 3 * * *"))
        self.assertIsNone(recovery.cron_interval_hours("0 3 * * 1-5"))

    def test_fetch_error_is_unknown_not_healthy(self):
        def boom(kind):
            raise RuntimeError("403")
        res = recovery.assess(boom, now=NOW)
        self.assertEqual("미확인", res["verdict"])
        self.assertTrue(res["notes"])

    def test_no_completed_backup_is_failure(self):
        res = recovery.assess(_velero(backups=[
            {"metadata": {"name": "b1"}, "status": {"phase": "Deleting"}}]), now=NOW)
        self.assertEqual("복구 불가 의심", res["verdict"])

    def test_healthy(self):
        res = recovery.assess(_velero(
            backups=[{"metadata": {"name": "b1"},
                      "status": {"phase": "Completed",
                                 "completionTimestamp": "2026-09-22T12:05:00Z"}}],
            schedules=[{"metadata": {"name": "hourly"},
                        "spec": {"schedule": "0 */4 * * *"},
                        "status": {"lastBackup": "2026-09-22T12:00:19Z"}}],
            bsls=[{"metadata": {"name": "default"}, "status": {"phase": "Available"}}]),
            now=NOW)
        self.assertEqual("복구 가능", res["verdict"])


class InvariantsTest(unittest.TestCase):
    def test_probe_failure_is_unknown(self):
        def boom(key):
            raise RuntimeError("403")
        res = invariants.run(boom)
        self.assertEqual(5, res["unknown_count"])
        self.assertEqual(0, res["fail_count"])

    def test_upstream_default_key_detected_without_printing_it(self):
        def probe(key):
            return {"repo_password": {"value": "static-passw0rd"}}.get(key) or {}
        out = [r for r in invariants.run(probe)["results"] if r["id"] == "I3"][0]
        self.assertEqual("FAIL", out["status"])
        self.assertNotIn("static-passw0rd", str(out))

    def test_unqueryable_lock_is_unknown_not_fail(self):
        def probe(key):
            return {"bucket_lock": {"queryable": False}}.get(key) or {}
        out = [r for r in invariants.run(probe)["results"] if r["id"] == "I2"][0]
        self.assertEqual("UNKNOWN", out["status"])


if __name__ == "__main__":
    unittest.main()
