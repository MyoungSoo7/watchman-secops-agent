"""카드의 증거 커버리지·동결 지시·신고 기한 시험 (E).

SKT 침해사고 조사결과가 지적한 두 가지를 카드가 구조적으로 못 숨기게 한다.
  ① 남아있던 로그 6건 중 1건만 확인 → '확인한 증거 N/M' 과 못 본 항목 이름 강제
  ② 서버 2대가 조치 과정에서 포렌식 불가 상태가 됨 → '만지기 전에 동결' 강제

실행: python3 -m unittest test_card_evidence -v
"""

import datetime
import os
import unittest

os.environ.setdefault("LLM_MODE", "mock")

import watchman as w


def _alert(labels, hours_ago=3):
    started = (datetime.datetime.now(datetime.timezone.utc)
               - datetime.timedelta(hours=hours_ago))
    return {"alerts": [{"startsAt": started.isoformat().replace("+00:00", "Z"),
                        "labels": labels}]}


def _result(coverage, classification="테스트 분류"):
    return {"classification": classification, "confidence": "중간",
            "evidence": ["e1"], "proposals": [],
            "run_id": "t-001", "coverage": list(coverage)}


FALCO_BPF = {"rule": "BPF filter attached to socket (BPFDoor pattern)",
             "k8s_ns_name": "settlement-prod", "k8s_pod_name": "api-7c9"}


class 라벨폴백(unittest.TestCase):
    def test_falco_라벨도_제목이_만들어진다(self):
        card = w.format_card(_alert(FALCO_BPF), _result([]))
        self.assertIn("BPFDoor pattern", card.splitlines()[0])
        self.assertIn("settlement-prod/api-7c9", card.splitlines()[0])
        self.assertNotIn("?", card.splitlines()[0])

    def test_대상이_없으면_슬래시만_남기지_않는다(self):
        card = w.format_card(
            _alert({"alertname": "PlaintextCredentialDelta", "source": "cred-sweep"}),
            _result([]))
        head = card.splitlines()[0]
        self.assertNotIn("/", head)
        self.assertIn("cred-sweep", head)


class 증거커버리지(unittest.TestCase):
    def test_못_본_증거원의_이름이_카드에_박힌다(self):
        card = w.format_card(_alert(FALCO_BPF), _result(["pod_status", "es"]))
        self.assertIn("확인한 증거 2/5", card)
        self.assertIn("컨테이너 로그", card)
        self.assertIn("네임스페이스 이벤트", card)

    def test_전부_봤으면_전부_확인으로_표시된다(self):
        full = ["pod_status", "pod_logs", "events", "workload", "es"]
        card = w.format_card(_alert(FALCO_BPF), _result(full))
        self.assertIn("확인한 증거 5/5", card)
        self.assertIn("전부 확인", card)

    def test_커버리지_키가_도구호출에서_환원된다(self):
        self.assertEqual(w.coverage_key("kube_read", {"verb": "logs"}), "pod_logs")
        self.assertEqual(w.coverage_key("kube_read", {"verb": "get", "resource": "pods"}),
                         "pod_status")
        self.assertEqual(w.coverage_key("kube_read", {"verb": "list", "resource": "events"}),
                         "events")
        self.assertEqual(w.coverage_key("es_search", {}), "es")
        self.assertIsNone(w.coverage_key("skill_query", {}))


class 동결과신고기한(unittest.TestCase):
    def test_침해의심이면_동결지시와_기한이_붙는다(self):
        card = w.format_card(_alert(FALCO_BPF), _result([]))
        self.assertIn("만지기 전에 동결", card)
        self.assertIn("/dev/shm", card)
        self.assertIn("신고 기한", card)
        self.assertIn("20시간", card)  # 3시간 경과 → 21시간 남음 근처

    def test_평범한_경보엔_붙지_않는다(self):
        card = w.format_card(
            _alert({"rule": "Contact K8S API Server From Container",
                    "k8s_ns_name": "logging", "k8s_pod_name": "fb-1"}),
            _result(["pod_status", "pod_logs", "events", "workload", "es"]))
        self.assertNotIn("만지기 전에 동결", card)
        self.assertNotIn("신고 기한", card)

    def test_크리덴셜_계열엔_파드동결이_아니라_회전금지가_나온다(self):
        card = w.format_card(
            _alert({"alertname": "PlaintextCredentialDelta", "source": "cred-sweep"}),
            _result([]))
        self.assertIn("키를 먼저 회전하지 말 것", card)
        self.assertNotIn("파드 재시작", card)

    def test_호스트_Falco_경보엔_키회전이_아니라_노드동결이_나온다(self):
        card = w.format_card(
            _alert({"rule": "Read sensitive file untrusted", "source": "falco",
                    "hostname": "david", "container_id": "host",
                    "fd_name": "/etc/pam.d/common-session"}),
            _result(["es"]))
        self.assertIn("만지기 전에 동결", card)
        self.assertIn("david 노드", card)
        self.assertNotIn("키를 먼저 회전하지 말 것", card)
        self.assertIn("신고 기한", card)

    def test_기한이_지나면_초과로_표시된다(self):
        card = w.format_card(_alert(FALCO_BPF, hours_ago=30), _result([]))
        self.assertIn("초과", card)

    def test_판정은_LLM_분류문이_아니라_라벨로_한다(self):
        # 분류문이 '정상' 이라고 해도 룰이 BPFDoor 계열이면 동결 지시는 남는다
        card = w.format_card(_alert(FALCO_BPF), _result([], classification="정상 운영"))
        self.assertIn("만지기 전에 동결", card)


class 사람몫(unittest.TestCase):
    def test_신고와_격리는_사람이_한다고_매번_적힌다(self):
        for labels in (FALCO_BPF, {"alertname": "X", "namespace": "default"}):
            card = w.format_card(_alert(labels), _result([]))
            self.assertIn("판단·신고·격리는 사람이 한다", card)


if __name__ == "__main__":
    unittest.main()
