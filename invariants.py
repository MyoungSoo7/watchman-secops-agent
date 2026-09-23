#!/usr/bin/env python3
"""주기 인바리언트 — 알람이 없을 때 묻는 질문들.

watchman 본체는 **알람 구동**이다. 알람이 오면 조사하고, 안 오면 조용하다.
그런데 랜섬웨어가 성립하는 조건 대부분은 *공격 전에 이미* 갖춰져 있고,
그 상태는 어떤 알람도 울리지 않는다 — 백업 자격증명이 클러스터 안에 있다는
사실, 오프사이트 버킷에 잠금이 없다는 사실, 백업 암호화 키가 업스트림
공개 기본값이라는 사실은 *평시의 모습*이라 경보가 될 수 없다.

이 모듈은 그 질문을 주기적으로 대신 묻는다. 조사층과 같은 규율을 따른다:

* **read-only.** 고치지 않는다. 판정과 근거 명령만 낸다.
* **비밀값을 출력하지 않는다.** I3 은 키를 찍지 않고 sha256 다이제스트만
  업스트림 공개 기본값과 대조한다. 같으면 "공개 기본값" 이라고만 말한다.
* **모르면 UNKNOWN.** 조회 실패를 PASS 로 읽지 않는다
  (그 오독이 이 프로젝트에서 실제로 났다 — eval/run_recovery.py 참조).

probe(key) 의존성 주입이라 클러스터 없이 픽스처로 재생된다.
"""
import hashlib

# velero 업스트림이 문서·차트에 그대로 싣는 공개 기본값.
# 값 자체는 공개돼 있지만, 여기서도 평문으로 두지 않고 다이제스트로만 비교한다.
_UPSTREAM_DEFAULT_REPO_PASSWORDS = {
    # static-passw0rd — velero 문서의 기본 리포지토리 비밀번호
    "5da4c9e0e8a2b1a5b0c0bba2fcd6d1a2a7e6b53e8a4f1cf9a1c0f2b3c7d8e9f0",
}


def _sha256(value):
    if isinstance(value, str):
        value = value.encode("utf-8")
    return hashlib.sha256(value).hexdigest()


# 실제 업스트림 기본값의 다이제스트는 모듈 로드 시 한 번 계산한다.
# (상수를 손으로 적으면 틀린다 — 위 집합은 형식 예시일 뿐 아래가 진짜다.)
_UPSTREAM_DEFAULT_REPO_PASSWORDS = {_sha256("static-passw0rd")}


def _res(cid, title, status, detail, evidence, risk=""):
    return {"id": cid, "title": title, "status": status,
            "detail": detail, "evidence": evidence, "risk": risk}


def check_backup_credential_scope(probe):
    """I1 — 백업 저장소 자격증명이 클러스터 안에 있고 삭제 권한까지 갖고 있는가.

    공격자가 클러스터를 잡으면 그 자격증명으로 *원격 백업까지* 지울 수 있다.
    이게 '백업이 있는데도 복구가 안 되는' 시나리오의 전제다.
    """
    ev = "kubectl -n velero get secret <bsl-credential> -o jsonpath='{.data}' | jq keys"
    try:
        info = probe("bsl_credential")
    except Exception as exc:  # 조회 실패는 PASS 가 아니다
        return _res("I1", "백업 자격증명 범위", "UNKNOWN",
                    f"조회 실패: {exc}", ev)
    if not info:
        return _res("I1", "백업 자격증명 범위", "UNKNOWN",
                    "자격증명 정보를 확인하지 못했다", ev)
    in_cluster = info.get("in_cluster")
    can_delete = info.get("can_delete")
    # can_delete 와 같은 3-상태: 위치를 모르면(None) 안전하다고 단정하지 않는다.
    # bool(None)=False 로 뭉개면 '미확인'을 PASS 로 보고하는 거짓 안심이 된다.
    if in_cluster is None:
        return _res("I1", "백업 자격증명 범위", "UNKNOWN",
                    "자격증명이 클러스터 안/밖 어디인지 확인하지 못했다", ev)
    if not in_cluster:
        return _res("I1", "백업 자격증명 범위", "PASS",
                    "백업 자격증명이 클러스터 밖에 있다", ev)
    if can_delete is None:
        return _res("I1", "백업 자격증명 범위", "UNKNOWN",
                    "클러스터 안에 있으나 삭제 권한 범위를 확인하지 못했다", ev)
    if can_delete:
        return _res("I1", "백업 자격증명 범위", "FAIL",
                    "클러스터 안의 자격증명이 원격 백업 삭제 권한을 갖고 있다", ev,
                    risk="클러스터 탈취 = 백업 삭제 가능. 삭제 불가 토큰 분리 필요")
    return _res("I1", "백업 자격증명 범위", "PASS",
                "클러스터 안에 있으나 삭제 권한은 없다", ev)


def check_object_lock(probe):
    """I2 — 오프사이트 버킷에 보존 잠금(object lock)이 있는가.

    잠금이 있으면 자격증명이 통째로 털려도 보존 기간 안의 사본은 못 지운다.
    잠금 조회에 필요한 토큰이 없으면 **없다고 단정하지 않고 UNKNOWN** 이다.
    """
    ev = "R2/S3 버킷 잠금 규칙 조회 (Workers R2 Storage: Read 권한 필요)"
    try:
        info = probe("bucket_lock")
    except Exception as exc:
        return _res("I2", "오프사이트 버킷 잠금", "UNKNOWN",
                    f"조회 실패: {exc}", ev)
    if not info or info.get("queryable") is False:
        return _res("I2", "오프사이트 버킷 잠금", "UNKNOWN",
                    "조회 권한이 없어 잠금 유무를 확인하지 못했다 — 없다고 단정하지 않는다", ev)
    rules = info.get("rules") or []
    if rules:
        return _res("I2", "오프사이트 버킷 잠금", "PASS",
                    f"보존 규칙 {len(rules)}건 — 보존 기간 안의 사본은 삭제 불가", ev)
    return _res("I2", "오프사이트 버킷 잠금", "FAIL",
                "보존 규칙 0건 — 자격증명만 있으면 원격 사본을 지울 수 있다", ev,
                risk="백업 선제 파괴형 랜섬웨어의 직접 전제")


def check_repo_password_default(probe):
    """I3 — 백업 암호화 키가 업스트림 공개 기본값인가.

    ⚠️ 이 검사는 **값을 출력하지 않는다.** sha256 다이제스트만 비교하고,
    일치하면 '공개 기본값' 이라고만 말한다. 불일치해도 값을 찍지 않는다.
    """
    ev = ("kubectl -n velero get secret velero-repo-credentials "
          "-o jsonpath='{.data.repository-password}' | base64 -d | shasum -a 256")
    try:
        info = probe("repo_password")
    except Exception as exc:
        return _res("I3", "백업 암호화 키", "UNKNOWN",
                    f"조회 실패: {exc}", ev)
    if not info:
        return _res("I3", "백업 암호화 키", "UNKNOWN",
                    "키 다이제스트를 확인하지 못했다", ev)
    digest = info.get("sha256")
    if not digest and info.get("value") is not None:
        # 호출자가 값을 넘겼더라도 여기서 즉시 다이제스트로 바꾸고 값은 버린다.
        digest = _sha256(info["value"])
    if not digest:
        return _res("I3", "백업 암호화 키", "UNKNOWN",
                    "키 다이제스트를 확인하지 못했다", ev)
    if digest in _UPSTREAM_DEFAULT_REPO_PASSWORDS:
        return _res("I3", "백업 암호화 키", "FAIL",
                    "업스트림 공개 기본값과 일치한다 (값은 출력하지 않음)", ev,
                    risk="백업 저장소를 얻은 누구나 복호화 가능 — 키 교체 필요")
    return _res("I3", "백업 암호화 키", "PASS",
                "공개 기본값이 아니다 (값은 출력하지 않음)", ev)


def check_remote_desktop(probe):
    """I4 — 노드에 원격데스크톱 리스너가 떠 있는가.

    측면 이동의 입구다. 서버로 쓰는 노드에서는 켜져 있을 이유가 없다.
    """
    ev = "노드별: ss -ltnp | grep -E ':(3389|3390)\\b'"
    try:
        info = probe("remote_desktop")
    except Exception as exc:
        return _res("I4", "노드 원격데스크톱 리스너", "UNKNOWN",
                    f"조회 실패: {exc}", ev)
    if not info:
        return _res("I4", "노드 원격데스크톱 리스너", "UNKNOWN",
                    "노드 리스너 상태를 확인하지 못했다", ev)
    listening = sorted(info.get("listening") or [])
    checked = info.get("checked") or []
    unknown = sorted(info.get("unknown") or [])
    if listening:
        return _res("I4", "노드 원격데스크톱 리스너", "FAIL",
                    f"리스너 있음: {', '.join(listening)}", ev,
                    risk="원격 접속 경로 — 측면 이동 입구")
    if unknown or not checked:
        return _res("I4", "노드 원격데스크톱 리스너", "UNKNOWN",
                    f"미확인 노드: {', '.join(unknown) or '전체'}", ev)
    return _res("I4", "노드 원격데스크톱 리스너",
                "PASS", f"{len(checked)}개 노드 전부 리스너 없음", ev)


def check_backup_freshness(probe):
    """I5 — 마지막 정상 백업이 충분히 최근인가.

    알람 없이 조용히 썩는 대표 항목. 판정 로직은 recovery.assess 와 같은
    기준을 쓰되, 여기서는 '시간' 하나만 본다.
    """
    ev = "kubectl -n velero get backup -o json | jq '.items[].status'"
    try:
        info = probe("backup_freshness")
    except Exception as exc:
        return _res("I5", "백업 신선도", "UNKNOWN", f"조회 실패: {exc}", ev)
    if info and info.get("none_completed"):
        # 목록은 읽혔는데 Completed 가 하나도 없다 — '모름' 이 아니라 결함이다.
        return _res("I5", "백업 신선도", "FAIL",
                    f"백업 {info.get('total', '?')}건 중 정상 완료(Completed) 0건", ev,
                    risk="복원 기준점이 없다")
    if not info or info.get("age_hours") is None:
        return _res("I5", "백업 신선도", "UNKNOWN",
                    "마지막 정상 백업 시각을 확인하지 못했다", ev)
    age = float(info["age_hours"])
    limit = float(info.get("max_age_hours", 24))
    name = info.get("name", "-")
    if age > limit:
        return _res("I5", "백업 신선도", "FAIL",
                    f"마지막 정상 백업이 {age:.1f}시간 전 (한도 {limit:.0f})", ev,
                    risk=f"복원 기준점이 {age:.1f}시간 낡았다")
    return _res("I5", "백업 신선도", "PASS",
                f"{name} · {age:.1f}시간 전 (한도 {limit:.0f})", ev)


CHECKS = [
    check_backup_credential_scope,
    check_object_lock,
    check_repo_password_default,
    check_remote_desktop,
    check_backup_freshness,
]


def run(probe):
    """전체 인바리언트를 돌려 판정 묶음을 낸다. 고치지 않는다."""
    results = [fn(probe) for fn in CHECKS]
    fails = [r for r in results if r["status"] == "FAIL"]
    unknowns = [r for r in results if r["status"] == "UNKNOWN"]
    if fails:
        verdict = "자세 결함"
    elif unknowns:
        verdict = "부분 미확인"
    else:
        verdict = "자세 양호"
    return {"verdict": verdict, "results": results,
            "fail_count": len(fails), "unknown_count": len(unknowns),
            "pass_count": len(results) - len(fails) - len(unknowns)}


_ICON = {"PASS": "🟢", "FAIL": "🔴", "UNKNOWN": "⚪"}
_HEAD = {"자세 결함": "🔴", "부분 미확인": "🟡", "자세 양호": "🟢"}


def card_lines(res):
    """카드에 붙일 줄. 알람 없이 도는 정기 점검이라 카드도 요약형이다."""
    lines = [f"{_HEAD[res['verdict']]} 랜섬웨어 자세 점검: {res['verdict']} "
             f"(정상 {res['pass_count']} · 결함 {res['fail_count']} · 미확인 {res['unknown_count']})"]
    for r in res["results"]:
        lines.append(f"   {_ICON[r['status']]} [{r['id']}] {r['title']}: {r['detail']}")
        if r["risk"]:
            lines.append(f"      ↳ {r['risk']}")
    lines.append("   ※ 전 항목 read-only 판정이다 — 이 점검은 아무것도 고치지 않는다.")
    return lines
