#!/usr/bin/env python3
"""킬체인 상관관계 — 단발로는 중간 심각도인 알림이 *순서*로 오면 최고 심각도다.

watchman 의 트리아지는 알림 1건 단위다. 그런데 랜섬웨어는 알림 1건으로 오지 않는다.
자격증명 열람 → 백업 파괴 → 대량 암호화 → 측면 이동은 각각 따로 보면 "조사 필요"
수준인데, 같은 시간창 안에서 *서로 다른 단계*로 이어지면 그 순간 최고 심각도다.

이 모듈은 **결정론적**이다(LLM 없음). 순수 함수 `assess(events)` 하나가 본체이고,
`observe()` 는 서버 경로에서 최근 알림을 링버퍼에 쌓아 같은 함수를 부르는 얇은 껍데기다.
그래서 eval 하네스가 클러스터 없이 그대로 재현한다.

통제: 읽기만 한다. 승격은 **카드 표시와 제안**에만 영향을 주고 자동 조치는 없다.
"""
import json
import re
import threading
from datetime import datetime, timedelta, timezone

# ── 단계 정의 ──────────────────────────────────────────────────────────────
# alertnames 에 걸리면 그 단계로 본다. 못 걸리면 keywords 로 보조 판정한다
# (알림 이름은 룰셋마다 다르지만 본문 어휘는 잘 안 변한다).
STAGES = [
    {
        "id": "S1-credential",
        "title": "자격증명 열람·탈취",
        "alertnames": {
            "AnomalousServiceAccountSecretAccess",
            "AnomalousObjectEnumerationOnConsultAPI",
            "UnauthorizedSecretAccess",
        },
        "keywords": [r"secret\w*\s*(를|을)?\s*(대량|다수)", r"bulk secret", r"secret enumerat"],
    },
    {
        "id": "S2-backup-destroy",
        "title": "백업 파괴·무력화",
        "alertnames": {
            "VeleroBackupDeleted",
            "VeleroScheduleDeleted",
            "VeleroBackupStorageLocationUnavailable",
            "BackupRepositoryTampered",
        },
        "keywords": [
            r"backup\w*\s*(삭제|제거)", r"백업\w*\s*(삭제|제거|무력화)",
            r"delete\w*\s+backup", r"backupstoragelocation\w*\s*(unavailable|삭제)",
            r"bucket\w*\s*(비움|empt)",
        ],
    },
    {
        "id": "S3-mass-encrypt",
        "title": "대량 암호화·파일 변조",
        "alertnames": {
            "FalcoMassFileRenameInContainer",
            "FalcoSuspiciousFileEncryption",
            "PersistentVolumeWriteSurge",
        },
        "keywords": [
            r"대량\s*(파일)?\s*(rename|이름\s*변경|암호화)", r"mass file rename",
            r"\.(locked|encrypted|crypt)\b", r"ransom", r"랜섬",
        ],
    },
    {
        "id": "S4-lateral-login",
        "title": "원격 접속·측면 이동",
        "alertnames": {
            "NodeInteractiveLoginAnomaly",
            "FalcoTerminalShellInContainer",
            "SshLoginFromUnknownSource",
        },
        "keywords": [
            r"\brdp\b", r"\b3389\b", r"원격\s*데스크톱", r"gnome-remote-desktop",
            r"미등록.{0,10}(대역|ip).{0,20}(로그인|접속)",
        ],
    },
]
STAGE_INDEX = {s["id"]: i for i, s in enumerate(STAGES)}

CHAIN = {
    "id": "ransomware-backup-first",
    "title": "랜섬웨어 — 백업 선제 파괴형",
    "window_minutes": 180,   # 이 창 안의 서로 다른 단계만 한 체인으로 본다
    "escalate_at": 2,        # 서로 다른 단계 2개부터 승격
}
# 이 단계가 체인에 들어 있으면 복구가능성 조사를 반드시 붙인다(recovery.py).
RECOVERY_TRIGGER = "S2-backup-destroy"

RING_MAX = 200
_RING = []                      # [(datetime, fingerprint, alert)]
# 픽스처(fx-) 알림은 따로 담는다. 한 링에 섞으면 데모 알림이 실제 알림의 체인 단계로
# 잡혀, 전송이 막히지 않은 *실제* 카드에 가짜 "랜섬웨어 3/4단계"가 붙는다(2026-09-24 실측).
_FX_RING = []
_LOCK = threading.Lock()


def _text(alert):
    return json.dumps(alert, ensure_ascii=False).lower()


def stage_of(alert):
    """알림 1건이 어느 단계인지. 해당 없으면 None."""
    return stage_basis(alert)[0]


def stage_basis(alert):
    """(단계 id, 근거) — 근거는 "name"(룰 이름 일치) 또는 "keyword"(본문 어휘). 해당 없으면 (None, None).

    둘의 신뢰도가 다르다. 룰 이름은 탐지기(Prometheus 룰·Falco)가 붙인 것이지만,
    본문 어휘는 공격자가 쓸 수 있다 — Falco 출력엔 proc.cmdline 이 그대로 실리므로
    `sh -c "echo ransom; echo delete backup"` 한 줄이 두 단계를 만든다.
    """
    name = str((alert.get("labels") or {}).get("alertname", ""))
    for st in STAGES:
        if name in st["alertnames"]:
            return st["id"], "name"
    body = _text(alert)
    for st in STAGES:
        for pat in st["keywords"]:
            if re.search(pat, body):
                return st["id"], "keyword"
    return None, None


def _ts(alert, fallback=None):
    raw = str(alert.get("startsAt") or "")
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return fallback or datetime.now(timezone.utc)


def _fp(alert):
    return str(alert.get("fingerprint") or (alert.get("labels") or {}).get("alertname") or "?")


def assess(events):
    """순수 함수. events = [(datetime, alert)] (시간 오름차순 가정 아님).

    반환: 체인 판정 dict, 또는 None(체인 아님).
    """
    staged = []
    for ts, alert in events:
        sid, basis = stage_basis(alert)
        if sid:
            staged.append((ts, sid, basis, alert))
    if not staged:
        return None
    staged.sort(key=lambda x: x[0])

    newest = staged[-1][0]
    window = timedelta(minutes=CHAIN["window_minutes"])
    inwin = [s for s in staged if newest - s[0] <= window]

    seen = {}
    for ts, sid, basis, alert in inwin:
        seen.setdefault(sid, {"stage": sid,
                              "title": STAGES[STAGE_INDEX[sid]]["title"],
                              "first_seen": ts.isoformat(),
                              "basis": "keyword",
                              "alerts": []})
        seen[sid]["alerts"].append(_fp(alert))
        if basis == "name":
            seen[sid]["basis"] = "name"
    order = sorted(seen.values(), key=lambda s: STAGE_INDEX[s["stage"]])
    count = len(order)
    # 승격(critical)은 룰 이름으로 잡힌 단계가 하나 이상 있을 때만. 전부 어휘로만 잡혔으면
    # "의심"(warning) — 사람이 확인할 대상이지 최고 심각도가 아니다. 단계 수 기준은 그대로.
    by_name = any(s["basis"] == "name" for s in order)
    enough = count >= CHAIN["escalate_at"]
    escalated = enough and by_name
    suspected = enough and not by_name

    missing = [s["id"] for s in STAGES if s["id"] not in seen]
    nxt = None
    for s in STAGES:
        if s["id"] not in seen and STAGE_INDEX[s["id"]] > STAGE_INDEX[order[-1]["stage"]]:
            nxt = {"stage": s["id"], "title": s["title"]}
            break

    return {
        "chain": CHAIN["id"],
        "title": CHAIN["title"],
        "window_minutes": CHAIN["window_minutes"],
        "stage_count": count,
        "stages": order,
        "missing": missing,
        "next_expected": nxt,
        "escalated": escalated,
        "suspected": suspected,
        "severity": "critical" if escalated else ("warning" if suspected else "info"),
        "needs_recovery_check": RECOVERY_TRIGGER in seen,
        "why": (
            f"{CHAIN['window_minutes']}분 창 안에서 서로 다른 단계 {count}개가 이어졌다 "
            f"({' → '.join(s['title'] for s in order)}). 단계별 알림은 각각 중간 심각도지만 "
            f"순서로 읽으면 {CHAIN['title']} 진행형이다."
            if escalated else
            f"단계 {count}개가 이어졌지만 전부 본문 어휘로만 잡혔다 — 알림 본문은 공격자가 "
            f"쓸 수 있으므로 승격하지 않고 의심으로 둔다."
            if suspected else
            f"단계 {count}개만 관측됐다 — 체인 승격 기준({CHAIN['escalate_at']}개) 미만."
        ),
    }


def observe(alert, now=None, fixture=False):
    """서버 경로용 — 링버퍼에 넣고 현재 창을 재판정한다. 중복 fingerprint 는 갱신.

    fixture=True 면 픽스처 전용 링에서만 판정한다 — 픽스처끼리만 체인이 되고
    실제 알림의 판정엔 절대 들어가지 않는다.
    """
    ts = _ts(alert, now)
    fp = _fp(alert)
    ring = _FX_RING if fixture else _RING
    with _LOCK:
        for i, (_, ofp, _a) in enumerate(ring):
            if ofp == fp:
                ring.pop(i)
                break
        ring.append((ts, fp, alert))
        if len(ring) > RING_MAX:
            del ring[: len(ring) - RING_MAX]
        snapshot = [(t, a) for t, _f, a in ring]
    info = assess(snapshot)
    # 체인 판정은 *이 알림이 그 체인의 한 단계일 때만* 돌려준다. 창 안에 체인이 있다는
    # 이유만으로 무관한 알림(예: lynis 정기 점검 Falco)에 랜섬웨어 배너가 붙어 발송됐다
    # (2026-09-24 실측). 체인 자체는 링에 남아 있어 다음 단계 알림이 오면 다시 잡힌다.
    if info and not any(fp in s["alerts"] for s in info["stages"]):
        return None
    return info


def reset():
    with _LOCK:
        _RING.clear()
        _FX_RING.clear()


def card_lines(info):
    """카드에 붙일 3줄 이하 요약. 승격·의심 아닐 땐 빈 리스트."""
    if info and info.get("suspected"):
        chain = " → ".join(f"{s['title']}" for s in info["stages"])
        return [f"🔍 킬체인 의심(어휘 기반·미승격) — {info['title']} ({info['stage_count']}/{len(STAGES)}단계)",
                f"   {chain}",
                "   룰 이름이 아니라 본문 어휘로만 맞았다 — 본문은 공격자가 쓸 수 있으니 원 알림을 확인"]
    if not info or not info.get("escalated"):
        return []
    chain = " → ".join(f"{s['title']}" for s in info["stages"])
    lines = [
        f"🔗 킬체인 감지 — {info['title']} ({info['stage_count']}/{len(STAGES)}단계)",
        f"   {chain}",
    ]
    if info.get("next_expected"):
        lines.append(f"   다음 예상 단계: {info['next_expected']['title']}")
    if info.get("needs_recovery_check"):
        lines.append("   ⚠ 백업 파괴 단계 포함 — 복구가능성 조사 필요(recovery_check)")
    return lines
