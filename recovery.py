#!/usr/bin/env python3
"""복구가능성 조사 — "백업이 있다"가 아니라 "지금 복구할 수 있는가"를 묻는다.

랜섬웨어 대응에서 조치 제안의 급을 가르는 것은 탐지가 아니라 이 한 줄이다:
*마지막으로 복구 가능한 시점은 언제인가.* 그 답이 없으면 어떤 제안도 "일단 격리"
이상으로 못 간다.

전부 **read-only** 다. velero 의 Backup·Schedule·BackupStorageLocation 을 조회해
세 가지를 판정한다.

  R1 최근 정상 백업의 나이      — Completed 백업이 있고 충분히 최신인가
  R2 스케줄 신선도              — 각 스케줄의 lastBackup 이 자기 주기 안에 있는가
  R3 백업 저장 위치 가용성      — BSL phase 가 Available 인가

의존성 주입 구조다. `assess(fetch)` 의 `fetch(kind)` 가 velero 리스트 응답(dict)을
돌려주면 되므로, 클러스터 없이 픽스처로 그대로 재현된다.

⚠ 여기서 '복구 가능'은 **백업 오브젝트가 온전하다**는 뜻이지 복원이 성공한다는
보장이 아니다. 복원 성공은 비파괴 복원 리허설로만 증명된다(SPEC 참조).
"""
import re
from datetime import datetime, timedelta, timezone

# 나이 임계 — 시간 단위. 스케줄 주기를 모를 때의 기본값.
DEFAULT_MAX_AGE_H = 24
STALE_FACTOR = 2.0   # 주기의 2배를 넘으면 지연으로 본다


def _dt(raw):
    if not raw:
        return None
    try:
        return datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    except ValueError:
        return None


def cron_interval_hours(cron):
    """아주 단순한 cron 주기 추정. 모르면 None 을 돌려준다(추측하지 않는다)."""
    if not cron:
        return None
    parts = str(cron).split()
    if len(parts) < 5:
        return None
    # 일·월·요일 필드가 하나라도 제한돼 있으면 주기가 균일하지 않다.
    # 예: "0 3 * * 1-5" 는 하루 주기처럼 보이지만 금→월 간격이 72시간이다.
    # 그 경우 24 를 돌려주면 주말마다 거짓 FAIL 이 난다 — 모른다고 답한다.
    if any(f != "*" for f in parts[2:5]):
        return None
    hour = parts[1]
    m = re.fullmatch(r"\*/(\d+)", hour)
    if m:
        return int(m.group(1))
    if hour == "*":
        return 1
    if re.fullmatch(r"\d+(,\d+)*", hour):
        n = len(hour.split(","))
        return max(1, 24 // n)
    return None


def _items(resp):
    return list((resp or {}).get("items") or [])


def assess(fetch, now=None):
    """fetch(kind) -> velero 리스트 응답. kind 는 backups|schedules|backupstoragelocations."""
    now = now or datetime.now(timezone.utc)
    findings = []
    notes = []

    # R1 — 최근 정상 백업
    try:
        backups = _items(fetch("backups"))
    except Exception as e:                       # 조회 실패는 '정상'이 아니라 '미확인'
        backups = []
        notes.append(f"backups 조회 실패: {e}")
    completed = []
    for b in backups:
        st = b.get("status") or {}
        if st.get("phase") == "Completed":
            ts = _dt(st.get("completionTimestamp") or st.get("startTimestamp"))
            if ts:
                completed.append((ts, b.get("metadata", {}).get("name") or b.get("name")))
    completed.sort()
    if completed:
        ts, name = completed[-1]
        age_h = (now - ts).total_seconds() / 3600.0
        findings.append({
            "id": "R1", "title": "최근 정상 백업",
            "status": "PASS" if age_h <= DEFAULT_MAX_AGE_H else "WARN",
            "detail": f"{name} · {age_h:.1f}시간 전 · Completed {len(completed)}건",
            "age_hours": round(age_h, 1), "last_good": name,
        })
    else:
        findings.append({
            "id": "R1", "title": "최근 정상 백업",
            "status": "FAIL" if backups else "UNKNOWN",
            "detail": ("Completed 백업 0건 — 복원 기준점 없음" if backups
                       else "백업 목록을 조회하지 못했다(권한·연결 미확인)"),
            "age_hours": None, "last_good": None,
        })

    # R2 — 스케줄 신선도
    try:
        schedules = _items(fetch("schedules"))
    except Exception as e:
        schedules = []
        notes.append(f"schedules 조회 실패: {e}")
    stale = []
    for s in schedules:
        name = (s.get("metadata") or {}).get("name") or s.get("name")
        spec = s.get("spec") or {}
        cron = spec.get("schedule")
        last = _dt((s.get("status") or {}).get("lastBackup"))
        iv = cron_interval_hours(cron) or DEFAULT_MAX_AGE_H
        if spec.get("paused"):
            stale.append(f"{name}: 일시중지됨")
            continue
        if not last:
            stale.append(f"{name}: lastBackup 없음")
            continue
        age = (now - last).total_seconds() / 3600.0
        if age > iv * STALE_FACTOR:
            stale.append(f"{name}: {age:.1f}시간 전 (주기 {iv}시간)")
    if schedules:
        findings.append({
            "id": "R2", "title": "스케줄 신선도",
            "status": "PASS" if not stale else "FAIL",
            "detail": (f"스케줄 {len(schedules)}개 모두 자기 주기 안" if not stale
                       else "지연·중지: " + " · ".join(stale)),
        })
    else:
        findings.append({"id": "R2", "title": "스케줄 신선도", "status": "UNKNOWN",
                         "detail": "스케줄을 조회하지 못했거나 0개"})

    # R3 — 저장 위치 가용성
    try:
        bsls = _items(fetch("backupstoragelocations"))
    except Exception as e:
        bsls = []
        notes.append(f"backupstoragelocations 조회 실패: {e}")
    bad = []
    for b in bsls:
        name = (b.get("metadata") or {}).get("name") or b.get("name")
        phase = (b.get("status") or {}).get("phase")
        if phase != "Available":
            bad.append(f"{name}: {phase or '상태없음'}")
    if bsls:
        findings.append({
            "id": "R3", "title": "백업 저장 위치",
            "status": "PASS" if not bad else "FAIL",
            "detail": (f"{len(bsls)}개 전부 Available" if not bad
                       else "이상: " + " · ".join(bad)),
        })
    else:
        findings.append({"id": "R3", "title": "백업 저장 위치", "status": "UNKNOWN",
                         "detail": "BSL 을 조회하지 못했거나 0개"})

    st = {f["status"] for f in findings}
    if "FAIL" in st:
        verdict, headline = "복구 불가 의심", "복원 기준점이 깨졌거나 저장 위치가 이상하다"
    elif "UNKNOWN" in st:
        verdict, headline = "미확인", "복구 가능 여부를 관측으로 확인하지 못했다"
    elif "WARN" in st:
        verdict, headline = "복구 가능(지연)", "복원은 가능하나 최신 백업이 오래됐다"
    else:
        verdict, headline = "복구 가능", "최근 정상 백업·스케줄·저장 위치 모두 정상"

    return {"verdict": verdict, "headline": headline,
            "findings": findings, "notes": notes,
            "checked_at": now.isoformat()}


def card_lines(res):
    if not res:
        return []
    icon = {"복구 가능": "🟢", "복구 가능(지연)": "🟡",
            "미확인": "⚪", "복구 불가 의심": "🔴"}.get(res["verdict"], "⚪")
    lines = [f"{icon} 복구가능성: {res['verdict']} — {res['headline']}"]
    for f in res["findings"]:
        lines.append(f"   [{f['status']}] {f['title']}: {f['detail']}")
    if res.get("notes"):
        lines.append("   미확인 사유: " + " · ".join(res["notes"]))
    lines.append("   ※ '복구 가능'은 백업 오브젝트가 온전하다는 뜻이다 — 복원 성공은 리허설로만 증명된다.")
    return lines
