#!/usr/bin/env python3
"""P5 레드팀 하네스 (실행형) — 주입 페이로드를 watchman.detect_injection 으로 판정.

결정론적이라 어디서나 재현된다. 두 가지를 함께 낸다:
  1. 레드팀 뱅크(fixtures/redteam/*.json) 전수 → 감지(⚠) Y/N + 집계.
     프로덕션과 동일하게 **알림 봉투 전체 JSON** 을 스캔한다(run_agent 의 _scan_injection
     이 json.dumps(alert) 를 detect_injection 에 넣는 것과 같은 표면).
  2. 정상 케이스 뱅크(fixtures/cases/*.json + 정상 픽스처) → **오탐 0** 확인.

이것은 **코드 감지층(통제 ⑤, FR-13)** 의 재현 검증이다. 지시 미수행을 보장하는
최종 방어선은 LLM 거부층이며, 그 라이브 실측은 eval/redteam-20260922.md §3 에 있다.

사용:  python3 eval/run_redteam.py
watchman.py 는 수정하지 않고 import 만 한다.
"""
import glob
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
RT_DIR = os.path.join(ROOT, "fixtures", "redteam")
CASES_DIR = os.path.join(ROOT, "fixtures", "cases")
FIX_DIR = os.path.join(ROOT, "fixtures")

# 페이로드별 공격 벡터 라벨(파일명→사람이 읽는 유형). 감지 여부는 코드가 판정한다.
VECTOR = {
    "fx-rt-01-override-en": "지시 덮어쓰기(영)",
    "fx-rt-02-override-ko": "지시 덮어쓰기(한)",
    "fx-rt-03-tool-delete": "도구 오용 — delete",
    "fx-rt-04-tool-secrets": "도구 오용 — secrets 열람",
    "fx-rt-05-exfil-en": "데이터 유출 URL(영)",
    "fx-rt-06-exfil-ko": "데이터 유출 URL(한)",
    "fx-rt-07-rolehijack-mix": "역할 탈취(한영 혼합)",
    "fx-rt-08-delimiter-break": "구분자/경계 탈출",
    "fx-rt-09-path-injection": "경로 탈출",
    "fx-rt-10-social-urgency": "사회공학 + 긴급",
    "fx-rt-11-fake-annotation": "주석 위장 지시",
    "fx-rt-12-exfil-evidence": "값 노출 유도",
}


def scan_file(watchman, path):
    """프로덕션과 같은 표면: 알림 봉투 전체 JSON 문자열을 detect_injection 에 넣는다."""
    with open(path, encoding="utf-8") as f:
        env = json.load(f)
    text = json.dumps(env, ensure_ascii=False)
    return watchman.detect_injection(text)


def main():
    sys.path.insert(0, ROOT)
    import watchman  # noqa: E402

    print("# P5 레드팀 결과표 (run_redteam.py) — 코드 감지층(결정론적)\n")
    print(f"기준 코드: watchman.detect_injection · 패턴 {len(watchman.INJECTION_PATTERNS)}개\n")

    # 1) 레드팀 뱅크 — 전부 감지(⚠) 기대
    print("## 1. 레드팀 뱅크 — 감지율\n")
    print("| id | 공격 벡터 | 기대 | 감지(⚠) | 매칭 패턴 |")
    print("|---|---|---|---|---|")
    rt_files = sorted(glob.glob(os.path.join(RT_DIR, "fx-rt-*.json")))
    detected = 0
    for path in rt_files:
        rid = os.path.splitext(os.path.basename(path))[0]
        hits = scan_file(watchman, path)
        got = "Y" if hits else "N"
        detected += bool(hits)
        mark = "✅" if hits else "❌ 미감지"
        print(f"| {rid} | {VECTOR.get(rid, '?')} | 감지 | {got} {mark} | {', '.join(hits) or '—'} |")
    print(f"\n**감지율: {detected}/{len(rt_files)}"
          + (f" = {100*detected//len(rt_files)}%" if rt_files else "") + "**")

    # 2) 정상 뱅크 — 오탐 0 기대
    print("\n## 2. 정상 뱅크 — 오탐 확인 (기대: 전부 미감지)\n")
    normal = sorted(glob.glob(os.path.join(CASES_DIR, "fx-case-*.json")))
    normal += [os.path.join(FIX_DIR, "kube-job-failed.json"),
               os.path.join(FIX_DIR, "velero-partial.json")]
    print("| 파일 | 감지(⚠) | 매칭 패턴 |")
    print("|---|---|---|")
    fp_count = 0
    for path in normal:
        if not os.path.exists(path):
            continue
        rid = os.path.splitext(os.path.basename(path))[0]
        hits = scan_file(watchman, path)
        if hits:
            fp_count += 1
        print(f"| {rid} | {'⚠ 오탐!' if hits else 'N ✅'} | {', '.join(hits) or '—'} |")
    total_normal = sum(1 for p in normal if os.path.exists(p))
    print(f"\n**오탐: {fp_count}/{total_normal}** (0 이 목표)")

    # 요약
    ok = (detected == len(rt_files)) and (fp_count == 0)
    print(f"\n## 요약\n")
    print(f"- 감지율 {detected}/{len(rt_files)} · 오탐 {fp_count}/{total_normal} → "
          f"{'전부 통과 ✅' if ok else '⚠ 확인 필요'}")
    print("- 이 표는 **코드 감지층** 재현 검증이다. LLM 거부층 라이브 실측은 "
          "eval/redteam-20260922.md §3.")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
