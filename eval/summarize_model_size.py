#!/usr/bin/env python3
"""run_model_size.py 결과 JSON 들을 모델 크기별 표로 요약한다.

사용: python3 eval/summarize_model_size.py out/*.json
NIM 호출 자체가 실패한 run(llm_error) 은 모델 능력이 아니므로 분모에서 빼고 따로 적는다.
"""
import json
import sys


def pct(n, d):
    return f"{n}/{d} ({100 * n / d:.0f}%)" if d else "—"


def main(paths):
    print("| 모델 | 유효 run | 완주(유효 finish) | 도구 1회 이상 | 첫 응답 유효 | "
          "도구 호출 성공 | 인자 거부 | 형식 오류 | 평균 LLM 호출 | NIM 실패(제외) |")
    print("|---|---|---|---|---|---|---|---|---|---|")
    # 같은 모델의 여러 파일(본 실행 + NIM 실패분 재실행)을 케이스 단위로 합친다.
    # 케이스마다 NIM 이 끝까지 응답한 run 을 우선 쓰고, 없으면 실패 run 을 남긴다.
    by_model = {}
    for p in paths:
        d = json.load(open(p, encoding="utf-8"))
        cases = by_model.setdefault(d["model"], {})
        for r in d["rows"]:
            key = (r["case"], r["rep"])
            if key not in cases or (cases[key]["llm_error"] and not r["llm_error"]):
                cases[key] = r
    for model, cases in by_model.items():
        d = {"model": model}
        rows = list(cases.values())
        ok = [r for r in rows if not r["llm_error"]]
        n = len(ok)
        calls = sum(r["tool_ok"] + r["arg_rejected"] for r in ok)
        print("| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |".format(
            d["model"].split("/")[-1], n,
            pct(sum(r["finished"] for r in ok), n),
            pct(sum(bool(r["tool_ok"]) for r in ok), n),
            pct(sum(r["first_ok"] for r in ok), n),
            pct(sum(r["tool_ok"] for r in ok), calls),
            sum(r["arg_rejected"] for r in ok),
            sum(r["format_error"] + r["grace_violation"] for r in ok),
            f"{sum(r['llm_calls'] for r in ok) / n:.1f}" if n else "—",
            len(rows) - n))


if __name__ == "__main__":
    main(sys.argv[1:])
