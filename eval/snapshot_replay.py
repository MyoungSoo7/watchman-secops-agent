"""알림 시점 증거 재생 — 도구를 실행하지 않고, 운영이 그 알림을 조사할 때 받은 결과를 돌려준다.

nat eval 재생은 지금 클러스터를 조사하므로 이미 복구된 사고는 증거가 사라져 있다
(2026-09-25: 운영 당시 incident 13/13 '사고' → 재생 3/13). 이 모듈은 도구 호출을
운영 run 의 기록과 (도구, 인자) 로 맞춰 그때 결과를 준다.

기록은 두 등급이다.
  - full   : snapshots.jsonl (watchman.snapshot_record) — LLM 이 본 마스킹 후 JSON 원문.
  - digest : 감사로그 tool.result_digest — repr 앞 1,500자. 스냅샷 도입 전 알림은 이것뿐이다.
운영과 다른 인자로 부르면 기록이 없다(miss). miss 는 현재 클러스터로 대체하지 않는다 —
섞으면 다시 "지금 상태" 재생이 된다. hit·digest·miss 건수를 run 마다 센다.
"""
import collections
import json


def alert_key(alert):
    return json.dumps(alert, ensure_ascii=False, sort_keys=True)


def _args_key(tool, args):
    return tool + " " + json.dumps(args or {}, ensure_ascii=False, sort_keys=True)


MISS = {"snapshot_miss": True,
        "error": "알림 시점 조사 기록에 없는 조회다. 이 재생에서는 그때 받은 결과가 있는 조회만 답한다."}


class Cursor:
    """한 run 의 기록. 같은 (도구, 인자) 가 여러 번이면 운영 순서대로 하나씩 꺼낸다."""

    def __init__(self, run_id, records):
        self.run_id = run_id
        self.left = collections.defaultdict(collections.deque)
        for r in records:
            self.left[_args_key(r["tool"], r["args"])].append(r)
        self.stats = {"hit": 0, "digest": 0, "miss": 0}

    def call(self, tool, args):
        q = self.left.get(_args_key(tool, args))
        if not q:
            self.stats["miss"] += 1
            return dict(MISS)
        r = q.popleft()
        if r["grade"] == "full":
            self.stats["hit"] += 1
            try:
                return json.loads(r["text"])
            except ValueError:  # 상한에서 잘린 기록 — 파싱은 못 해도 본문은 준다
                return {"result_text": r["text"]}
        self.stats["digest"] += 1
        return {"result_head": r["text"], "note": "알림 시점 결과의 앞 1,500자만 남아 있다"}


class Snapshots:
    def __init__(self, audit_paths=(), snapshot_paths=()):
        self.run_of = collections.defaultdict(list)  # alert_key → 운영 run id 들(같은 알림 재수신 포함)
        by_run = collections.defaultdict(list)
        full_runs = set()
        for p in snapshot_paths:
            for r in _jsonl(p):
                by_run[r["run"]].append({"tool": r["tool"], "args": r.get("args"),
                                         "text": r.get("text", ""), "grade": "full"})
                full_runs.add(r["run"])
        for p in audit_paths:
            for r in _jsonl(p):
                kind, run = r.get("kind"), r.get("run")
                if kind == "alert_in":
                    self.run_of[alert_key(r.get("payload"))].append(run)
                elif kind == "tool" and run not in full_runs:  # 원문이 있으면 요약은 안 쓴다
                    pl = r.get("payload") or {}
                    by_run[run].append({"tool": pl.get("tool"), "args": pl.get("args"),
                                        "text": pl.get("result_digest", ""), "grade": "digest"})
        self.by_run = dict(by_run)
        self.full_runs = full_runs

    def cursor_for(self, alert):
        runs = self.run_of.get(alert_key(alert)) or []
        # 같은 알림이 여러 번 들어왔으면 원문 기록이 있는 run → 요약이라도 있는 run → 첫 run 순
        for pick in (lambda r: r in self.full_runs, lambda r: r in self.by_run, lambda r: True):
            for run in runs:
                if pick(run):
                    return Cursor(run, self.by_run.get(run, []))
        return None


def _jsonl(path):
    with open(path, encoding="utf-8") as f:
        for line in f:
            try:
                yield json.loads(line)
            except ValueError:
                continue
