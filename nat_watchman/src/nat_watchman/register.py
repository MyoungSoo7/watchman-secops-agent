"""Watchman 을 NeMo Agent Toolkit(NAT) 플러그인으로 등록한다.

watchman.py 는 표준 라이브러리만 쓰는 단일 파일 에이전트다(운영 파드에 그대로 뜬다). 여기서는
그 루프를 **다시 짜지 않고 감싼다** — 운영과 같은 코드 경로를 NAT 의 `nat eval`·프로파일러로
재기 위해서다. 다시 짜면 "NAT 판에서 잰 숫자"가 운영 에이전트의 숫자가 아니게 된다.

등록하는 것:
  - watchman_triage     : 알림 JSON 1건 → 조사 → finish 판정(JSON). 워크플로 진입점.
  - watchman_es_search  : 읽기 전용 로그 검색 도구(허용목록 인덱스만).
  - watchman_kube_read  : 읽기 전용 K8s 조회 도구(secrets 무권한).
  - watchman_verdict    : 평가기 — 판정을 블라인드 라벨과 대조.

watchman 의 LLM·도구 호출은 NAT 콜백을 거치지 않으므로, 워커 스레드에서 호출마다 시각·토큰을
기록해 두었다가 조사가 끝나면 NAT 중간 스텝(LLM_START/END·TOOL_START/END)으로 옮긴다.
프로파일러가 보는 토큰·지연은 NIM 응답의 usage 필드와 벽시계 시각 그대로다(추정 없음).
"""
import asyncio
import json
import logging
import os
import sys
import threading
import time

from pydantic import Field

from nat.data_models.intermediate_step import IntermediateStepPayload
from nat.data_models.intermediate_step import IntermediateStepType
from nat.data_models.intermediate_step import StreamEventData
from nat.data_models.intermediate_step import UsageInfo
from nat.data_models.token_usage import TokenUsageBaseModel
from nat.plugin_api import Builder
from nat.plugin_api import Context
from nat.plugin_api import EvaluatorBaseConfig
from nat.plugin_api import EvaluatorInfo
from nat.plugin_api import FunctionBaseConfig
from nat.plugin_api import FunctionInfo
from nat.plugin_api import register_evaluator
from nat.plugin_api import register_function

logger = logging.getLogger(__name__)

_DEFAULT_REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
_wm = None
_wm_lock = threading.Lock()
_tl = threading.local()  # 워커 스레드별 호출 기록 — run 끼리 섞이지 않게


def _load_watchman(repo_dir: str, llm_mode: str, audit_path: str):
    """watchman 모듈을 한 번만 적재한다. 설정은 import 시점 ENV 로 굳으므로 그 전에 넣는다."""
    global _wm
    with _wm_lock:
        if _wm is not None:
            return _wm
        os.environ["LLM_MODE"] = llm_mode
        if audit_path:
            os.environ["AUDIT_PATH"] = audit_path
        # 평가 중 카드·메일이 실제로 나가면 안 된다 — .env 의 값보다 빈 값이 이기게 명시한다.
        os.environ["TELEGRAM_BOT_TOKEN"] = ""
        os.environ["SMTP_HOST"] = ""
        sys.path.insert(0, repo_dir)
        sys.path.insert(0, os.path.join(repo_dir, "eval"))
        try:
            import localnet  # 로컬 재생 시 ES 이름만 127.0.0.1 로 (TLS 검증은 그대로)
            localnet.install()
        except ImportError:
            pass
        import watchman as wm

        for name, fn in list(wm.TOOLS.items()):
            wm.TOOLS[name] = _record_tool(name, fn)
        _wm = wm
        return wm


def _record_tool(name, fn):
    def wrapped(args):
        rec = getattr(_tl, "rec", None)
        t0 = time.time()
        status, out = "ok", None
        try:
            out = fn(args)
            return out
        except Exception as e:
            status = type(e).__name__
            raise
        finally:
            if rec is not None:
                rec.append({"kind": "tool", "name": name, "t0": t0, "t1": time.time(),
                            "input": args, "status": status,
                            "output": (json.dumps(out, ensure_ascii=False, default=str)[:2000]
                                       if out is not None else None)})

    return wrapped


def _record_llm(wm, base):
    def llm(messages):
        rec = getattr(_tl, "rec", None)
        t0 = time.time()
        status, out = "ok", None
        try:
            out = base(messages)
            return out
        except Exception as e:
            status = type(e).__name__
            raise
        finally:
            u = getattr(wm._llm_usage, "last", None) or {}
            if rec is not None:
                rec.append({"kind": "llm", "name": u.get("model") or wm.NIM_MODEL, "t0": t0,
                            "t1": time.time(), "status": status, "output": (out or "")[:2000],
                            "prompt_tokens": int(u.get("prompt_tokens") or 0),
                            "completion_tokens": int(u.get("completion_tokens") or 0)})

    return llm


def _push_steps(rec):
    """기록을 NAT 중간 스텝으로 옮긴다. START/END 를 같은 UUID 로 짝지어 원래 시각을 싣는다."""
    mgr = Context.get().intermediate_step_manager
    for ev in rec:
        llm = ev["kind"] == "llm"
        start_t = IntermediateStepType.LLM_START if llm else IntermediateStepType.TOOL_START
        end_t = IntermediateStepType.LLM_END if llm else IntermediateStepType.TOOL_END
        start = IntermediateStepPayload(event_type=start_t, name=ev["name"], event_timestamp=ev["t0"],
                                        data=StreamEventData(input=ev.get("input")))
        mgr.push_intermediate_step(start)
        usage = None
        if llm:
            tok = TokenUsageBaseModel(prompt_tokens=ev["prompt_tokens"],
                                      completion_tokens=ev["completion_tokens"],
                                      total_tokens=ev["prompt_tokens"] + ev["completion_tokens"])
            usage = UsageInfo(token_usage=tok, num_llm_calls=1)
        mgr.push_intermediate_step(IntermediateStepPayload(
            UUID=start.UUID, event_type=end_t, name=ev["name"], event_timestamp=ev["t1"],
            span_event_timestamp=ev["t0"], usage_info=usage,
            metadata={"status": ev["status"]},
            data=StreamEventData(input=ev.get("input"), output=ev.get("output"))))


class WatchmanTriageConfig(FunctionBaseConfig, name="watchman_triage"):
    """Watchman SecOps 트리아지 — 알림 1건을 읽기 전용으로 조사해 판정(오탐/의심/사고)을 제안한다."""
    repo_dir: str = Field(default=_DEFAULT_REPO, description="watchman.py 가 있는 디렉터리")
    llm_mode: str = Field(default="nim", description="nim(실 NIM) | mock(결정적 대본, 키 불필요)")
    audit_path: str = Field(default="", description="감사로그 경로. 비우면 watchman 기본값")
    run_prefix: str = Field(default="nat", description="run id 접두사 — 운영 run 과 구분")


@register_function(config_type=WatchmanTriageConfig)
async def watchman_triage(config: WatchmanTriageConfig, builder: Builder):
    wm = _load_watchman(config.repo_dir, config.llm_mode, config.audit_path)
    seq = iter(range(1, 10**9))

    async def _triage(alert_json: str) -> str:
        """Alertmanager/Falco 알림 JSON 을 받아 조사하고 finish 판정을 JSON 문자열로 돌려준다."""
        alert = json.loads(alert_json) if isinstance(alert_json, str) else alert_json
        run_id = f"{config.run_prefix}-{time.strftime('%Y%m%d-%H%M%S')}-{next(seq):03d}"
        base = wm.MockLLM() if config.llm_mode == "mock" else wm.llm_chat_nim
        llm = _record_llm(wm, base)
        rec = []

        def work():
            _tl.rec = rec
            try:
                return wm.run_agent(alert, llm=llm, run_id=run_id)
            finally:
                _tl.rec = None

        t0 = time.time()
        res = await asyncio.to_thread(work) or {}
        _push_steps(rec)
        llms = [e for e in rec if e["kind"] == "llm"]
        out = {
            "run_id": run_id,
            "verdict": res.get("verdict"),
            "classification": res.get("classification"),
            "confidence": res.get("confidence"),
            "partial": bool(res.get("partial")),
            "seconds": round(time.time() - t0, 1),
            "llm_calls": len(llms),
            "tool_calls": sum(1 for e in rec if e["kind"] == "tool"),
            "prompt_tokens": sum(e["prompt_tokens"] for e in llms),
            "completion_tokens": sum(e["completion_tokens"] for e in llms),
            "models": sorted({e["name"] for e in llms if e["status"] == "ok"}),
        }
        return json.dumps(out, ensure_ascii=False)

    yield FunctionInfo.from_fn(_triage, description=_triage.__doc__)


class WatchmanToolConfig(FunctionBaseConfig, name="watchman_es_search"):
    """읽기 전용 로그 검색(허용목록 인덱스만). 인자는 watchman es_search 와 같다."""
    repo_dir: str = Field(default=_DEFAULT_REPO)
    llm_mode: str = Field(default="nim")


@register_function(config_type=WatchmanToolConfig)
async def watchman_es_search(config: WatchmanToolConfig, builder: Builder):
    wm = _load_watchman(config.repo_dir, config.llm_mode, "")

    async def _es_search(args_json: str) -> str:
        """ES 로그를 읽기 전용으로 검색한다. 입력: {"index": ..., "query": ..., "size": ...} JSON."""
        return json.dumps(await asyncio.to_thread(wm.TOOLS["es_search"], json.loads(args_json)),
                          ensure_ascii=False, default=str)

    yield FunctionInfo.from_fn(_es_search, description=_es_search.__doc__)


class WatchmanKubeConfig(FunctionBaseConfig, name="watchman_kube_read"):
    """읽기 전용 K8s 조회(get/list, secrets 무권한). 인자는 watchman kube_read 와 같다."""
    repo_dir: str = Field(default=_DEFAULT_REPO)
    llm_mode: str = Field(default="nim")


@register_function(config_type=WatchmanKubeConfig)
async def watchman_kube_read(config: WatchmanKubeConfig, builder: Builder):
    wm = _load_watchman(config.repo_dir, config.llm_mode, "")

    async def _kube_read(args_json: str) -> str:
        """K8s 리소스를 읽기 전용으로 조회한다. 입력: {"resource": ..., "namespace": ..., "name": ...} JSON."""
        return json.dumps(await asyncio.to_thread(wm.TOOLS["kube_read"], json.loads(args_json)),
                          ensure_ascii=False, default=str)

    yield FunctionInfo.from_fn(_kube_read, description=_kube_read.__doc__)


# 블라인드 라벨 → 정답 판정. unverifiable 등은 데이터셋 단계에서 뺀다.
EXPECT = {"benign": "오탐", "incident": "사고"}


class WatchmanVerdictConfig(EvaluatorBaseConfig, name="watchman_verdict"):
    """판정 정확도: 라벨(benign/incident)과 watchman verdict 를 대조한다. 부분 결과는 오답으로 센다."""


@register_evaluator(config_type=WatchmanVerdictConfig)
async def watchman_verdict(config: WatchmanVerdictConfig, builder):
    from nat.plugins.eval.data_models.evaluator_io import EvalOutputItem
    from nat.plugins.eval.evaluator.base_evaluator import BaseEvaluator

    class _Eval(BaseEvaluator):

        async def evaluate_item(self, item):
            gt = str(item.expected_output_obj).strip()
            try:
                out = json.loads(item.output_obj) if isinstance(item.output_obj, str) else item.output_obj
            except ValueError:
                out = {}
            got = (out or {}).get("verdict")
            want = EXPECT.get(gt, gt)
            ok = got == want and not (out or {}).get("partial")
            return EvalOutputItem(id=item.id, score=1.0 if ok else 0.0,
                                  reasoning={"expected": want, "got": got,
                                             "partial": (out or {}).get("partial"),
                                             # 치명 방향: 정상 알림을 '사고' 로 올린 경우
                                             "benign_escalated": gt == "benign" and got == "사고"})

    yield EvaluatorInfo(config=config, evaluate_fn=_Eval().evaluate,
                        description="Watchman 판정 vs 블라인드 라벨")
