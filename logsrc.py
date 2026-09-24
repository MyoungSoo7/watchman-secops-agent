#!/usr/bin/env python3
"""로그 백엔드 어댑터 — ES 가 아닌 곳(Loki·Datadog)에서 같은 조사를 하게 한다.

고객사 로그가 ES 에 있다는 보장은 없다. 그래서 `LOG_BACKEND` 가 es 가 아니면
es_search 대신 `log_search` 도구 하나를 노출하고, 조회는 이 모듈이 한다.

통제 ①(인자는 코드가 조립) 을 그대로 지킨다. LLM 은 LogQL·Datadog 쿼리 문법을
**쓰지 않는다.** 넘기는 것은 네 가지뿐이다:

  namespace     k8s 이름 규칙으로 검증(비우면 전체)
  contains      포함 문자열 — 따옴표 리터럴 안에 이스케이프해서만 들어간다
  minutes_back  1~240
  limit         1~50 (초과는 50 으로 자른다 — es_search 와 같은 규칙)

의존성 주입 구조다. `search(cfg, args, http)` 의 `http(url, data=None,
headers=None, method=None, verify=True)` 가 JSON 을 돌려주면 되므로, 백엔드 없이
가짜 응답으로 그대로 재현된다. 반환 모양은 es_search 와 같다
(`{"total": .., "hits": [{"@timestamp", "log", "kubernetes.*"}]}`) — 뒤쪽
(카드·감사로그·마스킹)은 백엔드를 모른다.
"""
import base64
import re
import time
import urllib.parse

BACKENDS = ("es", "loki", "datadog")
MAX_MINUTES = 240
MAX_LIMIT = 50
MAX_CONTAINS = 200
MAX_LINE = 2000          # 한 줄 로그 상한 — 스택트레이스 한 덩어리가 컨텍스트를 먹지 않게

_NS_RE = re.compile(r"^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?$")
_LABEL_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")
_SITE_RE = re.compile(r"^[a-z0-9]([a-z0-9.\-]{0,62})$")


class ArgError(ValueError):
    """인자 검증 실패 — 호출자가 LLM 에 돌려줄 오류로 바꾼다."""


def config_from_env(env):
    backend = (env.get("LOG_BACKEND", "es") or "es").strip().lower()
    if backend not in BACKENDS:
        raise ValueError(f"LOG_BACKEND={backend!r} — 허용값 {BACKENDS}")
    ns_label = env.get("LOKI_NAMESPACE_LABEL", "namespace")
    if not _LABEL_RE.match(ns_label):
        raise ValueError(f"LOKI_NAMESPACE_LABEL={ns_label!r} 은 라벨 이름이 아니다")
    site = env.get("DD_SITE", "datadoghq.com").strip().lower()
    if not _SITE_RE.match(site):
        raise ValueError(f"DD_SITE={site!r} 이 도메인 형식이 아니다")
    return {
        "backend": backend,
        "loki_url": env.get("LOKI_URL", "").rstrip("/"),
        "loki_user": env.get("LOKI_USER", ""),
        "loki_pass": env.get("LOKI_PASS", ""),
        "loki_token": env.get("LOKI_TOKEN", ""),
        "loki_tenant": env.get("LOKI_TENANT", ""),
        "loki_verify": env.get("LOKI_VERIFY_TLS", "1") != "0",
        "loki_ns_label": ns_label,
        "dd_site": site,
        "dd_api_key": env.get("DD_API_KEY", ""),
        "dd_app_key": env.get("DD_APP_KEY", ""),
    }


def label(cfg):
    return {"loki": "Loki", "datadog": "Datadog"}.get(cfg["backend"], "ES")


# ---------------------------------------------------------------- 인자 검증


def validate(args):
    ns = str(args.get("namespace", "") or "").strip()
    if ns and not _NS_RE.match(ns):
        raise ArgError(f"namespace '{ns[:80]}' 는 k8s 이름 형식이 아니다")
    contains = str(args.get("contains", "") or "")
    # 개행은 공백으로 — 줄 필터 한 줄 밖으로 새지 않게. 제어문자도 같이 걷는다.
    contains = re.sub(r"[\x00-\x1f\x7f]+", " ", contains).strip()[:MAX_CONTAINS]
    try:
        minutes = int(args.get("minutes_back", 60))
        limit = int(args.get("limit", 20))
    except (TypeError, ValueError):
        raise ArgError("minutes_back·limit 은 정수")
    if not (1 <= minutes <= MAX_MINUTES):
        raise ArgError(f"minutes_back 은 1~{MAX_MINUTES}")
    if limit < 1:
        raise ArgError(f"limit 은 1~{MAX_LIMIT}")
    return ns, contains, minutes, min(limit, MAX_LIMIT)


def _quote(s):
    """따옴표 문자열 리터럴 — 역슬래시·따옴표만 이스케이프하면 리터럴 밖으로 못 나간다."""
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


# ---------------------------------------------------------------- Loki


def loki_query(ns, contains, ns_label="namespace"):
    sel = f"{{{ns_label}={_quote(ns)}}}" if ns else f'{{{ns_label}=~".+"}}'
    return sel + (f" |= {_quote(contains)}" if contains else "")


def _loki_headers(cfg):
    h = {"Accept": "application/json"}
    if cfg["loki_token"]:
        h["Authorization"] = "Bearer " + cfg["loki_token"]
    elif cfg["loki_user"]:
        h["Authorization"] = "Basic " + base64.b64encode(
            f"{cfg['loki_user']}:{cfg['loki_pass']}".encode()).decode()
    if cfg["loki_tenant"]:
        h["X-Scope-OrgID"] = cfg["loki_tenant"]
    return h


def _first(d, keys):
    for k in keys:
        if d.get(k):
            return d[k]
    return None


def search_loki(cfg, ns, contains, minutes, limit, http, now_ns=None):
    if not cfg["loki_url"]:
        raise RuntimeError("LOKI_URL 미설정 — 이 환경에선 log_search 사용 불가")
    end = now_ns if now_ns is not None else time.time_ns()
    start = end - minutes * 60 * 1_000_000_000
    q = loki_query(ns, contains, cfg["loki_ns_label"])
    params = urllib.parse.urlencode({
        "query": q, "start": str(start), "end": str(end),
        "limit": str(limit), "direction": "backward",
    })
    data = http(f"{cfg['loki_url']}/loki/api/v1/query_range?{params}",
                headers=_loki_headers(cfg), method="GET",
                verify=cfg["loki_verify"])
    if data.get("status") != "success":
        raise RuntimeError(f"Loki 응답 status={data.get('status')!r}")
    hits = []
    for stream in (data.get("data") or {}).get("result") or []:
        lbl = stream.get("stream") or {}
        for ts, line in stream.get("values") or []:
            hits.append({
                "@timestamp": _ns_to_iso(ts),
                "log": str(line)[:MAX_LINE],
                "kubernetes.namespace_name": lbl.get(cfg["loki_ns_label"]),
                "kubernetes.pod_name": _first(lbl, ("pod", "pod_name", "k8s_pod_name")),
                "kubernetes.container_name": _first(
                    lbl, ("container", "container_name", "k8s_container_name")),
                "_ts": int(ts),
            })
    hits.sort(key=lambda h: h["_ts"], reverse=True)
    hits = hits[:limit]
    for h in hits:
        del h["_ts"]
    return {"total": {"value": len(hits), "relation": "gte" if len(hits) >= limit else "eq"},
            "query": q, "hits": hits}


def _ns_to_iso(ts):
    try:
        sec, frac = divmod(int(ts), 1_000_000_000)
    except (TypeError, ValueError):
        return str(ts)
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(sec)) + ".%03dZ" % (frac // 1_000_000)


# ---------------------------------------------------------------- Datadog


def datadog_query(ns, contains):
    parts = []
    if ns:
        parts.append(f"kube_namespace:{ns}")   # ns 는 이름 규칙 검증을 통과한 값만
    if contains:
        parts.append(_quote(contains))
    return " ".join(parts) or "*"


def _tag(tags, key):
    pre = key + ":"
    for t in tags or []:
        if isinstance(t, str) and t.startswith(pre):
            return t[len(pre):]
    return None


def search_datadog(cfg, ns, contains, minutes, limit, http):
    if not (cfg["dd_api_key"] and cfg["dd_app_key"]):
        raise RuntimeError("DD_API_KEY·DD_APP_KEY 미설정 — 이 환경에선 log_search 사용 불가")
    q = datadog_query(ns, contains)
    body = {
        "filter": {"query": q, "from": f"now-{minutes}m", "to": "now"},
        "sort": "-timestamp",
        "page": {"limit": limit},
    }
    data = http(f"https://api.{cfg['dd_site']}/api/v2/logs/events/search",
                data=body, method="POST",
                headers={"Content-Type": "application/json",
                         "Accept": "application/json",
                         "DD-API-KEY": cfg["dd_api_key"],
                         "DD-APPLICATION-KEY": cfg["dd_app_key"]})
    hits = []
    for ev in data.get("data") or []:
        a = ev.get("attributes") or {}
        tags = a.get("tags") or []
        hits.append({
            "@timestamp": a.get("timestamp"),
            "log": str(a.get("message") or "")[:MAX_LINE],
            "kubernetes.namespace_name": _tag(tags, "kube_namespace"),
            "kubernetes.pod_name": _tag(tags, "pod_name"),
            "kubernetes.container_name": _tag(tags, "kube_container_name"),
            "service": a.get("service"),
            "status": a.get("status"),
        })
    more = bool(((data.get("meta") or {}).get("page") or {}).get("after"))
    return {"total": {"value": len(hits), "relation": "gte" if more else "eq"},
            "query": q, "hits": hits}


# ---------------------------------------------------------------- 진입점


def search(cfg, args, http, now_ns=None):
    ns, contains, minutes, limit = validate(args)
    if cfg["backend"] == "loki":
        return search_loki(cfg, ns, contains, minutes, limit, http, now_ns=now_ns)
    if cfg["backend"] == "datadog":
        return search_datadog(cfg, ns, contains, minutes, limit, http)
    raise RuntimeError("LOG_BACKEND=es 에서는 log_search 가 없다 — es_search 를 써라")


def tool_doc(cfg):
    """시스템 프롬프트의 도구 설명 — es 가 아닐 때 es_search 설명 자리를 대신한다."""
    case = ", 대소문자 구분" if cfg["backend"] == "loki" else ""
    return (
        '   - log_search {"namespace": str, "contains": str, "minutes_back": int<=240, "limit": int<=50}\n'
        f"     {label(cfg)} 로그 조회. 쿼리 문법은 쓰지 마라 — namespace(비우면 전체)와\n"
        f"     포함 문자열(contains{case})만 주면 코드가 쿼리를 조립한다.\n"
        '     0건은 "사건이 없었다" 는 뜻이 아니다. 조회 범위 밖이었을 수도 있으므로\n'
        "     0건만으로 부재를 단정하지 말고 kube_read 로 교차 확인한 뒤 결론을 내라.\n"
    )
