#!/usr/bin/env python3
"""유출(egress) 통제 — read-only 에이전트라도 *자기 출력*이 유출 경로가 된다.

주입(injection)은 입력 축이다. 이 모듈은 반대쪽, 즉 에이전트가 밖으로 내보내는
표면(텔레그램 카드·이메일·감사로그)에 시크릿이 섞여 나가는 것을 막는다.

실제 사고에서 나온 규칙이다. 2026-09-23 운영 조사 중 `kubectl get secret -o custom-columns`
출력이 그대로 세션 로그에 남았다. 도구는 읽기 전용이었고 인가도 정상이었다 —
**차단되지 않은 것은 쓰기가 아니라 출력이었다.**

설계
  · `scan(text)` → 탐지 히트 목록(값은 절대 담지 않는다. 규칙·위치·길이만).
  · `redact(text)` → (마스킹된 텍스트, 히트). 값은 `[REDACTED:<규칙>]` 로 치환.
  · `guard(obj, where)` → 문자열/딕셔너리/리스트를 재귀 마스킹해 돌려준다.
base64 는 정규식만으로는 해시·ID 와 구분되지 않으므로, **디코딩해서 내용을 보고**
판정한다(출력 가능 문자 비율·길이·16진수 제외). 그래서 오탐이 낮다.
"""
import base64
import hashlib
import hmac
import os
import re

# (규칙 id, 한글 라벨, 정규식) — 값 자체는 어디에도 기록하지 않는다.
RULES = [
    ("pem_private_key", "PEM 개인키",
     re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----")),
    ("jwt", "JWT·서비스어카운트 토큰",
     re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
    ("nvidia_api_key", "NVIDIA API 키", re.compile(r"\bnvapi-[A-Za-z0-9_\-]{16,}")),
    ("github_token", "GitHub 토큰", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{16,}")),
    ("aws_access_key_id", "S3·R2 액세스 키 ID", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("slack_token", "Slack 토큰", re.compile(r"\bxox[abprs]-[A-Za-z0-9\-]{10,}")),
    ("telegram_bot_token", "텔레그램 봇 토큰",
     re.compile(r"\b\d{8,12}:[A-Za-z0-9_\-]{30,}\b")),
    ("bearer_header", "Authorization Bearer 값",
     re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=\-]{20,}")),
    ("vendor_api_key", "LLM·클라우드 API 키",
     re.compile(r"\bsk-(?:ant-|proj-)?[A-Za-z0-9_\-]{20,}|\bAIza[0-9A-Za-z_\-]{30,}")),
    ("url_userinfo", "URL 안의 비밀번호",
     # postgres://user:pw@host — 비밀번호(그룹 1)만 가리고 계정·호스트는 남긴다.
     re.compile(r"(?i)\b[a-z][a-z0-9+.\-]*://[^\s/:@\"']+:([^\s/@\"']+)@")),
    ("kv_secret", "키=값 형태의 비밀값",
     # 환경변수 꼴(R2_SECRET_ACCESS_KEY=...)까지 잡도록 접두사를 허용한다.
     # 키 뒤의 닫는 따옴표(["']?)는 2026-09-24 추가 — 없으면 JSON·repr 꼴
     # {"password": "..."} 이 통째로 통과했다. redact 는 json.dumps 결과에 걸리므로
     # 사실상 도구 결과 전부가 이 꼴이었다. 값 최소 길이도 12 → 8.
     re.compile(r"(?i)(?<![A-Za-z0-9_])[A-Za-z0-9_\-]{0,24}"
                r"(?:password|passwd|secret|api[_-]?key|access[_-]?key|token|credential)"
                r"[A-Za-z0-9_\-]{0,12}[\"']?\s*[:=]\s*[\"']?([^\s\"',}]{8,})")),
]

# guard() 가 딕셔너리를 돌 때, 키 이름이 이 꼴이면 값의 생김새와 무관하게 통째로 가린다.
# 끝이 맞아야 한다 — prompt_tokens·token_count 같은 수치 필드는 비밀이 아니다.
_SENSITIVE_KEY = re.compile(
    r"(?i)(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?key|private[_-]?key"
    r"|token|credentials?)\Z")

# k8s Secret 응답 형태 — data 블록의 base64 값을 통째로 잡는다.
_SECRET_DATA = re.compile(r"(?i)\"?data\"?\s*:\s*[\{\[]([^\}\]]{16,})[\}\]]")
_B64 = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/])")
_HEX = re.compile(r"\A[0-9a-fA-F]+\Z")


def _looks_like_secret_b64(token):
    """base64 문자열이 '디코딩되는 비밀값'처럼 생겼는가. 해시·ID 는 걸러낸다."""
    if _HEX.fullmatch(token) or token.isdigit():
        return False
    pad = token + "=" * (-len(token) % 4)
    try:
        raw = base64.b64decode(pad, validate=True)
    except Exception:
        return False
    if len(raw) < 12:
        return False
    printable = sum(1 for b in raw if 32 <= b < 127)
    # 디코딩 결과가 대부분 읽히는 문자면(키·비밀번호·인증서 문자열) 시크릿으로 본다.
    return printable / len(raw) >= 0.85


def _b64_spans(text):
    spans = []
    for m in _B64.finditer(text):
        if _looks_like_secret_b64(m.group(0)):
            spans.append((m.start(), m.end(), "base64_secret", "base64 시크릿 값"))
    return spans


_PLACEHOLDER = re.compile(r"\[REDACTED:[a-z0-9_]+\]|\[PII:[a-z_]+:[0-9a-f]{8}\]")

# 개인정보(PII) — 시크릿과 달리 "누구였는지" 는 조사에 쓸모가 있다(같은 사람이 여러 번 나왔나).
# 그래서 이메일·전화번호는 지우지 않고 키 붙은 HMAC 으로 가명화한다: 같은 값 → 같은 자리표시자.
# 키는 PII_KEY 환경변수, 없으면 프로세스마다 새로 뽑는다(재시작하면 대응이 끊긴다 — 의도한 것).
# 주민등록번호는 대응도 남기지 않고 지운다. 외부로 나가는 관문(LLM·가드·카드·메일)에서만 쓴다.
PII_RULES = [
    ("email", "이메일 주소",
     re.compile(r"(?<![A-Za-z0-9._%+\-])[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,24}\b")),
    ("kr_rrn", "주민등록번호", re.compile(r"(?<!\d)\d{6}-[1-4]\d{6}(?!\d)")),
    ("kr_mobile", "휴대전화번호",
     re.compile(r"(?<![\d\-])01[016789][\-. ]\d{3,4}[\-. ]\d{4}(?![\d\-])")),
]
PII_PSEUDONYMIZE = ("email", "kr_mobile")
_PII_KEY = (os.environ.get("PII_KEY") or "").encode() or os.urandom(32)


def pseudonym(rule, value):
    """같은 값·같은 키면 같은 8자리. 키 없이는 되돌릴 수 없다(무차별 대입도 키가 필요)."""
    d = hmac.new(_PII_KEY, f"{rule}:{value.strip().lower()}".encode("utf-8"), hashlib.sha256)
    return f"[PII:{rule}:{d.hexdigest()[:8]}]"


def _pii_spans(text):
    holes = [(m.start(), m.end()) for m in _PLACEHOLDER.finditer(text)]
    out = []
    for rid, label, rx in PII_RULES:
        for m in rx.finditer(text):
            a, b = m.start(), m.end()
            if not any(a < he and hs < b for hs, he in holes):
                out.append((a, b, rid, label))
    out.sort(key=lambda s: (s[0], -(s[1] - s[0])))
    merged, end = [], -1
    for sp in out:
        if sp[0] >= end:
            merged.append(sp)
            end = sp[1]
    return merged


def _spans(text):
    # 이미 마스킹된 자리표시자 — 여기에 겹치는 탐지는 버린다(redact 멱등성).
    holes = [(m.start(), m.end()) for m in _PLACEHOLDER.finditer(text)]

    def _in_hole(a, b):
        return any(a < he and hs < b for hs, he in holes)

    out = []
    for rid, label, rx in RULES:
        for m in rx.finditer(text):
            # 그룹이 있는 규칙(kv_secret·url_userinfo)은 값 부분만 가린다
            # (키 이름·계정은 남겨야 무엇이 걸렸는지 읽힌다).
            if rx.groups:
                out.append((m.start(1), m.end(1), rid, label))
            else:
                out.append((m.start(), m.end(), rid, label))
    out.extend(_b64_spans(text))
    out = [sp for sp in out if not _in_hole(sp[0], sp[1])]
    out.sort(key=lambda s: (s[0], -(s[1] - s[0])))
    # 겹치는 구간은 먼저·긴 쪽을 남긴다(JWT 가 base64 규칙과 겹치는 등).
    merged, end = [], -1
    for s in out:
        if s[0] >= end:
            merged.append(s)
            end = s[1]
    return merged


def scan(text):
    """탐지 결과. 값은 담지 않는다 — 규칙 id·라벨·길이만."""
    if not isinstance(text, str):
        text = str(text)
    hits = []
    for a, b, rid, label in _spans(text):
        hits.append({"rule": rid, "label": label, "length": b - a})
    return hits


def redact(text, pii=False):
    """(마스킹된 텍스트, 히트). 입력이 문자열이 아니면 그대로 돌려준다.
    pii=True 면 시크릿을 먼저 가린 뒤 개인정보를 가명화한다(URL 비번이 이메일로 오인되지 않게
    두 번에 나눈다 — 첫 패스의 자리표시자는 둘째 패스가 건드리지 않는다)."""
    if not isinstance(text, str):
        return text, []
    text, hits = _apply(text, _spans(text), lambda rid, v: f"[REDACTED:{rid}]")
    if pii:
        text, h2 = _apply(text, _pii_spans(text),
                          lambda rid, v: pseudonym(rid, v) if rid in PII_PSEUDONYMIZE
                          else f"[REDACTED:{rid}]")
        hits += h2
    return text, hits


def _apply(text, spans, repl):
    if not spans:
        return text, []
    out, prev, hits = [], 0, []
    for a, b, rid, label in spans:
        out.append(text[prev:a])
        out.append(repl(rid, text[a:b]))
        hits.append({"rule": rid, "label": label, "length": b - a})
        prev = b
    out.append(text[prev:])
    return "".join(out), hits


def guard(obj, _hits=None):
    """문자열·딕셔너리·리스트를 재귀 마스킹. (마스킹된 객체, 히트 목록) 반환."""
    hits = [] if _hits is None else _hits
    if isinstance(obj, str):
        clean, h = redact(obj)
        hits.extend(h)
        return clean, hits
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if (isinstance(k, str) and isinstance(v, str) and v
                    and _SENSITIVE_KEY.search(k) and not _PLACEHOLDER.fullmatch(v)):
                out[k] = "[REDACTED:sensitive_key]"
                hits.append({"rule": "sensitive_key", "label": "비밀 키 이름의 값",
                             "length": len(v)})
            else:
                out[k] = guard(v, hits)[0]
        return out, hits
    if isinstance(obj, (list, tuple)):
        return [guard(v, hits)[0] for v in obj], hits
    return obj, hits


def summary_line(hits):
    """카드 말미에 붙일 한 줄. 히트 없으면 빈 문자열."""
    if not hits:
        return ""
    kinds = {}
    for h in hits:
        kinds[h["label"]] = kinds.get(h["label"], 0) + 1
    body = ", ".join(f"{k} {v}건" for k, v in sorted(kinds.items()))
    return f"🛡 유출 차단 — 출력에서 비밀값을 가림({body}). 원문은 전송·기록되지 않았다."
