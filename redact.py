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
    ("kv_secret", "키=값 형태의 비밀값",
     # 환경변수 꼴(R2_SECRET_ACCESS_KEY=...)까지 잡도록 접두사를 허용한다.
     re.compile(r"(?i)(?<![A-Za-z0-9_])[A-Za-z0-9_\-]{0,24}"
                r"(?:password|passwd|secret|api[_-]?key|access[_-]?key|token|credential)"
                r"[A-Za-z0-9_\-]{0,12}\s*[:=]\s*[\"']?([^\s\"',}]{12,})")),
]

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


_PLACEHOLDER = re.compile(r"\[REDACTED:[a-z0-9_]+\]")


def _spans(text):
    # 이미 마스킹된 자리표시자 — 여기에 겹치는 탐지는 버린다(redact 멱등성).
    holes = [(m.start(), m.end()) for m in _PLACEHOLDER.finditer(text)]

    def _in_hole(a, b):
        return any(a < he and hs < b for hs, he in holes)

    out = []
    for rid, label, rx in RULES:
        for m in rx.finditer(text):
            # kv_secret 은 값 부분만 가린다(키 이름은 남겨야 무엇이 걸렸는지 읽힌다).
            if rid == "kv_secret":
                g = m.lastindex or 0
                out.append((m.start(g), m.end(g), rid, label))
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


def redact(text):
    """(마스킹된 텍스트, 히트). 입력이 문자열이 아니면 그대로 돌려준다."""
    if not isinstance(text, str):
        return text, []
    spans = _spans(text)
    if not spans:
        return text, []
    out, prev, hits = [], 0, []
    for a, b, rid, label in spans:
        out.append(text[prev:a])
        out.append(f"[REDACTED:{rid}]")
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
        return {k: guard(v, hits)[0] for k, v in obj.items()}, hits
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
