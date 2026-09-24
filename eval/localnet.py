"""로컬 재생용 이름 고정 — 클러스터 밖에서 port-forward 로 ES 를 부를 때만 쓴다.

ES 인증서의 SAN 은 클러스터 DNS 이름(logs-es-http.logging.svc 등)뿐이라 ES_URL 을
https://127.0.0.1:19200 으로 주면 호스트명 검증에서 실패한다(2026-09-24 첫 재생에서
es_search 가 전부 인증서 오류로 끝났다). 검증을 끄는 대신 **이름 해석만** 바꾼다:
ES_URL 은 인증서에 있는 이름으로 두고, 그 이름을 127.0.0.1 로 해석시킨다.
TLS 검증(CA·호스트명)은 운영과 똑같이 켜져 있다.

  LOCAL_RESOLVE="logs-es-http.logging.svc=127.0.0.1"
  ES_URL=https://logs-es-http.logging.svc:19200
"""
import os
import socket


def install():
    spec = os.environ.get("LOCAL_RESOLVE", "")
    table = dict(p.split("=", 1) for p in spec.split(",") if "=" in p)
    if not table:
        return
    real = socket.getaddrinfo

    def getaddrinfo(host, *a, **kw):
        return real(table.get(host, host), *a, **kw)

    socket.getaddrinfo = getaddrinfo
