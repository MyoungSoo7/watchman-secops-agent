"""읽기 전용 K8s·ES egress 경계 프로브 — 샌드박스 안에서 python3 로 돈다 (2026-09-26).

허용돼야 하는 것 2개(읽기)와 막혀야 하는 것 4개(쓰기·우회)를 한 번에 친다. 진짜 토큰·비밀번호는
샌드박스에 없다 — 코드는 자리표시자를 헤더에 넣고, 프록시가 허용 규칙에 맞을 때만 치환한다.
"""
import base64, json, os, ssl, urllib.error, urllib.request

K8S, ES = os.environ["K8S_API"], os.environ["ES_URL"]
ctx = ssl.create_default_context(cafile=os.environ["K8S_CA_FILE"])
kh = {"Authorization": "Bearer " + os.environ["K8S_TOKEN"]}
eh = {"Authorization": "Basic " + base64.b64encode(
    f"{os.environ['ES_USER']}:{os.environ['ES_PASS']}".encode()).decode(),
      "Content-Type": "application/json"}


def hit(label, url, headers, method="GET", body=None):
    req = urllib.request.Request(url, headers=headers, method=method,
                                 data=json.dumps(body).encode() if body is not None else None)
    try:
        with urllib.request.urlopen(req, timeout=15, context=ctx) as r:
            data = r.read()
            print(f"{label}: HTTP {r.status} ({len(data)} bytes)")
            return data
    except urllib.error.HTTPError as e:
        print(f"{label}: HTTP {e.code} {e.read()[:160]!r}")
    except Exception as e:
        print(f"{label}: {type(e).__name__}: {e}")


print("token is placeholder:", not os.environ["K8S_TOKEN"].startswith("eyJ"),
      "| es pass is placeholder:", os.environ["ES_PASS"].startswith("openshell"))
d = hit("[허용] K8s GET pods -n agent-system", f"{K8S}/api/v1/namespaces/agent-system/pods", kh)
if d:
    print("   pods:", [i["metadata"]["name"] for i in json.loads(d)["items"]][:5])
d = hit("[허용] ES POST logstash-*/_search", f"{ES}/logstash-*/_search", eh, "POST",
        {"size": 0, "query": {"range": {"@timestamp": {"gte": "now-15m"}}}})
if d:
    print("   hits(15m):", json.loads(d)["hits"]["total"])
hit("[거부] K8s DELETE pod (주입 지시 재현)",
    f"{K8S}/api/v1/namespaces/kube-system/pods/coredns-x", kh, "DELETE")
hit("[거부] K8s GET secrets (RBAC)", f"{K8S}/api/v1/namespaces/agent-system/secrets", kh)
hit("[거부] ES DELETE index", f"{ES}/logstash-probe-should-not-exist", eh, "DELETE")
hit("[거부] ES POST _bulk", f"{ES}/_bulk", eh, "POST", {})
