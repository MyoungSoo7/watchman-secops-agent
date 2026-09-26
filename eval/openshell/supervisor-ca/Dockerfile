# OpenShell supervisor 0.1.1 + 클러스터 사설 CA 2개를 신뢰 번들에 덧붙인 이미지.
#
# 왜 필요한가: L7 검사를 하려면 프록시(supervisor 컨테이너)가 TLS 를 풀고 상위로 *다시* 건다.
# 이때 상위 인증서를 검증하는 신뢰 번들은 샌드박스 이미지가 아니라 supervisor 이미지의
# /etc/ssl/certs/ca-certificates.crt 다 (crates/openshell-supervisor-network/src/l7/tls.rs
# build_upstream_root_store: webpki 루트 + 이 파일). k3s API·ECK ES 는 사설 CA 라 원본 이미지로는
# 검증이 실패한다. tls: skip 으로 우회하면 L7 규칙·자리표시자 치환이 둘 다 꺼지므로 쓰지 않는다.
#
# CA 인증서는 비밀이 아니지만 내부 PKI 라 리포에 넣지 않는다. 빌드 직전에 옆에 둔다:
#   k3s-server-ca.crt  ← kubeconfig 의 certificate-authority-data
#   eck-logs-ca.crt    ← agent-system/eck-logs-ca ConfigMap (운영 watchman 이 쓰는 것과 같은 사본)
# 게이트웨이는 ~/.config/openshell/gateway.toml 의 [openshell.drivers.docker] supervisor_image 로 이 태그를 쓴다.
FROM ghcr.io/nvidia/openshell/supervisor:0.1.1 AS base
FROM busybox:1.36 AS bundle
COPY --from=base /etc/ssl/certs/ca-certificates.crt /in/base.crt
COPY k3s-server-ca.crt eck-logs-ca.crt /in/
RUN cat /in/base.crt /in/k3s-server-ca.crt /in/eck-logs-ca.crt > /out.crt
FROM base
COPY --from=bundle /out.crt /etc/ssl/certs/ca-certificates.crt
