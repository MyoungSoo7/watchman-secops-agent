# Watchman 을 NVIDIA OpenShell 샌드박스 안에서 돌리기 위한 이미지 (BYOC).
# 표준 라이브러리만 쓰므로 pip 설치가 없다. CMD 는 OpenShell 슈퍼바이저가 대체한다 —
# 실행 명령은 `openshell sandbox create ... -- python3 /app/watchman.py replay ...` 로 준다.
FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends curl iproute2 nftables \
    && rm -rf /var/lib/apt/lists/*
RUN groupadd --gid 1500 app && useradd --uid 1500 --gid app --create-home app \
    && install -d -o app -g app /sandbox
# 코드는 /app (정책상 read-only), 쓰기는 /sandbox·/tmp 만.
COPY watchman.py redact.py chain.py invariants.py logsrc.py recovery.py /app/
COPY fixtures /app/fixtures
COPY eval/openshell/probes.sh /app/probes.sh
WORKDIR /sandbox
USER app
CMD ["python3", "/app/watchman.py"]
