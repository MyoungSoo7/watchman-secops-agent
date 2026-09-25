# Falco BPFDoor 룰 — 이름 위장 우회 차단 카나리 (2026-09-25)

Watchman 이 받는 Falco 알림의 상류 룰 이야기다. 탐지가 새면 Watchman 도 볼 게 없다.

## 문제

BPFDoor 계열 탐지 룰 두 개(`BPF filter attached to socket`, `Packet socket created on host`)에는
정상 데몬 예외가 있다. 그런데 그 예외가 `proc.name` 만 보고 있었다. `proc.name` 은 실행 파일
이름이라 공격자가 마음대로 정한다. BPFDoor 도 실제로 `/dev/shm` 같은 곳에서 정상 데몬
이름으로 위장해 돈다. 그래서 `dhclient` 라는 이름으로 복사한 임플란트는 두 룰을 모두
통과했다.

## 변경

예외 조건을 `bpf_exempt_proc` 매크로 하나로 합쳤다. 예외가 되려면 두 조건이 **모두** 맞아야 한다.

- 이름이 허용 목록에 있다.
- `proc.exepath` 가 `/usr/`, `/sbin/`, `/bin/`, `/lib/` 중 하나로 시작한다.

6노드의 정상 데몬 실경로를 먼저 확인했다. tcpdump, dhcpcd, systemd-networkd, NetworkManager,
wpa_supplicant, chronyd, arping, nmap 은 전부 `/usr` 아래였다. 반영 전에 falco 파드 안에서
`falco -V` 로 로드를 검증했다. 에러는 0 이었고, 기존부터 있던 `evt.dir` 폐기 경고만 떴다.
반영 커밋은 helm-deploy `62ca46b` 다.

## 카나리 실측 (david 노드)

`/usr/bin/tcpdump` 를 복사해 3초 실행하고 삭제했다. 캡처 대상은 `-i lo`, 필터는 `udp port 9` 다.

| 실행 | 변경 전 | 변경 후 |
|---|---|---|
| `/dev/shm/dhclient` (이름 위장) | **0건** | **3건** (BPF 2 + packet socket 1) |
| `/dev/shm/bpfcanary` (대조군) | 3건 | 3건 |
| `/usr/bin/tcpdump` (정상) | — | 0건 (예외 유지) |

반영 뒤 약 20분 동안 6노드의 두 룰 발화는 0건이다. 정상 데몬의 오탐은 없었다.

## 한계

- root 가 `/usr/sbin/` 안에 직접 심으면 여전히 예외에 걸린다. 이건 파일 무결성 감시가 할 일이다.
- 컨테이너 안에서는 `exepath` 가 컨테이너 파일시스템 기준이다. 공격자가 이미지를 통제하면 경로도 통제한다.
- 카나리는 1노드, 1회다.
