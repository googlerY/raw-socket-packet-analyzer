# 🔍 Raw Socket 기반 TCP 패킷 아날라이저 (TCP Packet Analyzer)

## 📌 프로젝트 개요
본 프로젝트는 운영체제의 사용자 영역(User Space)에서 네트워크 계층(L3)과 전송 계층(L4)의 패킷을 직접 캡처하고 분석하기 위해 C 언어로 구현한 패킷 아날라이저입니다. 

기존의 패킷 캡처 라이브러리(pcap 등)에 의존하지 않고, **Linux Raw Socket(`SOCK_RAW`)**을 개방하여 NIC로 들어오는 패킷을 바이트 단위로 직접 파싱했습니다. 이를 통해 TCP의 3-Way Handshake 과정과 신뢰성 보장 메커니즘을 정량적으로 실증하고, 혼잡 제어(Congestion Control) 메커니즘을 분석하는 것을 목표로 합니다.

## ⚙️ 개발 환경
*   **OS:** Ubuntu 24.04 (Linux 64-bit)
*   **Language:** C (gcc)
*   **Key Interface:** `<sys/socket.h>`, `<netinet/ip.h>`, `<netinet/tcp.h>`

## 🛠️ 핵심 기능 및 구현 상세

### 1. Raw Socket 기반 패킷 수신
*   `socket(PF_INET, SOCK_RAW, IPPROTO_TCP)` 시스템 콜을 사용하여 TCP 프로토콜을 통과하는 패킷만을 필터링하여 수신합니다.
*   `recvfrom` 함수를 통해 수신 버퍼(`RX Buffer`)에 패킷의 원시 바이트 데이터를 저장합니다.

### 2. IP 헤더 파싱 및 ECN(명시적 혼잡 알림) 분석
*   수신된 바이트 배열을 `struct iphdr` 구조체로 매핑하여 출발지/목적지 IP와 헤더 길이를 정확히 추출합니다.
*   **비트 마스킹 연산(`iph->tos & 0x03`)**을 통해 TOS(Type of Service) 필드의 하위 2비트를 추출하여 ECN(Explicit Congestion Notification) 상태를 분석합니다.

### 3. TCP 플래그 및 혼잡 제어 분석
*   가변적인 IP 헤더 길이(`ihl * 4`)를 계산하여 동적으로 `struct tcphdr` 구조체의 시작 메모리 주소를 매핑합니다.
*   SEQ(Sequence Number)와 ACK(Acknowledge Number)를 추적하여 3-Way Handshake의 신뢰성 연결 상태를 확인합니다.
*   **13번째 바이트 비트 연산**을 통해 6개의 기본 제어 플래그(URG, ACK, PSH, RST, SYN, FIN)뿐만 아니라, **네트워크 보조 혼잡 제어(Network Assisted Congestion Control)의 핵심인 CWR 및 ECE 플래그**의 활성화 여부를 추출합니다.

### 4. 페이로드(Payload) 추출
*   IP 헤더의 `tot_len`에서 (IP 헤더 길이 + TCP 헤더 길이)를 감산하여 페이로드의 정확한 시작점과 길이를 계산합니다.
*   출력 가능한 ASCII 문자는 텍스트로, Non-printable 문자는 `.`으로 치환하여 와이어샤크(Wireshark)와 유사한 형태의 헥사 덤프를 제공합니다.

## 🚀 빌드 및 실행 방법
> **⚠️ 주의:** Raw Socket을 개방(`socket` 생성)하기 위해서는 반드시 **루트(root) 권한**이 필요합니다.

```bash
# 1. 소스 코드 컴파일
gcc -Wall -Wextra -o tcp_analyzer src/main.c

# 2. 관리자 권한으로 실행 (Raw Socket 권한 요구)
sudo ./tcp_analyzer