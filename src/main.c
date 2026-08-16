#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h> 

#include <netinet/ip.h>     // struct iphdr 사용
#include <netinet/tcp.h>    // struct tcphdr 사용


//출력 함수 선언
void print_payload(const u_char *payload, int payload_len);
void print_ip(struct iphdr *iphdr, int total_len_rcvd); 
void print_tcp(struct tcphdr *tcph, const u_char *payload, int payload_len); 


int main()
{
    int sd;
    socklen_t len;
    
    //recvfrom의 반환 값 = 패킷 사이즈
    int packet_len; 

    // RX (수신) 버퍼 사이즈 설정 
    int rx_packet_size = 65536; 
    char *rx_packet = malloc(rx_packet_size); 

    // 구조체 선언
    struct tcphdr *rx_tcph;
    struct iphdr *rx_iph;

    struct sockaddr_in local;
    
    // RAW 소켓 생성
    if ((sd = socket(PF_INET, SOCK_RAW, IPPROTO_TCP)) < 0) {
        printf("socket open error\n");
        exit(-1);
    }
    
    // 수신 루프
    while(1) {
        bzero(rx_packet, rx_packet_size);
        
        len = sizeof(local);
        // recvfrom의 반환 값 = 패킷 사이즈
        packet_len = recvfrom(sd, rx_packet, rx_packet_size, 0, (struct sockaddr *)&local, &len);

        if (packet_len < 0)
        	continue; 

        rx_iph = (struct iphdr*)rx_packet;
        
        // TCP 패킷만 처리
        if (rx_iph->protocol != IPPROTO_TCP) continue;

	//ip header와 tcp header 시작 주소 계산
        unsigned int ip_header_len = rx_iph->ihl * 4;
        rx_tcph = (struct tcphdr*)(rx_packet + ip_header_len); 
        
        // Payload 계산 로직 (IP Total Length 기준)
        unsigned int tcp_header_len = rx_tcph->doff * 4; 
        unsigned int total_header_len = ip_header_len + tcp_header_len;
        
        // Payload 길이는 IP 헤더에 기록된 길이에서 헤더 길이를 뺀 값.
        unsigned int ip_total_len = ntohs(rx_iph->tot_len);
        int payload_len = (ip_total_len > total_header_len) ? (ip_total_len - total_header_len) : 0;
        
        //payload 시작 주소 계산
	const u_char *payload = (const u_char *)(rx_packet + total_header_len);

        // 가독성을 위한 구분선 출력
        printf("\n======================================================\n");

        print_ip(rx_iph, packet_len); 
        print_tcp(rx_tcph, payload, payload_len); 
    }
    
    close(sd);
    free(rx_packet);
    return 0;
}


// 출력 함수 정의

// IP 정보 출력 함수 (print_ip)
void print_ip(struct iphdr *iph, int total_len_rcvd) // total_len_rcvd = packet_len
{
    printf("[IP HEADER]\n");
    printf("  Total RCV Len: %d bytes (by recvfrom)\n", total_len_rcvd); 
    printf("  IP Total Len (Header + Data): %u bytes (by iph->tot_len)\n", ntohs(iph->tot_len)); 

    printf("  Version: %1u | Header Len: %2u bytes | Protocol: TCP (%3u)\n", 
           iph->version, iph->ihl * 4, iph->protocol); 

    // ECN 필드 분석: TOS 필드 (IP 헤더의 두 번째 바이트)의 하위 2비트
    // iph->tos 필드를 사용
    unsigned char ecn_field = iph->tos & 0x03; // TOS 필드에서 하위 2비트(0x03=00000011b)만 마스킹

    printf("  ECN Field: %u (", ecn_field);

    if (ecn_field == 0) {
        printf("Not ECN-Capable");
    } else if (ecn_field == 3) {
        printf("CE - CONGESTION EXPERIENCED");
    } else { // 1 또는 2
        printf("ECT - ECN-Capable");
    }
    printf(")\n");

    
    printf("  SRC IP: %15s\n", inet_ntoa(*(struct in_addr *)&iph->saddr));
    printf("  DEST IP: %15s\n", inet_ntoa(*(struct in_addr *)&iph->daddr));
}

// TCP 정보 출력 함수 (print_tcp)
void print_tcp(struct tcphdr *tcph, const u_char *payload, int payload_len)
{
    printf("[TCP HEADER]\n");
    printf("  Source Port: %5u -> Dest Port: %5u\n", ntohs(tcph->source), ntohs(tcph->dest));
    
    printf("  Sequence Number (SEQ): %u\n", ntohl(tcph->seq));
    printf("  Acknowledge Num (ACK): %u\n", ntohl(tcph->ack_seq));

    // TCP 헤더 옵션 길이 확인용 (doff)
    printf("  Header Len: %u bytes (doff * 4)\n", tcph->doff * 4); 
   
    // TCP 플래그는 TCP 헤더 시작 주소에서 13번째 바이트에 위치
    u_char flags_byte = *((u_char *)tcph + 13);
    // 플래그 분석 (와이어샤크 스타일로 'A(1) P(0)'처럼 출력되도록 수정)
    printf("  Flags: ");
    //*------------------------------------------------------ 
    // CWR 플래그 (Congestion Window Reduced)
    (flags_byte & 0x80) ? printf(" C(1)") : printf(" C(0)"); 
    // ECE 플래그 (Explicit Congestion Experienced)
    (flags_byte & 0x40) ? printf(" E(1)") : printf(" E(0)");
    //------------------------------------------------------* 
    
    // URG 플래그 (0x20)
    (flags_byte & 0x20) ? printf(" U(1)") : printf(" U(0)");
    // ACK 플래그 (0x10)
    (flags_byte & 0x10) ? printf(" A(1)") : printf(" A(0)");
    // PSH 플래그 (0x08)
    (flags_byte & 0x08) ? printf(" P(1)") : printf(" P(0)");
    // RST 플래그 (0x04)
    (flags_byte & 0x04) ? printf(" R(1)") : printf(" R(0)");
    // SYN 플래그 (0x02)
    (flags_byte & 0x02) ? printf(" S(1)") : printf(" S(0)");
    // FIN 플래그 (0x01)
    (flags_byte & 0x01) ? printf(" F(1)") : printf(" F(0)");

    printf("\n");
    
    // Payload 출력
    print_payload(payload, payload_len);
}

// Payload 출력 함수
void print_payload(const u_char *payload, int payload_len) {
    if (payload_len <= 0) {
        printf("    [Payload] No data. (Payload Length: %d)\n", payload_len);
        return;
    }
    printf("    [Payload] (%d bytes):\n", payload_len);
    
    // ASCII 문자로 출력
    for (int i = 0; i < payload_len; i++) {
        if (i != 0 && i % 32 == 0) {
            printf("\n");
        }
        if (payload[i] >= 32 && payload[i] <= 126) {
            printf("%c", payload[i]);
        } else {
            printf(".");
        }
    }
    printf("\n");
}
