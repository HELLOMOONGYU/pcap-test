#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>

#define ETHER_ADDR_LEN  6

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

struct libnet_ethernet_hdr
{
    u_int8_t  ether_dhost[ETHER_ADDR_LEN];/* destination ethernet address */
    u_int8_t  ether_shost[ETHER_ADDR_LEN];/* source ethernet address *///ETHER_ADDR_LEN
    u_int16_t ether_type;                 /* protocol */
};

struct libnet_ipv4_hdr
{
#if (LIBNET_LIL_ENDIAN)
    u_int8_t ip_hl:4,      /* header length */
           ip_v:4;         /* version */
#endif
#if (LIBNET_BIG_ENDIAN)
    u_int8_t ip_v:4,       /* version */
           ip_hl:4;        /* header length */
#endif
    u_int8_t ip_tos;       /* type of service */
#ifndef IPTOS_LOWDELAY
#define IPTOS_LOWDELAY      0x10
#endif
#ifndef IPTOS_THROUGHPUT
#define IPTOS_THROUGHPUT    0x08
#endif
#ifndef IPTOS_RELIABILITY
#define IPTOS_RELIABILITY   0x04
#endif
#ifndef IPTOS_LOWCOST
#define IPTOS_LOWCOST       0x02
#endif
    u_int16_t ip_len;         /* total length */
    u_int16_t ip_id;          /* identification */
    u_int16_t ip_off;
#ifndef IP_RF
#define IP_RF 0x8000        /* reserved fragment flag */
#endif
#ifndef IP_DF
#define IP_DF 0x4000        /* dont fragment flag */
#endif
#ifndef IP_MF
#define IP_MF 0x2000        /* more fragments flag */
#endif
#ifndef IP_OFFMASK
#define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
#endif
    u_int8_t ip_ttl;          /* time to live */
    u_int8_t ip_p;            /* protocol */
    u_int16_t ip_sum;         /* checksum */
    struct in_addr ip_src, ip_dst; /* source and dest address */
};

struct libnet_tcp_hdr
{
    u_int16_t th_sport;       /* source port */
    u_int16_t th_dport;       /* destination port */
    u_int32_t th_seq;          /* sequence number */
    u_int32_t th_ack;          /* acknowledgement number */
#if (LIBNET_LIL_ENDIAN)
    u_int8_t th_x2:4,         /* (unused) */
           th_off:4;        /* data offset */
#endif
#if (LIBNET_BIG_ENDIAN)
    u_int8_t th_off:4,        /* data offset */
           th_x2:4;         /* (unused) */
#endif
    u_int8_t  th_flags;       /* control flags */
#ifndef TH_FIN
#define TH_FIN    0x01      /* finished send data */
#endif
#ifndef TH_SYN
#define TH_SYN    0x02      /* synchronize sequence numbers */
#endif
#ifndef TH_RST
#define TH_RST    0x04      /* reset the connection */
#endif
#ifndef TH_PUSH
#define TH_PUSH   0x08      /* push data to the app layer */
#endif
#ifndef TH_ACK
#define TH_ACK    0x10      /* acknowledge */
#endif
#ifndef TH_URG
#define TH_URG    0x20      /* urgent! */
#endif
#ifndef TH_ECE
#define TH_ECE    0x40
#endif
#ifndef TH_CWR
#define TH_CWR    0x80
#endif
    u_int16_t th_win;         /* window */
    u_int16_t th_sum;         /* checksum */
    u_int16_t th_urp;         /* urgent pointer */
};


typedef struct {
    char* dev_;
} Param;

Param param  = {
    .dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

void eth_mac(u_int8_t *eth, u_char * packet, int c)
{
    int i = 0;
    if(c==2)
        i = 6;
    for(i;i<ETHER_ADDR_LEN*c;i++)
    {
        if(i<6)
            eth[i] = packet[i];
        else
            eth[i-6] = packet[i];

        printf("%02x:",packet[i]);
    }
    printf("\b ");
}

void IPheader_IP(uint8_t * addr, u_char * packet,int c)
{
    for(int i=26+c;i<(30+c);i++)
    {
        if(i<30)
            addr[i-26] = packet[i];
        else
            addr[i-30] = packet[i];

        printf("%d.",packet[i]);
    }
    printf("\b ");
}

void Tcp_port(uint16_t* p, u_char * packet, int c)
{
    for(int i=0x22+c;i<0x24+c;i++)
    {
        if(i<0x24)
        {
            if(i==0x22)
                p[i-0x22] = packet[i]<<8;
            else
                p[i-0x22] = packet[i];
        }
        else
        {
            if(i==0x24)
                p[i-0x24] = packet[i]<<8;
            else
                p[i-0x24] = packet[i];
        }
    }
    int port = p[0] + p[1];
    printf("%d", port);
}

void read_Data(u_char * packet)
{
        for(int i=0x36;i<0x36+8;i++)
            printf(" %02x",packet[i]);
}

int main(int argc, char* argv[]) {
    if (!parse(&param, argc, argv))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    while (true) {
        struct libnet_ethernet_hdr ethernet_hdr;
        struct libnet_ipv4_hdr ipv4_hdr;
        struct libnet_tcp_hdr tcp_hdr;

        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);

        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }
        printf("Ethernet\nDest: ");
        eth_mac(&ethernet_hdr.ether_shost, packet,1); //soure_mac
        printf(" Src: ");
        eth_mac(&ethernet_hdr.ether_dhost,packet,2); //dest_mac
        printf("\n");
        //ipv4
        printf("IPv4 address\nSrc: ");
        IPheader_IP(&ipv4_hdr.ip_src,packet,0); //src
        printf("  Dst: ");
        IPheader_IP(&ipv4_hdr.ip_dst,packet,4); //dst
        printf("\nTcp Header Port\nSrc port: ");
        Tcp_port(&tcp_hdr.th_sport,packet,0);
        printf(" Dst port: ");
        Tcp_port(&tcp_hdr.th_dport,packet,2);
        printf("\nData: ");
        read_Data(packet);


        printf("\n %u bytes captured\n\n", header->caplen);
    }

    pcap_close(pcap);
}
