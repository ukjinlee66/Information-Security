#include <pcap.h>
#include <stdio.h>

int all_hdr_len;
int cap_len;
struct ether_addr {
    unsigned char ether_addr_octet[6];
};

struct  ether_header {
    struct  ether_addr ether_dhost;
    struct  ether_addr ether_shost;
    unsigned short ether_type;          // 0x0800 for IP
};
struct ip_hdr{
   unsigned char ip_header_len:4;
   unsigned char ip_version:4;
   unsigned char ip_tos;
   unsigned short ip_total_length;
   unsigned short ip_id;
   unsigned char ip_frag_offset:5;
   unsigned char ip_more_fragment:1;
   unsigned char ip_dont_fragment:1;
   unsigned char ip_reserved_zero:1;
   unsigned char ip_frag_offset1;
   unsigned char ip_ttl;
   unsigned char ip_protocol;
   unsigned short ip_checksum;
   unsigned int ip_srcaddr;
   unsigned int ip_destaddr;
};
struct tcp_hdr{
   unsigned short source_port;
   unsigned short dest_port;
   unsigned int sequence;
   unsigned int acknowledge;
   unsigned char ns:1;
   unsigned char reserved_part1:3;
   unsigned char data_offset:4;
   unsigned char fin:1;
   unsigned char syn:1;
   unsigned char rst:1;
   unsigned char psh:1;
   unsigned char ack:1;
   unsigned char urg:1;
   unsigned char ecn:1;
   unsigned char cwr:1;
   unsigned short window;
   unsigned short checksum;
   unsigned short urgent_pointer;
};

void print_raw_packet(const unsigned char *pkt_data, bpf_u_int32 caplen)
{
	printf("================================\n");
	printf("\nprint raw packet\n");
	for(int i=0;i<caplen;i+=2)
		printf("%x%x ",pkt_data[i],pkt_data[i+1]);
	printf("================================\n");
	cap_len = caplen;
}

void print_ether_header(const unsigned char *pkt_data)
{
	struct ether_header *eth;
	eth = (struct ether_header*)pkt_data;


	printf("print_ether_header\n");
	printf("\n==============dest==================\n");
	for (int i=0;i < 6;i++)
		printf("%02x", eth->ether_dhost.ether_addr_octet[i]);
	printf("\n==============src==================\n");
	for (int i=0;i < 6;i++)
		printf("%02x", eth->ether_shost.ether_addr_octet[i]);
	printf("\n==============type==================\n");
	printf("%04x", eth->ether_type);
	printf("\n");
}

void print_ip_header(const unsigned char *pkt_data)
{
	struct ip_hdr *ip;
	pkt_data += 14;

	ip = (struct ip_hdr*)pkt_data;
	printf("print_ip_header\n");
	printf("HEADER_LEN : %x\n",ip->ip_header_len);
	printf("IP_VERSION : %x\n",ip->ip_version);
	printf("IP_TOS : %x\n", ip->ip_tos);
	printf("IP_TOTAL_LENGTH : %x\n",ip->ip_total_length);
	printf("IP_ID : %x\n",ip->ip_id);
	printf("IP_FRAG_OFFSET : %x\n",ip->ip_frag_offset);
	printf("IP_MORE_FRAGMENT : %x\n",ip->ip_more_fragment);
	printf("IP_DONT_FRAGMENT : %x\n",ip->ip_dont_fragment);
	printf("IP_RESERVED_ZERO : %x\n",ip->ip_reserved_zero);
	printf("IP_FRAG_OFFSET1 : %x\n",ip->ip_frag_offset1);
	printf("IP_TTL : %x\n",ip->ip_ttl);
	printf("IP_PROTOCOL : %x\n",ip->ip_protocol);
	printf("IP_CHECKSUM : %x\n",ntohs(ip->ip_checksum));
	printf("IP_SRCADDR : %x\n",ntohl(ip->ip_srcaddr));
	printf("IP_DESTADDR : %x\n",ntohl(ip->ip_destaddr));
	all_hdr_len = 14 + ip->ip_header_len * 4;
}
void print_tcp_header(const unsigned char *pkt_data)
{
	int sequence;
	int acknowledge;
	int divide;
	struct tcp_hdr *tcp;
	
	pkt_data += 34;
	tcp = (struct tcp_hdr*)pkt_data;
	printf("\nprint_tcp_header\n");
	printf("SOURCE PORT : %x\n", ntohs(tcp->source_port));
	printf("DEST_PORT : %x\n", ntohs(tcp->dest_port));
	printf("SEQUENCE : %x\n",ntohl(tcp->sequence));
	printf("ACKNOWLEDGE : %x\n",ntohl(tcp->acknowledge));
	printf("NS : %x\n",tcp->ns);
	printf("RESERVED PART1 : %x\n",tcp->reserved_part1);
	printf("DATA_OFFSET : %x\n",tcp->data_offset);
	printf("FIN : %x\n",tcp->fin);
	printf("SYN : %x\n",tcp->syn);
	printf("RST : %x\n",tcp->rst);
	printf("PSH : %x\n",tcp->psh);
	printf("ACK : %x\n",tcp->ack);
	printf("URG : %x\n",tcp->urg);
	printf("ECN : %x\n",tcp->ecn);
	printf("CWR : %x\n",tcp->cwr);
	printf("WINDOW : %x\n",ntohs(tcp->window));
	printf("CHECKSUM : %x\n",ntohs(tcp->checksum));
	printf("URENT_POINTER : %x\n",ntohs(tcp->urgent_pointer));
	all_hdr_len = all_hdr_len + tcp->data_offset * 4;
}
void print_data(const unsigned char *pkt_data)
{
	printf("print_data\n");
	for(int i=all_hdr_len;i<cap_len;i++)
		printf("%x ",pkt_data[i]);
	printf("\nPRINT END\n");
}

struct pcap_pkhdr{
	struct timeval ts;
	bpf_u_int32 caplen;
	bpf_u_int32 len;
};

int main(){
        pcap_if_t *alldevs=NULL;
        char errbuf[PCAP_ERRBUF_SIZE];
		int inum;
		pcap_t *fp;
		all_hdr_len = 0;
		cap_len = 0;

		//find all network
        if (pcap_findalldevs(&alldevs, errbuf)==-1){
                printf("dev find failed\n");
                return (-1);
        }
        if (alldevs==NULL){
                printf("no devs found\n");
                return (-1);
        }
        pcap_if_t *d;
        int i;
        for(d=alldevs,i=0; d!=NULL;d=d->next){
                printf("%d-th dev:%s ",++i,d->name);
                if (d->description){
                        printf(" (%s)\n", d->description);
				}
                else
                        printf(" (No description available)\n");
		}
		printf("enter the interfaace number. ");
		scanf("%d",&inum);
		for (d=alldevs,i=0;i<inum-1;d=d->next,i++);
		if ((fp = pcap_open_live(d->name,
						65536,
						1,
						20,
						errbuf
						))==NULL){
			printf("pcap open failed\n");
			pcap_freealldevs(alldevs);
			return (-1);
		}
		printf("pcap oepn successful\n");
		struct bpf_program fcode;
		if(pcap_compile(fp, &fcode,
					(char *)("host 165.246.38.151 and port 12147"),
					1,
					NULL)<0){
			printf("pcap compile failed\n");
			pcap_freealldevs(alldevs);
			return (-1);
		}
		if (pcap_setfilter(fp, &fcode) < 0){
			printf("pcap setfilter failed\n");
			pcap_freealldevs(alldevs);
			return (-1);
		}
		printf("filter setting successful\n");
		pcap_freealldevs(alldevs);
		struct pcap_pkthdr *header;
		const unsigned char *pkt_data;
		int res;
		while ((res=pcap_next_ex(fp,&header,&pkt_data))>=0){
			if (res == 0) continue;
				print_raw_packet(pkt_data,header->caplen);
				cap_len = header->caplen;
				print_ether_header(pkt_data);
				print_ip_header(pkt_data);
				print_tcp_header(pkt_data);
				print_data(pkt_data);
		}
		return (0);
}

