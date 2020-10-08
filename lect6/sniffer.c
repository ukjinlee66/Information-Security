#include <pcap.h>
#include <stdio.h>

void print_raw_packet(const unsigned char *pkt_data, bpf_u_int32 caplen);
void print_ether_header(const unsigned char *pkt_data);
void print_ip_header(const unsigned char *pkt_data);
void print_tcp_header(const unsigned char *pkt_data);
void print_data(const unsigned char *pkt_data);


int main(){
        pcap_if_t *alldevs=NULL;
        char errbuf[PCAP_ERRBUF_SIZE];
		int inum;
		pcap_t *fp;
		
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
		return (0);
}

