#include <stdio.h>
#include "main.h"
#include <pcap.h>
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include<net/ethernet.h>
#include<netinet/ip_icmp.h>
#include<netinet/udp.h>
#include<netinet/tcp.h>
#include<netinet/ip.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <signal.h>
#include <fcntl.h>
#define ERR_SIZE 512

pcap_t *handle;
char *log = NULL;
void sigterm_h(signum);


void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
    #ifdef DEBUG
    printf("New Packet\n");
    #endif
    int size = header->len;
	struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
	print_packet(buffer , size);
}
void print_ip_header(const u_char * Buffer, int Size)
{
    struct sockaddr_in source,dest;
    unsigned short iphdrlen;
	struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr));
	iphdrlen =iph->ihl*4;
	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;
	memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;
    #ifdef DEBUG
	printf("\n");
	printf("   IP Address\n");
	printf("   |-IP Version       : %d\n",(unsigned int)iph->version);
    printf("   |-Source IP        : %s\n" , inet_ntoa(source.sin_addr) );
    printf("   |-Destination IP   : %s\n" , inet_ntoa(dest.sin_addr) );
    printf("   |-Source IP in unsigned long:        : %lu\n" ,source.sin_addr);
    #endif
    next_packet(source.sin_addr.s_addr);
    signal(SIGUSR1, sigterm_h);
    signal(SIGTERM, sigterm_h);
} 
void print_packet(const u_char *Buffer , int Size)
{
	unsigned short iphdrlen;
	struct iphdr *iph = (struct iphdr *)(Buffer +  sizeof(struct ethhdr));
	iphdrlen = iph->ihl*4;
	struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen  + sizeof(struct ethhdr));
	int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;
	print_ip_header(Buffer,Size);
}

int sniff(char * iface)
{
    char *devname;
    pcap_if_t *allDevices, *device;
    char errbuff[ERR_SIZE];
    if (pcap_findalldevs(&allDevices, errbuff))
    {
        printf("Error while finding devices: %s\n", errbuff);
    }
    for(device = allDevices ; device != NULL ; device = device->next)
    {
        if(device->name != NULL)
        {
            if ((strcmp(iface,device->name)) == 0)
            {
                #ifdef DEBUG
                printf("Match device name is %s\n", iface);
                #endif
                break;
            }
        }
    }
    #ifdef DEBUG
    printf("Opening device %s for sniffing\n" , iface);
    #endif
    handle = pcap_open_live(iface, 65536 , 1 , 0 , errbuff);
    if (handle == NULL)
    {
        fprintf(stderr, "Couldn't open device %s : %s\n" , devname , errbuff);
        exit(1);
    }
    
    /* Check if the data from previous launch is avaliable in file */
    log = malloc(strlen(iface) + 1);
    strcpy(log, iface);
    logptr=fopen(log,"rb");
    if(logptr == NULL)
    {
        st = (struct context*)malloc(sizeof(struct context));
        context_initialize();
        pcap_loop(handle, -1,process_packet, NULL);
    }
    else
    {
        st = (struct context*)malloc(sizeof(struct context));
        context_initialize_from_file();
        #ifdef DEBUG
        for(int i = 0; i < st->size; i++)
        {
            print_ip(st->packet[i].inIpaddr,i);
        
        }
        #endif
        pcap_loop(handle, -1,process_packet, NULL);
    }
    free(log);
}

int main(int argc, char** argv)
{
    int abc=3;
    if (argc == 1) {
        /*No interface specified, use default */
        #ifdef DEBUG
        printf("No interface specified, wlan0 would be used if avalible\n");
        #endif
        sniff("wlan0");
    } else if (argc == 2)
        {
            printf("The next interface would be used: %s\n", argv[1]);
            sniff(argv[1]);
        } else {
            #ifdef DEBUG
            printf("Wrong usage\nTerminating...\n");
            #endif
        }
    return 0;
}

void sigterm_h(int signum)
{
    
    if (signum == SIGTERM)
    {
        pcap_breakloop(handle);
        logptr = fopen(log, "wb");
        if (logptr == NULL)
        {
            printf("Cannot open the file\n");
            exit (1);
        }
        fwrite(&st->size, sizeof(int), 1, logptr);
        fwrite(&st->capacity, sizeof(int), 1, logptr);
        fwrite(st->packet, sizeof(struct iface_packet), st->size, logptr);
        fclose(logptr);
    } 
    else if (signum == SIGUSR1)
    {
       // pcap_breakloop(handle);
        logptr = fopen(log, "wb");
        if (logptr == NULL)
        {
            printf("Cannot open the file\n");
            exit (1);
        }
        /*Get interface name via named pipe*/
        int fd;
        char *iface = malloc(sizeof(char)*12);
        mkfifo(PIPEFILE,0666);
        fd = open(PIPEFILE,O_RDONLY);
        read(fd,iface,sizeof iface);
        //#ifdef DEBUG
        printf("Information about %s interface requested\n", iface);
        //#endif
        close(fd);
        /*Send back the results about request*/
        int nd;
        int test2=10000000;
        nd = open(PIPEFILE,O_WRONLY);
        write(nd, &test2, sizeof(int));
        //fwrite(test2, sizeof(int), 1, fd);
        // printf("out     !!!\n");
        //fwrite(&st->capacity, sizeof(int), 1, fd);
        //fwrite(st->packet, sizeof(struct iface_packet), st->size, fd);
        fclose(fd);
    }
}
