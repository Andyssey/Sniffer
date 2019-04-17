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
	//printf("   IP Address\n");
	//printf("   |-IP Version       : %d\n",(unsigned int)iph->version);
    //printf("   |-Source IP        : %s\n" , inet_ntoa(source.sin_addr) );
    //printf("   |-Destination IP   : %s\n" , inet_ntoa(dest.sin_addr) );
    //printf("   |-Source IP in unsigned long:        : %lu\n" ,source.sin_addr);
    #endif
    next_packet(source.sin_addr.s_addr);
    signal(SIGUSR1, sigterm_h);
    signal(SIGUSR2, sigterm_h);
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
    /*Get the process id and save it to file, so that CLI could sent signals*/
    int sniffer_pid = getpid();
    int id_file = open(PIDFILE, O_WRONLY | O_APPEND | O_CREAT, 0644);
    int ret_val = write(id_file,&sniffer_pid, sizeof(int));
    close(id_file);
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
        unlink(PIDFILE);
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
        logptr = fopen(log, "wb");
        if (logptr == NULL)
        {
            printf("Cannot open the file\n");
            exit (1);
        }
        /*Get interface name via named pipe*/
        int fd;
        char *iface = malloc(sizeof(char)* IFACE_SIZE);
        mkfifo(PIPEFILE,0666);
        fd = open(PIPEFILE,O_RDONLY);
        read(fd,iface,sizeof iface);
        close(fd);
        /*Send back the results about request*/
        int nd;
        nd = open(PIPEFILE,O_WRONLY);
        write(nd, &st->size, sizeof(int));
        for (int i = 0; i < st->size; i++)
        {
            write(nd, &st->packet[i].inIpaddr, sizeof(int));
            write(nd, &st->packet[i].count, sizeof(int));   
        }
        close(nd);
        unlink(PIPEFILE);
        free(iface);
    }else if (signum == SIGUSR2)
    {
        unsigned long ip = 0;
        mkfifo(PIPEFILE_2,0666);
        int fd = open(PIPEFILE_2,O_RDONLY);
        read(fd,&ip,sizeof(unsigned long));
        int index = bin_search(ip);
        int count = st->packet[index].count;
        fd = open(PIPEFILE_2,O_WRONLY);
        usleep(200000);
        write(fd, &count, sizeof(int));
        close(fd);
        unlink(PIPEFILE_2);
    }
}
