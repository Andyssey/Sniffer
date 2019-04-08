#include <stdio.h>
#include "main.h"
#include <pcap.h>
#include<stdio.h>
#include<stdlib.h> //exit()
#include<string.h> //memset
#include<sys/socket.h>
#include<arpa/inet.h> // for inet_ntoa()
#include<net/ethernet.h>
#include<netinet/ip_icmp.h>
#include<netinet/udp.h>
#include<netinet/tcp.h>
#include<netinet/ip.h>
#include <sys/types.h> // for mkfifo()
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/signal.h>
#define ERR_SIZE 512
pcap_t *handle;
int total = 0;
/*Perform some checks and start sniffing if possible*/
int sniff(char * iface);


void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
    printf("New Packet\n");
    int size = header->len;
	struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
	++total;
	print_packet(buffer , size);
}

void print_ip_header(const u_char * Buffer, int Size)
{
    struct sockaddr_in source,dest;
    unsigned short iphdrlen;
	struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );
	iphdrlen =iph->ihl*4;
	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;
	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;
	printf("\n");
	printf("   IP Address\n");
	printf("   |-IP Version       : %d\n",(unsigned int)iph->version);
	printf("   |-Source IP        : %s\n" , inet_ntoa(source.sin_addr) );
	printf("   |-Destination IP   : %s\n" , inet_ntoa(dest.sin_addr) );
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
    char *err_buff[ERR_SIZE];
    // pcap_t *handle;
    handle = pcap_open_live(iface, 65536, 1, 0, err_buff);
    if (handle = NULL) 
    {
        fprintf(stderr, "Couldn't open device %s : %s\n" , iface , err_buff);
        return 0;
    }
    printf("Done\n");
    pcap_loop(handle, 0,process_packet, iface); // loop function to sniff packets
    printf("After loop");
}

int main(int argc, char** argv)
{
    char *devname, devs[100][100];
    int n = 0;
    if (argc == 1) {
        /*No interface specified, use default */
        printf("No interface specified, eth0 would be used if avalible\n");
        // sniff("eth0");
    } else if (argc == 2)
        {
            printf("The next interface would be used: %s\n", argv[1]);
        } else {

            printf("Wrong usage\nTerminating...\n");
        }
    /*TODO Check for root user or capabilities*/
    pcap_if_t *allDevices, *device;
    char errbuff[ERR_SIZE];
    int count = 0;
    printf("Here is the list of all devices\n");
    if (pcap_findalldevs( &allDevices, errbuff))
    {
        printf("Error while finding devices: %s\n", errbuff);
    }
    printf("Done");

    printf("\nAvailable Devices:\n");
    for(device = allDevices ; device != NULL ; device = device->next)
    {
        printf("%d. %s - %s\n" , count , device->name , device->description);
        if(device->name != NULL)
        {
            strcpy(devs[count] , device->name);
        }
        count++;
    }
    printf("Enter the number of the device you want to sniff : ");
    scanf("%d" , &n);
    devname = devs[n];
    printf("Opening device %s for sniffing\n" , devname);
    handle = pcap_open_live(devname , 65536 , 1 , 0 , errbuff);
    if (handle == NULL)
    {
        fprintf(stderr, "Couldn't open device %s : %s\n" , devname , errbuff);
        exit(1);
    }
    printf("Done\n");
    pcap_loop(handle, -1,process_packet, NULL);
    return 0;
}
