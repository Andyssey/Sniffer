#include <sys/stat.h>
#include<pcap.h>
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include <unistd.h>
#include <signal.h>
#include "main.h"
#include <netinet/in.h>
#include <fcntl.h>
#include <errno.h>
#define COMAND_BUFF 512
#define DEFAULT_IFACE "wlan0"

/*Define of CLI tokens*/
#define START "start"
#define STOP "stop"
#define SHOW "show"
#define COUNT "count"
#define SELECT "select iface"
#define STAT "stat"
#define HELP "--help"


int pid =-1;
char *iface;
char inBuffer[COMAND_BUFF];


int main()
{
    printf("Welcome to the command line of Pcapd Demon. Enter your commands or use --help to see help menun\n");
    /*Main loop to get command*/
    while(printf("$") && fgets(inBuffer,COMAND_BUFF,stdin))
    {
        if(strncmp(inBuffer,START,5) == 0)
        {
            if(iface == NULL)
            {
                start(DEFAULT_IFACE);    
            }
            else
            {
                start(iface);
            }
        }
        else if (strncmp(inBuffer,STOP,4) == 0)
        {
            stop();
        }
        else if ((strncmp(inBuffer,SHOW,4) && strncmp(inBuffer,COUNT,5)) == 0)
        {
            /*Not fully implmented*/
            char *ipAddr = NULL;
            int domain = AF_INET;
            ipAddr = strtok(inBuffer," ");
            ipAddr = strtok(NULL," ");
            struct sockaddr_in ip4addr;
            inet_pton(domain,ipAddr , &ip4addr.sin_addr);
            unsigned long ip = ip4addr.sin_addr.s_addr;
            show(ip);
        }
        else if (strncmp(inBuffer,SELECT,12) == 0)
        {
            char *temp;
            temp = strtok(inBuffer," ");
            temp = strtok(NULL," ");
            temp = strtok(NULL," ");
            iface = malloc(strlen(temp) + 1);
            strcpy(iface,temp);
        }
        else if (strncmp(inBuffer,STAT,4) == 0)
        {
            char *interface = NULL;
            interface = strtok(inBuffer," ");
            interface = strtok(NULL," ");
            stat_iface(interface);
        }
        else if (strncmp(inBuffer,HELP,6) == 0)
        {
            printf("\n                Command list                      \n");
			printf("    start                    Start pcaket sniffing\n");
			printf("    stop                     Stop pcaket sniffing\n");
			printf("    show [ip] count          Show the number of packets from [ip]\n");
			printf("    select iface [iface]     Select [iface] interface to sniff\n");
			printf("    stat [iface]             Get statistics about [iface] interface\n");
			printf("    --help                   Show this help menu\n");
        }
        else
        {
            printf("Unknown  command, please try again or use --help\n");
        }
    }
    return 0;
}


void start(char *iface)
{
    /*Get the daemon process id*/
    if (pid == -1)
    {
        int id_file = open(PIDFILE, O_RDONLY, 0644);
        if (id_file != -1)
        {
            read(id_file,&pid, sizeof(int));
            kill(pid,SIGCONT); 
            return;   
        }    
    } 
    pid = fork();
    if (pid == -1)
    {
        printf("Cannot execute...");
        exit (1);
    }
    if(pid == 0)
    {
       // freopen("/dev/null", "a", stdout);
       // freopen("/dev/null", "a", stderr);
       // freopen("/dev/null", "r", stdin);
        if (iface == NULL)
        {
            char * argv_list[] = {"./main","wlan0",NULL};
            iface = "wlan0"; 
        }
        char * argv_list[] = {"./main",iface,NULL}; 
        execv("./main",argv_list);
        printf("I am here\n");
        printf ("CPID is %d", pid); 
    }
    else
    {
        /*Nothing to do in parent*/
        return 0;
    }

}
void stop()
{
    if(pid == -1)
    {
        printf("No process to stop...\n");
    }
    else
    {
        pid = -1;
        kill(pid, SIGSTOP);
    }
}
void stat_iface(char *interface)
{
    if (interface == NULL)
    {
        pcap_if_t *allDevices, *device;
        char errbuff[512];
        printf("Here is the list of all devices\n");
        if (pcap_findalldevs(&allDevices, errbuff))
        {
            printf("Error while finding devices: %s\n", errbuff);
        }
        for(device = allDevices ; device != NULL ; device = device->next)
        {
            if (device->name != NULL)
            {
                get_if_statistic(device->name);
            }
        }
    }
    else
    {
        get_if_statistic(interface,0);
    }
}

void get_if_statistic(char *iface_name)
{
    /*Send a signal and interface name via named pipe*/
    kill(pid, SIGUSR1);
    /*Give some time*/
    usleep(200000);
    int fd = open(PIPEFILE,O_WRONLY);
    write(fd,iface_name,strlen(iface_name)+1);
    close(fd);
    /*Get the results from sniffer*/
    fd = open(PIPEFILE,O_RDONLY);
    int size = 0;
    read(fd, &size, sizeof(int));
    printf ("Get the size of %d\n", size);
    for (int i = 0; i < size; i++)
    {
        unsigned long ip = 0;
        unsigned long count = 0;
        read(fd, &ip, sizeof(int));
        read(fd, &count, sizeof(int));
        int net_ip = htonl(ip);
        show_ip(net_ip,count);
    }
    close(fd);
    unlink(PIPEFILE);
}
void show(unsigned long ip)
{
    int count = 0;
    kill(pid,SIGUSR2);
    /*Give some time*/
    usleep(200000);
    int fd = open(PIPEFILE_2,O_WRONLY);
    write(fd,&ip,sizeof(unsigned long));
    usleep(200000);
    fd = open(PIPEFILE_2,O_RDONLY);
    printf("The amout of bytes is %d\n",fd);
    read(fd, &count, sizeof(int));
    printf("The count on CLI is %lu\n", count);
    int net_ip = htonl(ip);
    show_ip(net_ip,count);
    close(fd);
}
void show_ip(int ip, int i)
{
    unsigned char bytes[4];
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;   
    printf(" Source ip addr is: %d.%d.%d.%d   Count of packets is: %d\n", bytes[3], bytes[2], bytes[1], bytes[0], i);        
}