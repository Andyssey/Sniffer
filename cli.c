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
            unsigned char buf[sizeof(struct in_addr)];
            ipAddr = strtok(inBuffer," ");
            ipAddr = strtok(NULL," ");
            inet_pton(domain,ipAddr , buf);
            printf("Iface is %s", iface);
            get_if_statistic(iface,buf);
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
        kill(pid, SIGTERM);
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
        if(pid == -1)
        {
            printf("Seems like Sniffer is not started from cli.\nUse start command of check --help menu\n");
        }
        else
        {
            get_if_statistic(interface,0);
        }
    }
}




void get_if_statistic(char *iface_name, unsigned int ip)
{
    /*Send a signal and interface name via named pipe*/
    kill(pid, SIGUSR1);
    int fd = open(PIPEFILE,O_WRONLY);
    write(fd,iface_name,strlen(iface_name)+1);
    close(fd);
    /*Get the results from sniffer*/
    fd = open(PIPEFILE,O_RDONLY);
    st = (struct context*)malloc(sizeof(struct context));
    int test = 0;
    read(fd, &test, sizeof(int));
    //fread(&st->size, sizeof(int), 1, fd);
    printf("Thssssse size isssssss %d\n", test);
    // fread(&st->capacity, sizeof(int), 1, fd);
    //st->packet = calloc(sizeof(struct iface_packet),st->capacity);
    //int is = 0;
    //is = fread(st->packet, sizeof(struct iface_packet), st->size, fd);
    //for(int i = 0; i < st->size; i++)
    //{
    //    print_ip(st->packet[i].inIpaddr,i);
    
   // }

    /*
    usleep(1000000); 
    char *filename = malloc(strlen(iface_name));
    strncpy(filename, iface_name,strlen(iface_name) -1);
    FILE *file;
    file = fopen(filename,"rb");
    if (file == NULL)
    {
        printf("No statistic for this interface\n");
        return ;
    }
    else
    {
        st = (struct context*)malloc(sizeof(struct context));
        fread(&st->size, sizeof(int), 1, file);
        fread(&st->capacity, sizeof(int), 1, file);
        st->packet = calloc(sizeof(struct iface_packet),st->capacity);
        int is = 0;
        is = fread(st->packet, sizeof(struct iface_packet), st->size, file);
        /*For show ip count command*/
        /*
        if (ip == 0)
        {
            for(int i = 0; i < st->size; i++)
            {
                print_ip(st->packet[i].inIpaddr,i);
            
            }
        }
        else
        {
            int index = -1;
            index = bin_search(ip);
            print_ip(ip, index);
        }
        free(filename);
        fclose(file);
    }
*/
}