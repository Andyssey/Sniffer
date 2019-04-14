#include <sys/stat.h>
#include<pcap.h>
#include<stdio.h>
#include<stdlib.h> //exit()
#include<string.h> //memset
#include <unistd.h>
#include <signal.h>
#include "main.h"
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


char inBuffer[COMAND_BUFF];



int main()
{
    printf("Welcome to the command line of Pcapd Demon. Enter your commands or use --help to see help menun\n");
    while(printf("> ") && fgets(inBuffer,COMAND_BUFF,stdin))
    {
        if(strncmp(inBuffer,START,5) == 0)
        {
            printf("We got start command\n");
            start("wlan0");
        }
        else if (strncmp(inBuffer,STOP,4) == 0)
        {
            printf("We got stop command\n");
            stop();
        }
        else if ((strncmp(inBuffer,SHOW,4) && strncmp(inBuffer,COUNT,5)) == 0)
        {
            printf("We got show count command\n");
        }
        else if (strncmp(inBuffer,SELECT,12) == 0)
        {
            printf("We got select command\n");
        }
        else if (strncmp(inBuffer,STAT,4) == 0)
        {
            char *interface = NULL;
            interface = strtok(inBuffer," ");
            printf("First token is %s\n", interface);
            interface = strtok(NULL," ");
            printf("Second token is %s\n", interface);
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
        freopen("/dev/null", "a", stdout);
        freopen("/dev/null", "a", stderr);
        freopen("/dev/null", "r", stdin);
        char * argv_list[] = {"./main","wlan0",NULL}; 
        execv("./main",argv_list);
        printf("I am here\n");
        printf ("CPID is %d", pid); 
    }
    else
    {
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
        printf("No interface specified...");
    }
    else
    {
        if(pid == -1)
        {
            printf("Seems like Sniffer is not started from cli.\nUse start command of check --help menu\n");
        }
        else
        {
            kill(pid, SIGUSR1);
            usleep(1000000); 
            char *log = NULL;
            log = malloc(strlen(interface) + 1);
            strcpy(log, interface);
            printf("Iface is %s and logfile is %s\n" , interface,log);
            FILE *file;
            file = fopen(log,"rb");
            if (file == NULL)
            {
                printf("Wrong interface name, or statistic is missing\n");
            }
            else
            {
                st = (struct context*)malloc(sizeof(struct context));
                context_initialize_from_file();
                for(int i = 0; i < st->size; i++)
                {
                    printf("Source IP Addres is: %s  and the amount is: %d\n",inet_ntoa(st->packet[i].inIpaddr),st->packet[i].count);
                }

            }

        }
    }
}