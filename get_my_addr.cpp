#include "get_my_addr.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>


// 출처 : 네이버 블로그(https://url.kr/wt71i2)
// 도움 : copilot

int get_my_mac(char *mac_str, const char *if_name)
{
    unsigned char *mac = NULL;
    struct ifreq ifr;
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        perror("socket");
        return -1;
    }
    strcpy(ifr.ifr_name, if_name);
    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0)
    {
        perror("ioctl");
        return -1;
    }
    mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;
    sprintf(mac_str, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    close(sockfd);
    return 0;
};

int get_my_ip(char *ip_str, const char *if_name)
{
    struct ifreq ifr;
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
    {
        perror("socket");
        return -1;
    }
    strcpy(ifr.ifr_name, if_name);
    if (ioctl(sockfd, SIOCGIFADDR, &ifr) < 0)
    {
        perror("ioctl");
        return -1;
    }
    sprintf(ip_str, "%s", inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
    close(sockfd);
    return 0;
};


