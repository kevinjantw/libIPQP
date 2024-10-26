#include "test_common.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>

#define BUFFER_SIZE 2048

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        fprintf(stderr, "Usage: %s [port]\r\n", argv[0]);
        fflush(stderr);
        return EXIT_FAILURE;
    }

    int port = atoi(argv[1]);

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1)
    {
        printf("Fail to create a socket.\r\n");
        return EXIT_FAILURE;
    }

    struct timeval tv;
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof tv);

    struct sockaddr_in info;
    bzero(&info, sizeof(info));

    info.sin_family = PF_INET;
    info.sin_addr.s_addr = htonl(INADDR_ANY); // inet_addr("127.0.0.1");
    info.sin_port = htons(port);

    int err = connect(sockfd, (struct sockaddr *)&info, sizeof(info));
    if (err == -1)
    {
        printf("Connection error\r\n");
        return EXIT_FAILURE;
    }

    // Send a message to server
    char message[BUFFER_SIZE];
    char receiveMessage[BUFFER_SIZE] = {};
    scanf("%s", message);

    bool print_bin = false;
    int rcv_len = 0;
    int snd_len = 0;
    if (message[0] == '0')
    {
        print_bin = true;
        for (int i = 0; i < BUFFER_SIZE; i++)
            message[i] = i % 256;
        snd_len = send(sockfd, message, BUFFER_SIZE, 0);
        if (snd_len < 0)
        {
            printf("Send message error\r\n");
            close(sockfd);
            return EXIT_FAILURE;
        }

        printf("snd(%d):\r\n", snd_len);
        print_arr((uint8_t *)message, snd_len, 32, NULL);
    }
    else
    {

        snd_len = send(sockfd, message, strlen(message), 0);
        if (snd_len < 0)
        {
            printf("Send message error\r\n");
            close(sockfd);
            return EXIT_FAILURE;
        }

        printf("snd(%d): %s\r\n", snd_len, message);
    }

    int idx = 1;
    while (snd_len > 0)
    {
        rcv_len = recv(sockfd, receiveMessage, sizeof(receiveMessage), 0);

        if (print_bin)
        {
            printf("rcv_%d(%d):\r\n", idx++, rcv_len);
            print_arr((uint8_t *)receiveMessage, rcv_len, 32, NULL);
        }
        else
        {
            printf("rcv_%d(%d): %s\r\n", idx++, rcv_len, receiveMessage);
        }

        if (rcv_len > 0)
            snd_len -= rcv_len;
    }

    printf("close Socket\r\n");
    close(sockfd);

    return EXIT_SUCCESS;
}
