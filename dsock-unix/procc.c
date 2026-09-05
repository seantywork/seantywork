#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

int main() {
    int server_socket;
    struct sockaddr_un server_addr;
    int connection_result;

    char ch='C';

    server_socket = socket(AF_UNIX, SOCK_STREAM, 0);

    server_addr.sun_family = AF_UNIX;
    strcpy(server_addr.sun_path, "sock.d/procd.sock");

    connection_result = connect(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr));

    if (connection_result == -1) {
        perror("Error:");
        exit(1);
    }

    write(server_socket, &ch, 1);
    read(server_socket, &ch, 1);
    printf("Client: I recieved %c from server!\n", ch);
    close(server_socket);
    exit(0);
}