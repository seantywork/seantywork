
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <inttypes.h>

int str_to_uint16(const char *str, uint16_t *res){
  
  char *end;

  intmax_t val = strtoimax(str, &end, 10);

  if (val < 0 || val > UINT16_MAX || end == str || *end != '\0')
    return -1;
  *res = (uint16_t) val;
  return 0;
}

int terminate_newline(char* buff){

    size_t len = strlen(buff);

    if (len > 0 && buff[len-1] == '\n'){

        buff[len - 1] = '\0';
        return 0;
    } else {
        return 1;
    }


}


 
int main(int argc, char const* argv[])
{
    int status, valread, client_fd;
    struct sockaddr_in serv_addr;
    char* hello = "Hello from client";
    char port_char[20] = "";
    char buffer[1024] = { 0 };
    int ret_code = 0;
    uint16_t PORT = 0;
    int KEEP = 0;
    int COMMAND_LIMIT = 20;
    char cmd_input[20] = "";

    if ((client_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("\n Socket creation error \n");
        return -1;
    }
    
    if (argc != 2){
        printf("\n invalid arg counts: args: PORT\n");
        return -1;
    }


    strcpy(port_char, argv[1]);
 
    printf("argument: %s\n", port_char);

    ret_code = str_to_uint16(port_char, &PORT);

    if (ret_code != 0){

        printf("failed to convert port number: %s",port_char);

        return ret_code;

    }

    printf("port number: %d\n",PORT);

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
 
    
    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
        printf(
            "\nInvalid address/ Address not supported \n");
        return -1;
    }
 
    if ((status = connect(client_fd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)))
        < 0) {
        printf("\nConnection Failed \n");
        return -1;
    }
    

    while (KEEP == 0){

        printf("$ ");

        fgets(cmd_input, COMMAND_LIMIT, stdin);

        send(client_fd, cmd_input, strlen(cmd_input), 0);
        printf("cmd sent:\n");
        printf("-----BEGIN RESULT-----\n");
        valread = read(client_fd, buffer, 1024 - 1);
        printf("%s", buffer);
        memset(buffer, 0, strlen(buffer));
        printf("-----END RESULT-----\n");

        memset(cmd_input, 0, 20);

    } 
    
    close(client_fd);

    return 0;
}