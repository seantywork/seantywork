#ifndef _RPSPI_SERVER_H_
#define _RPSPI_SERVER_H_


#define _GNU_SOURCE


#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <ctype.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <time.h>
#include <sys/time.h>
#include <math.h>

#include <linux/spi/spidev.h>


#include <sched.h>


#define SPI_MAX_BYTE_LEN       4096
#define SPI_MODE 0
#define SPI_BPW 32
#define SPI_SPEED 40000000 

#define WRITE_LEN 2
#define READ_LEN 10240

typedef struct spi_config_t {
    uint8_t mode;
    uint8_t bits_per_word;
    uint32_t speed;
    uint16_t delay;
} spi_config_t;





int spi_open(char *device, spi_config_t config);
int spi_close(int fd);
int spi_xfer(int fd, uint8_t *tx_buffer, uint32_t tx_len, uint8_t *rx_buffer, uint32_t rx_len);


static char* spidev_name = "/dev/spidev0.0";


#endif