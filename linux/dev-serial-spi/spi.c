#include "spi.h"


int spi_open(char *device, spi_config_t config) {
    int fd;

    fd = open(device, O_RDWR);
    if (fd < 0) {
        return fd;
    }


#if SPI_BPW == 8

    
    if (ioctl(fd, SPI_IOC_WR_MODE, &config.mode) < 0) {
        return -1;
    }
    if (ioctl(fd, SPI_IOC_RD_MODE, &config.mode) < 0) {
        return -1;
    }
    

#elif SPI_BPW == 32

    if (ioctl(fd, SPI_IOC_WR_MODE32, &config.mode) < 0) {
        return -1;
    }
    if (ioctl(fd, SPI_IOC_RD_MODE32, &config.mode) < 0) {
        return -1;
    }
#endif

    if (ioctl(fd, SPI_IOC_WR_BITS_PER_WORD, &config.bits_per_word) < 0) {
        return -1;
    }
    if (ioctl(fd, SPI_IOC_RD_BITS_PER_WORD, &config.bits_per_word) < 0) {
        return -1;
    }

    if (ioctl(fd, SPI_IOC_WR_MAX_SPEED_HZ, &config.speed) < 0) {
        return -1;
    }
    if (ioctl(fd, SPI_IOC_RD_MAX_SPEED_HZ, &config.speed) < 0) {
        return -1;
    }
    return fd;
}

int spi_close(int fd) {
    return close(fd);
}




int spi_xfer(int fd, uint8_t *tx_buffer, uint32_t tx_len, uint8_t *rx_buffer, uint32_t rx_len){
    struct spi_ioc_transfer spi_message[2];
    memset(spi_message, 0, sizeof(spi_message));
    
    spi_message[0].tx_buf = (unsigned long)tx_buffer;
    spi_message[0].len = tx_len;
    spi_message[0].delay_usecs = 0;
    spi_message[0].word_delay_usecs = 0;


    spi_message[1].rx_buf = (unsigned long)rx_buffer;
    spi_message[1].len = rx_len;
    spi_message[1].delay_usecs = 0;
    spi_message[1].word_delay_usecs = 0;

    
    return ioctl(fd, SPI_IOC_MESSAGE(2), spi_message);
}
