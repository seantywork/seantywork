#include "spi.h"





int main(){




    int spi_fd;
    uint32_t tx_len;
    uint32_t rx_len;
    uint8_t tx_buffer[SPI_MAX_BYTE_LEN];
    uint8_t rx_buffer[SPI_MAX_BYTE_LEN];


    uint8_t write_buffer[WRITE_LEN] = {0};
    uint8_t read_buffer[READ_LEN] = {0};    
    int read_buffer_count;

    spi_config_t sconfig;

    int status;

    sconfig.bits_per_word = SPI_BPW;
    sconfig.delay = 0;
    sconfig.mode = SPI_MODE;
    sconfig.speed = SPI_SPEED;

    cpu_set_t  mask;

    
    CPU_ZERO(&mask);
    CPU_SET(2, &mask);

    int result = sched_setaffinity(0, sizeof(mask), &mask);

    spi_fd  = spi_open(spidev_name, sconfig);

    if(fd < 0 ){

        return -1;
    }

    memset(tx_buffer, 0, SPI_MAX_BYTE_LEN * sizeof(uint8_t));
    memset(rx_buffer, 0, SPI_MAX_BYTE_LEN * sizeof(uint8_t));

    // some random write
    write_buffer[0] = 0xF1;
    write_buffer[1] = 0xCC;

    memcpy(tx_buffer, write_buffer, WRITE_LEN * sizeof(uint8_t));

    status = spi_xfer(spi_fd, tx_buffer, WRITE_LEN, rx_buffer, 0);


    int xfer_end = 0;
    int read_total_len = READ_LEN;

    read_buffer_count = 0;
    for(;;){

        memset(tx_buffer, 0, SPI_MAX_BYTE_LEN * sizeof(uint8_t));
        memset(rx_buffer, 0, SPI_MAX_BYTE_LEN * sizeof(uint8_t));

        int read_target_len = 0;

        if(read_total_len > SPI_MAX_BYTE_LEN){

            read_target_len = SPI_MAX_BYTE_LEN;

            read_total_len -= SPI_MAX_BYTE_LEN;

        } else {

            read_target_len = read_total_len;

            xfer_end = 1;
        }


        status = spi_xfer(spi_fd, tx_buffer, 0, rx_buffer, read_target_len);

        for(int i = 0; i < read_target_len; i++){

            int read_buff_idx = read_buffer_count + i;

            read_buffer[read_buff_idx] = rx_buffer[i];

            read_buffer_count += 1;
        }

        if(xfer_end == 1){
            break;
        }

    }



    spi_close(spi_fd);


    return 0;
}