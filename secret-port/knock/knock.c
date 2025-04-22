#include "knock.h"


void* process_rx(const int fd, char* rx_ring, int* len){

    struct tpacket2_hdr* header;
    struct pollfd				  pollset;
    int							  ret;
    char*				 off;



    for (int i = 0; i < CONF_RING_FRAMES; i++){
        // fetch a frame
        
        header = (void*)rx_ring + (i * FRAME_SIZE);
        assert((((unsigned long)header) & (FRAME_SIZE - 1)) == 0);

        if (header->tp_status != TP_STATUS_AVAILABLE){
            // if none available: wait on more data
            pollset.fd		= fd;
            pollset.events	= POLLIN;
            pollset.revents = 0;
            ret				= poll(&pollset, 1, 1 /* don't hang */);

        }


        if (header->tp_status & TP_STATUS_USER){

            if (header->tp_status & TP_STATUS_COPY){
                printf("copy\n");
                continue;
            }
            *len = header->tp_len;

            return (void*)header;
        }
    }
    return NULL;
}


void process_rx_release(char* packet){
    struct tpacket2_hdr* header = (struct tpacket2_hdr*)packet;
    header->tp_status					 = TP_STATUS_KERNEL;
}

void rx_flush(void* ring){
    for (int i = 0; i < CONF_RING_FRAMES; i++){
        struct tpacket2_hdr* hdr = ring + (i * FRAME_SIZE);
        hdr->tp_status					  = TP_STATUS_KERNEL;
    }
}


void do_rx(){

    int	  status = 1;
    char *rxRing, *pkt;
    int	  rxFd;
    int	  len;

    struct sockaddr_ll txdest_daddr;
    struct sockaddr_ll rxdest_daddr;


    rxFd = init_packetsock(&rxRing, PACKET_RX_RING, 1, &rxdest_daddr);
    if (rxFd < 0){
        printf("failed to init rx packet sock\n");
        return;
    }

    

    if (bind(rxFd, (struct sockaddr*)&rxdest_daddr, sizeof(rxdest_daddr)) != 0)
    {
        printf("bind rxfd\n");
        return;
    }



    int needs_flush = 0;
    int count = 0;
    while(1){

        
        int	  offset = 0;
        char* pkt	 = NULL;


        while (pkt = process_rx(rxFd, rxRing, &len)){

            uint8_t* off = ((void*)pkt) + RX_DATA_OFFSET;

            printf("server RX: %d \n", count);

            view_packet(off);

            printf("\n");

            process_rx_release(pkt);

            needs_flush = 1;

            count += 1;
            
        }

        if (needs_flush == 1){
            rx_flush(rxRing);
            needs_flush = 0;
        }
    
    }



    if (exit_packetsock(rxFd, rxRing, 1))
        return;



    return;
}

