

#ifndef _WC_H_
#define _WC_H_
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>


typedef struct WC_SUMMARY {

    uint64_t byte_count;
    uint64_t line_count;
    uint64_t word_count;
    char* file_path;

} WC_SUMMARY;




void WC_default_summary(WC_SUMMARY* wcs);

int WC_get_buff_from_file_path(uint8_t** buff, size_t* byte_len,char* file_path);

int WC_count_line_from_buff(uint64_t* line_count, size_t byte_len, uint8_t* buff);

int WC_count_word_from_buff(uint64_t* word_count, size_t byte_len, uint8_t* buff);



void WC_free_buff(uint8_t* buff);












#endif