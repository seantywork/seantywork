#include "wc.h"


void WC_default_summary(WC_SUMMARY* wcs){


    int status = 0;


    uint8_t* buff;
    size_t byte_len = 0;
    uint64_t lc = 0;
    uint64_t wc = 0;

    status = WC_get_buff_from_file_path(&buff, &byte_len, wcs->file_path);


    if(status < 0){

        fputs("failed to get buffer from file\n", stderr);

        return;

    }


    wcs->byte_count = (uint64_t)byte_len;

    fputs("got byte buffer from file\n", stderr);

    status = WC_count_line_from_buff(&lc, byte_len, buff);

    if(status < 0){
        fputs("failed to get line count from buffer\n", stderr);

        return;
    }


    wcs->line_count = lc;

    fputs("got line count from buffer\n", stderr);

    status = WC_count_word_from_buff(&wc, byte_len, buff);

    if(status < 0){

        fputs("failed to get word count from buffer\n", stderr);

        return;

    }



    wcs->word_count = wc;

    fputs("got word count from buffer\n", stderr);

    printf("%lu %lu %lu %s\n", wcs->line_count, wcs->word_count, wcs->byte_count, wcs->file_path);

    WC_free_buff(buff);


}



int WC_get_buff_from_file_path(uint8_t** buff, size_t* byte_len, char* file_path){

    int valread = 0;

    FILE* fp;


    fp = fopen(file_path, "r");

    if (fp == NULL){

        return -1;

    }


    if (fseek(fp, 0L, SEEK_END) == 0) {

        long bufsize = ftell(fp);

        if (bufsize == -1) { 
            return -2;
        }


        if (fseek(fp, 0L, SEEK_SET) != 0) { 
            return -3;
        }


        *buff = (uint8_t*)malloc(bufsize * sizeof(uint8_t));


        memset(*buff, 0, bufsize * sizeof(uint8_t));


        size_t read_len = fread(*buff, sizeof(uint8_t), bufsize, fp);

        if ( ferror( fp ) != 0 ) {

            return -4;

        } else {

            valread = (int)read_len;

            *byte_len = read_len;

        }
    }
    fclose(fp);

    return valread;

}



int WC_count_line_from_buff(uint64_t* line_count, size_t byte_len, uint8_t* buff){

    uint64_t new_lines = 0;

    char* new_line_delim = "\n";

    char* target_buff = (char*)malloc(byte_len * sizeof(char));

    memset(target_buff, 0, byte_len * sizeof(char));

    memcpy(target_buff, buff, byte_len * sizeof(char));

    char* septr = strsep(&target_buff, new_line_delim);


    while(septr != NULL){

        new_lines += 1;

        septr = strsep(&target_buff, new_line_delim);

    }


    *line_count = new_lines;

    free(target_buff);

    return 0;

}


int WC_count_word_from_buff(uint64_t* word_count, size_t byte_len, uint8_t* buff){

    uint64_t words = 0;

    char* words_delim = " ";

    char* target_buff = (char*)malloc(byte_len * sizeof(char));

    memset(target_buff, 0, byte_len * sizeof(char));

    memcpy(target_buff, buff, byte_len * sizeof(char));

    char* tokptr = strtok(target_buff, words_delim);

    while(tokptr != NULL){

        words += 1;

        tokptr = strtok(NULL, words_delim);

    }

    *word_count = words;

    free(target_buff);

    return 0;

}



void WC_free_buff(uint8_t* buff){


    free(buff);



}