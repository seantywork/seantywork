#include "grep.h"

int main(int argc, char** argv){


    BITGREP_TARGET bg_t;

    BITGREP_FLAG flag = BITGREP_FlagParser(&bg_t, argc, argv);



    BITGREP_INPUT2D bg_in2d;

    bg_in2d.row_count = 0;

    BITGREP_FOUND bg_found;

    bg_found.found_count = 0;

    int status = 0;

    switch(flag){

        case EARG:

            fputs("wrong argument\n", stderr);

            return -1;

        case FIND:

            status = BITGREP_MapStdinTo2d(&bg_in2d);

            if(status < 0){

                fputs("map failed\n", stderr);

                return -2;
            }

            status = BITGREP_PopulateSearchResult(bg_t.target_string, &bg_in2d, &bg_found);

            if(status < 0 ){

                fputs("search failed\n", stderr);

                return -3;
            }

            BITGREP_PrintFound(&bg_found);

            BITGREP_Clear(&bg_t, &bg_in2d, &bg_found);

            break;

    }



    return 0;
}