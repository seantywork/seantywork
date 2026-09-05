#include "wc.h"



int main(int argc, char** argv){


    WC_SUMMARY wcs;


    if(argc != 2){

        fputs("needs [ file path ]\n", stderr);

        return -1;
    }

    wcs.file_path = argv[1];
    
    WC_default_summary(&wcs);


    
}