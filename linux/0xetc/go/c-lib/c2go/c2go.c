#include <stdlib.h>
#include "c2go.h"


APerson *get_person(const char *name, const char *long_name){

    APerson *fmt = malloc(sizeof(APerson));
    fmt->name = name;
    fmt->long_name = long_name;

    return fmt;
};