#ifndef PERSON_H
#define PERSON_H

typedef struct APerson  {
    const char * name;
    const char * long_name;
} APerson ;

APerson *get_person(const char * name, const char * long_name);

#endif