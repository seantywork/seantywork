#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>


struct human {

    char name[32];
    int age;

};


int main(void){

    struct human** people = (struct human**)malloc(9 * sizeof(struct human*));

    for(int i = 0 ; i < 9; i ++){

        people[i] = (struct human*)malloc(sizeof(struct human));

        memset(people[i], 0, sizeof(struct human));

        sprintf(people[i]->name, "hello %d world", i);

        people[i]->age = i + 10;

    }

    for(int i = 0; i < 10; i++){


        printf("name: %s age: %d\n", people[i]->name, people[i]->age);

    }

}
