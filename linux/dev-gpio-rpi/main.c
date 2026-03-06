#include "gpio.h"




int main(){



    if (gpioInitialise() < 0){

        return -1;

    }




    gpioSetMode(7, PI_OUTPUT);
    gpioSetMode(14, PI_OUTPUT);
    gpioSetMode(16, PI_INPUT);
    gpioSetMode(17, PI_OUTPUT);


    gpioWrite(7, PI_LOW);
    gpioWrite(14, PI_LOW);


    gpioWrite(17, PI_LOW);

    sleep(1);

    gpioWrite(17, PI_HIGH);





    gpioSetAlertFunc(16, gpio_input_handler);


    while(1){
        
        sleep(1);

    }

    gpioTerminate();

    return 0;
}



void gpio_input_handler(int gpio, int level, uint32_t tick){


    printf("gpio: %d\n", gpio);
    printf("level: %d\n", level);


}