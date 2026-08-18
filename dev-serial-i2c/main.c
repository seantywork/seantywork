#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wiringPiI2C.h>
#define DEVICE_ID 0x53
#define REG_POWER_CTL   0x2D
#define REG_DATA_X_LOW  0x32
#define REG_DATA_X_HIGH 0x33
#define REG_DATA_Y_LOW  0x34
#define REG_DATA_Y_HIGH 0x35
#define REG_DATA_Z_LOW  0x36
#define REG_DATA_Z_HIGH 0x37
int main (int argc, char **argv)
{
    // Setup I2C communication
    int fd = wiringPiI2CSetup(DEVICE_ID);
    if (fd == -1) {
        return -1;
    }
    printf("I2C communication successfully setup.\n");
    // Switch device to measurement mode
    wiringPiI2CWriteReg8(fd, REG_POWER_CTL, 0b00001000);
    while (1) {
        int dataX = wiringPiI2CReadReg16(fd, REG_DATA_X_LOW);
        dataX = -(~(int16_t)dataX + 1);
        int dataY = wiringPiI2CReadReg16(fd, REG_DATA_Y_LOW);
        dataY = -(~(int16_t)dataY + 1);
        int dataZ = wiringPiI2CReadReg16(fd, REG_DATA_Z_LOW);
        dataZ = -(~(int16_t)dataZ + 1);

        printf("x: %d, y: %d, z: %d\n", dataX, dataY, dataZ);

    }
    return 0;
}