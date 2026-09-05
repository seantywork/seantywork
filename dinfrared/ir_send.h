#ifndef IRSLINGER_H
#define IRSLINGER_H

#include <stdio.h>
#include <string.h>
#include <math.h>
#include <pigpio.h>

#define MAX_COMMAND_SIZE 512
#define MAX_PULSES 12000

void addPulse(uint32_t onPins, uint32_t offPins, uint32_t duration, gpioPulse_t *irSignal, int *pulseCount);

// Generates a square wave for duration (microseconds) at frequency (Hz)
// on GPIO pin outPin. dutyCycle is a floating value between 0 and 1.
void carrierFrequency(uint32_t outPin, double frequency, double dutyCycle, double duration, gpioPulse_t *irSignal, int *pulseCount);

// Generates a low signal gap for duration, in microseconds, on GPIO pin outPin
void gap(uint32_t outPin, double duration, gpioPulse_t *irSignal, int *pulseCount);

// Transmit generated wave
int transmitWave(uint32_t outPin, gpioPulse_t *irSignal, unsigned int *pulseCount);

int irSlingRC5(uint32_t outPin,
	int frequency,
	double dutyCycle,
	int pulseDuration,
	const char *code);

int irSling(uint32_t outPin,
	int frequency,
	double dutyCycle,
	int leadingPulseDuration,
	int leadingGapDuration,
	int onePulse,
	int zeroPulse,
	int oneGap,
	int zeroGap,
	int sendTrailingPulse,
	const char *code);

int irSlingRaw(uint32_t outPin,
	int frequency,
	double dutyCycle,
	const int *pulses,
	int numPulses);

#endif