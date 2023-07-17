#!/bin/bash

while true; do cat resp | nc -l 0.0.0.0 8001; done

