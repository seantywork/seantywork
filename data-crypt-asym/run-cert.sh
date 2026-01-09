#!/bin/bash

make clean

make

./asym.out cert-verify

#valgrind --leak-check=full \
#         --show-leak-kinds=all \
#         --track-origins=yes \
#         --verbose \
#         ./asym.out cert