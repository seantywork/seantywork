#!/bin/bash

rm -rf target

cargo build --release 

/bin/cp -Rf target/release/ncat ncat.out
