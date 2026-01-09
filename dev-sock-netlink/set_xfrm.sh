#!/bin/bash


ip xfrm state add \
    src 192.168.62.5/24 dst 192.168.62.6/24 proto esp spi 0x01000000 reqid 0x01000000 mode tunnel flag af-unspec \
    aead 'rfc4106(gcm(aes))' 0xaabbccddeeffaabbccddeeffaabbccddeeffaabbccddeeffaabbccddeeffaabbccddeeff 128 \
    sel src 192.168.62.5/24 dst 192.168.62.6/24 


ip xfrm state add \
    src 192.168.62.6/24 dst 192.168.62.5/24 proto esp spi 0x02000000 reqid 0x02000000 mode tunnel flag af-unspec \
    aead 'rfc4106(gcm(aes))' 0xaabbccddeeffaabbccddeeffaabbccddeeffaabbccddeeffaabbccddeeffaabbccddeeff 128 \
    sel src 192.168.62.6/24 dst 192.168.62.5/24 

ip xfrm policy add \
    src 192.168.62.5/24 dst 192.168.62.6/24 dir out \
    tmpl src 192.168.62.5/24 dst 192.168.62.6/24 proto esp reqid 0x01000000 mode tunnel

ip xfrm policy add \
    src 192.168.62.6/24 dst 192.168.62.5/24 dir in \
    tmpl src 192.168.62.6/24 dst 192.168.62.5/24 proto esp reqid 0x02000000 mode tunnel

