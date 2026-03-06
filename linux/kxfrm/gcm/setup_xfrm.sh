#!/bin/bash

ip xfrm state add \
    src 10.168.66.1/24 dst 10.168.66.2/24 proto esp spi 0x01000000 reqid 0x01000000 mode tunnel flag af-unspec \
    aead 'rfc4106(gcm(aes))' 0xaabbccddeeffaabbccddeeffaabbccddeeffaabbccddeeffaabbccddeeffaabbccddeeff 128 \
    sel src 10.168.66.1/24 dst 10.168.66.2/24

ip xfrm state add \
    src 10.168.66.2/24 dst 10.168.66.1/24 proto esp spi 0x02000000 reqid 0x02000000 mode tunnel flag af-unspec \
    aead 'rfc4106(gcm(aes))' 0xaabbccddeeffaabbccddeeffaabbccddeeffaabbccddeeffaabbccddeeffaabbccddeeff 128 \
    sel src 10.168.66.2/24 dst 10.168.66.1/24

ip xfrm policy add \
    src 10.168.66.1/24 dst 10.168.66.2/24 dir out \
    tmpl src 10.168.66.1/24 dst 10.168.66.2/24 proto esp reqid 0x01000000 mode tunnel

ip xfrm policy add \
    src 10.168.66.2/24 dst 10.168.66.1/24 dir in \
    tmpl src 10.168.66.2/24 dst 10.168.66.1/24 proto esp reqid 0x02000000 mode tunnel


ip netns exec vnet ip xfrm state add \
    src 10.168.66.1/24 dst 10.168.66.2/24 proto esp spi 0x01000000 reqid 0x01000000 mode tunnel flag af-unspec \
    aead 'rfc4106(gcm(aes))' 0xaabbccddeeffaabbccddeeffaabbccddeeffaabbccddeeffaabbccddeeffaabbccddeeff 128 \
    sel src 10.168.66.1/24 dst 10.168.66.2/24

ip netns exec vnet ip xfrm state add \
    src 10.168.66.2/24 dst 10.168.66.1/24 proto esp spi 0x02000000 reqid 0x02000000 mode tunnel flag af-unspec \
    aead 'rfc4106(gcm(aes))' 0xaabbccddeeffaabbccddeeffaabbccddeeffaabbccddeeffaabbccddeeffaabbccddeeff 128 \
    sel src 10.168.66.2/24 dst 10.168.66.1/24

ip netns exec vnet ip xfrm policy add \
    src 10.168.66.1/24 dst 10.168.66.2/24 dir in \
    tmpl src 10.168.66.1/24 dst 10.168.66.2/24 proto esp reqid 0x01000000 mode tunnel

ip netns exec vnet ip xfrm policy add \
    src 10.168.66.2/24 dst 10.168.66.1/24 dir out \
    tmpl src 10.168.66.2/24 dst 10.168.66.1/24 proto esp reqid 0x02000000 mode tunnel
