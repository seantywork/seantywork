#!/bin/bash

set -xe



sudo ip xfrm state add \
	src 10.168.66.1 dst 10.168.66.2 \
	proto esp spi 0x10000000 reqid 1000000 mode tunnel \
	replay-window 0 flag af-unspec \
	aead 'rfc4106(gcm(aes))' 0x1039bd9829ddb04d9cfed0432aa2f30d99784b4910910f71d160c5b40bfe585ba963fcc0 128 \
	encap espinudp 4500 4500 0.0.0.0

sudo ip xfrm state add \
	src 10.168.66.2 dst 10.168.66.1 \
	proto esp spi 0x10000001 reqid 1000000 mode tunnel \
	replay-window 0 flag af-unspec \
	aead 'rfc4106(gcm(aes))' 0x1139bd9829ddb04d9cfed0432aa2f30d99784b4910910f71d160c5b40bfe585ba963fcc0 128 \
	encap espinudp 4500 4500 0.0.0.0




sudo ip xfrm policy add \
	src 192.168.10.0/24 dst 172.31.99.2/32 \
	dir out priority 368255 \
	tmpl src 10.168.66.1 dst 10.168.66.2 \
	proto esp spi 0x10000000 reqid 1000000 mode tunnel

sudo ip xfrm policy add \
	src 172.31.99.2/32 dst 192.168.10.0/24 \
	dir fwd priority 368255 \
	tmpl src 10.168.66.2 dst 10.168.66.1 \
	proto esp reqid 1000000 mode tunnel

sudo ip xfrm policy add \
	src 172.31.99.2/32 dst 192.168.10.0/24 \
	dir in priority 368255 \
	tmpl src 10.168.66.2 dst 10.168.66.1 \
	proto esp reqid 1000000 mode tunnel


sudo ip netns exec vnet ip xfrm state add \
	src 10.168.66.2 dst 10.168.66.1 \
	proto esp spi 0x10000001 reqid 1000000 mode tunnel \
	replay-window 0 flag af-unspec \
	aead 'rfc4106(gcm(aes))' 0x1139bd9829ddb04d9cfed0432aa2f30d99784b4910910f71d160c5b40bfe585ba963fcc0 128 \
	encap espinudp 4500 4500 0.0.0.0

sudo ip netns exec vnet ip xfrm state add \
	src 10.168.66.1 dst 10.168.66.2 \
	proto esp spi 0x10000000 reqid 1000000 mode tunnel \
	replay-window 0 flag af-unspec \
	aead 'rfc4106(gcm(aes))' 0x1039bd9829ddb04d9cfed0432aa2f30d99784b4910910f71d160c5b40bfe585ba963fcc0 128 \
	encap espinudp 4500 4500 0.0.0.0


sudo ip netns exec vnet ip xfrm policy add \
	src 192.168.10.0/24 dst 172.31.99.2/32 \
	dir in priority 368255 \
	tmpl src 10.168.66.1 dst 10.168.66.2 \
	proto esp reqid 1000000 mode tunnel

sudo ip netns exec vnet ip xfrm policy add \
	src 192.168.10.0/24 dst 172.31.99.2/32 \
	dir fwd priority 368255 \
	tmpl src 10.168.66.1 dst 10.168.66.2 \
	proto esp reqid 1000000 mode tunnel

sudo ip netns exec vnet ip xfrm policy add \
	src 172.31.99.2/32 dst 192.168.10.0/24 \
	dir out priority 368255 \
	tmpl src 10.168.66.2 dst 10.168.66.1 \
	proto esp spi 0x10000001 reqid 1000000 mode tunnel