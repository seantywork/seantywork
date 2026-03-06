IFACE="$1"
PORT="$2"



sudo tcpdump -i $IFACE -A -X -c 20 -v port $PORT 