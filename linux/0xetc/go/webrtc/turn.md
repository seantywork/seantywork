sudo vim /etc/default/coturn

TURNSERVER_ENABLED=1

sudo systemctl start coturn

sudo vim /etc/turnserver.conf

listening-ip=0.0.0.0

listening-port=3478

external-ip=feebdaed.xyz/192.168.0.1 

min-port=3479 max-port=3579

verbose

lt-cred-mech

user=MYUSER:MYPASS

realm=feebdaed.xyz

sudo systemctl restart coturn