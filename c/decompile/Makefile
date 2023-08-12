vuln-debug: basic.c
	gcc basic.c -g -o basic_d -fno-stack-protector -z execstack -no-pie

vuln: basic.c
	gcc basic.c -o basic -fno-stack-protector -z execstack -no-pie