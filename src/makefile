all: RShellServer1 RShellClient1

RShellServer1: RShellServer1.c
	gcc -o RShellServer1 RShellServer1.c -lcrypto
RShellClient1: RShellClient1.c
	gcc -o RShellClient1 RShellClient1.c
clean:
	rm -f RShellServer1
	rm -f RShellClient1
