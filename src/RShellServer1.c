#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <strings.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/errno.h>
#include <openssl/sha.h>
#define DEBUG

int
serversock(int UDPorTCP, int portN, int qlen)
{
	struct sockaddr_in svr_addr;	/* my server endpoint address		*/
	int    sock;			/* socket descriptor to be allocated	*/

	if (portN<0 || portN>65535 || qlen<0)	/* sanity test of parameters */
		return -2;

	bzero((char *)&svr_addr, sizeof(svr_addr));
	svr_addr.sin_family = AF_INET;
	svr_addr.sin_addr.s_addr = INADDR_ANY;

    /* Set destination port number */
	svr_addr.sin_port = htons(portN);

    /* Allocate a socket */
	sock = socket(PF_INET, UDPorTCP, 0);
	if (sock < 0)
		return -3;

    /* Bind the socket */
	if (bind(sock, (struct sockaddr *)&svr_addr, sizeof(svr_addr)) < 0)
		return -4;

	if (UDPorTCP == SOCK_STREAM && listen(sock, qlen) < 0)
		return -5;

	return sock;
}

int 
serverTCPsock(int portN, int qlen) 
{
  return serversock(SOCK_STREAM, portN, qlen);
}

int 
serverUDPsock(int portN) 
{
  return serversock(SOCK_DGRAM, portN, 0);
}

void 
usage(char *self)
{
	fprintf(stderr, "Usage: %s port\n", self);
	exit(1);
}

void 
errmesg(char *msg)
{
	fprintf(stderr, "**** %s\n", msg);
	exit(1);

}

/*------------------------------------------------------------------------
 * reaper - clean up zombie children
 *------------------------------------------------------------------------
 */
void
reaper(int signum)
{
/*
	union wait	status;
*/

	int status;

	while (wait3(&status, WNOHANG, (struct rusage *)0) >= 0)
		/* empty */;
}

/*
 * Extract text from the file and add to the char array.
 * Return the pointer of the char array.
 */
char *getText (char *fileName) {
	unsigned char *text = NULL;
	FILE *file = fopen(fileName, "r");
	if (file == NULL) {
		printf("Invalid file.\n");
		exit(1);
	}

	fseek(file, 0, SEEK_END);
	int length = ftell(file);
	fseek(file, 0, SEEK_SET);
	text = malloc(length + 1);

	int token;
	int i = 0;
	while ((token = fgetc(file)) != EOF) {
		text[i++] = (unsigned char) token;
	}
	fclose(file);
	return text;
}
/*------------------------------------------------------------------------
 *  This is a very simplified remote shell, there are some shell command it 
	can not handle properly:

	cd
 *------------------------------------------------------------------------
 * Added SHA1 Authentication.
 */
int
RemoteShellD(int sock, char *fileName)
{
#define	BUFSZ		128
#define resultSz	4096
	char cmd[BUFSZ+20];
	char result[resultSz];
	int	cc, len;
	int rc=0;
	FILE *fp;
	/*Get text from the file*/
	char *text = getText(fileName);
	/*Use Stotok to seperate ID and Password from the file*/
	char space[] = " ";
	char delim[] = ";";

	char *token = strtok(text, space);
	char *ID = token;

	token = strtok(NULL, space);
	char *pw = token;
	token = strtok(ID, delim);
	ID = token;

	char IDreceived[BUFSZ+20];
	char PWreceived[BUFSZ+20];
	int i;
	/*Read the ID from the client and add to IDreceived array.*/
	if ((cc = read(sock, IDreceived, BUFSZ)) > 0)
	{	/*Compare each character from the ID received from client and ID from the file 
		* Write back the result to the client whether the ID is accepted or not.
		* If ID is not accepted, exit immediately.
		*/
		for (i = 0; i < strlen(ID); i++)
		{
			if (ID[i] != IDreceived[i]) {
				char *ID_fail = "Server: Invalid ID - Authentication Failed!\n";
				write(sock, ID_fail, strlen(ID_fail));
				exit(1);
			}
		}
		char *ID_success = "Server: ID accepted - Now checking Password.\n";
		write(sock, ID_success, strlen(ID_success));
	}
	/*Read the Password from the client and add to PWreceieved array */
	if ((cc = read(sock, PWreceived, BUFSZ)) > 0)
	{
		/*
		 * Obtain the SHA1 hex representation of the PWreceived.
		 */ 
		unsigned char hash[SHA_DIGEST_LENGTH];
		char buf[SHA_DIGEST_LENGTH*2];
		memset(buf, 0x0, SHA_DIGEST_LENGTH *2);
		memset(hash, 0x0, SHA_DIGEST_LENGTH);
		/* After sucessfully obtaining the SHA1 hex representation.
		 * Convert it to char and add to the buf array for pw checking.
		 */
		SHA1((unsigned char *) PWreceived, strlen(PWreceived), hash);
		for (i = 0 ; i < SHA_DIGEST_LENGTH; i++) {
			sprintf((char*) & (buf[i*2]), "%02x", hash[i]);
		}
		/*
		 * Compare each letter between the pw obtained from the text file 
		 * and pw received from the client.
		 * If password is not accepted, write back the result to client and exit.
		 */
		for (i = 0; i < strlen(buf); i++) {
			if (buf[i] != pw[i]) {
				char *PW_fail = "Server: Invalid Password - Authentication Failed!\n";
				write(sock, PW_fail, strlen(PW_fail));
				exit(1);
			}
		}
		/* If pw is accepted, write back the result to client. */
		char *PW_success = "Server: Password accepted - Authentication is successful.\n";
		write(sock, PW_success, strlen(PW_success));
	}
#ifdef DEBUG
	printf("***** RemoteShellD(sock=%d) called\n", sock);
#endif

	while ((cc = read(sock, cmd, BUFSZ)) > 0)	/* received something */
	{	
		
		if (cmd[cc-1]=='\n')
			cmd[cc-1]=0;
		else cmd[cc] = 0;

#ifdef DEBUG
		printf("***** RemoteShellD(%d): received %d bytes: `%s`\n", sock, cc, cmd);
#endif

		strcat(cmd, " 2>&1");
#ifdef DEBUG
	printf("***** cmd: `%s`\n", cmd); 
#endif 
		if ((fp=popen(cmd, "r"))==NULL)	/* stream open failed */
			return -1;

		/* stream open successful */

		while ((fgets(result, resultSz, fp)) != NULL)	/* got execution result */
		{
			len = strlen(result);
			printf("***** sending %d bytes result to client: \n`%s` \n", len, result);

			if (write(sock, result, len) < 0)
			{ rc=-1;
			  break;
			}
		}
		fclose(fp);

	}

	if (cc < 0)
		return -1;

	return rc;
}

/*------------------------------------------------------------------------
 * main - Concurrent TCP server 
 *------------------------------------------------------------------------
 */
int
main(int argc, char *argv[])
{
	int	 msock;			/* master server socket		*/
	int	 ssock;			/* slave server socket		*/
	int  portN;			/* port number to listen */
	struct sockaddr_in fromAddr;	/* the from address of a client	*/
	unsigned int  fromAddrLen;		/* from-address length          */
	int  prefixL, r;

	if (argc==3)
		portN = atoi(argv[1]);
	else usage(argv[0]);
	/* Get the name of the file from the input.*/
	char *fileName = argv[2];
	msock = serverTCPsock(portN, 5);

	(void) signal(SIGCHLD, reaper);
	if (listen(msock, 5) < 0) {
		perror("Error listening.\n");
		exit(1);
	}
	else {
		printf("Server established - Now listening on Port #: %s\n", argv[1]);
	}
	while (1) 
	{
		fromAddrLen = sizeof(fromAddr);
		ssock = accept(msock, (struct sockaddr *)&fromAddr, &fromAddrLen);
		if (ssock < 0) {
			if (errno == EINTR)
				continue;
			errmesg("accept error\n");
		}

		switch (fork()) 
		{
			case 0:		/* child */
				close(msock);
				r=RemoteShellD(ssock, fileName);
				close(ssock);
				exit(r);

			default:	/* parent */
				(void) close(ssock);
				break;
			case -1:
				errmesg("fork error\n");
		}
	}
	close(msock);
}


