#include <pcap.h>  
#include <time.h>  
#include <stdlib.h>  
#include <stdio.h>  
#include <netinet/in.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <linux/ip.h>
#include <netinet/tcp.h>
#include <iostream>
#include <ctime>
using namespace std;

void getPacket(u_char * arg, const struct pcap_pkthdr * pkthdr, const u_char * packet)  
{ 
    struct in_addr addr;
    struct tcphdr *tcpptr; 
    int * id = (int *)arg;  
    unsigned char *mac_string;                
    struct ether_header *ethernet_protocol; //以太网头部 
    unsigned short ethernet_type;           //二层头部的以太网类型 
    struct iphdr *ipptr; 
    ethernet_protocol = (struct ether_header *)packet;
   
    //printf("id: %d\n", ++(*id));  //抓包计数
    //printf("Packet length: %d\n", pkthdr->len);  
    //printf("Number of bytes: %d\n", pkthdr->caplen);
    printf("抓包时间: %s", ctime((const time_t *)&pkthdr->ts.tv_sec));   
  
       //分析二层头部信息 
    cout <<"二层头部解析:\t["; 
    mac_string = (unsigned char *)ethernet_protocol->ether_shost;//获取源mac地址  
        printf("源MAC地址: %02x:%02x:%02x:%02x:%02x:%02x  ",*(mac_string+0),*(mac_string+1),*(mac_string+2),*(mac_string+3),*(mac_string+4),*(mac_string+5)); //输出源MAC地址

        mac_string = (unsigned char *)ethernet_protocol->ether_dhost;//获取目的mac  
        printf("目的MAC地址: %02x:%02x:%02x:%02x:%02x:%02x  ",*(mac_string+0),*(mac_string+1),*(mac_string+2),*(mac_string+3),*(mac_string+4),*(mac_string+5)); //输出目的MAC地址  
    ethernet_type = ntohs(ethernet_protocol->ether_type);//获得以太网的类型
  
    //分析数据包二层头部，解析出上层协议
    if (ethernet_type == ETHERTYPE_IP){ //IP protocol
	cout<<"Type:IP ]"<<endl; 
	 
	cout <<"三层头部解析:\t"<<"["; 
        //分析三层头部信息 
	addr.s_addr = ipptr->saddr;//目的IP地址
	cout<<"源IP地址:"<< inet_ntoa(addr) <<"  "; 
	addr.s_addr = ipptr->daddr;//目的IP地址
	cout<<"目的IP地址:"<< inet_ntoa(addr)<<"  ";  
	ipptr = (struct iphdr*)    (packet+sizeof(struct ether_header));//得到ip包头 
	cout <<"Protocol:"; 
	switch(ipptr->protocol){//三层IP报文头部IP协议类型解析
	    case 1://ICMP
	    {
		cout <<"ICMP ]"<<endl;
		break;
	    }
	    case 6://TCP
	    {
		cout <<"TCP ]"<<endl;
		//分析四层头部信息
		cout <<"四层头部解析:\t"<<"["; 
		tcpptr = (struct tcphdr*)(packet+sizeof(struct ether_header)+sizeof(struct iphdr));//得到tcp包头
		cout <<"源端口:"<<ntohs(tcpptr->source)<<"  目的端口:"<<ntohs(tcpptr->dest);
		cout<<" ]";
		break;
	    }
	    case 17://UDP
	    {
		cout <<"UDP ]"<<endl;
		break;
	    }
	} 
    }
    else if (ethernet_type == ETHERTYPE_ARP){//ARP protocol
  	cout <<"Type:ARP "<<endl;
	//解析出源目MAC地址 
	mac_string = (unsigned char *)ethernet_protocol->ether_shost;//获取源mac地址  
	printf("源MAC地址  : %02x:%02x:%02x:%02x:%02x:%02x  ",*(mac_string+0),*(mac_string+1),*(mac_string+2),*(mac_string+3),*(mac_string+4),*(mac_string+5)); //输出源MAC地址
  
	mac_string = (unsigned char *)ethernet_protocol->ether_dhost;//获取目的mac  
	printf("目的MAC地址: %02x:%02x:%02x:%02x:%02x:%02x\n",*(mac_string+0),*(mac_string+1),*(mac_string+2),*(mac_string+3),*(mac_string+4),*(mac_string+5)); //输出目的MAC地址 
    }
    else if (ethernet_type == 0x0835)//ARP protocol
  	cout <<"以太网类型:RARP protocol"<<endl;
    
    //usleep(800*1000);
/*去掉该注释，显示报文详细内容 
    int i;  
    for(i=0; i<pkthdr->len; ++i)  
    {  
      printf(" %02x", packet[i]); 
      if( (i + 1) % 16 == 0 )  
      {  
        printf("\n");  
      }  
    } 
*/ 
    printf("\n\n"); 

}  
  
int main()  
{  
  char errBuf[PCAP_ERRBUF_SIZE], * devStr;  
    
  /* get a device */  
  devStr = pcap_lookupdev(errBuf);  
    
  if(devStr)  
  { 
    cout<<"Listen on interface "<<devStr<<endl; 
  }  
  else  
  {  
    printf("error: %s\n", errBuf);  
    exit(1);  
  }  
    
  /* open a device, wait until a packet arrives */  
  pcap_t * device = pcap_open_live(devStr, 65535, 1, 0, errBuf);  
    
  if(!device)  
  {  
    printf("error: pcap_open_live(): %s\n", errBuf);  
    exit(1);  
  }  
    
  /* construct a filter */  
  struct bpf_program filter;  
//  pcap_compile(device, &filter, "dst port 23", 1, 0);  

 // pcap_setfilter(device, &filter);  
    
  /* wait loop forever */  
  int id = 0;  
  pcap_loop(device, -1, getPacket, (u_char*)&id);  
    
  pcap_close(device);  
  
  return 0;  
}  
