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
#include <netinet/udp.h>
#include <iostream>
#include <ctime>
using namespace std;

void getPacket(u_char * arg, const struct pcap_pkthdr * pkthdr, const u_char * packet)  
{ 
    struct in_addr addr;
    struct ether_header *ethernet_hdrptr; //以太网头部 
    unsigned short ethernet_type;           //二层头部的以太网类型 
    struct iphdr *iphdrptr;  //IP头部结构体 
    struct tcphdr *tcphdrptr;//TCP头部结构体 
    struct udphdr *udphdrptr;//UDP头部结构体
    struct ether_arp *arp;
 
    int * id = (int *)arg;  
    unsigned char *mac_string;
                
    printf("抓包时间: %s", ctime((const time_t *)&pkthdr->ts.tv_sec));  
 
    ethernet_hdrptr = (struct ether_header *)packet;
   
    //printf("id: %d\n", ++(*id));  //抓包计数
    //printf("Packet length: %d\n", pkthdr->len);  
    //printf("Number of bytes: %d\n", pkthdr->caplen);
  
    //分析二层头部信息 
    cout <<"二层头部解析: ["; 
    mac_string = (unsigned char *)ethernet_hdrptr->ether_shost;//获取源mac地址
    //cout <<*(mac_string + 0); 
    printf("源MAC地址: %02x:%02x:%02x:%02x:%02x:%02x  ",*(mac_string+0),*(mac_string+1),*(mac_string+2),*(mac_string+3),*(mac_string+4),*(mac_string+5)); //输出源MAC地址

    mac_string = (unsigned char *)ethernet_hdrptr->ether_dhost;//获取目的mac  
    printf("目的MAC地址: %02x:%02x:%02x:%02x:%02x:%02x  ",*(mac_string+0),*(mac_string+1),*(mac_string+2),*(mac_string+3),*(mac_string+4),*(mac_string+5)); //输出目的MAC地址  
    ethernet_type = ntohs(ethernet_hdrptr->ether_type);//获得以太网的类型
  
    //分析数据包二层头部，解析出上层协议
    if (ethernet_type == ETHERTYPE_IP){ //IP protocol
	cout<<"Type:IP ]"<<endl; 
	 
	cout <<"三层头部解析: ["; 
        //分析三层头部信息
	iphdrptr = (struct iphdr*)    (packet+sizeof(struct ether_header));//得到ip包头 
	addr.s_addr = iphdrptr->saddr;//目的IP地址
	cout<<"源IP地址:"<< inet_ntoa(addr) <<"  "; 
	addr.s_addr = iphdrptr->daddr;//目的IP地址
	cout<<"目的IP地址:"<< inet_ntoa(addr)<<"  ";  
	cout <<"Protocol:"; 
	switch(iphdrptr->protocol){//三层IP报文头部IP协议类型解析
	    case 1://ICMP
	    {
		cout <<"ICMP ]"<<endl;
		break;
	    }
	    case 6://TCP
	    {
		cout <<"TCP ]"<<endl;
		//分析四层头部信息
		cout <<"四层头部解析: ["; 
		tcphdrptr = (struct tcphdr*)(packet+sizeof(struct ether_header)+sizeof(struct iphdr));//得到tcp包头
		cout <<"源端口:"<<ntohs(tcphdrptr->source)<<"  目的端口:"<<ntohs(tcphdrptr->dest);
		cout<<" ]";
		break;
	    }
	    case 17://UDP
	    {
		cout <<"UDP ]"<<endl;
		//分析四层头部信息
                cout <<"四层头部解析:\t"<<"[";
                udphdrptr = (struct udphdr*)(packet+sizeof(struct ether_header)+sizeof(struct iphdr));//得到tcp包头
                cout <<"源端口:"<<ntohs(udphdrptr->source)<<"  目的端口:"<<ntohs(udphdrptr->dest);
                cout<<" ]";

		break;
	    }
	} 
    }
    else if (ethernet_type == ETHERTYPE_ARP){//ARP protocol
  	cout <<"Type:ARP ]"<<endl;
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
  
int main()  {  
    char errBuf[PCAP_ERRBUF_SIZE], * interfaceName;  
      
    interfaceName = pcap_lookupdev(errBuf); //获取网络接口设备名,如eth0 
      
    if(interfaceName)  
    { 
      cout<<"Listen on interface "<<interfaceName<<endl; 
    }  
    else  
    {  
      printf("error: %s\n", errBuf);  
      exit(1);  
    }  
      
    pcap_t * device = pcap_open_live(interfaceName, 65535, 1, 0, errBuf); //打开一个用于捕获数据的网络接口 
      
    if(!device)  
    {  
      printf("error: pcap_open_live(): %s\n", errBuf);  
      exit(1);  
    }  
    
    /*  以下三行的注释去掉，则开启包过滤功能*/  
    //struct bpf_program filter; //bpf_program结 构的指针,用于pcap_compile，格式过滤
    //pcap_compile(device, &filter, "dst port 23", 1, 0); //编译 BPF 过滤规则 
    //pcap_setfilter(device, &filter); //应用 BPF 过滤规则 
      
    int id = 0; 
  
    //循环捕获网络数据包，直到遇到错误或者满足退出条件。每次捕获一个数据包就会调用 callback 指定的回调函数(此处为getPacket)
    pcap_loop(device, -1, getPacket, (u_char*)&id);  
      
    pcap_close(device); //释放网络接口 
    
    return 0;  
}  
