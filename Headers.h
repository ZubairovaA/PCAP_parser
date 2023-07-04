#pragma once
#include<Winsock2.h>
#pragma comment(lib, "ws2_32.lib")
#include <stdio.h>

struct pcap_pkthdr {        // структура заголовка всего пакета 
  struct timeval ts;	    // time stamp    
  unsigned int caplen;	// length of portion present 
  unsigned int len;	    // length of this packet (off wire) 
};

struct Link                        //структура заголовка Ethernet    Ethernet header struct
{
  unsigned char ether_dhost[6];  //MAC адрес получателя           MAC dest address
  unsigned char ether_shost[6];  //MAC адрес отправителя          MAC source address
  unsigned short ether_type;     //тип протокола сетевого уровня  next level protocol    
};

struct Internet_ip              //структура заголовка Internet    Internet  header struct
{
  unsigned char ip_vhl;		   // Версия ip протокола и длина заголовка(*4)  ip protocol version
  unsigned char ip_tos;		   // тип обслуживания   type of service
  unsigned short ip_len;		   // общий размер всего пакета   the size of the packet
  unsigned short ip_id;		   // идентификационный номер пакета при разбивке файла на части   identification
  unsigned short ip_off;		   // fragment offset field   
  unsigned char ip_ttl;		   // time to live
  unsigned char ip_p;		       // протокол след уровня                next level protocol
  unsigned short ip_sum;		   // чексумма                            checksum
  unsigned char ip_src[4];       //  адрес отправления                  source address
  unsigned char ip_dst[4];       //  адрес назначения                   dest address
};

struct Transport_tcp          //структура заголовка TCP    TCP  header struct
{
  unsigned short src_port;	  // номер порта отправителя                 source port
  unsigned short dst_port;	  // номер порта получателя                  destination port
  unsigned int th_seq;		    // номер пакета в последовательности       sequence number
  unsigned int th_ack;		    // номер подтверждения                     acknowledgement number
  unsigned char th_offx2;	    // длина заголовка (4 бита)  and reserved bits(3 bits) and flag Nonce( 1 bit)        TCP_Length = (tcp->th_offx2) >>4 
  unsigned char th_flags;     //флаги    flags
  unsigned short th_win;		//окно                      window
  unsigned short sum;		    //чексумма                  checksum
  unsigned short th_urp;		//экстренный указатель      urgent pointer  
};

bool Handle_Ethernet(Link& ethernet, FILE* ptrFile);   //working with ethernet protocol header
