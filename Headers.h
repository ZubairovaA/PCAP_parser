#pragma once
#include<Winsock2.h>
#pragma comment(lib, "ws2_32.lib")
#include <stdio.h>

struct pcap_pkthdr {        // ��������� ��������� ����� ������ 
  struct timeval ts;	    // time stamp    
  unsigned int caplen;	// length of portion present 
  unsigned int len;	    // length of this packet (off wire) 
};

struct Link                        //��������� ��������� Ethernet    Ethernet header struct
{
  unsigned char ether_dhost[6];  //MAC ����� ����������           MAC dest address
  unsigned char ether_shost[6];  //MAC ����� �����������          MAC source address
  unsigned short ether_type;     //��� ��������� �������� ������  next level protocol    
};

struct Internet_ip              //��������� ��������� Internet    Internet  header struct
{
  unsigned char ip_vhl;		   // ������ ip ��������� � ����� ���������(*4)  ip protocol version
  unsigned char ip_tos;		   // ��� ������������   type of service
  unsigned short ip_len;		   // ����� ������ ����� ������   the size of the packet
  unsigned short ip_id;		   // ����������������� ����� ������ ��� �������� ����� �� �����   identification
  unsigned short ip_off;		   // fragment offset field   
  unsigned char ip_ttl;		   // time to live
  unsigned char ip_p;		       // �������� ���� ������                next level protocol
  unsigned short ip_sum;		   // ��������                            checksum
  unsigned char ip_src[4];       //  ����� �����������                  source address
  unsigned char ip_dst[4];       //  ����� ����������                   dest address
};

struct Transport_tcp          //��������� ��������� TCP    TCP  header struct
{
  unsigned short src_port;	  // ����� ����� �����������                 source port
  unsigned short dst_port;	  // ����� ����� ����������                  destination port
  unsigned int th_seq;		    // ����� ������ � ������������������       sequence number
  unsigned int th_ack;		    // ����� �������������                     acknowledgement number
  unsigned char th_offx2;	    // ����� ��������� (4 ����)  and reserved bits(3 bits) and flag Nonce( 1 bit)        TCP_Length = (tcp->th_offx2) >>4 
  unsigned char th_flags;     //�����    flags
  unsigned short th_win;		//����                      window
  unsigned short sum;		    //��������                  checksum
  unsigned short th_urp;		//���������� ���������      urgent pointer  
};

bool Handle_Ethernet(Link& ethernet, FILE* ptrFile);   //working with ethernet protocol header
