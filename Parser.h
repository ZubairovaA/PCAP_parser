#pragma once
#include <iostream>
#include <vector>
#include <string>
#include "Headers.h"
#include "Exceptions.h"

struct Handshake
{
  unsigned short src_port;	// номер порта отправителя                 source port
  unsigned short dst_port;	// номер порта получателя                  destination portint 
  unsigned int sequence_number = 0;
  int contactStage = 0;
  int finishSession = 0;
  unsigned int ack_number = 0;
};

class Parser
{
private:
  Link ethernet;            //the struct of the Ethernet protocol header
  pcap_pkthdr ptk_header;   // the struct of the packet header
  Internet_ip ip;           //the struct of the IP protocol header
  Transport_tcp TCP;        //the struct of the TCP protocol header
  int handshakeSucsess = 0;
  int unfinishedSessions = 0;
  int unstandartFinishedSessions = 0;
public:
  Parser(FILE* ptrFile, std::vector<Handshake>& Sessions, std::ofstream& writeFile);
  void CountSessions(FILE* ptrFile, std::vector<Handshake>& Sessions, std::ofstream& writeFile);
  void Parse(FILE* ptrFile, std::vector<Handshake>& Sessions);
  int UnfinishedSessionsCount(std::vector<Handshake>& Sessions);
  int UnstandartFinishedSessionsCount(std::vector<Handshake>& Sessions);
  void Handle_TCP(std::vector<Handshake>& Sessions);   //Checking if there are any handshakes in the file
};


