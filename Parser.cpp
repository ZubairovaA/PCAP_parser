#include "Parser.h"
#include "Headers.h"

union BIT_FIELD 
{
  struct BITS
  {
    unsigned FIN : 1;
    unsigned SYN : 1;
    unsigned RST : 1;
    unsigned PUSH : 1;
    unsigned ACK : 1;
    unsigned URG : 1;
    unsigned ECE : 1;
    unsigned CWR : 1;
  } bits;
  unsigned char value;
} flags;

void Parser::Handle_TCP(std::vector<Handshake>& Sessions)
{
  flags.value = TCP.th_flags;
  if (flags.bits.SYN == 1 && flags.bits.ACK == 0)       //the first step of the handshake
  {
    Sessions.push_back({ TCP.src_port, TCP.dst_port, TCP.th_seq, 1 });
  }
  else if (flags.bits.SYN == 1 && flags.bits.ACK == 1)   // the second step of the handshake
  {
    for (int i = 0; i < Sessions.size(); i++)
    {
      if ((Sessions[i].dst_port == TCP.src_port) && (Sessions[i].src_port == TCP.dst_port) && (ntohl(TCP.th_ack) == (Sessions[i].sequence_number + 1)))
      {
        Sessions[i].sequence_number += 1;
        Sessions[i].ack_number = TCP.th_seq;
        Sessions[i].contactStage = 2;
        break;
      }
    }
  }
  else if (flags.bits.SYN == 0 && flags.bits.ACK == 1)  //the third step of the handshake
  {
    for (int i = 0; i < Sessions.size(); i++)
    {
      if ((Sessions[i].dst_port == TCP.dst_port) && (Sessions[i].src_port == TCP.src_port) && (ntohl(TCP.th_seq) == Sessions[i].sequence_number))
      {
        Sessions[i].contactStage = 3;
        break;
      }
    }
    handshakeSucsess++;
  }
  else if (flags.bits.FIN == 1 && flags.bits.ACK == 0)   // finish the session 
  {
    for (int i = 0; i < Sessions.size(); i++)
    {
      if ((Sessions[i].dst_port == TCP.dst_port) && (Sessions[i].src_port == TCP.src_port))
      {
        Sessions[i].finishSession = 1;
        break;
      }
      else if ((Sessions[i].dst_port == TCP.src_port) && (Sessions[i].src_port == TCP.dst_port))
      {
        Sessions[i].finishSession = 2;
        break;
      }
    }
  }
}


void Parser::CountSessions(FILE* ptrFile, std::vector<Handshake>& Sessions, std::ofstream& writeFile)
{
  Parse(ptrFile, Sessions);
  if (Sessions.size() > 0)
  {
    unfinishedSessions = UnfinishedSessionsCount(Sessions);
    unstandartFinishedSessions = UnstandartFinishedSessionsCount(Sessions);
    std::string result = "The.pcap file includes: \n Handshakes: "
    + std::to_string(handshakeSucsess) + "/n Unfinished sessions: "
    + std::to_string(unfinishedSessions) + "/n Unstarnadt sessions: "
    + std::to_string(unstandartFinishedSessions) + "/n";
    writeFile << result.c_str();
  }
  else
  {
    writeFile << "There are no handshakes in the .pcap file.\n";
  }
}

void Parser::Parse(FILE* ptrFile, std::vector<Handshake>& Sessions)
{
  int pkt_offset = 24;           // the pcap file header
  while (fseek(ptrFile, pkt_offset, SEEK_SET) == 0)
  {
    try
    {
      if (fread(&ptk_header, 16, 1, ptrFile) == 0)    //read pcap packet header 16 bytes
      {
        throw Exeptions("Reading the packet header failed");
      }
      if (fread(&ethernet, 14, 1, ptrFile) == 0)     //read ethernet header
      {
        throw Exeptions("Reading the link layer header failed");
      }

      bool checkIP = Handle_Ethernet(ethernet, ptrFile);
      if (checkIP == false)
      {
        throw Exeptions("Internet layer protocol is not the IP Verion 4");
      }
      if (fread(&ip, 14, 1, ptrFile) == 0)          //read internet header
      {
        throw Exeptions("Reading the IP header letgth failed");
      }
      int ipSize = 4 * (ip.ip_vhl & 0x0F);               //counting the IP header length 

      fseek(ptrFile, ipSize - 14, SEEK_CUR);        //moving to the source port in TCP header

      if (ip.ip_p == IPPROTO_TCP)
      {
        if (fread(&TCP, 20, 1, ptrFile) == 0)    //read pcap packet head
        {
           throw Exeptions("Reading the TCP header letgth failed");
        }
        int TCP_Length = 4 * (TCP.th_offx2 >> 4);
        fseek(ptrFile, TCP_Length - 20, SEEK_CUR);        //move pointer to the payload
        Handle_TCP(Sessions);
      }
    }
    catch (Exeptions& obj)
    {
       throw obj;
    }
    pkt_offset += 16 + ptk_header.caplen;
  }
}

int Parser::UnfinishedSessionsCount(std::vector<Handshake>& Sessions)
{
  int count = 0;
  for (int i = 0; i < Sessions.size(); i++)
  {
    if (Sessions[i].contactStage != 3)
    {
      count++;
    }
  }
  return count;
}

int Parser::UnstandartFinishedSessionsCount(std::vector<Handshake>& Sessions)
{
  int count = 0;
  for (int i = 0; i < Sessions.size(); i++)
  {
    if (Sessions[i].finishSession != 2)
    count++;
  }
  return count;
}

Parser::Parser(FILE* ptrFile, std::vector<Handshake>& Sessions, std::ofstream& writeFile)
{
  CountSessions(ptrFile, Sessions, writeFile);
}
