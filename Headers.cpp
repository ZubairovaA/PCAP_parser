#pragma once
#include "Headers.h"

void VLAN_Protocol(Link& ethernet, FILE* ptrFile)
{
  if (ntohs(ethernet.ether_type) == 0x8100) // checking for the VLAN tag  
  {
    fseek(ptrFile, 2, SEEK_CUR);               //if there is the VLAN tag, mooving the pointer for the 4 bytes to determinate the beginning of the ether type 
    fread(&ethernet.ether_type, 2, 1, ptrFile);
  }
}

bool Check_IP_Protocol(Link& ethernet, FILE* ptrFile)
{
  if (ntohs(ethernet.ether_type) != 0x0800)   //if the internet layer protocol is the Internet Protocol Verion 4
  {
    return true;
  }
  else
  {
    return false;
  }
}

bool Handle_Ethernet(Link& ethernet, FILE* ptrFile)
{
  VLAN_Protocol(ethernet, ptrFile);
  return  Check_IP_Protocol(ethernet, ptrFile);
}

