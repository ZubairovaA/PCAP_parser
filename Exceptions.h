#pragma once
#include<iostream>
#include <fstream>

class Exeptions
{
private:
  std::string Str_error = "";     //string for error messege
  int x = 0, y = 0, index = 0;    // x- off wire recieved bytes, y- planed length of the packet
  char C_Str[80];

public:
  Exeptions(const char* Error) : Str_error(Error) { };
  Exeptions(int X, int Y, int Index) : x(X), y(Y), index(Index)
  {
	  sprintf_s(C_Str, 80, "In the frame %d were recieved %d bytes instead of %d bytes", index, x, y);
	  Str_error = C_Str;
  }
  const char* getError() { return Str_error.c_str(); }
  void Handle_Exeption(std::ofstream& WriteFile)
  {
	  WriteFile << getError();                    //print error messeg
  }
};

