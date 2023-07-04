// PCAP_parcer.cpp : Этот файл содержит функцию "main". Здесь начинается и заканчивается выполнение программы.
#include <iostream>
#include <fstream>
#include <vector>
#include "Parser.h"
#include "Exceptions.h"

using namespace std;

int main(int argc, char* argv[])
{
 //"C:/Users/iranm/Desktop/PCAP-Parser-in-C-main/src/dump_sorm.pcap";
  if (argc != 3)
  {
    std::cout << "You should enter exactly 2 files.";
    return 0;
  }
  FILE* PtrFile = nullptr;                       // the pointer to the file for reading
  std::ofstream WriteFile;                     // the pointer to the file for writing
  errno_t Err = 0;                     //opening with mistake
  const char* File_Read = argv[1];               //"test.pcap";
  const char* File_Write = argv[2];              // "out.jpg.docx";
  std::vector<Handshake> Sessions;

  Err = fopen_s(&PtrFile, File_Read, "rb");      //check for the correct opening of the reading file
  WriteFile.open(File_Write, ios::out);
  if (!WriteFile.is_open())
  {
    std::cerr << "Can't open the file for writing";
    goto close_files;
  }
  if (Err == 0)                                   //if the reading file was opened correctly
  {
    try
    {
      Parser parser(PtrFile, Sessions, WriteFile);        //parse the .pcap file
    }
    catch (Exeptions& obj)
    {
      obj.Handle_Exeption(WriteFile);  //print the error messege and close writing and reading files
    }
    Err = fclose(PtrFile);                     //close reading file
    WriteFile.close();                  //close writing file
  }
  else
  {
    std::cerr << "Can't open the file for reading";
    goto close_files;
  }

 close_files:
   if (PtrFile)                                //if the reading file is still opened
   {
     Err = fclose(PtrFile);
   }
   if (WriteFile)                              //if the writing file is still opened
   {
     WriteFile.close();
   }
   return 0;
}


