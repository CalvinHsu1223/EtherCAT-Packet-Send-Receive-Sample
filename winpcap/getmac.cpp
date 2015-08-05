#include<winsock2.h>
#include<Iphlpapi.h>
#include<stdio.h>
#pragma comment(lib,"Iphlpapi.lib")

int getmac()
{
PIP_ADAPTER_ADDRESSES pAddresses;
ULONG outBufLen = 0;
DWORD dwRetVal = 0;

pAddresses = (IP_ADAPTER_ADDRESSES*) malloc(sizeof(IP_ADAPTER_ADDRESSES));

if (GetAdaptersAddresses(AF_INET, 
  0, 
  NULL, 
  pAddresses, 
  &outBufLen) == ERROR_BUFFER_OVERFLOW) 
{
  GlobalFree(pAddresses);
  pAddresses = (IP_ADAPTER_ADDRESSES*) malloc(outBufLen);
}


if ((dwRetVal = GetAdaptersAddresses(AF_INET, 
  0, 
  NULL, 
  pAddresses, 
  &outBufLen)) == NO_ERROR) 
{
  while (pAddresses) 
  {
   printf("AdapterName: %S ",pAddresses->AdapterName);
   printf("Description: %S ", pAddresses->Description);
   printf("PhysicalAddress: %02x-%02x-%02x-%02x-%02x-%02x ",
                        pAddresses->PhysicalAddress[0],
         pAddresses->PhysicalAddress[1],
         pAddresses->PhysicalAddress[2],
         pAddresses->PhysicalAddress[3],
         pAddresses->PhysicalAddress[4],
         pAddresses->PhysicalAddress[5]);
   pAddresses = pAddresses->Next;
  }
  return 0;
}
else
  printf("Get Adapter Information failed! ");

}