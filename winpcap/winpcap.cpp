#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <remote-ext.h> 
#include <packet32.h>
#include <ntddndis.h>
#define ETH_ALEN 6
#define WKC_LEN 2
#define ecat 0x88A4
unsigned char DataGramData[20];
const unsigned char BroadcastEthernetAddress[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
const unsigned char FirstMulticastEthernetAddress[6] = {0x01, 0x01, 0x05, 0x01, 0x00, 0x00};

typedef struct datagram_header 
{ 
  unsigned char  data_cmd;
  unsigned char  data_idx;
  unsigned short data_addr1;
  unsigned short data_addr2;
  unsigned short data_len :11;
  unsigned short data_r :3;
  unsigned short data_c :1;
  unsigned short data_m :1;
  unsigned short data_irq;
} datahdr, *pdatahdr;

typedef struct mailbox_header
{
  unsigned short mail_len;
  unsigned short mail_addr;
  unsigned char mail_channel :6;
  unsigned char mail_priority :2;
  unsigned char mail_type :4;
  unsigned char mail_ctr :3;
  unsigned char mail_0 :1;
} mailhdr, *pmailhdr;

typedef struct coe_header
{
  unsigned short coe_num :9;
  unsigned short coe_res :3;
  unsigned short coe_type :4;
} coehdr, *pcoehdr;

typedef struct sdo_header
{
  unsigned int sdo_ctl :8;
  unsigned int sdo_index :16;
  unsigned int sdo_subidx :8;
  unsigned int sdo_data;
} sdohdr, *psdohdr;

typedef struct sm_header
{
  unsigned short sm_addr;
  unsigned short sm_len;
  unsigned int	 sm_flags;
} smhdr, *psmhdr;

typedef struct fmmu_header
{
  unsigned int	 lg_start;
  unsigned short fmmu_len;
  unsigned char	 lg_startbit;
  unsigned char	 lg_stopbit;
  unsigned short phy_start;
  unsigned char	 phy_startbit;
  unsigned char	 fmmu_type;
  unsigned char	 fmmu_act;
  unsigned short fmmu_res;
} fmmuhdr, *pfmmuhdr;

typedef struct frame_header
{
  unsigned short len :11;
  unsigned short res :1;
  unsigned short type :4;
} framehdr, *pframehdr;

typedef struct ethernet_header
{
  unsigned char h_dest[ETH_ALEN]; 
  unsigned char h_source[ETH_ALEN]; 
  unsigned short h_proto; 
} ethhdr, *pethhdr;


void main(int argc, char **argv)
{
pcap_t *fp;
char errbuf[PCAP_ERRBUF_SIZE];
u_char packet[65536];
int i=0;
int inum=0;
int p_size =0;
int d_len[10];
pcap_if_t *alldevs;
pcap_if_t *d;
LPADAPTER	lpAdapter = 0;
DWORD		dwErrorCode;
PPACKET_OID_DATA  OidData;
BOOLEAN		Status;
void* endof = NULL;

/*取得網卡*/
//pcap_t *adhandle;
const u_char *res;
struct tm *ltime;
char timestr[16];
struct pcap_pkthdr header;
time_t local_tv_sec;
    /* Check the validity of the command line */
	    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
    {
        fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }
    for(d=alldevs; d; d=d->next)
    {
        printf("%d. %s\n", ++i, d->name);
    }
		 if (i == 0)   
	        printf("No interfaces found! Make sure WinPcap is installed.\n");   

    printf("Enter the interface number (1-%d):",i);   
    scanf_s("%d", &inum);   

    for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);  
	if ( (fp= pcap_open(d->name,            // name of the device
                        100,                // portion of the packet to capture (only the first 100 bytes)
                        PCAP_OPENFLAG_PROMISCUOUS,  // promiscuous mode
                        1000,               // read timeout
                        NULL,               // authentication on the remote machine
                        errbuf              // error buffer
                        ) ) == NULL)
    {
        fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		pcap_freealldevs(alldevs);//release
		system("Pause");
        return;
    }

	//封包初始化
    ethhdr   *ehdr;
    framehdr *fhdr;
    datahdr  *dhdr;
    mailhdr  *mhdr;
    coehdr   *chdr;
    sdohdr   *shdr;
    smhdr    *synhdr;
    fmmuhdr  *fmhdr;
    memset(&packet, 0x00, sizeof(packet));//封包內容清空

    ehdr = (pethhdr)packet;
  	lpAdapter =   PacketOpenAdapter(d->name+8);	
	if (!lpAdapter || (lpAdapter->hFile == INVALID_HANDLE_VALUE))
	{
		dwErrorCode=GetLastError();
		printf("Unable to open the adapter, Error Code : %lx\n",dwErrorCode); 
		return;
	}	
	
	// Allocate a buffer to get the MAC adress
	OidData = (PPACKET_OID_DATA)malloc(6 + sizeof(PACKET_OID_DATA));
	if (OidData == NULL) 
	{
		printf("error allocating memory!\n");
		PacketCloseAdapter(lpAdapter);
		return;
	}

	// Retrieve the adapter MAC querying the NIC driver
	OidData->Oid = OID_802_3_CURRENT_ADDRESS;
	OidData->Length = 6;
	ZeroMemory(OidData->Data, 6);
	
	Status = PacketRequest(lpAdapter, FALSE, OidData);
	if(Status)
	{
		ehdr->h_source[0]=(OidData->Data)[0];
		ehdr->h_source[1]=(OidData->Data)[1];
		ehdr->h_source[2]=(OidData->Data)[2];
		ehdr->h_source[3]=(OidData->Data)[3];
		ehdr->h_source[4]=(OidData->Data)[4];
		ehdr->h_source[5]=(OidData->Data)[5];
	}
	else
		printf("error retrieving the MAC address of the adapter!\n");
	free(OidData);
	PacketCloseAdapter(lpAdapter);  
	ehdr->h_proto = htons(ecat);
	int cmd_cnt, cmd_ini;


/*----------------------------------------------------------------------------------------------------------------------------------------------------------------------------*/
  /*ECat初始化封包區*/

  memcpy(ehdr->h_dest, BroadcastEthernetAddress, ETH_ALEN);//廣播
  /*封包 1*/
  cmd_cnt = 1;//命令數量
  cmd_ini = -1;
  fhdr = (pframehdr)(packet + sizeof(ethhdr));
  fhdr->len = 0x0e;
  fhdr->res = 0;
  fhdr->type = 1;
  endof = (void*)((int)fhdr + sizeof(framehdr));

  dhdr = (pdatahdr)endof;
  dhdr->data_cmd = 7;
  dhdr->data_idx = 0x00;
  dhdr->data_addr1 = 0x0000;
  dhdr->data_addr2 = 0x0000;
  dhdr->data_len = 2;
  d_len[++cmd_ini] = dhdr->data_len;
  dhdr->data_r = 0; 
  dhdr->data_c = 0;
  dhdr->data_m = 0;
  dhdr->data_irq = 0;
  endof = (void*)((int)endof + sizeof(datahdr));
  for(int n=0; n<cmd_cnt; n++)
	  endof = (void*)((int)endof + WKC_LEN + d_len[n]);
  p_size =  (int)endof - (int)packet;
    /* Send down the packet */
    if (pcap_sendpacket(fp, packet, p_size /* size */) != 0)
    {
        fprintf(stderr,"\nError sending the packet: \n", pcap_geterr(fp));
		system("Pause");
        return;
    }
  memset(packet+ sizeof(ethhdr) + sizeof(framehdr),0x00 ,sizeof(packet) - sizeof(ethhdr) - sizeof(framehdr));

  memcpy(ehdr->h_dest, FirstMulticastEthernetAddress, ETH_ALEN);//多播
  for(int ini = 0 ; ini <2 ; ini++){
  /*封包 2*/
  cmd_cnt = 1;//命令數量
  cmd_ini = -1;
  fhdr = (pframehdr)(packet + sizeof(ethhdr));
  fhdr->len = 0x0e;
  fhdr->res = 0;
  fhdr->type = 1;
  endof = (void*)((int)fhdr + sizeof(framehdr));

  dhdr = (pdatahdr)endof;
  dhdr->data_cmd = 7;
  dhdr->data_idx = 0x80;
  dhdr->data_addr1 = 0x0000;
  dhdr->data_addr2 = 0x0130;
  dhdr->data_len = 2;
  d_len[++cmd_ini] = dhdr->data_len;
  dhdr->data_r = 0; 
  dhdr->data_c = 0;
  dhdr->data_m = 0;
  dhdr->data_irq = 0;
  endof = (void*)((int)endof + sizeof(datahdr));
  for(int n=0; n<cmd_cnt; n++)
	  endof = (void*)((int)endof + WKC_LEN + d_len[n]);
  p_size =  (int)endof - (int)packet;
    /* Send down the packet */
    if (pcap_sendpacket(fp, packet, p_size /* size */) != 0)
    {
        fprintf(stderr,"\nError sending the packet: \n", pcap_geterr(fp));
		system("Pause");
        return;
    }
  memset(packet+ sizeof(ethhdr) + sizeof(framehdr),0x00 ,sizeof(packet) - sizeof(ethhdr) - sizeof(framehdr));

  /*封包 3*/
  cmd_cnt = 1;//命令數量
  cmd_ini = -1;
  fhdr = (pframehdr)(packet + sizeof(ethhdr));
  fhdr->len = 0x0e;
  fhdr->res = 0;
  fhdr->type = 1;
  endof = (void*)((int)fhdr + sizeof(framehdr));

  dhdr = (pdatahdr)(packet + sizeof(ethhdr) + sizeof(framehdr));
  dhdr->data_cmd = 7;
  dhdr->data_idx = 0x81;
  dhdr->data_addr1 = 0x0000;
  dhdr->data_addr2 = 0x0130;
  dhdr->data_len = 2;
  d_len[++cmd_ini] = dhdr->data_len;
  dhdr->data_r = 0; 
  dhdr->data_c = 0;
  dhdr->data_m = 0;
  dhdr->data_irq = 0;
  endof = (void*)((int)endof + sizeof(datahdr));
  for(int n=0; n<cmd_cnt; n++)
	  endof = (void*)((int)endof + WKC_LEN + d_len[n]);
  p_size =  (int)endof - (int)packet;

    /* Send down the packet */
    if (pcap_sendpacket(fp, packet, p_size /* size */) != 0)
    {
        fprintf(stderr,"\nError sending the packet: \n", pcap_geterr(fp));
		system("Pause");
        return;
    }
  memset(packet+ sizeof(ethhdr) + sizeof(framehdr),0x00 ,sizeof(packet) - sizeof(ethhdr) - sizeof(framehdr));

  /*封包 4*/
  cmd_cnt = 1;//命令數量
  cmd_ini = -1;
  fhdr = (pframehdr)(packet + sizeof(ethhdr));
  fhdr->len = 0x0e;
  fhdr->res = 0;
  fhdr->type = 1;
  endof = (void*)((int)fhdr + sizeof(framehdr));

  dhdr = (pdatahdr)(packet + sizeof(ethhdr) + sizeof(framehdr));
  dhdr->data_cmd = 8;
  dhdr->data_idx = 0x82;
  dhdr->data_addr1 = 0x0000;
  dhdr->data_addr2 = 0x0200;
  dhdr->data_len = 2;
  d_len[++cmd_ini] = dhdr->data_len;
  dhdr->data_r = 0; 
  dhdr->data_c = 0;
  dhdr->data_m = 0;
  dhdr->data_irq = 0;
  DataGramData[0] = 0x04;
  DataGramData[1] = 0x00;
  memcpy(&(dhdr->data_irq) + 1,DataGramData,d_len[cmd_ini]);
  endof = (void*)((int)endof + sizeof(datahdr));
  for(int n=0; n<cmd_cnt; n++)
	  endof = (void*)((int)endof + WKC_LEN + d_len[n]);
  p_size =  (int)endof - (int)packet;
    /* Send down the packet */
    if (pcap_sendpacket(fp, packet, p_size /* size */) != 0)
    {
        fprintf(stderr,"\nError sending the packet: \n", pcap_geterr(fp));
		system("Pause");
        return;
    }
  memset(packet+ sizeof(ethhdr) + sizeof(framehdr),0x00 ,sizeof(packet) - sizeof(ethhdr) - sizeof(framehdr));


  /*封包 5*/
  cmd_cnt = 1;//命令數量
  cmd_ini = -1;
  fhdr = (pframehdr)(packet + sizeof(ethhdr));
  fhdr->len = 0x0e;
  fhdr->res = 0;
  fhdr->type = 1;
  endof = (void*)((int)fhdr + sizeof(framehdr));

  dhdr = (pdatahdr)(packet + sizeof(ethhdr) + sizeof(framehdr));
  dhdr->data_cmd = 8;
  dhdr->data_idx = 0x83;
  dhdr->data_addr1 = 0x0000;
  dhdr->data_addr2 = 0x0010;
  dhdr->data_len = 2;
  d_len[++cmd_ini] = dhdr->data_len;
  dhdr->data_r = 0; 
  dhdr->data_c = 0;
  dhdr->data_m = 0;
  dhdr->data_irq = 0;
  endof = (void*)((int)endof + sizeof(datahdr));
  for(int n=0; n<cmd_cnt; n++)
	  endof = (void*)((int)endof + WKC_LEN + d_len[n]);
  p_size =  (int)endof - (int)packet;
    /* Send down the packet */
    if (pcap_sendpacket(fp, packet, p_size /* size */) != 0)
    {
        fprintf(stderr,"\nError sending the packet: \n", pcap_geterr(fp));
		system("Pause");
        return;
    }
  memset(packet+ sizeof(ethhdr) + sizeof(framehdr),0x00 ,sizeof(packet) - sizeof(ethhdr) - sizeof(framehdr));


  /*封包 6*/
  cmd_cnt = 1;//命令數量
  cmd_ini = -1;
  fhdr = (pframehdr)(packet + sizeof(ethhdr));
  fhdr->len = 0x0e;
  fhdr->res = 0;
  fhdr->type = 1;
  endof = (void*)((int)fhdr + sizeof(framehdr));
  
  dhdr = (pdatahdr)(packet + sizeof(ethhdr) + sizeof(framehdr));
  dhdr->data_cmd = 8;
  dhdr->data_idx = 0x84;
  dhdr->data_addr1 = 0x0000;
  dhdr->data_addr2 = 0x0300;
  dhdr->data_len = 8;
  d_len[++cmd_ini] = dhdr->data_len;
  dhdr->data_r = 0; 
  dhdr->data_c = 0;
  dhdr->data_m = 0;
  dhdr->data_irq = 0;
  endof = (void*)((int)endof + sizeof(datahdr));
  for(int n=0; n<cmd_cnt; n++)
	  endof = (void*)((int)endof + WKC_LEN + d_len[n]);
  p_size =  (int)endof - (int)packet;
    /* Send down the packet */
    if (pcap_sendpacket(fp, packet, p_size /* size */) != 0)
    {
        fprintf(stderr,"\nError sending the packet: \n", pcap_geterr(fp));
		system("Pause");
        return;
    }
  memset(packet+ sizeof(ethhdr) + sizeof(framehdr),0x00 ,sizeof(packet) - sizeof(ethhdr) - sizeof(framehdr));

  /*封包 7*/
  cmd_cnt = 1;//命令數量
  cmd_ini = -1;
  fhdr = (pframehdr)(packet + sizeof(ethhdr));
  fhdr->len = 0x010c;
  fhdr->res = 0;
  fhdr->type = 1;
  endof = (void*)((int)fhdr + sizeof(framehdr));

  dhdr = (pdatahdr)(packet + sizeof(ethhdr) + sizeof(framehdr));
  dhdr->data_cmd = 8;
  dhdr->data_idx = 0x85;
  dhdr->data_addr1 = 0x0000;
  dhdr->data_addr2 = 0x0600;
  dhdr->data_len = 256;
  d_len[0] = dhdr->data_len;
  dhdr->data_r = 0; 
  dhdr->data_c = 0;
  dhdr->data_m = 0;
  dhdr->data_irq = 0;

  p_size =  sizeof(ethhdr) + sizeof(framehdr) + sizeof(datahdr) + WKC_LEN + d_len[0];
    /* Send down the packet */
    if (pcap_sendpacket(fp, packet, p_size /* size */) != 0)
    {
        fprintf(stderr,"\nError sending the packet: \n", pcap_geterr(fp));
		system("Pause");
        return;
    }
  memset(packet+ sizeof(ethhdr) + sizeof(framehdr),0x00 ,sizeof(packet) - sizeof(ethhdr) - sizeof(framehdr));

  /*封包 8*/

  fhdr = (pframehdr)(packet + sizeof(ethhdr));
  fhdr->len = 0x010c;
  fhdr->res = 0;
  fhdr->type = 1;

  dhdr = (pdatahdr)(packet + sizeof(ethhdr) + sizeof(framehdr));
  dhdr->data_cmd = 8;
  dhdr->data_idx = 0x86;
  dhdr->data_addr1 = 0x0000;
  dhdr->data_addr2 = 0x0800;
  dhdr->data_len = 256;
  d_len[0] = dhdr->data_len;
  dhdr->data_r = 0; 
  dhdr->data_c = 0;
  dhdr->data_m = 0;
  dhdr->data_irq = 0;

  p_size =  sizeof(ethhdr) + sizeof(framehdr) + sizeof(datahdr) + WKC_LEN + d_len[0];
    /* Send down the packet */
    if (pcap_sendpacket(fp, packet, p_size /* size */) != 0)
    {
        fprintf(stderr,"\nError sending the packet: \n", pcap_geterr(fp));
		system("Pause");
        return;
    }
  memset(packet+ sizeof(ethhdr) + sizeof(framehdr),0x00 ,sizeof(packet) - sizeof(ethhdr) - sizeof(framehdr));

  /*封包 9*/

  fhdr = (pframehdr)(packet + sizeof(ethhdr));
  fhdr->len = 0x2c;
  fhdr->res = 0;
  fhdr->type = 1;

  dhdr = (pdatahdr)(packet + sizeof(ethhdr) + sizeof(framehdr));
  dhdr->data_cmd = 8;
  dhdr->data_idx = 0x87;
  dhdr->data_addr1 = 0x0000;
  dhdr->data_addr2 = 0x0910;
  dhdr->data_len = 32;
  d_len[0] = dhdr->data_len;
  dhdr->data_r = 0; 
  dhdr->data_c = 0;
  dhdr->data_m = 0;
  dhdr->data_irq = 0;

  p_size =  sizeof(ethhdr) + sizeof(framehdr) + sizeof(datahdr) + WKC_LEN + d_len[0];
    /* Send down the packet */
    if (pcap_sendpacket(fp, packet, p_size /* size */) != 0)
    {
        fprintf(stderr,"\nError sending the packet: \n", pcap_geterr(fp));
		system("Pause");
        return;
    }
  memset(packet+ sizeof(ethhdr) + sizeof(framehdr),0x00 ,sizeof(packet) - sizeof(ethhdr) - sizeof(framehdr));

  /*封包 10*/

  fhdr = (pframehdr)(packet + sizeof(ethhdr));
  fhdr->len = 0x0d;
  fhdr->res = 0;
  fhdr->type = 1;

  dhdr = (pdatahdr)(packet + sizeof(ethhdr) + sizeof(framehdr));
  dhdr->data_cmd = 8;
  dhdr->data_idx = 0x88;
  dhdr->data_addr1 = 0x0000;
  dhdr->data_addr2 = 0x0981;
  dhdr->data_len = 1;
  d_len[0] = dhdr->data_len;
  dhdr->data_r = 0; 
  dhdr->data_c = 0;
  dhdr->data_m = 0;
  dhdr->data_irq = 0;

  p_size =  sizeof(ethhdr) + sizeof(framehdr) + sizeof(datahdr) + WKC_LEN + d_len[0];
    /* Send down the packet */
    if (pcap_sendpacket(fp, packet, p_size /* size */) != 0)
    {
        fprintf(stderr,"\nError sending the packet: \n", pcap_geterr(fp));
		system("Pause");
        return;
    }
  memset(packet+ sizeof(ethhdr) + sizeof(framehdr),0x00 ,sizeof(packet) - sizeof(ethhdr) - sizeof(framehdr));

  /*封包 11*/

  fhdr = (pframehdr)(packet + sizeof(ethhdr));
  fhdr->len = 0x0e;
  fhdr->res = 0;
  fhdr->type = 1;

  dhdr = (pdatahdr)(packet + sizeof(ethhdr) + sizeof(framehdr));
  dhdr->data_cmd = 8;
  dhdr->data_idx = 0x89;
  dhdr->data_addr1 = 0x0000;
  dhdr->data_addr2 = 0x0930;
  dhdr->data_len = 2;
  d_len[0] = dhdr->data_len;
  dhdr->data_r = 0; 
  dhdr->data_c = 0;
  dhdr->data_m = 0;
  dhdr->data_irq = 0;
  DataGramData[0] = 0x00;
  DataGramData[1] = 0x10;
  memcpy(&(dhdr->data_irq) + 1,DataGramData,d_len[0]);

  p_size =  sizeof(ethhdr) + sizeof(framehdr) + sizeof(datahdr) + WKC_LEN + d_len[0];
    /* Send down the packet */
    if (pcap_sendpacket(fp, packet, p_size /* size */) != 0)
    {
        fprintf(stderr,"\nError sending the packet: \n", pcap_geterr(fp));
		system("Pause");
        return;
    }
  memset(packet+ sizeof(ethhdr) + sizeof(framehdr),0x00 ,sizeof(packet) - sizeof(ethhdr) - sizeof(framehdr));

  /*封包 12*/

  fhdr = (pframehdr)(packet + sizeof(ethhdr));
  fhdr->len = 0x0e;
  fhdr->res = 0;
  fhdr->type = 1;

  dhdr = (pdatahdr)(packet + sizeof(ethhdr) + sizeof(framehdr));
  dhdr->data_cmd = 8;
  dhdr->data_idx = 0x8a;
  dhdr->data_addr1 = 0x0000;
  dhdr->data_addr2 = 0x0934;
  dhdr->data_len = 2;
  d_len[0] = dhdr->data_len;
  dhdr->data_r = 0; 
  dhdr->data_c = 0;
  dhdr->data_m = 0;
  dhdr->data_irq = 0;
  DataGramData[0] = 0x00;
  DataGramData[1] = 0x0c;
  memcpy(&(dhdr->data_irq) + 1,DataGramData,d_len[0]);

  p_size =  sizeof(ethhdr) + sizeof(framehdr) + sizeof(datahdr) + WKC_LEN + d_len[0];
    /* Send down the packet */
    if (pcap_sendpacket(fp, packet, p_size /* size */) != 0)
    {
        fprintf(stderr,"\nError sending the packet: \n", pcap_geterr(fp));
		system("Pause");
        return;
    }
  memset(packet+ sizeof(ethhdr) + sizeof(framehdr),0x00 ,sizeof(packet) - sizeof(ethhdr) - sizeof(framehdr));

  /*封包 13*/

  fhdr = (pframehdr)(packet + sizeof(ethhdr));
  fhdr->len = 0x0d;
  fhdr->res = 0;
  fhdr->type = 1;

  dhdr = (pdatahdr)(packet + sizeof(ethhdr) + sizeof(framehdr));
  dhdr->data_cmd = 8;
  dhdr->data_idx = 0x8b;
  dhdr->data_addr1 = 0x0000;
  dhdr->data_addr2 = 0x0103;
  dhdr->data_len = 1;
  d_len[0] = dhdr->data_len;
  dhdr->data_r = 0; 
  dhdr->data_c = 0;
  dhdr->data_m = 0;
  dhdr->data_irq = 0;

  p_size =  sizeof(ethhdr) + sizeof(framehdr) + sizeof(datahdr) + WKC_LEN + d_len[0];
    /* Send down the packet */
    if (pcap_sendpacket(fp, packet, p_size /* size */) != 0)
    {
        fprintf(stderr,"\nError sending the packet: \n", pcap_geterr(fp));
		system("Pause");
        return;
    }
  memset(packet+ sizeof(ethhdr) + sizeof(framehdr),0x00 ,sizeof(packet) - sizeof(ethhdr) - sizeof(framehdr));

  /*封包 14*/

  for(int idx=0x8c;idx<=0x9f;idx++){
  fhdr = (pframehdr)(packet + sizeof(ethhdr));
  fhdr->len = 0x14;
  fhdr->res = 0;
  fhdr->type = 1;

  dhdr = (pdatahdr)(packet + sizeof(ethhdr) + sizeof(framehdr));
  dhdr->data_cmd = 8;
  dhdr->data_idx = idx;
  dhdr->data_addr1 = 0x0000;
  dhdr->data_addr2 = 0x0900;
  dhdr->data_len = 8;
  d_len[0] = dhdr->data_len;
  dhdr->data_r = 0; 
  dhdr->data_c = 0;
  dhdr->data_m = 0;
  dhdr->data_irq = 0;

  p_size =  sizeof(ethhdr) + sizeof(framehdr) + sizeof(datahdr) + WKC_LEN + d_len[0];
    /* Send down the packet */
    if (pcap_sendpacket(fp, packet, p_size /* size */) != 0)
    {
        fprintf(stderr,"\nError sending the packet: \n", pcap_geterr(fp));
		system("Pause");
        return;
    }
  memset(packet+ sizeof(ethhdr) + sizeof(framehdr),0x00 ,sizeof(packet) - sizeof(ethhdr) - sizeof(framehdr));
  }}

/*----------------------------------------------------------------------------------------------------------------------------------------------------------------------------*/
  /*Eprom讀寫封包區*/
  
  memcpy(ehdr->h_dest, BroadcastEthernetAddress, ETH_ALEN);//廣播
  /*封包 1*/

  fhdr = (pframehdr)(packet + sizeof(ethhdr));
  fhdr->len = 0x10;
  fhdr->res = 0;
  fhdr->type = 1;

  dhdr = (pdatahdr)(packet + sizeof(ethhdr) + sizeof(framehdr));
  dhdr->data_cmd = 1;
  dhdr->data_idx = 0xff;
  dhdr->data_addr1 = 0x0000;
  dhdr->data_addr2 = 0x0000;
  dhdr->data_len = 4;
  d_len[0] = dhdr->data_len;
  dhdr->data_r = 0; 
  dhdr->data_c = 0;
  dhdr->data_m = 0;
  dhdr->data_irq = 0;

  p_size =  sizeof(ethhdr) + sizeof(framehdr) + sizeof(datahdr) + WKC_LEN + d_len[0];
    /* Send down the packet */
    if (pcap_sendpacket(fp, packet, p_size /* size */) != 0)
    {
        fprintf(stderr,"\nError sending the packet: \n", pcap_geterr(fp));
		system("Pause");
        return;
    }
  memset(packet+ sizeof(ethhdr) + sizeof(framehdr),0x00 ,sizeof(packet) - sizeof(ethhdr) - sizeof(framehdr));


  /*封包 2*/

  fhdr = (pframehdr)(packet + sizeof(ethhdr));
  fhdr->len = 0x0d;
  fhdr->res = 0;
  fhdr->type = 1;

  dhdr = (pdatahdr)(packet + sizeof(ethhdr) + sizeof(framehdr));
  dhdr->data_cmd = 8;
  dhdr->data_idx = 0xff;
  dhdr->data_addr1 = 0x0000;
  dhdr->data_addr2 = 0x0500;
  dhdr->data_len = 1;
  d_len[0] = dhdr->data_len;
  dhdr->data_r = 0; 
  dhdr->data_c = 0;
  dhdr->data_m = 0;
  dhdr->data_irq = 0;

  p_size =  sizeof(ethhdr) + sizeof(framehdr) + sizeof(datahdr) + WKC_LEN + d_len[0];
    /* Send down the packet */
    if (pcap_sendpacket(fp, packet, p_size /* size */) != 0)
    {
        fprintf(stderr,"\nError sending the packet: \n", pcap_geterr(fp));
		system("Pause");
        return;
    }
  memset(packet+ sizeof(ethhdr) + sizeof(framehdr),0x00 ,sizeof(packet) - sizeof(ethhdr) - sizeof(framehdr));

  /*封包 3*/

  fhdr = (pframehdr)(packet + sizeof(ethhdr));
  fhdr->len = 0x20;
  fhdr->res = 0;
  fhdr->type = 1;

  dhdr = (pdatahdr)(packet + sizeof(ethhdr) + sizeof(framehdr));
  dhdr->data_cmd = 1;
  dhdr->data_idx = 0xff;
  dhdr->data_addr1 = 0x0000;
  dhdr->data_addr2 = 0x0000;
  dhdr->data_len = 4;
  d_len[0] = dhdr->data_len;
  dhdr->data_r = 0; 
  dhdr->data_c = 0;
  dhdr->data_m = 1;
  dhdr->data_irq = 0;

  dhdr = (pdatahdr)(packet + sizeof(ethhdr) + sizeof(framehdr) + sizeof(datahdr) + d_len[0] + WKC_LEN);
  dhdr->data_cmd = 1;
  dhdr->data_idx = 0xff;
  dhdr->data_addr1 = 0xffff;
  dhdr->data_addr2 = 0x0000;
  dhdr->data_len = 4;
  d_len[1] = dhdr->data_len;
  dhdr->data_r = 0; 
  dhdr->data_c = 0;
  dhdr->data_m = 0;
  dhdr->data_irq = 0;

  p_size =  sizeof(ethhdr) + sizeof(framehdr) + 2 * (sizeof(datahdr) + WKC_LEN) + d_len[0] + d_len[1];
    /* Send down the packet */
    if (pcap_sendpacket(fp, packet, p_size /* size */) != 0)
    {
        fprintf(stderr,"\nError sending the packet: \n", pcap_geterr(fp));
		system("Pause");
        return;
    }

  memset(packet+ sizeof(ethhdr) + sizeof(framehdr),0x00 ,sizeof(packet) - sizeof(ethhdr) - sizeof(framehdr));


  /*封包 4*/

  fhdr = (pframehdr)(packet + sizeof(ethhdr));
  fhdr->len = 0x24;
  fhdr->res = 0;
  fhdr->type = 1;

  dhdr = (pdatahdr)(packet + sizeof(ethhdr) + sizeof(framehdr));
  dhdr->data_cmd = 2;
  dhdr->data_idx = 0xff;
  dhdr->data_addr1 = 0x0000;
  dhdr->data_addr2 = 0x0502;
  dhdr->data_len = 6;
  d_len[0] = dhdr->data_len;
  dhdr->data_r = 0; 
  dhdr->data_c = 0;
  dhdr->data_m = 1;
  dhdr->data_irq = 0;
  DataGramData[0] = 0x00;
  DataGramData[1] = 0x01;
  DataGramData[2] = 0x08;
  DataGramData[3] = 0x00;
  DataGramData[4] = 0x00;
  DataGramData[5] = 0x00;
  memcpy(&(dhdr->data_irq) + 1,DataGramData,d_len[0]);

  dhdr = (pdatahdr)(packet + sizeof(ethhdr) + sizeof(framehdr) + sizeof(datahdr) + d_len[0] + WKC_LEN);
  dhdr->data_cmd = 2;
  dhdr->data_idx = 0xff;
  dhdr->data_addr1 = 0xffff;
  dhdr->data_addr2 = 0x0502;
  dhdr->data_len = 6;
  d_len[1] = dhdr->data_len;
  dhdr->data_r = 0; 
  dhdr->data_c = 0;
  dhdr->data_m = 0;
  dhdr->data_irq = 0;
  DataGramData[0] = 0x00;
  DataGramData[1] = 0x01;
  DataGramData[2] = 0x08;
  DataGramData[3] = 0x00;
  DataGramData[4] = 0x00;
  DataGramData[5] = 0x00;
  memcpy(&(dhdr->data_irq) + 1,DataGramData,d_len[1]);
  p_size =  sizeof(ethhdr) + sizeof(framehdr) + 2 * (sizeof(datahdr) + WKC_LEN) + d_len[0] + d_len[1];
    /* Send down the packet */
    if (pcap_sendpacket(fp, packet, p_size /* size */) != 0)
    {
        fprintf(stderr,"\nError sending the packet: \n", pcap_geterr(fp));
		system("Pause");
        return;
    }

  memset(packet+ sizeof(ethhdr) + sizeof(framehdr),0x00 ,sizeof(packet) - sizeof(ethhdr) - sizeof(framehdr));


  /*封包 5*/

  fhdr = (pframehdr)(packet + sizeof(ethhdr));
  fhdr->len = 0x34;
  fhdr->res = 0;
  fhdr->type = 1;

  dhdr = (pdatahdr)(packet + sizeof(ethhdr) + sizeof(framehdr));
  dhdr->data_cmd = 1;
  dhdr->data_idx = 0xff;
  dhdr->data_addr1 = 0x0000;
  dhdr->data_addr2 = 0x0508;
  dhdr->data_len = 8;
  d_len[0] = dhdr->data_len;
  dhdr->data_r = 0; 
  dhdr->data_c = 0;
  dhdr->data_m = 1;
  dhdr->data_irq = 0;

  dhdr = (pdatahdr)(packet + sizeof(ethhdr) + sizeof(framehdr) + sizeof(datahdr) + d_len[0] + WKC_LEN);
  dhdr->data_cmd = 1;
  dhdr->data_idx = 0xff;
  dhdr->data_addr1 = 0xffff;
  dhdr->data_addr2 = 0x0508;
  dhdr->data_len = 8;
  d_len[1] = dhdr->data_len;
  dhdr->data_r = 0; 
  dhdr->data_c = 0;
  dhdr->data_m = 0;
  dhdr->data_irq = 0;

  p_size =  sizeof(ethhdr) + sizeof(framehdr) + 2 * (sizeof(datahdr) + WKC_LEN) + d_len[0] + d_len[1];
    /* Send down the packet */
    if (pcap_sendpacket(fp, packet, p_size /* size */) != 0)
    {
        fprintf(stderr,"\nError sending the packet: \n", pcap_geterr(fp));
		system("Pause");
        return;
    }

  memset(packet+ sizeof(ethhdr) + sizeof(framehdr),0x00 ,sizeof(packet) - sizeof(ethhdr) - sizeof(framehdr));


  /*封包 6*/

  fhdr = (pframehdr)(packet + sizeof(ethhdr));
  fhdr->len = 0x24;
  fhdr->res = 0;
  fhdr->type = 1;

  dhdr = (pdatahdr)(packet + sizeof(ethhdr) + sizeof(framehdr));
  dhdr->data_cmd = 2;
  dhdr->data_idx = 0xff;
  dhdr->data_addr1 = 0x0000;
  dhdr->data_addr2 = 0x0502;
  dhdr->data_len = 6;
  d_len[0] = dhdr->data_len;
  dhdr->data_r = 0; 
  dhdr->data_c = 0;
  dhdr->data_m = 1;
  dhdr->data_irq = 0;
  DataGramData[0] = 0x00;
  DataGramData[1] = 0x01;
  DataGramData[2] = 0x0c;
  DataGramData[3] = 0x00;
  DataGramData[4] = 0x00;
  DataGramData[5] = 0x00;
  memcpy(&(dhdr->data_irq) + 1,DataGramData,d_len[0]);

  dhdr = (pdatahdr)(packet + sizeof(ethhdr) + sizeof(framehdr) + sizeof(datahdr) + d_len[0] + WKC_LEN);
  dhdr->data_cmd = 2;
  dhdr->data_idx = 0xff;
  dhdr->data_addr1 = 0xffff;
  dhdr->data_addr2 = 0x0502;
  dhdr->data_len = 6;
  d_len[1] = dhdr->data_len;
  dhdr->data_r = 0; 
  dhdr->data_c = 0;
  dhdr->data_m = 0;
  dhdr->data_irq = 0;
  DataGramData[0] = 0x00;
  DataGramData[1] = 0x01;
  DataGramData[2] = 0x0c;
  DataGramData[3] = 0x00;
  DataGramData[4] = 0x00;
  DataGramData[5] = 0x00;
  memcpy(&(dhdr->data_irq) + 1,DataGramData,d_len[1]);

  p_size =  sizeof(ethhdr) + sizeof(framehdr) + 2 * (sizeof(datahdr) + WKC_LEN) + d_len[0] + d_len[1];
    /* Send down the packet */
    if (pcap_sendpacket(fp, packet, p_size /* size */) != 0)
    {
        fprintf(stderr,"\nError sending the packet: \n", pcap_geterr(fp));
		system("Pause");
        return;
    }

  memset(packet+ sizeof(ethhdr) + sizeof(framehdr),0x00 ,sizeof(packet) - sizeof(ethhdr) - sizeof(framehdr));


  /*封包 7*/

  fhdr = (pframehdr)(packet + sizeof(ethhdr));
  fhdr->len = 0x34;
  fhdr->res = 0;
  fhdr->type = 1;

  dhdr = (pdatahdr)(packet + sizeof(ethhdr) + sizeof(framehdr));
  dhdr->data_cmd = 1;
  dhdr->data_idx = 0xff;
  dhdr->data_addr1 = 0x0000;
  dhdr->data_addr2 = 0x0502;
  dhdr->data_len = 14;
  d_len[0] = dhdr->data_len;
  dhdr->data_r = 0; 
  dhdr->data_c = 0;
  dhdr->data_m = 1;
  dhdr->data_irq = 0;

  dhdr = (pdatahdr)(packet + sizeof(ethhdr) + sizeof(framehdr) + sizeof(datahdr) + d_len[0] + WKC_LEN);
  dhdr->data_cmd = 1;
  dhdr->data_idx = 0xff;
  dhdr->data_addr1 = 0xffff;
  dhdr->data_addr2 = 0x0502;
  dhdr->data_len = 14;
  d_len[1] = dhdr->data_len;
  dhdr->data_r = 0; 
  dhdr->data_c = 0;
  dhdr->data_m = 0;
  dhdr->data_irq = 0;

  p_size =  sizeof(ethhdr) + sizeof(framehdr) + 2 * (sizeof(datahdr) + WKC_LEN) + d_len[0] + d_len[1];
    /* Send down the packet */
    if (pcap_sendpacket(fp, packet, p_size /* size */) != 0)
    {
        fprintf(stderr,"\nError sending the packet: \n", pcap_geterr(fp));
		system("Pause");
        return;
    }

  memset(packet+ sizeof(ethhdr) + sizeof(framehdr),0x00 ,sizeof(packet) - sizeof(ethhdr) - sizeof(framehdr));


  /*----------------------------------------------------------------------------------------------------------------------------------------------------------------------------*/
  /*新增刪除欄位*/
  
  memcpy(ehdr->h_dest, FirstMulticastEthernetAddress, ETH_ALEN);//多播

  /*封包 0*/
  cmd_cnt = 1;//命令數量
  cmd_ini = -1;
  fhdr = (pframehdr)(packet + sizeof(ethhdr));
  fhdr->len = 0x013a;
  fhdr->res = 0;
  fhdr->type = 1;
  endof = (void*)((int)fhdr + sizeof(framehdr));

  dhdr = (pdatahdr)endof;
  dhdr->data_cmd = 5;
  dhdr->data_idx = 0xa2;
  dhdr->data_addr1 = 0x03e9;
  dhdr->data_addr2 = 0x1020;
  dhdr->data_len = 2;
  d_len[++cmd_ini] = dhdr->data_len;
  dhdr->data_r = 0; 
  dhdr->data_c = 0;
  dhdr->data_m = 1;
  dhdr->data_irq = 0;
  DataGramData[0] = 0x04;
  DataGramData[1] = 0x00;
  memcpy(&(dhdr->data_irq) + 1,DataGramData,d_len[cmd_ini]);
  endof = (void*)((int)endof + sizeof(datahdr));
  endof = (void*)((int)endof + WKC_LEN + d_len[cmd_ini]);

  dhdr = (pdatahdr)endof;
  dhdr->data_cmd = 5;
  dhdr->data_idx = 0x00;
  dhdr->data_addr1 = 0x03ea;
  dhdr->data_addr2 = 0x0800;
  dhdr->data_len = 8;
  d_len[++cmd_ini] = dhdr->data_len;
  dhdr->data_r = 0; 
  dhdr->data_c = 0;
  dhdr->data_m = 1;
  dhdr->data_irq = 0;
  endof = (void*)((int)endof + sizeof(datahdr));
  synhdr = (psmhdr)endof;
  synhdr->sm_addr = 0x1000;
  synhdr->sm_len = 0x0002;
  synhdr->sm_flags = 0x00010000;
  endof = (void*)((int)endof + WKC_LEN + d_len[cmd_ini]);

  dhdr = (pdatahdr)endof;
  dhdr->data_cmd = 5;
  dhdr->data_idx = 0x00;
  dhdr->data_addr1 = 0x03eb;
  dhdr->data_addr2 = 0x1000;
  dhdr->data_len = 128;
  d_len[++cmd_ini] = dhdr->data_len;
  dhdr->data_r = 0; 
  dhdr->data_c = 0;
  dhdr->data_m = 1;
  dhdr->data_irq = 0;
  endof = (void*)((int)endof + sizeof(datahdr));
  mhdr = (pmailhdr)endof;
  mhdr->mail_len = 10;
  mhdr->mail_addr = 0;
  mhdr->mail_channel = 0;
  mhdr->mail_priority = 0;
  mhdr->mail_type = 3;
  mhdr->mail_ctr = 0;
  mhdr->mail_0 = 0;
  chdr = (pcoehdr)((int)endof + sizeof(mailhdr));
  chdr->coe_num = 0;
  chdr->coe_res = 0;
  chdr->coe_type = 2; 
  shdr = (psdohdr)((int)endof + sizeof(mailhdr) + sizeof(coehdr));
  shdr->sdo_ctl = 0x2f;
  shdr->sdo_index = 0x1c12;
  shdr->sdo_subidx = 0x00;
  shdr->sdo_data = 0;
  endof = (void*)((int)endof + WKC_LEN + d_len[cmd_ini]);

  dhdr = (pdatahdr)endof;
  dhdr->data_cmd = 4;
  dhdr->data_idx = 0x00;
  dhdr->data_addr1 = 0x03eb;
  dhdr->data_addr2 = 0x1080;
  dhdr->data_len = 128;
  d_len[++cmd_ini] = dhdr->data_len;
  dhdr->data_r = 0; 
  dhdr->data_c = 0;
  dhdr->data_m = 0;
  dhdr->data_irq = 0;
  endof = (void*)((int)endof + sizeof(datahdr));
  endof = (void*)((int)endof + WKC_LEN + d_len[cmd_ini]);

  p_size =  (int)endof - (int)packet;
    /* Send down the packet */
    if (pcap_sendpacket(fp, packet, p_size /* size */) != 0)
    {
        fprintf(stderr,"\nError sending the packet: \n", pcap_geterr(fp));
		system("Pause");
        return;
    }
  memset(packet+ sizeof(ethhdr) + sizeof(framehdr),0x00 ,sizeof(packet) - sizeof(ethhdr) - sizeof(framehdr));



  /*封包 0*/

  fhdr = (pframehdr)(packet + sizeof(ethhdr));
  fhdr->len = 0x8c;
  fhdr->res = 0;
  fhdr->type = 1;

  dhdr = (pdatahdr)(packet + sizeof(ethhdr) + sizeof(framehdr));
  dhdr->data_cmd = 4;
  dhdr->data_idx = 0x80;
  dhdr->data_addr1 = 0x03eb;
  dhdr->data_addr2 = 0x1080;
  dhdr->data_len = 128;
  d_len[0] = dhdr->data_len;
  dhdr->data_r = 0; 
  dhdr->data_c = 0;
  dhdr->data_m = 0;
  dhdr->data_irq = 0;

  p_size =  sizeof(ethhdr) + sizeof(framehdr) + sizeof(datahdr) + WKC_LEN + d_len[0];
    /* Send down the packet */
    if (pcap_sendpacket(fp, packet, p_size /* size */) != 0)
    {
        fprintf(stderr,"\nError sending the packet: \n", pcap_geterr(fp));
		system("Pause");
        return;
    }
  memset(packet+ sizeof(ethhdr) + sizeof(framehdr),0x00 ,sizeof(packet) - sizeof(ethhdr) - sizeof(framehdr));


  /*封包 1*/

  fhdr = (pframehdr)(packet + sizeof(ethhdr));
  fhdr->len = 0x8c;
  fhdr->res = 0;
  fhdr->type = 1;

  dhdr = (pdatahdr)(packet + sizeof(ethhdr) + sizeof(framehdr));
  dhdr->data_cmd = 5;
  dhdr->data_idx = 0x81;
  dhdr->data_addr1 = 0x03eb;
  dhdr->data_addr2 = 0x1000;
  dhdr->data_len = 128;
  d_len[0] = dhdr->data_len;
  dhdr->data_r = 0; 
  dhdr->data_c = 0;
  dhdr->data_m = 0;
  dhdr->data_irq = 0;

  mhdr = (pmailhdr)(packet + sizeof(ethhdr) + sizeof(framehdr) + sizeof(datahdr));
  mhdr->mail_len = 10;
  mhdr->mail_addr = 0;
  mhdr->mail_channel = 0;
  mhdr->mail_priority = 0;
  mhdr->mail_type = 3;
  mhdr->mail_ctr = 0;
  mhdr->mail_0 = 0;

  chdr = (pcoehdr)(packet + sizeof(ethhdr) + sizeof(framehdr) + sizeof(datahdr) + sizeof(mailhdr));
  chdr->coe_num = 0;
  chdr->coe_res = 0;
  chdr->coe_type = 2;
 
  shdr = (psdohdr)(packet + sizeof(ethhdr) + sizeof(framehdr) + sizeof(datahdr) + sizeof(mailhdr) + sizeof(coehdr));
  shdr->sdo_ctl = 0x2f;
  shdr->sdo_index = 0x1a00;
  shdr->sdo_subidx = 0x00;
  shdr->sdo_data = 0;

  p_size =  sizeof(ethhdr) + sizeof(framehdr) + sizeof(datahdr) + WKC_LEN + d_len[0];
    /* Send down the packet */
    if (pcap_sendpacket(fp, packet, p_size /* size */) != 0)
    {
        fprintf(stderr,"\nError sending the packet: \n", pcap_geterr(fp));
		system("Pause");
        return;
    }
  memset(packet+ sizeof(ethhdr) + sizeof(framehdr),0x00 ,sizeof(packet) - sizeof(ethhdr) - sizeof(framehdr));


  /*封包 2*/

  fhdr = (pframehdr)(packet + sizeof(ethhdr));
  fhdr->len = 0x8c;
  fhdr->res = 0;
  fhdr->type = 1;

  dhdr = (pdatahdr)(packet + sizeof(ethhdr) + sizeof(framehdr));
  dhdr->data_cmd = 4;
  dhdr->data_idx = 0x82;
  dhdr->data_addr1 = 0x03eb;
  dhdr->data_addr2 = 0x1080;
  dhdr->data_len = 128;
  d_len[0] = dhdr->data_len;
  dhdr->data_r = 0; 
  dhdr->data_c = 0;
  dhdr->data_m = 0;
  dhdr->data_irq = 0;

  p_size =  sizeof(ethhdr) + sizeof(framehdr) + sizeof(datahdr) + WKC_LEN + d_len[0];
    /* Send down the packet */
    if (pcap_sendpacket(fp, packet, p_size /* size */) != 0)
    {
        fprintf(stderr,"\nError sending the packet: \n", pcap_geterr(fp));
		system("Pause");
        return;
    }
  memset(packet+ sizeof(ethhdr) + sizeof(framehdr),0x00 ,sizeof(packet) - sizeof(ethhdr) - sizeof(framehdr));


  /*封包 3*/

  fhdr = (pframehdr)(packet + sizeof(ethhdr));
  fhdr->len = 0x8c;
  fhdr->res = 0;
  fhdr->type = 1;

  dhdr = (pdatahdr)(packet + sizeof(ethhdr) + sizeof(framehdr));
  dhdr->data_cmd = 5;
  dhdr->data_idx = 0x83;
  dhdr->data_addr1 = 0x03eb;
  dhdr->data_addr2 = 0x1000;
  dhdr->data_len = 128;
  d_len[0] = dhdr->data_len;
  dhdr->data_r = 0; 
  dhdr->data_c = 0;
  dhdr->data_m = 0;
  dhdr->data_irq = 0;

  mhdr = (pmailhdr)(packet + sizeof(ethhdr) + sizeof(framehdr) + sizeof(datahdr));
  mhdr->mail_len = 10;
  mhdr->mail_addr = 0;
  mhdr->mail_channel = 0;
  mhdr->mail_priority = 0;
  mhdr->mail_type = 3;
  mhdr->mail_ctr = 0;
  mhdr->mail_0 = 0;

  chdr = (pcoehdr)(packet + sizeof(ethhdr) + sizeof(framehdr) + sizeof(datahdr) + sizeof(mailhdr));
  chdr->coe_num = 0;
  chdr->coe_res = 0;
  chdr->coe_type = 2;
 
  shdr = (psdohdr)(packet + sizeof(ethhdr) + sizeof(framehdr) + sizeof(datahdr) + sizeof(mailhdr) + sizeof(coehdr));
  shdr->sdo_ctl = 0x23;
  shdr->sdo_index = 0x1a00;
  shdr->sdo_subidx = 0x01;
  shdr->sdo_data = 0x60410010;

  p_size =  sizeof(ethhdr) + sizeof(framehdr) + sizeof(datahdr) + WKC_LEN + d_len[0];
    /* Send down the packet */
    if (pcap_sendpacket(fp, packet, p_size /* size */) != 0)
    {
        fprintf(stderr,"\nError sending the packet: \n", pcap_geterr(fp));
		system("Pause");
        return;
    }
  memset(packet+ sizeof(ethhdr) + sizeof(framehdr),0x00 ,sizeof(packet) - sizeof(ethhdr) - sizeof(framehdr));

/*----------------------------------------------------------------------------------------------------------------------------------------------------------------------------*/
	/*開始監聽封包*/
	printf("\nlistening on %s...\n", d->description);
    
    /* At this point, we don't need any more the device list. Free it */
    pcap_freealldevs(alldevs);
    
    /* Retrieve the packets */
	printf("Cmds Counts\tTime\t\tSoruce\t\t\tDestination\t\tlen\t\tcmd\n");

    while(true){
		int cmds = 0;
		char cmd[100];
		memset(cmd,'\0',100);
		res = pcap_next(fp, &header);       
		ehdr = (pethhdr) res;
		if(res == NULL){
		//printf("packet == NULL\n");
		continue;}
		if (ehdr->h_proto == ntohs(ecat)){      
		cmds++;
		dhdr = (pdatahdr)(res + 16);
		switch(dhdr->data_cmd){
			case 0:
				strcat(cmd, "'NOP'");
				break;
			case 1:
				strcat(cmd, "'APRD'");
				break;
			case 2:
				strcat(cmd, "'APWR'");
				break;
			case 3:
				strcat(cmd, "'APRW'");
				break;
			case 4:
				strcat(cmd, "'FPRD'");
				break;
			case 5:
				strcat(cmd, "'FPWR'");
				break;
			case 6:
				strcat(cmd, "'FPRW'");
				break;
			case 7:
				strcat(cmd, "'BRD'");
				break;
			case 8:
				strcat(cmd, "'BWR'");
				break;
			case 9:
				strcat(cmd, "'BRW'");
				break;
			case 10:
				strcat(cmd, "'LRD'");
				break;
			case 11:
				strcat(cmd, "'LWR'");
				break;
			case 12:
				strcat(cmd, "'LRW'");
				break;
			case 13:
				strcat(cmd, "'ARMW'");
				break;
			case 255:
				strcat(cmd, "'EXT'");
				break;
		}
		while (dhdr->data_m == 1) {
		cmds++;
		dhdr = (pdatahdr)((int)&(dhdr->data_irq)+(dhdr->data_len)+2+WKC_LEN);				
		switch(dhdr->data_cmd){
			case 0:
				strcat(cmd, ",'NOP'");
				break;
			case 1:
				strcat(cmd, ",'APRD'");
				break;
			case 2:
				strcat(cmd, ",'APWR'");
				break;
			case 3:
				strcat(cmd, ",'APRW'");
				break;
			case 4:
				strcat(cmd, ",'FPRD'");
				break;
			case 5:
				strcat(cmd, ",'FPWR'");
				break;
			case 6:
				strcat(cmd, ",'FPRW'");
				break;
			case 7:
				strcat(cmd, ",'BRD'");
				break;
			case 8:
				strcat(cmd, ",'BWR'");
				break;
			case 9:
				strcat(cmd, ",'BRW'");
				break;
			case 10:
				strcat(cmd, ",'LRD'");
				break;
			case 11:
				strcat(cmd, ",'LWR'");
				break;
			case 12:
				strcat(cmd, ",'LRW'");
				break;
			case 13:
				strcat(cmd, ",'ARMW'");
				break;
			case 255:
				strcat(cmd, ",'EXT'");
				break;
		}}

        local_tv_sec = header.ts.tv_sec;
        ltime=localtime(&local_tv_sec);
        strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);      
		printf("%d cmds\t\t%s\t%02x:%02x:%02x:%02x:%02x:%02x\t%02x:%02x:%02x:%02x:%02x:%02x\t%d\t\t%s\n", cmds,
		timestr, ehdr->h_source[0], ehdr->h_source[1], ehdr->h_source[2], ehdr->h_source[3], ehdr->h_source[4], ehdr->h_source[5], 
		ehdr->h_dest[0], ehdr->h_dest[1], ehdr->h_dest[2], ehdr->h_dest[3], ehdr->h_dest[4], ehdr->h_dest[5], header.len, cmd);}
		}

	system("Pause");
    return;
}

