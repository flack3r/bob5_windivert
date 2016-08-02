#define _CRT_SECURE_NO_WARNINGS
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include "windivert.h"

#define MAXBUF 0xFFFF
#define MAXURL 4096
/*
* Pre-fabricated packets.
*/
typedef struct
{
	WINDIVERT_IPHDR  ip;
	WINDIVERT_TCPHDR tcp;
} PACKET, *PPACKET;

typedef struct
{
	PACKET header;
	UINT8 data[];
} DATAPACKET, *PDATAPACKET;

typedef struct _FILTERNODE
{
	char filterUrl[MAXURL];
	struct _FILTERNODE* next;
}FILTERNODE;

typedef struct _FILTERLIST
{
	FILTERNODE* head;
	int size;
}FILTERLIST;
/*
* Prototypes
*/
void InitUrlList(FILTERLIST* flist);
void InsertURL(FILTERLIST* flist, char* Url);
BOOL CheckFiltering(FILTERLIST* flist, UINT* url);
BOOL ParsePacket(UINT8* packet, UINT packet_len, PWINDIVERT_IPHDR* ip_header, PWINDIVERT_TCPHDR* tcp_header, PVOID* payload, UINT* payloadlen);
void ParseURL(char* payload, int payload_len, char* URL);
void ReadFilterURL(FILTERLIST* flist);

int __cdecl main(int argc, char **argv)
{
	HANDLE handle;
	WINDIVERT_ADDRESS addr;
	UINT8 packet[MAXBUF];
	UINT packet_len;
	PVOID payload;
	UINT payload_len;
	INT16 priority = 404;       // Arbitrary.
	PWINDIVERT_IPHDR ip_header;
	PWINDIVERT_TCPHDR tcp_header;
	FILTERLIST filterList;

	//init filter list
	InitUrlList(&filterList);
	ReadFilterURL(&filterList);

	// Open the Divert device:
	handle = WinDivertOpen(
		"outbound && "              // Outbound traffic only
		"ip && "                    // Only IPv4 supported
		"tcp.DstPort == 80 && "     // HTTP (port 80) only
		"tcp.PayloadLength > 0",    // TCP data packets only
		WINDIVERT_LAYER_NETWORK, priority, 0
	);
	if (handle == INVALID_HANDLE_VALUE)
	{
		fprintf(stderr, "error: failed to open the WinDivert device (%d)\n",
			GetLastError());
		exit(EXIT_FAILURE);
	}
	printf("OPENED WinDivert\n");

	// Main loop:
	while (TRUE)
	{
		if (!WinDivertRecv(handle, packet, sizeof(packet), &addr, &packet_len))
		{
			fprintf(stderr, "warning: failed to read packet (%d)\n",
				GetLastError());
			continue;
		}

		//!BlackListPayloadMatch(blacklist, payload, (UINT16)payload_len)
		if (ParsePacket(packet, packet_len, &ip_header, &tcp_header, &payload, &payload_len))
		{
			char Url[MAXURL] = { 0, };
			char CheckUrl[MAXURL+8] = "http://";
			ParseURL(payload, payload_len, Url);
			strcat(CheckUrl, Url);

			if (!CheckFiltering(&filterList, CheckUrl))
			{
				// Packet does not match the blacklist; simply reinject it.
				if (!WinDivertSend(handle, packet, packet_len, &addr, NULL))
				{
					fprintf(stderr, "warning: failed to reinject packet (%d)\n",
						GetLastError());
				}
			}
		}
	}
}

BOOL ParsePacket(UINT8* packet, UINT packet_len, PWINDIVERT_IPHDR* ip_header, PWINDIVERT_TCPHDR* tcp_header, PVOID* payload, UINT* payloadlen)
{
	DATAPACKET* Parse = (DATAPACKET*)malloc(sizeof(DATAPACKET));
	Parse = (DATAPACKET*)(packet);
	*ip_header = &Parse->header.ip;
	*tcp_header = &Parse->header.tcp;
	*payload = &Parse->data;
	*payloadlen = packet_len - sizeof(PWINDIVERT_IPHDR) - sizeof(PWINDIVERT_TCPHDR);
	return TRUE;
}


void ParseURL(char* payload, int payload_len, char* URL)
{
	int i = 0;
	char* Url_tmp = payload;
	char Url_path[MAXURL] = { 0, };

	while (*Url_tmp != '\x20')
	{
		Url_tmp += 1;
	}
	Url_tmp += 1;

	i = 0;

	while (*Url_tmp != '\x20')
	{
		Url_path[i] = *Url_tmp;
		i += 1;
		Url_tmp += 1;
	}

	Url_tmp = strstr(payload, "Host: ");
	if (Url_tmp != NULL)
	{
		while (*Url_tmp != '\x20')
		{
			Url_tmp += 1;
		}
		Url_tmp += 1;

		i = 0;
		while (*Url_tmp != '\x0d')
		{
			URL[i] = *Url_tmp;
			i += 1;
			Url_tmp += 1;
		}
	}
	return;
}

void InitUrlList(FILTERLIST* flist)
{
	flist->head = NULL;
	flist->size = 0;
}

void InsertURL(FILTERLIST* flist, char* Url)
{
	FILTERNODE* data = (FILTERNODE*)malloc(sizeof(FILTERNODE));
	strncpy(data->filterUrl, Url, MAXURL);
	data->next = NULL;
	FILTERNODE** tmp = &(flist->head);
	while (*tmp)
	{
		tmp = &(*tmp)->next;
	}
	*tmp = data;
	flist->size += 1;
}

//return True if filter match
BOOL CheckFiltering(FILTERLIST* flist, UINT* url)
{
	FILTERNODE* tmp = flist->head;
	while (tmp)
	{
		if (!strcmp(tmp->filterUrl, url))
		{
			return TRUE;
		}
		tmp = tmp->next;
	}
	return FALSE;
}

void ReadFilterURL(FILTERLIST* flist)
{
	FILE* f1 = fopen("mal_site.txt", "r");
	char Url[MAXURL] = { 0, };
	while (!feof(f1))
	{
		fscanf(f1, "%s", Url);
		InsertURL(flist, Url);
	}

	fclose(f1);
}