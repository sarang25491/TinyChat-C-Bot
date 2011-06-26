#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <sys/time.h>
#include <string.h>

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

struct votekick_user 
{
	int count;
	char nick[256];
};


char bot_nick[] = "leon";
struct votekick_user votekick_list[10];

/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

double t1, t2;

void handle_command(char *command, char *args)
{	
	// clearbans command
	if (strcmp(command, "!clearbans") == 0)
	{
		printf("Clearing bans...\n");
		system("curl -d \"roomname=ROOM_GOES_HERE&hash=HASH_GOES_HERE&ts=TIMESTAMP_GOES_HERE\" http://tinychat.com/clearbans");
	}
	
	if (strcmp(command, "!t") == 0)
	{
		printf("Grabbing twitter info... for %s\n", args);
		char __msg[9000];
		sprintf(__msg, "curl -d \"mode=tw&var=%s\" http://192.168.2.9/tc/main.php", args);
		printf("Calling command ... %s\n", __msg);
		system(__msg);
	}
	
	if (strcmp(command, "!votekick") == 0)
	{
		printf("Votekick for %s\n", args);
		
	 	int i;
		int match = 0;
		for (i = 0; i < 10; i++)
		{
			if (strcmp(args, votekick_list[i].nick) == 0)
			{
				votekick_list[i].count++;
				char __msg[9000];
				sprintf(__msg, "curl -d \"mode=normal&var=Votekick for '%s' is at %i votes.\" http://192.168.2.9/tc/main.php > /dev/null", votekick_list[i].nick, votekick_list[i].count);
				printf("Calling command ... %s\n", __msg);
				system(__msg);
				match = 1;
				break;
			}
		}
		
		if (match == 0)
		{
			printf("Creating new votekick for %s\n", args);
			for (i=0; i<10; i++)
			{
				printf("%i - %i\n", i, votekick_list[i].count);
				if (votekick_list[i].count == 0)
				{
					printf("Found open slot!\n");
					char __msg[9000];
					sprintf(votekick_list[i].nick, "%s", args);
					votekick_list[i].count = 1;
					sprintf(__msg, "curl -d \"mode=normal&var=Votekick for '%s' has begun!  Bwahaha!.\" http://192.168.2.9/tc/main.php > /dev/null", votekick_list[i].nick);
					printf("Calling command ... %s\n", __msg);
					system(__msg);
					break;
				}
			}
		}
	}
}

void handle_message(char *message, char *sender)
{
	int i;
	for (i=0; message[i] != '\0'; i++)
		message[i] = (char)tolower(message[i]);
	if (strstr(message, "khione"))
	{
		printf("Someone said Khione!\n");
		char *greetings[3] = { "hey", "sup", "hello" };
		int g;
		for (g = 0; g < 3; g++)
		{
			if (strstr(message, greetings[g]))
			{
				printf("Someone said '%s khione'\n", greetings[g]);
				char __msg[9000];
				sprintf(__msg, "curl -d \"mode=normal&var=Hey, %s\" http://192.168.2.9/tc/main.php > /dev/null", sender);
				system(__msg);
			}
		}
	}
	
	char *cmd_split = strtok(message, " ");
	char *command[25];
	char *arguments[256];
	int z = 0;
	while (cmd_split != NULL)
	{
		if (z == 0)
		{
			strcpy(command, cmd_split);
		}
		if (z == 1)
		{
			strcpy(arguments, cmd_split);
		}
		cmd_split = strtok(NULL, ", ");
		z++;
	}
	handle_command(command, arguments);
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	//static int count = 1;                   /* packet counter */
	
	/* declare pointers to packet headers */
	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp;            /* The TCP header */
	const char *payload;                    /* Packet payload */

	int size_ip;
	int size_tcp;
	int size_payload;
	
	/* define ethernet header */
	ethernet = (struct sniff_ethernet*)(packet);
	
	/* define/compute ip header offset */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}
	
	/* define/compute tcp header offset */
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < 20) {
		printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}
	
	/* define/compute tcp payload (segment) offset */
	payload = (char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
	
	
	/* compute tcp payload (segment) size */
	size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
	
	/*
	 * Print payload data; it might be binary, so don't just
	 * treat it as a string.
	 */
	if (size_payload > 0) 
	{
		struct
		{
			unsigned char header[6]; // I DON'T EVEN UNDERSTAND THE FIRST 4 BYTES
			unsigned char packet_size; // size of packet after this point... why?
			unsigned char a[4]; // 0x14 and then privmsg size 0x02 0x00 0x07
			unsigned char privmsg[7]; // privmsg
			unsigned char b[10]; // I have no fucking idea what this shit is
			unsigned char room_name_length[3];
			unsigned char roomshit[69]; // #txt-tinychat^ROOMNAME
			unsigned char message_length[3];
			unsigned char message[360]; // in decimal fucking tinychat you faggot
			unsigned char after_message[3];
			unsigned char color[7]; // #RRGGBB
			unsigned char stupidshit[3]; // ,XX this is the comma and language
			unsigned char name_length[3]; // name length duh
			unsigned char name[32];	// name
		} test_packet;		

		// fix some shit
		bzero(&test_packet.roomshit, 69);
		bzero(&test_packet.message, 360);
		bzero(&test_packet.name, 32);

		int z = 0;
		unsigned char *ch = (unsigned char*)payload;	
		
		for (z = 0; z < 6; z++)
		{
			test_packet.header[z] = *ch;
			ch = ch + 1;
		}

		for (z = 0; z < 1; z++)
		{
			test_packet.packet_size = *ch;
			ch = ch + 1;
		}
		
		for (z = 0; z < 4; z++)
		{
			test_packet.a[z] = *ch;
			ch = ch + 1;
		}
		for (z = 0; z < 7; z++)
		{
			test_packet.privmsg[z] = *ch;
			ch = ch + 1;
		}

		unsigned char pm[7] = { 0x70, 0x72, 0x69, 0x76, 0x6D, 0x73, 0x67 };
		for (z = 0; z < 7; z++)
		{
			if (test_packet.privmsg[z] != pm[z]) return;
		}
		
		FILE *fp = fopen("tc_bot_log", "a+");
		if (fp == NULL)	return;
		
		fprintf(fp, "\n\n\n%s\n\n\n", packet);
		
		unsigned char *tp = (unsigned char*)payload;
		int kkk;
		for (kkk = 0; kkk < size_payload; kkk++)
		{
			fprintf(fp, "%02X ", (unsigned char)*tp);
			tp = tp + 1;
		}
		fprintf(fp, "\n\n");

		for (z = 0; z < 10; z++)
		{
			if ((unsigned char)*ch == (unsigned char)0xC3) z--;
			else test_packet.b[z] = *ch;
			
			ch = ch + 1;
		}

		for (z = 0; z < 3; z++)
		{
			if ((unsigned char)*ch == (unsigned char)0xC3) z--;
			else test_packet.room_name_length[z] = *ch;

			ch = ch + 1;
		}
		
		for (z = 0; z < (int)test_packet.room_name_length[2]; z++)
		{
			if ((unsigned char)*ch == (unsigned char)0xC3) z--;
			else test_packet.roomshit[z] = *ch;
			
			ch = ch + 1;
		}

		for (z = 0; z < 3; z++)
		{
			if ((unsigned char)*ch == (unsigned char)0xC3) z--;
			else test_packet.message_length[z] = *ch;
			
			ch = ch + 1;
		}

		int mls = (int)test_packet.message_length[2];
		if ((int)test_packet.message_length[1] == (unsigned char)0x01)
		{
			mls += 0x100;
		}
		for (z = 0; z < mls; z++)
		{
			if ((unsigned char)*ch == (unsigned char)0xC3) z--;
			else test_packet.message[z] = *ch;
			
			ch = ch + 1;
		}
		
		// check for userinfo
		unsigned char ui[9] = { 0x2f, 0x75, 0x73, 0x65, 0x72, 0x69, 0x6e, 0x66, 0x6f };
		int uic = 0;
		for (z = 0; z < 9; z++)
		{
			if ((unsigned char)test_packet.message[z] == (unsigned char)ui[z]) uic++;
		}
		if (uic >= 8) return;

		for (z = 0; z < 3; z++)
		{
			if ((unsigned char)*ch == (unsigned char)0xC3) z--;
			else test_packet.after_message[z] = *ch;
			
			ch = ch + 1;
		}

		for (z = 0; z < 7; z++)
		{
			if ((unsigned char)*ch == (unsigned char)0xC3) z--;
			else test_packet.color[z] = *ch;
			
			ch = ch + 1;
		}

		for (z = 0; z < 3; z++)
		{
			if ((unsigned char)*ch == (unsigned char)0xC3) z--;
			else test_packet.stupidshit[z] = *ch;
			
			ch = ch + 1;
		}

		for (z = 0; z < 3; z++)
		{
			if ((unsigned char)*ch == (unsigned char)0xC3) z--;
			else test_packet.name_length[z] = *ch;
			
			ch = ch + 1;
		}
	
		for (z = 0; z < (int)test_packet.name_length[2]; z++)
		{
			if ((unsigned char)*ch == (unsigned char)0xC3) z--;
			else test_packet.name[z] = *ch;
			
			ch = ch + 1;
		}

		char *fmtmsg;
		char nmsg[90];
		bzero(nmsg, 90);
		fmtmsg = strtok((char*)test_packet.message, ", ");
		z = 0;
		while (fmtmsg != NULL)
		{
			char m = atoi(fmtmsg);
			nmsg[z++] = m;
			fmtmsg = strtok(NULL, ", ");
		}
		
		printf("%s: %s\n", test_packet.name, nmsg);
		fprintf(fp, "%s: %s\n\n", test_packet.name, nmsg);
		fclose(fp);
		
		handle_message((char*)nmsg, (char*)test_packet.name);
		
		// look for commands!
		char *cmd_split = strtok(nmsg, " ");
		char _msg[] = "/msg";
		z = 0;
		while (cmd_split != NULL)
		{
			if (z == 0)
			{
				if (strcmp(cmd_split, _msg) != 0) return;
			}
			if (z == 1)
			{
				if (strcmp(cmd_split, bot_nick) != 0) return;
			}
			if (z == 2)
			{
				// handle the command
				handle_command(cmd_split, NULL);
			}
			cmd_split = strtok(NULL, ", ");
			z++;
		}
	}

	return;
}

pcap_t *handle;	

int main(int argc, char **argv)
{
	int i;
	for (i=0; i<10; i++)
	{
		if (votekick_list[i].count == -1)
		{
			votekick_list[i].count = -1;
		}
	}


	char *dev = NULL;			/* capture device name */
	char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
	//pcap_t *handle;				/* packet capture handle */ made global!

	char filter_exp[] = "src port 443";		/* filter expression [3] */
	struct bpf_program fp;			/* compiled filter program (expression) */
	bpf_u_int32 mask;			/* subnet mask */
	bpf_u_int32 net;			/* ip */
	//int num_packets = 9001;			/* number of packets to capture */

	/* check for capture device name on command-line */
	if (argc == 2) {
		dev = argv[1];
	}
	else if (argc > 2) {
		fprintf(stderr, "error: unrecognized command-line options\n\n");
		exit(EXIT_FAILURE);
	}
	else {
		/* find a capture device if not specified on command-line */
		dev = pcap_lookupdev(errbuf);
		if (dev == NULL) {
			fprintf(stderr, "Couldn't find default device: %s\n",
			    errbuf);
			exit(EXIT_FAILURE);
		}
	}
	
	/* get network number and mask associated with capture device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}

	/* open capture device */
	handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
	}

	/* make sure we're capturing on an Ethernet device [2] */
	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet\n", dev);
		exit(EXIT_FAILURE);
	}

	/* compile the filter expression */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* apply the compiled filter */
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* now we can set our callback function */
	pcap_loop(handle, 0, got_packet, NULL);

	/* cleanup */
	pcap_freecode(&fp);
	pcap_close(handle);

	printf("\nCapture complete.\n");

	return 0;
}

