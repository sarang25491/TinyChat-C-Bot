/**
 * 	tc_packet_reader.c
 *	there isn't a license for this fucking file
 * 
 *  $ gcc -Wall -o tc_packet_reader tc_packet_reader.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// this shit is literally fucking pointless
// but do you think I care? 
// spoiler alert: I dont
#define ARG_CALL  	0
#define ARG_FILE 	1

int main(int argc, char *argv[])
{
	// you don't got enough arguments you fucking faggot
	if (argc != 2)
	{
		printf("usage: %s <file1>\n", argv[ARG_CALL]);
		return 1;
	}
	
	// our god damn file
	FILE *file1;
	
	if ((file1 = fopen(argv[ARG_FILE], "r")) == NULL)
	{
		// nice going faggot
		printf("Couldn't open file: '%s'\n", argv[ARG_FILE]);
	}

	// our file size
	long file1_size;
	
	// lets see how long these fuckers are
	fseek(file1, 0, SEEK_END);
	file1_size = ftell(file1);
	rewind(file1);
	
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
	bzero(&test_packet.message, 360);
	bzero(&test_packet.roomshit, 69);
	bzero(&test_packet.name, 32);
	
	fread(&test_packet.header, 1, 6, file1);
	fread(&test_packet.packet_size, 1, 1, file1);
	fread(&test_packet.a, 1, 4, file1);
	fread(&test_packet.privmsg, 1, 7, file1);
	fread(&test_packet.b, 1, 10, file1);
	fread(&test_packet.room_name_length, 1, 3, file1);
	fread(&test_packet.roomshit, 1, (int)test_packet.room_name_length[2], file1);
	fread(&test_packet.message_length, 1, 3, file1);
	//fread(&test_packet.message, 1, (int)test_packet.message_length[2], file1);
	// fuck you tinychat
	int i;
	int mls = (int)test_packet.message_length[2];
	if ((int)test_packet.message_length[1] == (unsigned char)0x01)
	{
		mls += 0x100;
	}	
	for (i = 0; i < mls; i++)
	{
		unsigned char b;
		fread(&b, 1, 1, file1);
		
		if (b == (unsigned char)0xC3) i--;
		else test_packet.message[i] = b;
	}
	fread(&test_packet.after_message, 1, 3, file1);
	fread(&test_packet.color, 1, 7, file1);
	fread(&test_packet.stupidshit, 1, 3, file1);
	fread(&test_packet.name_length, 1, 3, file1);
	//fread(&test_packet.name, 1, (int)test_packet.name_length[2], file1);
	for (i = 0; i < (int)test_packet.name_length[2]; i++)
	{
		unsigned char b;
		fread(&b, 1, 1, file1);
		
		if (b == (unsigned char)0xC3) i--;
		else test_packet.name[i] = b;
	}
	
	printf("\033[1;36mPACKET INFO inb4 SEGFAULT\033[0;0m\n");
	printf("\033[22;36mRoom:\033[0;0m %s\n", test_packet.roomshit);
	printf("\033[22;36mRoom size:\033[0;0m %i\n", (int)test_packet.room_name_length[2]);
	printf("\033[22;36mMessage (dec):\033[0;0m %s\n", test_packet.message);
	
	printf("\033[22;36mMesssage:\033[0;0m ");
	
	char *fmtmsg;
	fmtmsg = strtok((char*)test_packet.message, ", ");
	while (fmtmsg != NULL)
	{
		printf("%c", atoi(fmtmsg));
		fmtmsg = strtok(NULL, ", ");
	}
	printf("\n");
	
	printf("\033[22;36mMessage size:\033[0;0m %i\n", (int)test_packet.message_length[2]);
	printf("\033[22;36mColor:\033[0;0m %s\n", test_packet.color);
	printf("\033[22;36mBy:\033[0;0m %s\n", test_packet.name);
	printf("\033[22;36mName size:\033[0;0m %i\n", (int)test_packet.name_length[2]);

	fclose(file1);
	
	// you didn't goof
	// son, I am pride
	return 0;
}
