CC=gcc
CFLAGS=-c -Wall

all: tc_packet_reader tc_bot

tc_packet_reader: tc_packet_reader.o
	$(CC) tc_packet_reader.o -o tc_packet_reader
	
tc_packet_reader.o: tc_packet_reader.c
	$(CC) $(CFLAGS) tc_packet_reader.c

tc_bot: tc_bot.o
	$(CC) tc_bot.o -o tc_bot -lpcap

tc_bot.o: tc_bot.c
	$(CC) $(CFLAGS) tc_bot.c

clean:
	rm -rf *o tc_packet_reader tc_bot
