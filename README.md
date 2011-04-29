TinyChat C Bot
==============
Created by
----------
James Stine (leon.blade@gmail.com)

What is this?
-------------
This is a collection of resources and tools for creating the first ever TinyChat bot.
Check CHANGELOG to see what has been added/changed etc or just look through the commits if you're interested.

Building
--------
All code will be written with C and uses libpcap for packet handling.
A makefile is included for easy building any/all files and projects included in this repository.

tc_packet_reader
----------------
This binary will open up a saved packet file (just the payload no headers) and parse out information to be displayed in the shell.

To build ...

	$ make tc_packet_reader

To run ...

	$ ./tc_packet_reader <file>
	
tc_bot
------
You must run in either root or sudo if pcap doesn't have enough privileges to capture on the network device.
Look at the "handle_command" function to see what commands are available.  Set the nickname of the bot at the top
in the variable "bot_nick".

To build ...

	$ make tc_bot
	
To run ...

	$ sudo ./tc-bot <device>

Other files
-----------
README the file you're reading right now, of course.
TODO contains future planned additions or things that are currently being worked on.
CHANGELOG contains a simplified list of things changed and updated, this will also be shown in the commits.
DOX folder contains different text files to explain packet structure among other things.
