This archive consists of the following directories with the following files:

1) src: 
	king.c:Has the main function
	dns_rr_manipulation.c:Has functions to extract information from DNS resource records; Any DNS reply message is made of these resource records.
	utility_functions.c: Has a few functions that are used in main function in King.c


2) include:
	dns_rr_manipulation.h
	utility_functions.h

3) bin:
	To store the executable

4) lib:
	Currently, this is empty. The only library needed by King is the libresolv Any linux installation that supports "dig" tool would have this library. If not, download it and place it in this directory.


HOW TO USE KING: 

a) Unzip and extract the contents of the archive into a present
working directory.

b) cd src

c) make

d) ../bin/king IP_ADDRESS1 IP_ADDRESS2


To see the options that King currently supports type ../bin/king
(i.e., without any parameters). Also, currently king outputs a lot of
detailed information about its inner workings. The latency between the
two IP_Addressess is on the last line in the output.
