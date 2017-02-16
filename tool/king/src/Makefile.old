IDIR = ../include
LDIR = ../lib
BDIR = ../bin


LIBS = -lm -lresolv
CFLAGS = -Wall -g -I$(IDIR) -L$(LDIR)
CC = gcc

AO = dns_rr_manipulation.o utility_functions.o
AH = $(IDIR)/dns_rr_manipulation.h $(IDIR)/utility_functions.h

all : $(AO) king

king : king.c
	$(CC) $(CFLAGS) -o $(BDIR)/king king.c $(AO) $(LIBS)

dns_rr_manipulation.o : $(AH)

clean :
	rm -f $(BDIR)/* *.o *~ $(IDIR)/*~