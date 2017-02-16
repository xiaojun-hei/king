/*
 * Copyright (c) 2001
 * Krishna Gummadi and the University of Washington
 * All rights reserved. 
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author(s) may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.  
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR(S) ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR(S) BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
/*
 * HISTORY
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <netdb.h>

extern  u_short _getshort();
extern  u_long  _getlong();

#define DEFAULT_COUNT  4

char NS[16][128];
char RNS[16][128]; // recursive name server
char CNS[128];
int INDEX = 0, RINDEX = 0;
struct in_addr INADDR;
int INFINITY = 100000;


char akaname[] = "a338.g.akamaitech.net";

inline void Usage(int argc, char *argv[]) {
  printf("Usage: %s [-c count] IP_Address1 \n\n", argv[0]);
  printf(" Where count = number of tries to check for recursive name servers, the larger the better \n");
  printf("Example:\n%s -c 5 128.95.2.67\n", argv[0]);
  exit(-1);
}

char *ip2aka_cdname(char *cp, char *msg, int to_print) {
  char name[MAXDNAME];
  int n;

  if ((n = dn_expand(msg, msg + 512, cp, name, sizeof(name))) < 0)
    return (NULL);
  if (name[0] == '\0') {
    name[0] = '.';
    name[1] = '\0';
  }
  if(to_print) {
      printf("Name Server %d : %s\n", INDEX, name);
      memcpy(NS[INDEX++], name, 1 + strlen(name));
  }
  return (cp + n);
}

/********************************************************
 * Print resource record fields in human readable form.
 ********************************************************/
char *p_rr(char *cp, char *msg)
{
  int type, class, dlen;
  char *cp1;
  struct in_addr inaddr;
  unsigned long tmpttl;
  

  cp = (char*)(ip2aka_cdname(cp, msg, 0));
  if (cp == NULL)
    return (NULL);			/* compression error */

  type = _getshort(cp); 
  cp += sizeof(u_short);
  class = _getshort(cp);
  cp += sizeof(u_short);
  tmpttl = _getlong(cp);
  cp += sizeof(u_long);

  //  printf("\t%s\t%s\t%d",p_class(class), p_type(type), (int)(tmpttl));

  dlen = _getshort(cp);
  cp += sizeof(u_short);
  cp1 = cp;

  switch(type) {
  case T_SOA:
    cp = (char*)(ip2aka_cdname(cp, msg, 1));
    //    printf("\n");
    cp = (char*)(ip2aka_cdname(cp, msg, 1));
    //    printf("\n");
    
    //    printf("\n\t\t\t%ld\t;serial\n", _getlong(cp));
    cp += sizeof(u_long);
    //    printf("\t\t\t%ld\t;refresh\n", _getlong(cp));
    cp += sizeof(u_long);
    //    printf("\t\t\t%ld\t;retry\n", _getlong(cp));
    cp += sizeof(u_long);
    //    printf("\t\t\t%ld\t;expire\n", _getlong(cp));
    cp += sizeof(u_long);
    //    printf("\t\t\t%ld\t;minim\n", _getlong(cp));
    cp += sizeof(u_long);
    break;

  case T_NS:
    cp = (char*)(ip2aka_cdname(cp, msg, 1));
    break;    
    
  case T_PTR:
    cp = (char*)(ip2aka_cdname(cp, msg, 0));
    break;    
    
  case T_A:
    switch (class) {
    case C_IN:
      bcopy(cp, (char *)&inaddr, sizeof(inaddr));
      bzero(&INADDR, sizeof(INADDR));
      bcopy(cp, (char *)&INADDR, sizeof(INADDR));
      if (dlen == 4) {
	//printf("%s\n",inet_ntoa(inaddr));
	cp += dlen;
      } else if (dlen == 7) {
	//printf("%s\n",inet_ntoa(inaddr));
	//printf(";; proto: %d", cp[4]);
	//printf(", port: %d", (cp[5] << 8) + cp[6]);
	cp += dlen;
      }
      break;

    default:
      cp += dlen;
    }    
    break;

  default:
    printf("ERROR Unknown TYPE %d\n", type);
  }
    
  if (cp != cp1 + dlen)
    printf(";; packet size error (%#x != %#x)\n", (int)(cp-cp1), (int)(dlen));
  return (cp);
}

/*
 * Do the resource records decoding, a la dig
 */
char *do_rrset(char* msg, char *cp, int cnt)
{
  int n;
  char *pp;

  /*
   * Print  answer records
   */
  n = ntohs(cnt);
  while (--n >= 0) {
    pp = (char *) malloc(512);
    *pp=0;
    cp = p_rr(cp, msg);
    if ((cp - msg) > PACKETSZ)
      return (NULL);

    //    printf("%s",pp);
    free(pp);
  }
  return(cp);
}

/*
 * Resolve a given name at a given nameserver 
 * Return value is the time taken to query the server
 */
int resolve(const char * nameserver, const char * name, int query_type, char * answer, int ans_sz)
{
  struct hostent *hp;
  char packet[PACKETSZ];
  int bytes_out, bytes_in;
  long querytime;
  struct timeval timer_start, timer_end; 

  if(nameserver == NULL) {
    /* use local name server */
    res_init();
    _res.retry = 1;
  }
  else {
    /* use remote name server */
    res_init();
    hp = gethostbyname(nameserver);
    if(hp == NULL) {
      printf("Server could not be found \n");
      return(-1);
    }
    bcopy(hp->h_addr, &_res.nsaddr_list[0].sin_addr, hp->h_length);
    
    _res.nscount = 1;
    _res.retry = 1;
    _res.id = 1;
  }
    /*
     * Format the query for the IP address (domain) the right way
     */
    bytes_out = res_mkquery(QUERY, name, 1, query_type,
			    (char *)0, 0, NULL, packet, sizeof(packet));

    if(bytes_out < 0) {
      fflush(stderr);
      printf("buffer too small\n");
      exit(-1);
    }

    /*
     * Ask the query to our nameserver
     */
    gettimeofday(&timer_start, NULL);
    if ((bytes_in = res_send(packet, bytes_out, answer, ans_sz)) < 0) {
      printf("res_send returned an error...\n");
      return(-1);
    }
    gettimeofday(&timer_end,NULL);
    querytime = (timer_end.tv_usec - timer_start.tv_usec)/1000; 
    querytime+= (timer_end.tv_sec - timer_start.tv_sec)*1000; 
    printf("Query Time %d msec \n", querytime);

    return querytime;
    

} 

int main(int argc, char *argv[]) {

  char answer[PACKETSZ];
  struct in_addr ip;
  int match =0;
  char domain[128];
  int flag_ip1toip2 =1;
  HEADER *hdr;
  char* cp, *cp1;
  int n, k;
  char *dix[4], *dix_input[4];
  struct timeval rand_time;

  int count=DEFAULT_COUNT; 

  opterr=0;
  while ((n = getopt(argc, argv, "c:")) != EOF) {
    switch (n) {
      case 'c':
	count = atoi(optarg);
	break;
      default:
	Usage(argc, argv);
    }
  }
  /* 
   * Check if the input options are good
   */

  if(argc < 2){
    Usage(argc, argv);
  }
  if(NULL == argv[argc-1] || strlen(argv[argc-1]) > 15){
    printf("The IP addresse is incorrectly formatted.\n");
    Usage(argc, argv);
  }

  if(0 == inet_aton(argv[argc-1], &ip)) {
    printf("Invalid IP address passed in.\n");
    Usage(argc, argv);
  }

  printf("\n\n\nBEGIN OF STAGE 1 \n\n");
  bzero(domain, 128);
  cp = argv[argc-1];
  for(k = 0; k < 4; k += 1)
    dix_input[k] = strsep(&cp, ".");

  sprintf(domain, "%s.%s.%s.%s.in-addr.arpa.", dix_input[3], dix_input[2], dix_input[1], dix_input[0]);
  
  /*
   * Ask the query to our nameserver
   */
  printf("Querying your local name server for the NS records of %s ....\n", inet_ntoa(ip));
  if(resolve(NULL, domain, 255, answer, sizeof(answer)) >= 0) {
  
    /*
     * Process the answer 
     */
    hdr = (HEADER*)answer;

    /*
     * Skip question records.
     */
    cp = answer + sizeof(HEADER);
    n = ntohs(hdr->qdcount);
    while (--n >= 0) { 
      cp = (char*)(ip2aka_cdname(cp, answer, 0));
      if (cp == NULL) {
	printf("Badly formatted DNS answer\n");
	exit(-1);
      }
      cp += sizeof(u_short) << 1;
    }

    if ((cp = do_rrset(answer, cp, hdr->ancount)) == NULL)
      exit(-1);
    
    if ((cp = do_rrset(answer, cp, hdr->nscount)) == NULL)
      exit(-1);
  }


  printf(" \nEND OF STAGE 1 \n");

  if(INDEX == 0) {
    printf("\n\nEXITING PROGRAM DUE TO THE EXCEPTIONAL CASE OF LACK OF NAME SERVERS FOR ONE OF THE IP ADDRESSESS\n");
    exit(-1);
  }
  printf(" \n\nBEGIN OF STAGE 2 \n\n");
  

    for(k = 0; k < INDEX; k += 1) {
      printf("Querying to check if Remote name server %s is recursive .... \n", NS[k]);
      if( resolve(NS[k], akaname, 1, answer, sizeof(answer))>=0) {

	hdr = (HEADER*)answer;
	/*
	 * Skip question records.
	 */
	cp = answer + sizeof(HEADER);
	n = ntohs(hdr->qdcount);
	while (--n >= 0) {
	  cp = (char*)(ip2aka_cdname(cp, answer, 0));
	  
	  if (cp == NULL) {
	    printf("Badly formatted DNS answer\n");
	    exit(-1);
	  }
	  cp += sizeof(u_short) << 1;
	}
	if(hdr->ancount != 0) {
	  memcpy(RNS[RINDEX++], NS[k], 1 + strlen(NS[k]));
	  printf("%s IS a recursive name server \n", NS[k]);
	}
	else {
	  printf("%s IS NOT a recursive name server \n", NS[k]);
	}
	/* if ((cp = do_rrset(answer, cp, hdr->ancount)) == NULL)
	   exit(-1); 
	   if ((cp = do_rrset(answer, cp, hdr->nscount)) == NULL)
	   exit(-1);
	*/
      }
    }
    if(RINDEX == 0) {
	printf("\n\nEXITING PROGRAM DUE TO LACK OF RECURSIVE NAME SERVERS \n");
	exit(-1);
    }

printf(" \n\nEND OF STAGE 2 \n");

printf(" \n\nBEGIN OF STAGE 3 \n\n");
  
  /*
   * Now order the various Recursive Name servers with their ip address match with the host
   */
  CNS[0] = '\0';
  for(k = 0; k < RINDEX; k += 1) {
    /*
     * Ask the query to our nameserver
     */

    printf(" Querying your local name server for the IP of %s to find its closeness to %s .... \n", RNS[k], inet_ntoa(ip)); 
    if(resolve(NULL, RNS[k], 1, answer, sizeof(answer))>=0) {

      hdr = (HEADER*)answer;
      /*
       * Skip question records.
       */
      cp = answer + sizeof(HEADER);
      n = ntohs(hdr->qdcount);
      while (--n >= 0) {
	cp = (char*)(ip2aka_cdname(cp, answer, 0));
	
	if (cp == NULL) {
	  printf("Badly formatted DNS answer\n");
	  exit(-1);
	}
	cp += sizeof(u_short) << 1;
      }
      if(hdr->ancount >0){
	cp = do_rrset(answer, cp, hdr->ancount);
	cp = inet_ntoa(INADDR);
	for(n=0; n<4;n++){
	  dix[n] = strsep(&cp,".");
	  if(strcmp(dix[n],dix_input[n])!=0) {
	    printf("IP address of %s is %s and the extent of match %d \n", RNS[k], inet_ntoa(INADDR), n);
	    if(n >= match) {
	      memcpy(CNS, RNS[k], 1+strlen(RNS[k]));
	      match =n;
	    }
	    break;
	  }
	}
      } 
    }
  }
  if(CNS[0] == '\0') {
    printf(" \n\nEXITING PROGRAM AS AN APPROPRIATE NAME SERVER COULD NOT BE CHOSEN FROM THE RECURSIVE SERVERS \n");
    exit(-1);
  }
  printf("THE RECURSIVE SERVER CHOSEN IS %s \n", CNS);
  printf("\n\nEND OF STAGE 3 \n");
  
}
















