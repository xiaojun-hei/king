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
 * Modified by Yunxian Wang, 11/18/2006 to find the DNS server of a IP address
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
#define MAX_HOSTS 25000

/* Information for each host */
typedef struct host_entry {
	struct host_entry  *prev, *next;         /* doulbe linked list */
	int                i;                    /* index into array */
	char               *name;                /* name as given by user */
} host_entry;

char NS[16][128];
char RNS[16][128]; // recursive name server
char CNS[128];
int INDEX = 0, RINDEX = 0;
struct in_addr INADDR;
int INFINITY = 100000;
FILE *output_file=NULL;           /* file storing the results */
FILE *input_file=NULL;            /* file containing the IP Addresses*/
char *input_filename="../bin/hostfile";   /* name of file containing IP Addresses */
char *output_filename="/home/wang/tools/king/results/dns.txt";  /* name of output file */
host_entry *h_list = NULL; /* head of the list of hosts */
host_entry *t_list = NULL; /* tail of the list of hosts */
u_int num_hosts = 0;       /* total number of hosts */

char akaname[] = "a338.g.akamaitech.net";

inline void Usage(int argc, char *argv[]) {
  printf("Usage: %s [-c count] [-f input_filename] [IP_Address]\n", argv[0]);
  printf(" Where count = number of tries to check for recursive name servers, the larger the better \n");
  printf(" input_filename is the name of file with IP addresses \n");
  printf("Example:\n%s -c 5 128.95.2.67\n", argv[0]);
  printf("        %s -f ip.txt\n", argv[0]);
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
	  fprintf(output_file, " %s",name);
	  INDEX++;
     // memcpy(NS[INDEX++], name, 1 + strlen(name));
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

  dlen = _getshort(cp);
  cp += sizeof(u_short);
  cp1 = cp;

  switch(type) {
  case T_SOA:
    cp = (char*)(ip2aka_cdname(cp, msg, 1));
    cp = (char*)(ip2aka_cdname(cp, msg, 1));
    cp += sizeof(u_long);
    cp += sizeof(u_long);
    cp += sizeof(u_long);
    cp += sizeof(u_long);
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
	     cp += dlen;
      } else if (dlen == 7) {
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

  /*Print  answer records*/
  n = ntohs(cnt);
  while (--n >= 0) {
    pp = (char *) malloc(512);
    *pp=0;
    cp = p_rr(cp, msg);
    if ((cp - msg) > PACKETSZ)
      return (NULL);
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

/* Copy string */
char *cpstr(char *str)
{
	char *p;
	if (str) {
		p = (char *) malloc (1+strlen(str));
		if (!p){
	        printf("Can't allocate some space for a string\n");
			exit(1);
		}
		strcpy(p, str);
		return p;
	}
	else 
		return NULL;
}

/* Add hosts to the linked list */
void add_host(char *name)
{
	host_entry *he;
	he = (host_entry *) calloc(1, sizeof(host_entry));
	if(!he) {
        printf("Can't allocate memory to host_entry\n");
		exit(1);
	}

	he->i = num_hosts++;
	he->name = cpstr(name);

	/* add to the list */
	if(!t_list){
		t_list = he;
		h_list = he;
		he->next = NULL;
		he->prev = NULL;
	}
	else{
		t_list->next = he;
		he->prev = t_list;
		he->next = NULL; 
		t_list = he;
	}
	return;
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

  char line [20];
  char host [MAX_HOSTS];
  host_entry *p,*q;
  char* thisIP;

  opterr=0;
  while ((n = getopt(argc, argv, "c:f:")) != EOF) {
    switch (n) {
		case 'c':
		  count = atoi(optarg);
		break;
		case 'f':
		  // read IP addresses from a file
		  input_filename=optarg;
		  printf("input_filename: %s\n", input_filename);
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
  //open output file
    output_file = fopen(output_filename, "a");
	if (output_file == NULL) {
		printf("Open output file error!\n");
		exit(-1);
	}
    setlinebuf(output_file);
  //open IP addresses file
    input_file = fopen(input_filename, "r");
    if (input_file == NULL) {
		printf("Open input file error!\n");
		exit(-1);
	}

	//read IPs from input file and add them to a linked list
    while (fgets(line,MAX_HOSTS,input_file)){
		if (sscanf(line, "%s", host)!=1)
			continue;
		if ((!*host)||(host[0]=='#'))         /* avoid comments */
			continue;
		add_host(host);
	}
	printf("the total number of host is: %d\n", num_hosts);
	fclose(input_file);
    
	p = h_list;
	while(p){
		thisIP = p->name;
		cp = thisIP;
		printf("IP: %s\n", cp);
		if(strlen(cp)>15){
			printf("The IP address at %d is incorrectly formatted.\n",p->i);
		}
		if(0 == inet_aton(cp, &ip)) {
			printf("Invalid IP address at %d passed in.\n",p->i);
		}
		printf("\nBEGIN OF STAGE 1 \n\n");
		bzero(domain, 128);
		for(k = 0; k < 4; k += 1)
			dix_input[k] = strsep(&cp, ".");
		sprintf(domain, "%s.%s.%s.%s.in-addr.arpa.", dix_input[3], dix_input[2], dix_input[1], dix_input[0]);
		/*
		* Ask the query to our nameserver
		*/
		printf("Querying your local name server for the NS records of %s ....\n", inet_ntoa(ip));
		fprintf(output_file, "%s",inet_ntoa(ip));
		if(resolve(NULL, domain, 255, answer, sizeof(answer)) >= 0) {

			/*Process the answer*/
			hdr = (HEADER*)answer;
			/*skip question records.*/
			cp = answer + sizeof(HEADER);
			n = ntohs(hdr->qdcount);
			while (--n >= 0) { 
				cp = (char*)(ip2aka_cdname(cp, answer, 0));
				if (cp == NULL) {
					printf("Badly formatted DNS answer\n");
                    printf(" \nEND OF STAGE 1 \n");
                    fprintf(output_file, "\n");
					p=p->next;
					continue;
				}
				cp += sizeof(u_short) << 1;
			}

			if ((cp = do_rrset(answer, cp, hdr->ancount)) == NULL){
				printf(" \nEND OF STAGE 1 \n");
                fprintf(output_file, "\n");
				p=p->next;
				continue;
			}

			if ((cp = do_rrset(answer, cp, hdr->nscount)) == NULL){
				printf(" \nEND OF STAGE 1 \n");
                fprintf(output_file, "\n");
				p=p->next;
				continue;
			}
		}

		printf(" \nEND OF STAGE 1 \n");
        fprintf(output_file, "\n");
		if(INDEX == 0) {
			printf("\nEXITING QUERY DUE TO THE EXCEPTIONAL CASE OF LACK OF NAME SERVERS FOR ONE OF THE IP ADDRESSESS\n\n");
		}
		p=p->next;
		INDEX=0;
	}
    if(!output_file) fclose(output_file);
    return 0;
}
















