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
 * 11/01/2006 modified by Yunxian Wang to make it read IP addresses from a file
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

#include "dns_rr_manipulation.h"
#include "utility_functions.h"

extern  u_short _getshort();
extern  u_long  _getlong();

//typedef union msg dnsmsg; 
#define DEFAULT_COUNT  4
#define DEFAULT_DIR    'b'
#define MAX_HOSTS 25000

/* Information for each host */
typedef struct host_entry {
	struct host_entry  *prev, *next;         /* doulbe linked list */
	int                i;                    /* index into array */
	char               *name;                /* name as given by user */
} host_entry;

char NS1[NSLIMIT][MAXDNAME];
char NS2[NSLIMIT][MAXDNAME];
char RNS[NSLIMIT][MAXDNAME]; // recursive name server
char CNS[MAXDNAME];
int NSCOUNT1 = 0, NSCOUNT2 = 0, RNSCOUNT = 0;
struct in_addr INADDR;
int NS1_OR_NS2 = 1, INFINITY = 100000000;
FILE *output_file;           /* file storing the results */
FILE *input_file;            /* file containing the IP Addresses*/
char *input_filename;   /* name of file containing IP Addresses */
char *output_filename="/home/wang/tools/king/results/results_pl.txt";  /* name of output file */
host_entry *h_list = NULL; /* head of the list of hosts */
host_entry *t_list = NULL; /* tail of the list of hosts */
u_int num_hosts = 0;       /* total number of hosts */

inline void Usage(int argc, char *argv[]) {
  printf("Usage: %s [-c count] [-d dir] [-f inputfilename] [IP_Address1 IP_Address2] [-o outputfilename]\n\n", argv[0]);
  printf(" Where count = number of query packets sent, the larger the better, default count = 4 (strongly advised), min 2 \n dir = f for IP_Address1 to IP_Address2 only and  dir = b for either direction, Default dir = b\n");
  printf("inputfilename = files containing IP addresses, outputfilename = files storing results\n");
  printf("Example:\n%s -c 5 -d f 128.95.4.1 128.95.2.67\n", argv[0]);
  printf("%s -f hostfile.txt\n", argv[0]);
  exit(-1);
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
  union dnsmsg response; /* response buffers */
  int responselen; /* stores length of the response */
  //  u_char *endOfMsg; /* stores the end  location of the response received */
  
  struct in_addr ip1, ip2, ip;
  char dix_ip1[4][4], dix_ip2[4][4], *dix[4], *dix_ip[4];
  char domain1[MAXDNAME], domain2[MAXDNAME], tmp_domain[1][MAXDNAME], domain[MAXDNAME], hostName1[NSLIMIT][MAXDNAME], hostName2[NSLIMIT][MAXDNAME];
  int nsNum;
  int n, k;
  char dir = DEFAULT_DIR; // The default direction of latency measurement is from address 1 to 2
  int numOfAttempts=DEFAULT_COUNT;
  int match =0, best_match =-1, ping_time =INFINITY, rec_ping_time=INFINITY;
  int hostNSNameMatch1, hostNSNameMatch2;
  char *cp, cip[15], *tmp_cp;
  struct timeval rand_time;
  char line [20];
  char host [MAX_HOSTS];
  host_entry *p, *q, *tmp;
  int tmprnscount=0;

  opterr=0;
  while ((n = getopt(argc, argv, "c:d:f:o")) != EOF) {
    switch (n) {
    case 'c':
      numOfAttempts = atoi(optarg);
      break;
    case 'd' :
      //Direction of Latency Measurement. Ideally, it should be same
      //in both forward as well as backward directions
      dir = *optarg; 
      if(dir !='b' && dir != 'f') 
	      Usage(argc, argv);
      break;
	case 'f':
		// read IP addresses from a file
		input_filename=optarg;
		printf("input_filename: %s\n", input_filename);
		break;
	case 'o':
		// write results to a file
		output_filename=optarg;
		printf("output_filename: %s\n", output_filename);
		break;
    default:
      Usage(argc, argv);
    }
  }
  /* 
   * Check if the input options are good
   */
  
/*  if(argc <= 2){
    printf("Two IP addressess are not passed as input.\n");
    Usage(argc, argv);
  }
  if(argv[argc-2] == NULL || argv[argc-1] == NULL){
    printf("Insufficient number of arguments.\n");
    Usage(argc, argv);
  }
  */

  /*
   * In this stage we obtain the corresponding in-addr.arpa names for
   * ip addressess if any are passed. Currently we support only IP
   * addressess, but it should be trivial to modify this code to take
   * in host names rather than IP addressess as arguments
   */
    output_file = fopen(output_filename, "a");
	if (output_file == NULL) {
		printf("Open output file error!\n");
		exit(-1);
	}
    setlinebuf(output_file);
  
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
	tmp = h_list;
	while(p){
	      cp = p->name;
		  printf("P--IP: %s\n", cp);
		  bzero(domain1, MAXDNAME);
		  if(inet_aton(cp, &ip1) != 0) { /* An ip address is passed rather than a host name */
			for(n=0; n<4;n+=1) {
			  tmp_cp = strsep(&cp, ".");
			  if(tmp_cp  == NULL) {
				// The IP address passed does not have 4 octets, so reject and exit
				printf("IP address passed does not have 4 octets. Hence, exiting the program \n");
				p=p->next;
				continue;
			  }
			  memcpy(dix_ip1[n],tmp_cp, 1+strlen(tmp_cp)); 
			}
			sprintf(domain1, "%s.%s.%s.%s.in-addr.arpa.", dix_ip1[3], dix_ip1[2], dix_ip1[1], dix_ip1[0]);
		  }
		  else {
			printf("Two IP addressess are not passed as input.\n");
			printf("1\n");
			Usage(argc, argv);
		  }
		 printf("Begin of stage 1 of 1\n");
		bzero(domain, MAXDNAME);
		  memcpy(domain, domain1, 1+strlen(domain1)); 
		  cp = domain; /* just store the pointer into a this pointer variable as 
				  strsep function below is destructive */
		  for(n=0; n<3; n++) {
			fetchPTRRR(cp, hostName1, &nsNum);
			fetchNSRR(cp, NS1, &nsNum); 
			if(nsNum != 0) {
			  break;
			}
			strsep(&cp, ".");
		  }

		  if((NSCOUNT1 = nsNum) <= 0) { /* This is some error case */
			if(nsNum <0){
			  printf("EXITING DUE TO ERROR IN QUERY RESOLUTION FOR NAME SERVERS FOR %s\n", domain1); 
			  fprintf(output_file, "%s ",inet_ntoa(ip1));
			  fprintf(output_file, "%s ----\n",inet_ntoa(ip2));
			}
			else {
			  printf("EXITING DUE TO FAILURE TO RESOLVE THE NAME %s\n", domain1); 
			  fprintf(output_file, "%s ",inet_ntoa(ip1));
			  fprintf(output_file, "%s ----\n",inet_ntoa(ip2));
			}
			tmp=tmp->next;
			p=tmp;
			NSCOUNT1 = 0;
			NSCOUNT2 = 0;
			RNSCOUNT = 0;
			nsNum = 0;
			continue;
		  } 
		  for(k=0; k<nsNum; k++) {
			printf("Name Server %d: %s \n", k, NS1[k]);
		  }

		   printf("\nBEGIN OF STAGE 1 of 2 \n");
		   fetchRecNS(NS1, NSCOUNT1, RNS, &(RNSCOUNT));
		   tmprnscount=RNSCOUNT;
		  q=p->next;
		  while(q){
			  cp = q->name;
			  printf("Q--IP: %s\n", cp);
			  bzero(domain2, MAXDNAME);
			  if(inet_aton(cp, &ip2) != 0) { /* An ip address is passed rather than a host name */
				for(n=0; n<4;n+=1) {
				  tmp_cp = strsep(&cp, ".");
				  if(tmp_cp  == NULL) {
					// The IP address passed does not have 4 octets, so reject and exit
					printf("IP address passed does not have 4 octets. Hence, exiting the program \n");
					q=q->next;
					continue;
				  }
				  memcpy(dix_ip2[n],tmp_cp, 1+strlen(tmp_cp)); 
				}
				sprintf(domain2, "%s.%s.%s.%s.in-addr.arpa.", dix_ip2[3], dix_ip2[2], dix_ip2[1], dix_ip2[0]);
				sprintf(q->name, "%s.%s.%s.%s",dix_ip2[0], dix_ip2[1], dix_ip2[2], dix_ip2[3]); 
			  }
			  else { 
				printf("Two IP addressess are not passed as input.\n");
				printf("2\n");
				Usage(argc, argv);
			  }
			  printf("\nLatency is estimated between %s and %s \n",domain1, domain2); 
			 
			  /* 
			   * In this stage we find out the name servers which can resolve the 
			   * names found in domain1 and domain 2 respectively. This is to help 
			   * us choose a name server.from among the many name servers. We need 
			   * to choose one that is recursive and is close to the end host.
			   */
			  printf("\n\nBEGIN OF STAGE 2 0f 1 \n\n"); 
			  /*
			   * Suppose the domain1 is 4.1.95.128.in-addr.arpa, below we first try to
			   * resolve 4.1.95.128.in-addr.arpa and then 1.95.128.in-addr.arpa and finally
			   * 95.128.in-addr.arpa. If these do not work then, we give up. 
			   */
			  bzero(domain, MAXDNAME); 
			  memcpy(domain, domain2, 1+strlen(domain2)); 
			  cp = domain; /* just store the pointer into a this pointer variable as 
					  strsep function below is destructive */
			  for(n=0; n<3; n++) {
				fetchPTRRR(cp, hostName2, &nsNum);
				fetchNSRR(cp, NS2, &nsNum); 
				if(nsNum != 0) {
				  break;
				}
				strsep(&cp, ".");
			  }  
			  if((NSCOUNT2 = nsNum) <= 0) { /* This is some error case */
				if(nsNum <0){
				  printf("EXITING DUE TO ERROR IN QUERY RESOLUTION FOR NAME SERVERS FOR %s\n", domain2); 
				  fprintf(output_file, "%s ",inet_ntoa(ip1));
				  fprintf(output_file, "%s ----\n",inet_ntoa(ip2));
				}
				else {
				  printf("EXITING DUE TO FAILURE TO RESOLVE THE NAME %s\n", domain2); 
				  fprintf(output_file, "%s ",inet_ntoa(ip1));
				  fprintf(output_file, "%s ----\n",inet_ntoa(ip2));
				}
				q=q->next;
				NSCOUNT2 = 0;
				RNSCOUNT=tmprnscount;
				nsNum = 0;
				continue;
			  }
			  for(k=0; k<nsNum; k++) {
				printf("Name Server %d: %s \n", k, NS2[k]);
			  }
			  
			  /* Now we quit if the name servers at either end host includes a
				 root name server */
			  printf("\nChecking if there are root name servers among authoritative name servers for either end hosts\n");
			  if(ContainRootNameServer(NS1, NSCOUNT1)>0 || ContainRootNameServer(NS2, NSCOUNT2)>0){
				printf("EXITING DUE TO PRESENCE OF ROOT NAME SERVER AMONG THE AUTHORITATIVE NAME SERVERS\n");
				fprintf(output_file, "%s ",inet_ntoa(ip1));
				fprintf(output_file, "%s ----\n",inet_ntoa(ip2));
				q=q->next;
				NSCOUNT2 = 0;
				RNSCOUNT=tmprnscount;
				nsNum = 0;
				continue;
			  }
			  printf("Check Succeeded without any failures\n");
			  
			  printf("\n\nEND OF STAGE 1 \n"); 
			  
			  /*
			   * In this stage, we check the recursive name servers among
			   * the list of existing Name servers in arrays NS1 and NS2 We
			   * check for the direction of latency measurement. If it is
			   * only in forward dir, we donot check the list NS2 even when
			   * there are no recursive name servers in NS1. If it is any
			   * dir then, we do both.  Yet to be explored, in case of any
			   * dir, we first try 2->1 only when the measurement 1->2 fails
			   * and not other-wise. Ideally, we could do much better.  
			   */
			  
			  printf("\n\nBEGIN OF STAGE 2 of 2 \n\n");
			 /* fetchRecNS(NS1, NSCOUNT1, RNS, &(RNSCOUNT));*/
			  if(tmprnscount==0 && dir == 'b') {
				/*
				 * No name server for the first host is recursive, so
				 * try the other if there are no constraints on the
				 * direction of measurements 
				 */
				fetchRecNS(NS2, NSCOUNT2, RNS, &(RNSCOUNT));
				dir = 'r'; /* update dir to the actual direction of measurement */
			  }
			  else {dir ='f';} /* update dir to the actual direction of measurement; */
			  if(RNSCOUNT==0) { 
				printf("EXITING THE PROGRAM DUE TO LACK OF RECURSIVE NAME SERVERS\n");
				fprintf(output_file, "%s ",inet_ntoa(ip1));
				fprintf(output_file, "%s ----\n",inet_ntoa(ip2));
				q=q->next;
				NSCOUNT2 = 0;
				RNSCOUNT=tmprnscount;
				nsNum = 0;
				dir='b';
				continue;
			  }
			  printf("Number of Recursive Name Servers = %d", RNSCOUNT);
			  printf("\n\nEND OF STAGE 2 \n");

			  /*
			   * In this stage we choose that name server from the list of
			   * recursive name servers which shares the longest common ip prefix
			   * with the host 
			   */
			  printf("\n\n\nBEGIN OF STAGE 3 \n\n");
			  for(k=0; k < RNSCOUNT; k++) {
				printf("Querying for ip address of %s .... \n", RNS[k]);
				fetchARR(RNS[k], tmp_domain, &nsNum);
				cp = tmp_domain[0];
				if(nsNum <= 0 || inet_aton(cp, &ip) == 0) {
				  printf("No IP was found for the name server %s\n",RNS[k]);
				  continue;
				}
				printf("The IP Address of %s is %s\n", RNS[k], cp);
				for(n=0; n<4;n++){ 
				  if(dir == 'r') dix_ip[n]=dix_ip2[n]; else dix_ip[n]=dix_ip1[n]; 
				  dix[n] = strsep(&cp,"."); 
				}
				match =0;
				for(n=0; n<4;n++){ 
				  if(strcmp(dix[n],dix_ip[n])!=0) { 
					if(n > match) match =n;	   
					break; 
				  } 
				  else if(n == 3) match=4; 
				} 
				printf("The extent of match of %s is %d \n", RNS[k], match); 
				if(best_match < match) {
				  best_match = match;
				  sprintf(CNS, RNS[k]); 
				  sprintf(cip, "%s.%s.%s.%s", dix[0],dix[1],dix[2],dix[3]);
				}
			  }
				if(CNS[0] == '\0') { 
				  printf(" \n\nEXITING PROGRAM AS AN APPROPRIATE NAME SERVER COULD NOT BE CHOSEN FROM THE RECURSIVE SERVERS \n"); 
				  fprintf(output_file, "%s ",inet_ntoa(ip1));
				  fprintf(output_file, "%s ----\n",inet_ntoa(ip2));
				  q=q->next;
				  NSCOUNT2 = 0;
				  RNSCOUNT=tmprnscount;
				  nsNum = 0;
				  dir='b';
				  continue;
				} 
				printf("THE RECURSIVE SERVER CHOSEN IS %s AND ITS IP ADDRESS is %s\n", CNS, cip); 

				// Now we determine the extent of match between the names of the
				// end hosts and their name servers

				bzero(tmp_domain[0], MAXDNAME);
				memcpy(tmp_domain[0], CNS, strlen(CNS)+1);
				if(dir == 'r'){
				  hostNSNameMatch1 = hostNameServerMatch(hostName2[0], tmp_domain, 1);
				  hostNSNameMatch2 = hostNameServerMatch(hostName1[0], NS1, NSCOUNT1);
				}
				else {
				  hostNSNameMatch1 = hostNameServerMatch(hostName1[0], tmp_domain, 1);
				  hostNSNameMatch2 = hostNameServerMatch(hostName2[0], NS2, NSCOUNT2);
				}
				printf("\nExtent of Name and IP Match Between End Host and Name Servers are %d %d %d\n", hostNSNameMatch1, hostNSNameMatch2, best_match);

				printf("\n\nEND OF STAGE 3 \n\n");

				/* 
				 * In this stage of the algorithm, we find the latency to the chosen
				 * remote name server as well as the latency of the recursive query
				 * resolution. We pick the minimum query duration for the latencies 
				 */
			    
				printf("\n\n\nBEGIN OF STAGE 4 \n\n");
				ping_time = INFINITY; /* Assign a very large number to ping time */
				rec_ping_time = INFINITY; /* Assign a very large number to recursive ping time */
				for(k=0; k<numOfAttempts; k++){
				  /* first find the ping time to the remote name server */
				  printf("Ping Attempt %d to %s\n", k, CNS);  
				  responselen = sizeof(response);
				  if(ping_time > (n=resolve(CNS, CNS, T_SOA, &response, &responselen))) {if(n>=0) ping_time=n;} 
				  /* 
				   * Now find the recursive ping time, i.e., make the first
				   * remote name server to query the second remote name server
				   * by asking it for a non-existent name in in the domain of
				   * the second name server
				   */
				  gettimeofday(&rand_time, NULL);
				  if(dir == 'r') {sprintf(domain, "%ld.%s", (rand_time.tv_usec*1000 + rand_time.tv_usec)+300,domain1); }
				  else {sprintf(domain, "%ld.%s", (rand_time.tv_usec)+300,domain2); }
				  printf("Recursive Ping Attempt %d from %s to %s\n", k, CNS, domain);  
				  responselen = sizeof(response);
				  if(rec_ping_time > (n= resolve(CNS, domain, T_SOA, &response, &responselen))) { if(n>=0) rec_ping_time=n;}
				  usleep(200000);
				}
				printf("\n\nEND OF STAGE 4 \n\n");
			    
				if(ping_time != INFINITY && rec_ping_time != INFINITY) { 
				  if(dir == 'r') {
					printf("The direction of estimation is BACKWARD\n");
				  }
				  else{
					printf("The direction of estimation is FORWARD\n");
				  }
				  printf("THE ESTIMATED LATENCY BETWEEN %s ", inet_ntoa(ip1)); 
				  fprintf(output_file, "%s ", inet_ntoa(ip1));
				  printf("and %s IS %d usec\n", inet_ntoa(ip2), rec_ping_time - ping_time);
				  fprintf(output_file, "%s %d usec\n",inet_ntoa(ip2), rec_ping_time - ping_time);
				} 
				else {
				  printf(" \n\n EXITING PROGRAM AS THERE WAS AN ERROR IN ESTIMATING LATENCIES DIRECT OR RECURSIVE \n"); 
				  fprintf(output_file, "%s ",inet_ntoa(ip1));
				  fprintf(output_file, "%s ----\n",inet_ntoa(ip2));
				}
				q=q->next;
				NSCOUNT2 = 0;
				RNSCOUNT=tmprnscount;
				dir='b';
				nsNum = 0;
		}
		tmp=tmp->next;
		p=tmp;
        NSCOUNT1 = 0;
		NSCOUNT2 = 0;
		RNSCOUNT = 0;
		nsNum = 0;
		dir='b';
	}
	fclose(output_file);
    return 0;
}
  
















