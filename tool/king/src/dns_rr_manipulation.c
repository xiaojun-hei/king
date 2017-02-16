/* This file has funtions to manipulate and extract information from
 *  various DNS resource records
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

char akaname[] = "a338.g.akamaitech.net";

void fetchRecNS(char NS[][MAXDNAME], int nsCount, char rns[][MAXDNAME], int *rnsCount){
  int k, n;
  for(k=0; k<nsCount; k++) {
    printf("Querying to check if name server %s is recursive\n", NS[k]);
    n = isNSRec(NS[k]);
    if(n <0) {
      printf("ERROR WHILE CHECKING WHETHER Name Server %s is recursive\n", NS[k]);
    }
    else if( n == 0) {
      printf("Name Server %s IS NOT recursive \n", NS[k]);
    }
    else {
      printf("Name Server %s IS recursive \n", NS[k]);
      memcpy(rns[(*rnsCount)++], NS[k], 1+strlen(NS[k]));
    }
  }
  return; 
}

void fetchNSRR(char * domain, char NS[][MAXDNAME], int * nsNum){
  
  union dnsmsg response; 
  int responselen;
  u_char *endOfMsg;
  char * cp;
  
  *nsNum =0;
  responselen = sizeof(response);
  printf("Querying local name server for name servers for %s .... \n", domain);
  
  if(resolve(NULL, domain, T_ANY, &response, &responselen) >= 0) {
    /* Process the response */
    endOfMsg = response.msg + responselen;
    cp= response.msg;
    /* Skipping the header and question portions of the dns message */
    cp+=skipToRR(cp, endOfMsg, &response);
    fetchRR(&response, endOfMsg, cp, NS, nsNum, NSLIMIT, T_NS);
  }
  else{
    *nsNum = -1;
    return;
  }
  return;
}

void fetchSOARR(char * domain, char SOA[][MAXDNAME], int * nsNum){
  
  union dnsmsg response; 
  int responselen;
  u_char *endOfMsg;
  char * cp;
  
  *nsNum =0;
  responselen = sizeof(response);
  printf("Querying local name server for SOA name server for %s .... \n", domain);

  if(resolve(NULL, domain, T_SOA, &response, &responselen) >= 0) {
    /* Process the response */
    endOfMsg = response.msg + responselen;
    cp= response.msg;
    /* Skipping the header and question portions of the dns message */
    cp+=skipToRR(cp, endOfMsg, &response);
    fetchRR(&response, endOfMsg, cp, SOA, nsNum, 1, T_SOA);
  }
  else{
    *nsNum = -1;
  }
  return;
}
void fetchARR(char * domain, char A[][MAXDNAME], int * nsNum){
  
  union dnsmsg response; 
  int responselen;
  u_char *endOfMsg;
  char * cp;
  
  *nsNum =0;
  responselen = sizeof(response);
  if(resolve(NULL, domain, T_A, &response, &responselen) >= 0) {
    /* Process the response */
    endOfMsg = response.msg + responselen;
    cp= response.msg;
    /* Skipping the header and question portions of the dns message */
    cp+=skipToRR(cp, endOfMsg, &response);
    fetchRR(&response, endOfMsg, cp, A, nsNum, 1, T_A);
  }
  else{
    *nsNum = -1;
  }
  return;
}
void fetchPTRRR(char * domain, char PTR[][MAXDNAME], int * nsNum){
  
  union dnsmsg response; 
  int responselen;
  u_char *endOfMsg;
  char * cp;
  
  *nsNum =0;
  responselen = sizeof(response);
  if(resolve(NULL, domain, T_PTR, &response, &responselen) >= 0) {
    /* Process the response */
    endOfMsg = response.msg + responselen;
    cp= response.msg;
    /* Skipping the header and question portions of the dns message */
    cp+=skipToRR(cp, endOfMsg, &response);
    fetchRR(&response, endOfMsg, cp, PTR, nsNum, 1, T_PTR);
  }
  else{
    *nsNum = -1;
  }
  return;
}
/*
 * In the following implementation we ask the NS to resolve 
 * the name of an akamai server, and see if it returns any answer
 */
int isNSRec(char * NS) {
  union dnsmsg response; 
  int responselen, result =-1;
  
  responselen = sizeof(response);
  if(resolve(NS, akaname, T_A, &response, &responselen) >=0) {
    if(response.hdr.ancount > 0) result =1; else result =0;
  }
  return result;
}
int skipName(u_char *cp, u_char *endOfMsg) 
{
  int len;
  if((len=dn_skipname(cp, endOfMsg))<0) {
    printf("dn_skipname failed\n");
    exit (-1);
  }
  return len;
}
int skipToData(u_char *cp, u_char *endOfMsg, u_short *type, u_short *class, u_long *ttl, u_short *dlen){
  u_char * tmp_cp= cp;
  // printf("Reached skipToData %d \t %d\n", cp, endOfMsg);
  /* skip the domain name we looked up */
  tmp_cp+= skipName(tmp_cp, endOfMsg);
  //  printf("Reached Begin of skipToData %d\n", tmp_cp);
  *type = _getshort(tmp_cp);
  //  printf("Reached end of skipToData %d\n", tmp_cp);
  tmp_cp+= sizeof(u_short);
  //  printf("Reached end of skipToData %d\n", tmp_cp);
  *class = _getshort(tmp_cp);
  tmp_cp+= sizeof(u_short);
  *ttl = _getlong(tmp_cp);
  tmp_cp+= sizeof(u_long);
  *dlen = _getshort(tmp_cp);
  tmp_cp+= sizeof(u_short);
  //  printf("Reached end of skipToData %d\n", tmp_cp);
  return (tmp_cp - cp);
}

int skipToRR(u_char *cp, u_char *endOfMsg, union dnsmsg * response) {
  
  int n;
  u_char *tmp_cp=cp;
  //  printf("Reached Begin of skipToRR %d\n", tmp_cp);
  /* Skipping the header portion of the dnsmessage */
  tmp_cp+= sizeof(HEADER);
  /* Skip question records */
  n = ntohs(response->hdr.qdcount); /* find the number of questions, in this case it is 1 */
  
  while (--n >= 0) { 
    tmp_cp+= skipName(tmp_cp, endOfMsg)+ QFIXEDSZ;
  }
  //  printf("Reached end of skipToRR %d \t %d\n", tmp_cp,n);
  return(tmp_cp-cp); 
}

int resolve(const char * nameserver, const char * name, int query_type, union dnsmsg * answer, int * ans_sz){
  struct hostent *hp;
  char packet[PACKETSZ];
  int bytes_out;
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
   *turn iff the default search algorithm which tries to append 
   * local name extensions to the Domain names not ending with a '.'
   */
  _res.options &= ~(RES_DNSRCH | RES_DEFNAMES); 
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
  if ((*ans_sz = res_send(packet, bytes_out, (char *) answer, *ans_sz)) < 0) {
    printf("res_send returned an error...\n");
    return(-1);
  }
  gettimeofday(&timer_end,NULL);
  querytime = tvsub(&timer_end, &timer_start);
  //querytime = (timer_end.tv_usec - timer_start.tv_usec)/1000; 
  //  querytime+= (timer_end.tv_sec - timer_start.tv_sec)*1000; 
  printf("Query Time %ld usec \n", querytime);
  
  return querytime;
} 

void fetchRR(union dnsmsg * response, u_char *endOfMsg, u_char *cp, char rrList[][MAXDNAME], int *rrNum, int nsLimit, int type){
  
  int numANS_NSrr, i, dup;
  u_long ttl;
  u_short typeRR, class, dlen;
  struct in_addr cip;

  /* count the total number of answer and authroity records */
  numANS_NSrr = ntohs(response->hdr.ancount) + ntohs(response->hdr.nscount);
  
  /* initialise rrNum to 0 */
  *rrNum=0;
  while ((--numANS_NSrr >=0) && (cp < endOfMsg) && (*rrNum < nsLimit)){
    cp+=skipToData(cp,endOfMsg,&typeRR, &class, &ttl,&dlen); 

    if(type == typeRR){
      
      if(type != T_A) { 
	/* 
	 * If type is not an Answer record, Expand compressed Name in the data.
	 * If it is an answer record then the data is an struct in_addr
	 * Which should not be expanded
	 */
	if(dn_expand(response->msg, /* start of the message packet */
		     endOfMsg, /* End of message packet */
		     cp, /* Position in the packet */
		     (u_char *) rrList[*rrNum], /* Result */
		     MAXDNAME) 
	   < 0) {/* Negative:Error */
	  fprintf(stderr, "dn_expand failed\n");
	  exit(-1);
	}
      }
      else {
	bcopy(cp, &cip, sizeof(cip));
	sprintf(rrList[*rrNum],"%s",inet_ntoa(cip));
     }
      /* 
       * Check if the name we have just unpacked is a duplicate
       * if it is a duplicate, just ignore it
       */
      for(i=0, dup=0; (i < *rrNum) && !dup; i++)
	dup = !strcasecmp(rrList[i], rrList[*rrNum]);
      if(dup)
	bzero(rrList[*rrNum], MAXDNAME);
      else
	(*rrNum)++;
    }
    /* Advance the pointer over the resource record data */
    cp+=dlen;
  }/* end of while */
}

