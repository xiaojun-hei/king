#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/nameser.h>
#include <netdb.h>
#include <sys/time.h>

#include "utility_functions.h"

int ContainRootNameServer(char ns[][MAXDNAME], int nsNum){
  // Returns 1 if one of the names in the ns array contains a root
  // name server. Returns -1 otherwise

  int count0, count1, delimCount = 7;
  char fqdn[MAXDNAME], delim[][MAXDNAME]= {"IANA", "ROOT-SERVERS", ".EU.net", "ARIN", "arin", "RIPE", "ripe"};

  for(count0=0; count0 < nsNum; count0++){
    // Check if there ns[count] is a root name server
    for(count1=0; count1 < delimCount; count1++){
      bzero(fqdn, MAXDNAME);
      memcpy(fqdn, ns[count0], 1+strlen(ns[count0]));
      if(ContainsString(fqdn, delim[count1]) == 1) {
      printf("NAME SERVER %s is a ROOT NAME SERVER as it contains %s\n", fqdn, delim[count1]);	

	return 1;
      }
    }
  }
  return -1;
}


int ContainsString(char *str1, char * str2){
  // Return 1 if str2 is contained in str1. 0 if it is not and a
  // negative val if there is an error

  char *cp;
  int count;

  if(strlen(str1)>=1024 || strlen(str2)>=1024){
    printf("Error -- The string passed are longer than 1024 bytes. They cannot be manipulated \n");
    return -1;
  }
  for(count =0; count < strlen(str1); count++){
    cp = str1+count;
    if(!(strncmp(cp, str2, strlen(str2)))){
      return 1;
    }
  } 
  return 0;
}


int reverseString(const char * str1, char * str2, int len){
  // copies the reverse of str1 into str2. The lengths of both the
  // arrays have to be of size len
  int counter1, counter2;

  if(len <= strlen(str1)){
    exit(-1);
  }
  bzero(str2, len);
  counter2 = 0;
  for(counter1 = strlen(str1)-1; counter1 >=0; counter1--){
    str2[counter2++]=str1[counter1];
  }
  return 1;
}

int findHierarchyLevelsMatch(const char *str1, const char * str2, int len){
  // find the number of levels of hierarcy that 2 domain names in str1
  // and str2 match. The arrays are of size len

  char revStr1[len], revStr2[len];
  char *cp1, * cp2, * cp3, *cp4;
  int match;

  if(reverseString(str1, revStr1, len) <0) return -1;
  if(reverseString(str2, revStr2, len) <0) return -1;
  cp1 = revStr1; cp2 =revStr2;
  match =0;
  while((cp3 = strsep(&cp1, ".")) && (cp4 = strsep(&cp2, "."))){
    if(strcmp(cp3, cp4) == 0)match++;
    else break;
    if(cp3 == NULL || cp4 == NULL) break;
  }
  return match;
}


int hostNameServerMatch(const char * host, char ns[][MAXDNAME], int numNS){
  // Returns -1 if all the name servers for the end host have nothing
  // or atmost one level of hierarchy in common to the end host's
  // name, 0 if atleast one of the name servers has atleast 2 levels
  // of hierarchy in common and 1 if all the name servers have atleast
  // 2 levels in common
  int i, matchAtleast = -1, matchAtmost = 1;

  for(i=0; i<numNS; i++){
    if(findHierarchyLevelsMatch(host, ns[i], MAXDNAME)>1){matchAtleast = 0;}
    if(findHierarchyLevelsMatch(host, ns[i], MAXDNAME)<=1){matchAtmost = 0;}
  }
  if(matchAtmost == 1) return 1;
  if(matchAtleast == 0) return 0; else return -1;
  
}

time_t tvsub(struct timeval *t2, struct timeval *t1){
	register time_t usec;

	t2->tv_usec -= t1->tv_usec;
	while (t2->tv_usec < 0)
	{
		t2->tv_usec += 1000000;
		if (t2->tv_sec != 0)
			t2->tv_sec--;
		else
			t2->tv_usec = 0;
	}

	if (t2->tv_sec < t1->tv_sec)
	{
		t2->tv_sec = 0;
		t2->tv_usec = 0;
	}
	else
		t2->tv_sec -= t1->tv_sec;

	if (t2->tv_sec > MAXSECS)
	{
		t2->tv_sec = MAXSECS;
		t2->tv_usec = 0;
	}

	usec = t2->tv_sec*1000000 + t2->tv_usec;
	return(usec);
}
