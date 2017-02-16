#define NSLIMIT 20 //Max Number if Name servers returned for any query

//typedef union msg dnsmsg: A structure that holds a typical DNS message 
union dnsmsg{
  HEADER hdr; /* defined in resolv.h */
  u_char msg[PACKETSZ]; /* defined in arpa/nameser.h */
}; /* response buffers */


/*
 * Function prototype declarations
 */

/*
 * This function returns the length of the domain name to be skipped
 */
int skipName(u_char *cp, u_char *endOfMsg); 

/*
 *This function returns the offset of the data portion of a resource
 *record it also returns the type, class, ttl and length in octets of
 *the data in the *resource record
 */ 
int skipToData(u_char *cp, u_char *endOfMsg, u_short *type, u_short *class, u_long *ttl, u_short *dlen);

/*
 * This function returns the length of the header and question regions of 
 * the dns message
 */
int skipToRR(u_char *cp, u_char *endOfMsg, union dnsmsg *response);

/*
 * This function fetches the data in resource records which are of
 *type 'type' contained in the response into the list rrList and the
 *number of rr data items fetched is returned in rrNum. The max number
 *of data records it retrieves is specified by nsLimit
 */

void fetchRR(union dnsmsg * response, u_char *endOfMsg, u_char *cp, char rrList[][MAXDNAME], int *rrNum, int nsLimit, int type);
/* 
 * This function fetches the NS records for the name in domain
 * into a list of name servers in NS
 */
void fetchNSRR(char * domain, char NS[][MAXDNAME], int * nsNum);
/* 
 * This function fetches the SOA record for the name in domain
 * into SOA
 */
void fetchSOARR(char * domain, char SOA[][MAXDNAME], int * nsNum);
/* 
 * This function fetches the A records (answer records) for the name in domain
 * into A
 */
void fetchARR(char * domain, char A[][MAXDNAME], int * nsNum);
/* 
 * This function fetches the PTR records (reverse lookup records) for
 * the name in domain into A 
 */
void fetchPTRRR(char * domain, char PTR[][MAXDNAME], int * nsNum);
/*
 * Returns 0 if the NS is not recursive, 1 if it is, -1 for any other error
 * This function can be implemented in 3 different ways
 * Positive lookup, ask for a known query and check the returned answer
 * Negative lookup, ask for a non-exitent query and check for NXDOMAIN 
 * Look up the RA (recursion available) bit in the header of the response.
 * We use getHostByName to resolve the NS to an ipaddress
 */
int isNSRec(char * NS);
/*
 * This function fetches the recursive name servers from the array NS
 * into the array rns. The number of recursive servers is returned in
 * rnsCount
 */
void fetchRecNS(char NS[][MAXDNAME], int nsCount, char rns[][MAXDNAME], int * rnsCount);
/*
 * Resolve a given query at a given nameserver
 * Return value is the time taken to query the server
 */
int resolve(const char * nameserver, const char * name, int query_type, union dnsmsg * answer, int * ans_sz);
