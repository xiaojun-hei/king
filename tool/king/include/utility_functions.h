int ContainRootNameServer(char ns[][MAXDNAME], int nsNum);
int ContainsString(char *str1, char * str2);
int reverseString(const char * str1, char * str2, int len);
int findHierarchyLevelsMatch(const char *str1, const char * str2, int len);
int hostNameServerMatch(const char * host, char ns[][MAXDNAME], int numNS);

#define MAXSECS		2146	/* 2147,483,647 usec */

/*
 * TVSUB -- Subtract two timeval structs
 * -------------------------------------
 *
 *	Returns:
 *		Time difference in micro(!)seconds.
 *
 *	Side effects:
 *		The difference of the two timeval structs
 *		is stored back into the first.
 *
 *	This implementation assumes that time_t is a signed value.
 *	On 32-bit machines this limits the range to ~35 minutes.
 *	That seems sufficient for most practical purposes.
 *	Note that tv_sec is an *un*signed entity on some platforms.
 */
time_t tvsub(struct timeval *t2, struct timeval *t1);
