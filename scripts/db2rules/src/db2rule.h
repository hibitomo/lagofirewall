/************************************************************************/
/* predefination                                                        */
/************************************************************************/
#define TRUE			1
#define FALSE			0
#define ERROR           (-1)
#define SUCCESS         1

#define MAXRULES	65535	// maximum number of rules
#define BINTH		8		// maximum number of rules in leaf nodes
#define SPFAC		4		// the space factor

#define IPv4_LENGTH 32
#define L4Pt_LENGTH 16
#define IP_PROTO_LENGTH 8

/************************************************************************/
/* structures for filters                                               */
/************************************************************************/
struct RULE
{
  unsigned int pos;
  unsigned int priority;
  unsigned int sIP[2];
  unsigned int dIP[2];
  unsigned short sPt[2];
  unsigned short dPt[2];
  unsigned int protocol[2];
};

struct RULESET
{
	unsigned int numRules;				// totoal number of rules
	struct RULE ruleList[MAXRULES];	// rule list, through which we can visit each rule in the classifier
};

/************************************************************************/
/* functions for reading rules                                          */
/************************************************************************/ 
// Load Rule Set into memory
void LoadRules(FILE *fp, struct RULESET *ruleSet);
// Read one filter from each line of the filter file, called by LoadFilters(...)
int ReadRules(FILE *fp, struct RULESET *ruleSet, unsigned int pos);
// Read ip prefix, called by ReadFilter
void ReadPrefix(FILE *fp, unsigned char* IPpref, unsigned char *IPmask);
// Read port, called by ReadFilter
void ReadPort(FILE *fp, unsigned int *Pt);

int port_list(unsigned short key0, unsigned short key1,
              unsigned short dPt_list[][2], int *i, int length);

int print_rules(char* filename);
