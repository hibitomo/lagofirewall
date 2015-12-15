#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <math.h>
#include <arpa/inet.h>

#include "db2rule.h"


/************************************************************************/
/* functions for loading rules                                          */
/************************************************************************/
void ReadPrefix(FILE *fp, unsigned char *IPpref, unsigned char *IPmask)
{
	unsigned int tpref[4], tMask;
        int ret;
	tMask = 32;	// default mask length for ip address(with no '/??' specification)

	ret = fscanf(fp,"%d.%d.%d.%d/%d",&tpref[0],&tpref[1],&tpref[2],&tpref[3], &tMask);
        if (ret != 5) return;
	IPpref[0] = (unsigned char)tpref[0];
	IPpref[1] = (unsigned char)tpref[1];
	IPpref[2] = (unsigned char)tpref[2];
	IPpref[3] = (unsigned char)tpref[3];
	*IPmask	  = (unsigned char)tMask;
}

void ReadPort(FILE *fp, unsigned int *Pt)
{
  int ret;
  ret = fscanf(fp,"%d : %d", &Pt[0], &Pt[1]);
  if (ret != 2) return;
}

void ReadProtocol(FILE *fp, unsigned int *protocol)
{
  int ret;
  ret = fscanf(fp, "%x/%x\n", &protocol[0], &protocol[1]);
  if (ret != 2) return;
}


int ReadRules(FILE *fp, struct RULESET *ruleSet, unsigned int pos) {
  char validRule;
  int ret;

  while(TRUE) {
    ret = fscanf(fp, "%c", &validRule);
    if (ret ==0 || validRule != '@') break;

    unsigned char sIP[4] = {0,0,0,0};
    unsigned char dIP[4] = {0,0,0,0};
    unsigned char sIPmask = 0;
    unsigned char dIPmask = 0;
    ReadPrefix(fp, sIP, &sIPmask);
    ReadPrefix(fp, dIP, &dIPmask);

    unsigned int sIPHEX = (unsigned int)((sIP[0] << 24)^(sIP[1] << 16)^(sIP[2] << 8)^(sIP[3])); 
    unsigned int dIPHEX = (unsigned int)((dIP[0] << 24)^(dIP[1] << 16)^(dIP[2] << 8)^(dIP[3])); 

    ruleSet->ruleList[ruleSet->numRules].sIP[1]
        = sIPmask ? (0xffffffff) << (unsigned int)(32 - sIPmask) : 0;
    ruleSet->ruleList[ruleSet->numRules].dIP[1]
        = dIPmask ? (0xffffffff) << (32 - dIPmask) : 0;

    ruleSet->ruleList[ruleSet->numRules].sIP[0]
        = sIPHEX & ruleSet->ruleList[ruleSet->numRules].sIP[1];
    ruleSet->ruleList[ruleSet->numRules].dIP[0]
        = dIPHEX & ruleSet->ruleList[ruleSet->numRules].dIP[1];


    unsigned int sPt[2], dPt[2];
    ReadPort(fp, sPt);
    ReadPort(fp, dPt);
    ruleSet->ruleList[ruleSet->numRules].sPt[0]
      = (unsigned short)sPt[0];
    ruleSet->ruleList[ruleSet->numRules].sPt[1]
      = (unsigned short)sPt[1];
    ruleSet->ruleList[ruleSet->numRules].dPt[0]
      = (unsigned short)dPt[0];
    ruleSet->ruleList[ruleSet->numRules].dPt[1]
      = (unsigned short)dPt[1];
    ruleSet->ruleList[ruleSet->numRules].pos = pos;

    
    unsigned int protocol[2];
    ReadProtocol(fp, protocol);
    ruleSet->ruleList[ruleSet->numRules].protocol[0]
        = protocol[0];
    ruleSet->ruleList[ruleSet->numRules].protocol[1]
        = protocol[1];
    
    ruleSet->numRules++;
    return 1;
  }
  return 0;
}

void LoadRules(FILE *fp, struct RULESET *ruleSet)	// load 
{
  ruleSet->numRules=0;
  unsigned int pos = 0;	// the posisiton of the rules
  while(!(feof(fp))) 
  {
    pos++;
    ReadRules(fp, ruleSet, pos);
  }
}

int port_list(unsigned short key0, unsigned short key1,
              unsigned short dPt_list[][2], int *i, int length) {
  int ret = 0;
  unsigned short tmp_mask;

  tmp_mask = (unsigned short)(length > 0 ? (0xffff << (16 - length)) : 0);
  
  if ((key0 & tmp_mask) == key0 
      && (unsigned short)(key1 | ~(tmp_mask)) == key1) {
    if ((key0 & tmp_mask) != (key1 & tmp_mask)) {
      length --;
      tmp_mask = (unsigned short)(length > 0 ? (0xffff << (16 - length)) : 0);
    }
    
    dPt_list[*i][0] = key0;
    dPt_list[*i][1] = tmp_mask;
    *i = *i + 1;
    return 0;
  }

  if ((key0 & tmp_mask) == (key1 & tmp_mask)){
    port_list(key0, key1, dPt_list, i, length + 1);    
  } else {
    port_list(key0, (unsigned short)(key0 | ~(tmp_mask)),
              dPt_list, i, length + 1);
    port_list((unsigned short)(key1 & (tmp_mask)), key1,
              dPt_list, i, length + 1);
  }
  return ret;
}

int print_rules(char* filename) {
  FILE *fp;
  struct RULESET ruleSet;
  unsigned int i;

  fp = fopen(filename,"r");
  if(fp == NULL) {
    printf("ERROR:Couldnt open rule set file \n");
    exit(0);
  }
  LoadRules(fp, &ruleSet);
  fclose(fp);

  for(i = 0; i < ruleSet.numRules; i++) {
    int sPt_num=0, dPt_num=0;
    unsigned short sPt_list[32][2];
    unsigned short dPt_list[32][2];
    int j, k;

    port_list(ruleSet.ruleList[i].sPt[0],
	      ruleSet.ruleList[i].sPt[1], sPt_list, &sPt_num, 0);
    port_list(ruleSet.ruleList[i].dPt[0],
	      ruleSet.ruleList[i].dPt[1], dPt_list, &dPt_num, 0);

    for (j = 0; j < sPt_num; j++) {
      for (k = 0; k < dPt_num; k++) {
	printf("%d, %08x,%08x, %08x,%08x, %04x,%04x, %04x,%04x, %02x,%02x\n",
	       MAXRULES - i,
	       ruleSet.ruleList[i].sIP[0], ruleSet.ruleList[i].sIP[1],
	       ruleSet.ruleList[i].dIP[0], ruleSet.ruleList[i].dIP[1],
	       sPt_list[j][0], sPt_list[j][1],
	       dPt_list[k][0], dPt_list[k][1],
	       ruleSet.ruleList[i].protocol[0], ruleSet.ruleList[i].protocol[1]);
      }
    }
  }

  return 0;
}

