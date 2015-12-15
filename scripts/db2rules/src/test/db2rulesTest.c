#include "unity_fixture.h"
#include "db2rule.h"

TEST_GROUP(db2rules);

TEST_SETUP(db2rules) {
}

TEST_TEAR_DOWN(db2rules) {
}

TEST(db2rules, LoadRules) {
  FILE *fp;
  struct RULESET ruleSet;

  fp = fopen("./src/test/testset/1.txt", "r");
  TEST_ASSERT_FALSE(fp == NULL);
  
  LoadRules(fp, &ruleSet);
  
  TEST_ASSERT_EQUAL(2, ruleSet.numRules);

  TEST_ASSERT_EQUAL(1, ruleSet.ruleList[0].pos);
  TEST_ASSERT_EQUAL(0xAAAA5555, ruleSet.ruleList[0].sIP[0]);
  TEST_ASSERT_EQUAL(0xFFFFFFFF, ruleSet.ruleList[0].sIP[1]);
  TEST_ASSERT_EQUAL(0x5555AA00, ruleSet.ruleList[0].dIP[0]);
  TEST_ASSERT_EQUAL(0xFFFFFF00, ruleSet.ruleList[0].dIP[1]);
  TEST_ASSERT_EQUAL(0, ruleSet.ruleList[0].sPt[0]);
  TEST_ASSERT_EQUAL(65535, ruleSet.ruleList[0].sPt[1]);
  TEST_ASSERT_EQUAL(62600, ruleSet.ruleList[0].dPt[0]);
  TEST_ASSERT_EQUAL(62609, ruleSet.ruleList[0].dPt[1]);
  TEST_ASSERT_EQUAL(0x06, ruleSet.ruleList[0].protocol[0]);
  TEST_ASSERT_EQUAL(0xFF, ruleSet.ruleList[0].protocol[1]);

  TEST_ASSERT_EQUAL(2, ruleSet.ruleList[1].pos);
  TEST_ASSERT_EQUAL(0, ruleSet.ruleList[1].sIP[0]);
  TEST_ASSERT_EQUAL(0, ruleSet.ruleList[1].sIP[1]);
  TEST_ASSERT_EQUAL(0x5555AA00, ruleSet.ruleList[1].dIP[0]);
  TEST_ASSERT_EQUAL(0xFFFFFF00, ruleSet.ruleList[1].dIP[1]);
  TEST_ASSERT_EQUAL(0, ruleSet.ruleList[1].sPt[0]);
  TEST_ASSERT_EQUAL(65535, ruleSet.ruleList[1].sPt[1]);
  TEST_ASSERT_EQUAL(62600, ruleSet.ruleList[1].dPt[0]);
  TEST_ASSERT_EQUAL(62609, ruleSet.ruleList[1].dPt[1]);
  TEST_ASSERT_EQUAL(0x00, ruleSet.ruleList[1].protocol[0]);
  TEST_ASSERT_EQUAL(0x00, ruleSet.ruleList[1].protocol[1]);
  
  fclose(fp);
}

TEST(db2rules, PtRuleSet) {
  unsigned short Pt_list[32][2];
  int rule_num;
  int i;
  
  rule_num = 0;
  port_list(0, 65535, Pt_list, &rule_num, 0);
  TEST_ASSERT_EQUAL(1, rule_num);
  TEST_ASSERT_EQUAL(0, Pt_list[0][0]);
  TEST_ASSERT_EQUAL(0, Pt_list[0][1]);

  rule_num = 0;
  port_list(1000, 1000, Pt_list, &rule_num, 0);
  TEST_ASSERT_EQUAL(1, rule_num);
  TEST_ASSERT_EQUAL(1000, Pt_list[0][0]);
  TEST_ASSERT_EQUAL(0xFFFF, Pt_list[0][1]);

  rule_num = 0;
  port_list(8, 15, Pt_list, &rule_num, 0);
  TEST_ASSERT_EQUAL(1, rule_num);
  TEST_ASSERT_EQUAL(8, Pt_list[0][0]);
  TEST_ASSERT_EQUAL(0xFFF8, Pt_list[0][1]);

  rule_num = 0;
  port_list(1024, 65535, Pt_list, &rule_num, 0);
  TEST_ASSERT_EQUAL(6, rule_num);
  for (i = 0; i < rule_num; i++) {
    unsigned short keys[6] = {0x0400, 0x0800, 0x1000, 0x2000, 0x4000, 0x8000};
    unsigned short masks[6] = {0xfc00, 0xf800, 0xf000, 0xe000, 0xc000, 0x8000};
    int j;
    int flag = 0;
    for (j = 0; j < rule_num; j++) {
      if(Pt_list[i][0] == keys[j] && Pt_list[i][1] == masks[j]) {
	flag = 1; break;
      }
    }
    TEST_ASSERT_TRUE(flag);
  }
}

TEST(db2rules, PrintRules) {

  print_rules("./src/test/testset/2.txt");

}

TEST_GROUP_RUNNER(db2rules) {
  RUN_TEST_CASE(db2rules, LoadRules);
  RUN_TEST_CASE(db2rules, PtRuleSet);
  RUN_TEST_CASE(db2rules, PrintRules);
}
