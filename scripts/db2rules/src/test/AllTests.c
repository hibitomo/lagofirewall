#include "unity_fixture.h"

static void runAllTests()
{
  RUN_TEST_GROUP(db2rules);
}

int main(int argc, const char* argv[])
{
  return UnityMain(argc, argv, runAllTests);
}
