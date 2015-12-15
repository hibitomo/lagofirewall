#include <stdio.h>
#include "db2rule.h"

int main (int argc, char** argv) {
  if (argc < 2) {
    printf("Please, set db files.\n");
    return 1;
  }

  print_rules(argv[1]);

  return 0;
}
