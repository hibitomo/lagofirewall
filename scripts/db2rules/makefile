#---- Outputs ----#
TARGET_BASE = __test
TARGET_EXTENSION=
TARGET = $(TARGET_BASE)$(TARGET_EXTENSION)

MAIN_TARGET = db2rules

#--- Inputs ----#
PROJECT_HOME_DIR = ../..
UNITY_HOME = $(PROJECT_HOME_DIR)/tools/unity
UNITY_FIXTURE = $(UNITY_HOME)/extras/fixture
UNITY_BUILD_HOME=$(UNITY_HOME)/extras/fixture/build

C_COMPILER=gcc

# Unity File
TEST_SRC_FILES  =$(UNITY_HOME)/src/unity.c
# Unity Fixture File
TEST_SRC_FILES +=$(UNITY_FIXTURE)/src/unity_fixture.c

# Source Files
SRC_FILES = src/db2rule.c

# main Files
MAIN_SRC_FILES = src/main.c

SRC_DIR = src

# Test Files
TEST_SRC_FILES += src/test/db2rulesTest.c
TEST_SRC_FILES += src/test/AllTests.c

TEST_DIR = src/test

INC_DIRS  =-Isrc
INC_DIRS +=-Isrc/test
INC_DIRS +=-I$(UNITY_HOME)/src
INC_DIRS +=-I$(UNITY_FIXTURE)/src

OBJ = $(SRC_FILES:%.c=%.o)
TEST_OBJ = $(TEST_SRC_FILES:%.c=%.o)
MAIN_OBJ = $(MAIN_SRC_FILES:%.c=%.o)

#SYMBOLS=-DTEST -DUNITY_SUPPORT_64
SYMBOLS=-DUNITY_SUPPORT_64

#Options
C_FLAGS=-Wall
C_FLAGS+=-Wsign-conversion
C_FLAGS+=-Wconversion
C_FLAGS+=-Wimplicit-function-declaration
C_FLAGS+=-Wpointer-sign
C_FLAGS+=-W

CLEANUP = rm -f $(SRC_DIR)/*.o $(TEST_DIR)/*.o ; rm -f $(TARGET)

all: default

$(OBJ):
	$(C_COMPILER) $(C_FLAGS) $(INC_DIRS) -o $@ -c $(@:%.o=%.c) $<

$(MAIN_OBJ):
	$(C_COMPILER) $(C_FLAGS) $(INC_DIRS) -o $@ -c $(@:%.o=%.c) $<

$(TEST_OBJ):
	$(C_COMPILER) $(C_FLAGS) $(INC_DIRS) -o $@ -c $(@:%.o=%.c) $<

default: $(OBJ) $(MAIN_OBJ)
	$(C_COMPILER) $(C_FLAGS) $(INC_DIRS) $(SYMBOLS) $(MAIN_OBJ) $(OBJ) -o $(MAIN_TARGET)

check: $(OBJ) $(TEST_OBJ)
	$(C_COMPILER) $(C_FLAGS) $(INC_DIRS) $(SYMBOLS) $(OBJ) $(TEST_OBJ) -o $(TARGET)
	./$(TARGET)
	rm ./$(TARGET) -f

clean:
	$(CLEANUP)
