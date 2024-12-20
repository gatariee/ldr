BIN     = .
OUT     = main.exe
CC      = g++

CPP     = -std=c++20
CFLAGS  = -O2
CFLAGS  += $(CPP)


SRC     = $(wildcard *.cc)

all: build

build:
	$(CC) -o $(BIN)/$(OUT) $(SRC) $(CFLAGS) -s
	./$(BIN)/$(OUT)

debug:
	$(CC) -o $(BIN)/$(OUT) $(SRC) $(CFLAGS) -g


clean:
	rm -rf $(BIN)/main.exe