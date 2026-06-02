# Makefile - klient SecVault (SVP) w C++17, OpenSSL 3.x.
CXX      := g++
CXXFLAGS := -std=c++17 -Wall -Wextra -O2 -Isrc
LDLIBS   := -lssl -lcrypto

SRC := $(wildcard src/*.cpp)
OBJ := $(SRC:.cpp=.o)
BIN := secvault

.PHONY: all clean test

all: $(BIN)

$(BIN): $(OBJ)
	$(CXX) $(CXXFLAGS) -o $@ $(OBJ) $(LDLIBS)

src/%.o: src/%.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Self-test modułu kryptograficznego (nie wymaga serwera).
test: $(BIN)
	./$(BIN) --selftest

clean:
	rm -f $(OBJ) $(BIN)
