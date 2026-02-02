CXX ?= g++
CXX ?= g++-12
CXXFLAGS ?= -std=c++20
LDLIBS ?= -ldl -lsodium

BIN := CyberShield
SO := CyberShield.so
SRC := cyber_shield.cpp

build: $(BIN) $(SO)

$(BIN): $(SRC)
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDLIBS)

$(SO): $(SRC)
	$(CXX) $(CXXFLAGS) -fPIC -shared -o $@ $< $(LDLIBS)

debug: CXXFLAGS += -g
debug: build

sanity: CXXFLAGS += -Wall -Wextra -Wpedantic
sanity: build

clean:
	rm -f $(BIN) $(SO)

.PHONY: build clean debug sanity
