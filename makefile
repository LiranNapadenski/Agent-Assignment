CXX = g++
CXXFLAGS = -Wall -g -std=c++17

OBJS = file_scanner.o catch_amalgamated.o

all: find_sig tests

find_sig: find_sig.cpp file_scanner.o 
	$(CXX) $(CXXFLAGS) find_sig.cpp file_scanner.o -o find_sig

tests: tests.cpp $(OBJS)
	$(CXX) $(CXXFLAGS) tests.cpp $(OBJS) -o tests
	./tests

file_scanner.o: file_scanner.cpp
	$(CXX) $(CXXFLAGS) -c file_scanner.cpp -o file_scanner.o

catch_amalgamated.o: catch_amalgamated.cpp
	$(CXX) $(CXXFLAGS) -c catch_amalgamated.cpp -o catch_amalgamated.o

clean:
	rm -f $(OBJS) tests find_sig
