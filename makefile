CXX = g++
CXXFLAGS = -Wall -g -std=c++17

OBJS = file_scanner.o catch_amalgamated.o

test: tests.cpp $(OBJS)
	$(CXX) $(CXXFLAGS) tests.cpp $(OBJS) -o tests
	./tests

catch_amalgamated.o: catch_amalgamated.cpp
	$(CXX) $(CXXFLAGS) -c catch_amalgamated.cpp -o catch_amalgamated.o

clean:
	rm -f $(OBJS) tests
