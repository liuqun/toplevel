programs += udp_daytime_server
programs += async_udp_daytime_server

CC = gcc-9
CXX = g++-9
CFLAGS = -g -O0 -pthread
CXXFLAGS = $(CFLAGS) -std=c++17
LIBS = -lpthread -lgcc_s

RM = rm -rf

.PHONY: all
all: $(programs)
%: %.cpp
	$(LINK.cpp) -o $@ $< $(LIBS)
%: %.o
	$(LINK.o) -o $@ $< $(LIBS) -lstdc++
%.o: %.cpp
	$(COMPILE.cpp) $< -o $@
.PHONY: clean
clean:
	$(RM) $(programs) *.o
