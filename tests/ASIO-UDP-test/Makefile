programs += udp_daytime_server
programs += async_udp_daytime_server
programs += udp_echo_server
programs += dtls_echo_server

CC = gcc
CXX = g++
CFLAGS = -g -O0 -pthread
CXXFLAGS = $(CFLAGS) -std=c++11
CPPFLAGS = -DNDEBUG
LIBS = -lpthread -lgcc_s
OPENSSL_CFLAGS = -I/opt/openssl/include
OPENSSL_LIBS = /opt/openssl/lib/libssl.a /opt/openssl/lib/libcrypto.a -ldl

RM = rm -rf

.PHONY: all
all: $(programs)
dtls_%_server.o: CFLAGS += $(OPENSSL_CFLAGS)
dtls_%_server: LIBS := $(OPENSSL_LIBS) $(LIBS)
dtls_%_server: dtls_%_server.o
	$(LINK.o) -o $@ $< $(LIBS) -lstdc++
%: %.cpp
	$(LINK.cpp) -o $@ $< $(LIBS)
%: %.o
	$(LINK.o) -o $@ $< $(LIBS) -lstdc++
%.o: %.cpp
	$(COMPILE.cpp) $< -o $@
.PHONY: clean
clean:
	$(RM) $(programs) *.o
