
CC=$(CROSS)gcc
CXX=$(CROSS)g++
AR=$(CROSS)ar
RM=rm -f
INCLUDES=-I../../include -I../../spdlog/include
CPPFLAGS=-pthread -std=c++14 -Wall -Wno-reorder -Wno-sign-compare -O2
LDFLAGS=-pthread
LDLIBS=-lssl -lcrypto ../../librtcdcpp.a
LDLIBS+=$(shell pkg-config --libs glib-2.0 gobject-2.0 nice) ../../usrsctp/usrsctplib/.libs/libusrsctp.a

SRCS=WebSocketWrapper.cpp easywsclient.cpp jsoncpp.cpp
OBJS=$(subst .cpp,.o,$(SRCS)) 

all: testclient testclient_offer testclient_answer

%.o: %.cpp
	$(CXX) $(INCLUDES) $(CPPFLAGS) -I. -MMD -MP -o $@ -c $<

-include $(subst .o,.d,$(OBJS))

testclient: $(OBJS) testclient.o
	$(CXX) $(LDFLAGS) -o $@ $(OBJS) $@.o $(LDLIBS)

testclient_offer: $(OBJS) testclient_offer.o
	$(CXX) $(LDFLAGS) -o $@ $(OBJS) $@.o $(LDLIBS)

testclient_answer: $(OBJS) testclient_answer.o
	$(CXX) $(LDFLAGS) -o $@ $(OBJS) $@.o $(LDLIBS)

clean:
	$(RM) *.o *.d

dist-clean: clean
	$(RM) $(NAME)
	$(RM) *~
