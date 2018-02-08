
CC=$(CROSS)gcc
CXX=$(CROSS)g++
AR=$(CROSS)ar
RM=rm -f
CPPFLAGS=-pthread -std=c++14 -Wall -Wno-reorder -Wno-sign-compare -Og -g -DSPDLOG_TRACE_ON
LDFLAGS=-pthread
LDLIBS=$(shell pkg-config --libs glib-2.0 gobject-2.0 nice)
INCLUDES=-I../../include -I../../spdlog/include
ALIBS=../../librtcdcpp.a ../../libusrsctp.a

USE_GNUTLS ?= 0
ifeq ($(USE_GNUTLS), 1)
	CPPFLAGS+= -DUSE_GNUTLS
	LDLIBS+= -lgnutls
else
	LDLIBS+= -lssl -lcrypto
endif

SRCS=WebSocketWrapper.cpp easywsclient.cpp jsoncpp.cpp
OBJS=$(subst .cpp,.o,$(SRCS)) 

all: testclient testclient_offer testclient_answer

%.o: %.cpp
	$(CXX) $(INCLUDES) $(CPPFLAGS) -I. -MMD -MP -o $@ -c $<

-include $(subst .o,.d,$(OBJS))

testclient: $(OBJS) testclient.o ../../librtcdcpp.a
	$(CXX) $(LDFLAGS) -o $@ $(OBJS) $@.o $(LDLIBS) $(ALIBS)

testclient_offer: $(OBJS) testclient_offer.o ../../librtcdcpp.a
	$(CXX) $(LDFLAGS) -o $@ $(OBJS) $@.o $(LDLIBS) $(ALIBS)

testclient_answer: $(OBJS) testclient_answer.o ../../librtcdcpp.a
	$(CXX) $(LDFLAGS) -o $@ $(OBJS) $@.o $(LDLIBS) $(ALIBS)

clean:
	$(RM) *.o *.d

dist-clean: clean
	$(RM) $(NAME)
	$(RM) *~

