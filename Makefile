
NAME=librtcdcpp
CC=$(CROSS)gcc
CXX=$(CROSS)g++
AR=$(CROSS)ar
RM=rm -f
CPPFLAGS=-pthread -std=c++14 -fPIC -Wall -Wno-reorder -Wno-sign-compare -Og -g
LDFLAGS=-pthread -shared
LDLIBS=$(shell pkg-config --libs glib-2.0 gobject-2.0 nice) -lgnutls
INCLUDES=$(shell pkg-config --cflags glib-2.0 gobject-2.0 nice) -Iinclude -Iusrsctp/usrsctplib -DINET -DINET6 -Ispdlog/include
CLIENTDIR=examples/websocket_client

USE_GNUTLS ?= 0
ifeq ($(USE_GNUTLS), 1)
	CPPFLAGS+= -DUSE_GNUTLS
	LDLIBS+= -lgnutls
else
	LDLIBS+= -lssl -lcrypto
endif

USE_SPDLOG ?= 1
ifeq ($(USE_SPDLOG), 1)
	CPPFLAGS+= -DSPDLOG_DEBUG_ON
else
	CPPFLAGS+= -DSPDLOG_DISABLED
endif

SRCS=$(shell printf "%s " src/*.cpp)
OBJS=$(subst .cpp,.o,$(SRCS)) 

all: $(NAME).a $(NAME).so $(CLIENTDIR)/testclient

%.o: %.cpp
	$(CXX) $(INCLUDES) $(CPPFLAGS) -I. -MMD -MP -o $@ -c $<

-include $(subst .o,.d,$(OBJS))

$(NAME).a: $(OBJS)
	$(AR) crf $@ $(OBJS)

$(NAME).so: libusrsctp.a $(OBJS)
	$(CXX) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS) libusrsctp.a

$(CLIENTDIR)/testclient: $(NAME).a
	cd $(CLIENTDIR) && $(MAKE)

clean:
	$(RM) src/*.o src/*.d
	cd $(CLIENTDIR) && make clean

dist-clean: clean
	$(RM) $(NAME).a
	$(RM) $(NAME).so
	$(RM) libusrsctp.a
	$(RM) src/*~
	cd $(CLIENTDIR) && make dist-clean

libusrsctp.a: 
	cd usrsctp && ./bootstrap && CPPFLAGS=-fPIC ./configure --enable-static && make
	cp usrsctp/usrsctplib/.libs/libusrsctp.a .
