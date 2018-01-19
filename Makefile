
NAME=librtcdcpp
CC=$(CROSS)gcc
CXX=$(CROSS)g++
AR=$(CROSS)ar
RM=rm -f
USRSCTPLIB=usrsctp/usrsctplib/.libs/libusrsctp.a
CLIENTDIR=examples/websocket_client
INCLUDES=$(shell pkg-config --cflags glib-2.0 gobject-2.0 nice) -Iinclude -Iusrsctp/usrsctplib -DINET -DINET6 -Ispdlog/include
CPPFLAGS=-pthread -std=c++14 -fPIC -Wall -Wno-reorder -Wno-sign-compare -O2 -DSPDLOG_TRACE_ON
LDFLAGS=-pthread -shared
LDLIBS=$(shell pkg-config --libs glib-2.0 gobject-2.0 nice) $(USRSCTPLIB)

SRCS=$(shell printf "%s " src/*.cpp)
OBJS=$(subst .cpp,.o,$(SRCS)) 

all: $(NAME).a $(NAME).so $(CLIENTDIR)/testclient

%.o: %.cpp
	$(CXX) $(INCLUDES) $(CPPFLAGS) -I. -MMD -MP -o $@ -c $<

-include $(subst .o,.d,$(OBJS))

$(NAME).a: $(USRSCTPLIB) $(OBJS)
	$(AR) crf $@ $(USRSCTPLIB) $(OBJS)

$(NAME).so: $(USRSCTPLIB) $(OBJS)
	$(CXX) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)

$(CLIENTDIR)/testclient: $(NAME).a
	cd $(CLIENTDIR) && $(MAKE)

clean:
	$(RM) src/*.o src/*.d
	cd $(CLIENTDIR) && make clean

dist-clean: clean
	$(RM) $(NAME).a
	$(RM) $(NAME).so
	$(RM) src/*~
	cd $(CLIENTDIR) && make dist-clean

$(USRSCTPLIB): 
	cd usrsctp && ./bootstrap && CPPFLAGS=-fPIC ./configure --enable-static && make

