
NAME=librtcdcpp
CC=$(CROSS)gcc
CXX=$(CROSS)g++
AR=$(CROSS)ar
RM=rm -f
INCLUDES=$(shell pkg-config --cflags glib-2.0) -Iinclude -Iusrsctp/usrsctplib -Ispdlog/include
CPPFLAGS=$(INCLUDES) -std=c++14 -fPIC -Wall -Wno-reorder -Wno-sign-compare -O2
LDFLAGS=-shared
LDLIBS=$(shell pkg-config --cflags glib-2.0) -lpthread -lnice -Llibusrsctp.a

SRCS=$(shell printf "%s " src/*.cpp)
OBJS=$(subst .cpp,.o,$(SRCS)) 

all: $(NAME).a $(NAME).so

%.o: %.cpp
	$(CXX) $(CPPFLAGS) -I. -MMD -MP -o $@ -c $<

-include $(subst .o,.d,$(OBJS))

$(NAME).a: libusrsctp.a $(OBJS)
	$(AR) crf $(NAME).a libusrsctp.a $(OBJS)

$(NAME).so: libusrsctp.a $(OBJS)
	$(CXX) $(LDFLAGS) -o $(NAME).so $(OBJS) $(LDLIBS)

clean:
	$(RM) src/*.o src/*.d

dist-clean: clean
	$(RM) libusrsctp.a
	$(RM) $(NAME).a
	$(RM) $(NAME).so
	$(RM) src/*~

libusrsctp.a:
	cd usrsctp && ./bootstrap && ./configure --enable-static && make
	cp usrsctp/usrsctplib/.libs/libusrsctp.a .

