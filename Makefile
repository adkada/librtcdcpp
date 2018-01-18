
NAME=librtcdcpp
CC=$(CROSS)gcc
CXX=$(CROSS)g++
AR=$(CROSS)ar
RM=rm -f
INCLUDES=$(shell pkg-config --cflags glib-2.0) -Iinclude
CPPFLAGS=$(INCLUDES) -std=c++14 -fPIC -Wall -Wno-reorder -Wno-sign-compare -O2
LDFLAGS=-shared
LDLIBS=$(shell pkg-config --cflags glib-2.0) -lpthread -lnice -lusrsctp

SRCS=$(shell printf "%s " src/*.cpp)
OBJS=$(subst .cpp,.o,$(SRCS))

all: $(NAME).a $(NAME).so

%.o: %.cpp
	$(CXX) $(CPPFLAGS) -I. -MMD -MP -o $@ -c $<

-include $(subst .o,.d,$(OBJS))

$(NAME).a: $(OBJS)
	$(AR) crf $(NAME).a $(OBJS)

$(NAME).so: $(OBJS)
	$(CXX) $(LDFLAGS) -o $(NAME).so $(OBJS) $(LDLIBS)

clean:
	$(RM) src/*.o src/*.d

dist-clean: clean
	$(RM) $(NAME).a
	$(RM) $(NAME).so
	$(RM) src/*~

