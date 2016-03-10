OBJS := $(patsubst %.c,%.o, $(wildcard *.c))
OBJS += $(patsubst %.cpp,%.o, $(wildcard *.cpp))

COMMON_FLAGS := -Wall -g -Werror=incompatible-pointer-types -Werror=return-type
CXXFLAGS += -std=c++14 $(COMMON_FLAGS)
CFLAGS += -std=c99 -I/usr/include/libnl3 $(COMMON_FLAGS)
LDFLAGS += -static-libgcc -static-libstdc++ -Bstatic -ltoxcore -lsodium -lnl-3 -lnl-route-3 -lcap -ljansson -Bdynamic

OUTFILE := toxvpn

all: $(OUTFILE)

$(OUTFILE): $(OBJS)
	$(CXX) $(OBJS) $(LDFLAGS) -o $@

%.o: %.c
		$(CC) $(CFLAGS) -c -o $@ $<

%.o: %.cpp
		$(CXX) $(CXXFLAGS) -c -o $@ $<

clean:
		rm -f $(OBJS) $(OUTFILE)
