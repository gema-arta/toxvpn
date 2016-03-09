OBJS := $(patsubst %.c,%.o, $(wildcard *.c))
OBJS += $(patsubst %.cpp,%.o, $(wildcard *.cpp))

CXXFLAGS += -std=c++14
CFLAGS += -std=c99 -I/usr/include/libnl3
LDFLAGS += -Bstatic -ltoxcore -lsodium -lnl-3 -lnl-route-3 -lcap -ljansson

OUTFILE := toxvpn

all: $(OUTFILE)

$(OUTFILE): $(OBJS)
	$(CC) $(OBJS) $(LDFLAGS) -o $@

%.o: %.c
		$(CC) $(CFLAGS) -c -o $@ $<

%.o: %.cpp
		$(CXX) $(CXXFLAGS) -c -o $@ $<

clean:
		rm -f $(OBJS) $(OUTFILE)
