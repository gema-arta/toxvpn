VERSION ?= 0.0.0
LINK_STATICALLY ?= false

REVISION = $(shell git rev-parse HEAD)
PREFIX ?= /usr/local/
COMMON_FLAGS := -Wall -g -Werror=incompatible-pointer-types -Werror=return-type -DVERSION="\"$(VERSION)\"" -DREVISION="\"$(REVISION)\""
CXXFLAGS += -std=c++14 $(COMMON_FLAGS)
CFLAGS += -std=c99 -I/usr/include/libnl3 $(COMMON_FLAGS)
LDFLAGS += -pthread -static-libgcc -static-libstdc++

ifeq ($(LINK_STATICALLY),true)
	LDFLAGS += -Wl,-Bstatic -lrt
endif
LDFLAGS += -ltoxcore -lsodium -lnl-3 -lnl-route-3 -lcap -ljansson

OUTDIR := ./out
OUTFILE := toxvpn

OBJS := $(patsubst %.c,%.o, $(wildcard *.c))
OBJS += $(patsubst %.cpp,%.o, $(wildcard *.cpp))

all: $(OUTFILE)

$(OUTFILE): $(OBJS)
	mkdir -p $(OUTDIR)
	$(CXX) $(OBJS) $(LDFLAGS) -o $@
	readelf -d $@ | grep "Shared library"
	objdump -T $@ | grep  GLIBC_2 | awk '{print $4}' | sort -u

%.o: %.c
		$(CC) $(CFLAGS) -c -o $@ $<

%.o: %.cpp
		$(CXX) $(CXXFLAGS) -c -o $@ $<

memcheck: $(OUTFILE)
	valgrind --leak-check=full --tool=memcheck ./$<

clean:
		rm -f $(OBJS) $(OUTFILE)

toxcore:
	git clone https://github.com/irungentoo/toxcore.git
	cd toxcore && autoreconf -i && ./configure
	make -C toxcore
	make -C toxcore install

install:
	install -m 0755 $(OUTFILE)  $(PREFIX)/bin/$(OUTFILE)
	mkdir -p $(PREFIX)/lib/systemd/system/
	setcap cap_net_admin+ep $(PREFIX)/bin/$(OUTFILE)

	install system/linux/toxvpn.service /lib/systemd/system/toxvpn.service
	systemctl daemon-reload

	useradd -M toxpvn || :
	mkdir -p /var/run/toxvpn
	chown toxvpn /var/run/toxvpn
