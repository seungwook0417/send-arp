LDLIBS=-lpcap

all: send-arp-test

send-arp-test: main.o arphdr.o ethhdr.o ip.o mac.o get_my_addr.cpp
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f send-arp-test *.o
