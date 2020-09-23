all : pcap-test

pcap-test : pcap-test.o
	gcc -o pcap-test pcap-test.o -lpcap

pcap-test.o: pcap-test.cpp
	gcc -c -o pcap-test.o pcap-test.cpp

clean:
	rm -f pcap-test *.o
