all: pcap-test

pcap-test: main.o pcap_test.o
	g++ -o pcap-test main.o pcap_test.o -lpcap
	rm *.o
pcap_test.o: pcap_test.cpp pcap_test.h
	g++ -c -o pcap_test.o pcap_test.cpp

main.o: main.cpp
	g++ -c -o main.o main.cpp

clean:
	rm -f pcap-test
