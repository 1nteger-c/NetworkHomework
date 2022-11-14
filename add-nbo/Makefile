all: add-nbo

add-nbo: add.o main.o
	g++ -o add-nbo add.o main.o

add.o: add.cpp add.h
	g++ -c -o add.o add.cpp

main.o: main.cpp add.h
	g++ -c -o main.o main.cpp

clean:
	rm -f add-nbo *.o
