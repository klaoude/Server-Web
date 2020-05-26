all: 	
	gcc -I lib/ -L lib/ -o bin/server src/main.c -lparser -lrequest -ggdb