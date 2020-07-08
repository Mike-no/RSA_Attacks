CC 			  = gcc
AR            = ar
CFLAGS 		  += -std=c99 -Wall -pedantic -g
ARFLAGS       = rvs
INCLUDES      = -I./include
LDFLAGS       = -L./lib/
OPTFLAGS	  = -O3
LIBS 		  = -lrsa

TARGETS 	  = test

INCLUDE_FILES = ./include/routines_rsa.h	\
				./include/attacks_rsa.h

.PHONY: all clean

.SUFFIXES: .c .h

vpath %.c ./src

%: ./src/%.c
	$(CC) $(CFLAGS) $(INCLUDES) $(OPTFLAGS) -o $@ $< $(LDFLAGS) $(LIBS)

./obj/%.o: ./src/%.c
	$(CC) $(CFLAGS) $(INCLUDES) $(OPTFLAGS) -c -o $@ $<

all : $(TARGETS)

test: ./obj/test.o ./lib/librsa.a ./lib/libattacks.a
	$(CC) $(CFLAGS) $(INCLUDES) $(OPTFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

./lib/librsa.a: ./obj/rsa.o $(INCLUDE_FILES)
	$(AR) $(ARFLAGS) $@ $<

./obj/rsa.o: ./src/rsa.c $(INCLUDE_FILES)

./lib/libattacks.a: ./obj/attacks.o $(INCLUDE_FILES)
	$(AR) $(ARFLAGS) $@ $<

./obj/attacks.o: ./src/attacks.c $(INCLUDE_FILES)

./obj/test.o: ./src/test.c $(INCLUDE_FILES)

clean:
	\rm -f $(TARGETS)
	\rm -f *.o *~ *.a
	\rm -f ./lib/*.o ./lib/*~ ./lib/*.a
	\rm -f ./src/*.o ./src/*~ ./src/*.a
	\rm -f ./obj/*.o