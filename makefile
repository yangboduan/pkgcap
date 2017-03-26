CPP      = g++
CC       = gcc
CFLAGS   = -g -Wall
OBJ      = main.o
LINKOBJ  = main.o
BIN      = pkgsniff
RM       = rm -rf
LIB	 = -lpcap
$(BIN): $(OBJ)
	$(CPP) $(LINKOBJ) -o $(BIN)   $(LIB) $(CFLAGS) 

	
clean: 
	${RM} $(OBJ) $(BIN)

cleanobj:
	${RM} *.o
