CXX = g++
TARGET = user
SRC = ./src/henc.cpp ./src/paillier.cpp ./src/tools.cpp ./src/user.cpp
#OBJ = henc.o paillier.o test.o tools.o
OBJ = *.o

$(TARGET):$(OBJ)
	$(CXX) -o $@ $^ -lntl -pthread -lboost_program_options -lgmp

$(OBJ):$(SRC)
	$(CXX) -c $^ -I ./include

.PHONY:clean

clean:
	rm -f *.o