from gcc

RUN apt-get update -y && \
    apt-get upgrade && \
    apt-get install -y gdb 

COPY ./ /app/

WORKDIR /app

RUN rm -f *.o c-min gunicorn

RUN g++ -O3 -g -c utils.cpp -o utils.o
RUN g++ -O3 -g -c main.cpp -o main.o
RUN g++ -O3 -g -c SimpleJsonRpcClient.cpp -o SimpleJsonRpcClient.o
RUN g++ -O3 -g -c stratum.cpp -o stratum.o
RUN g++ -O3 -g -c mining.cpp -o mining.o
RUN g++ -O3 -g -c sha/nerdSHA256plus.cpp -o nerdSHA256plus.o
RUN g++ -O3 -g -c sha/sha.cpp -o sha.o

RUN g++ -O3 -I./include/rapidjson -I./drivers/storage -I./sha -g utils.o SimpleJsonRpcClient.o stratum.o mining.o nerdSHA256plus.o sha.o main.o -o btc-cpu-miner -pthread

CMD ["./btc-cpu-miner"]
