all: benchmark validate

LD_LIBRARY_PATH = /usr/local/lib
export LD_LIBRARY_PATH

benchmark: benchmark.c
	$(CC) -g -O0 benchmark.c -o benchmark -lckv
validate: validate.c
	$(CC) -g -O0 validate.c -o validate -lckv
clean:
	rm -f benchmark validate
