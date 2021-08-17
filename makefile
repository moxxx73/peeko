include_path = include/
exec_path = ~/bin/
object_files = memory.o raw_engine.o queue.o raw_net.o scan_engine.o cafebabe.o main.o bpf.o
c_flags = -Wall -Wextra -Wpedantic -Wformat=2 -Wno-unused-parameter -Wshadow \
          -Wwrite-strings -Wstrict-prototypes -Wold-style-definition -Wredundant-decls \
		  -Wnested-externs -Wmissing-include-dirs
exe = cafebabe


$(exe): $(object_files)
	gcc $(object_files) $(c_flags) -o ./$(exe)
	mv ./$(exe) $(exec_path)/$(exe)

bpf.o: $(include_path)bpf.c $(include_path)bpf.h
	gcc -c $(include_path)bpf.c

memory.o: $(include_path)memory.c $(include_path)memory.h
	gcc -c $(include_path)memory.c

raw_engine.o: $(include_path)raw_engine.c $(include_path)raw_engine.h
	gcc -c $(include_path)raw_engine.c

queue.o: $(include_path)queue.c $(include_path)queue.h
	gcc -c $(include_path)queue.c

raw_net.o: $(include_path)raw_net.c $(include_path)raw_net.h
	gcc -c $(include_path)raw_net.c

scan_engine.o: $(include_path)scan_engine.c $(include_path)scan_engine.h
	gcc -c $(include_path)scan_engine.c

cafebabe.o: $(include_path)cafebabe.c $(include_path)cafebabe.h
	gcc -c $(include_path)cafebabe.c

main.o: main.c
	gcc -c main.c

clean:
	rm $(object_files)
