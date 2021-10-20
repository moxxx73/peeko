include_path = include/
exec_path = ~/bin
object_files = memory.o low_net.o stack.o scan.o utils.o cafebabe.o main.o net_filter.o packets.o results.o
c_flags = -Wall -Wextra -Wpedantic -Wformat=2 -Wno-unused-parameter -Wshadow \
          -Wwrite-strings -Wstrict-prototypes -Wold-style-definition -Wredundant-decls \
		  -Wnested-externs -Wmissing-include-dirs -lpthread
exe = cafebabe


$(exe): $(object_files)
	gcc $(object_files) $(c_flags) -o ./$(exe)
	mv ./$(exe) $(exec_path)/$(exe)

memory.o: $(include_path)memory.c $(include_path)memory.h
	gcc -c $(include_path)memory.c

net_filter.o: $(include_path)net_filter.c $(include_path)net_filter.h
	gcc -c $(include_path)net_filter.c

stack.o: $(include_path)stack.c $(include_path)stack.h
	gcc -c $(include_path)stack.c

low_net.o: $(include_path)low_net.c $(include_path)low_net.h
	gcc -c $(include_path)low_net.c

scan.o: $(include_path)scan.c $(include_path)scan.h
	gcc -c $(include_path)scan.c

cafebabe.o: $(include_path)cafebabe.c $(include_path)cafebabe.h
	gcc -c $(include_path)cafebabe.c

results.o: $(include_path)results.c $(include_path)results.h
	gcc -c $(include_path)results.c

packets.o: $(include_path)packets.c $(include_path)packets.h
	gcc -c $(include_path)packets.c

utils.o: $(include_path)utils.c $(include_path)utils.h
	gcc -c $(include_path)utils.c

main.o: main.c
	gcc -c main.c

clean:
	rm $(object_files)
