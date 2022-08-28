CC = gcc
CFLAGS = -Wall
LDFLAGS = -pie

OBJS = linux_net.o main.o memory.o net.o net_filter.o packets.o peeko.o results.o scan.o stack.o utils.o
SRCPATH = src/

peeko: $(OBJS)
	gcc $(LDFLAGS) $(OBJS) -o peeko

$(OBJS): %.o: $(SRCPATH)%.c
	gcc -c $<

clean:
	rm *.o