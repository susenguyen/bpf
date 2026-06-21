TARGETS = test

all: $(TARGETS)
.PHONY: all

$(TARGETS): %: %.bpf.o %
	#sudo bpftool prog load test.bpf.o /sys/fs/bpf/test
	gcc -I/usr/src/linux/tools/lib -L/usr/src/linux/tools/lib/bpf -lbpf -o test test.c

%.bpf.o: %.bpf.c
	clang \
	    -target bpf \
		-I/usr/src/linux/tools/lib \
		-g \
	    -O2 -o $@ -c $<

clean: 
	- rm *.bpf.o ${TARGETS}
	#- sudo rm -f /sys/fs/bpf/test
