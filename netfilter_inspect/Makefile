TARGETS = kretprobe_ipt_do_table

all: $(TARGETS)
.PHONY: all

$(TARGETS): %: %.bpf.o %
	#sudo bpftool prog load test.bpf.o /sys/fs/bpf/test
	gcc -I/usr/src/linux/tools/lib -L/usr/src/linux/tools/lib/bpf -lbpf -o ${TARGETS} ${TARGETS}.c

%.bpf.o: %.bpf.c /sys/kernel/btf/vmlinux
	sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
	clang \
	    -target bpf \
		-I/usr/src/linux/tools/lib \
		-g \
	    -O2 -o $@ -c $<

clean: 
	- rm *.bpf.o ${TARGETS}
	- rm vmlinux.h
	#- sudo rm -f /sys/fs/bpf/test
