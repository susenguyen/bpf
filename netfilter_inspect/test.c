#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>		/* pause() and read() 	*/
#include <string.h>		/* memdet()		*/
#include <fcntl.h>		/* open() 		*/
#include <errno.h>
#include <bpf/libbpf.h>

#define PROGRAM_NAME "ipt_do_table_exit"
#define TRACE_PIPE "/sys/kernel/tracing/trace_pipe"
#define READ_BUFFER_SIZE 256

int view_trace_pipe(const char *trace_pipe)
{
	int fd, num;
	char buf[READ_BUFFER_SIZE];

	fd = open(TRACE_PIPE, O_RDONLY);
	if (fd < 0) {
		perror("ERROR: open()");
		goto exit_failure;
	}

	memset(buf, 0, READ_BUFFER_SIZE);
	for(;;) {
		num = read(fd, buf, READ_BUFFER_SIZE);
		if (num < 0) {
			perror("ERROR: read()");
			goto exit_failure;
		}

		/* Always forget to zero out the last character not read... */
		buf[num] = '\0';

		fprintf(stdout, "%s", buf);
	}

exit:
	close(fd);
	return 0;

exit_failure:
	close(fd);
	return -1;
}

int main(int argc, char *argv[])
{
	char filename[64];
	struct bpf_object *obj;
	struct bpf_program *prog;
	struct bpf_link *link = NULL;
	uid_t euid;

	euid = geteuid();
	if (euid != 0) {
		fprintf(stderr, "ERROR: %s needs to be run as root\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	snprintf(filename, sizeof(filename), "%s.bpf.o", argv[0]);
	fprintf(stdout, "Loading %s\n", filename);

	obj = bpf_object__open_file(filename, NULL);
	if (libbpf_get_error(obj)) {
		fprintf(stderr, "ERROR: bpf_object__open_file()\n");
		exit(EXIT_FAILURE);
	}

	prog = bpf_object__find_program_by_name(obj, PROGRAM_NAME);
	if (!prog) {
		fprintf(stderr, "ERROR: bpf_object__find_program_by_name()\n");
		goto exit_failure;
	}

	if (bpf_object__load(obj)) {
		fprintf(stderr, "ERROR: bpf_object__load()\n");
		goto exit_failure;
	}

	link = bpf_program__attach(prog);
	if (libbpf_get_error(link)) {
		fprintf(stderr, "ERROR: bpf_program__attach()\n");
		link = NULL;
		goto exit_failure;
	}

	fprintf(stdout, "Tailing trace_pipe\n");
	view_trace_pipe(TRACE_PIPE);

exit_failure:
	bpf_link__destroy(link);
	bpf_object__close(obj);
	exit(EXIT_FAILURE);
}
