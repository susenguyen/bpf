#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>		// pause()
#include <bpf/libbpf.h>

#define PROGRAM_NAME "test"

int main(int argc, char *argv[])
{
	char filename[64];
	struct bpf_object *obj;
	struct bpf_program *prog;
	struct bpf_link *link = NULL;

	snprintf(filename, sizeof(filename), "%s.bpf.o", argv[0]);
	fprintf(stdout, "Loading %s\n", filename);

	obj = bpf_object__open_file(filename, NULL);
	if (libbpf_get_error(obj)) {
		fprintf(stderr, "ERROR: bpf_object__open_file()\n");
		return EXIT_FAILURE;
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

	pause();


exit_failure:
	bpf_link__destroy(link);
	bpf_object__close(obj);
	return EXIT_FAILURE;
}
