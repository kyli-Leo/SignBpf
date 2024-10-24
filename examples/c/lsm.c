// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2024 David Di */
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <bpf/libbpf.h>
#include "lsm.skel.h"

/* Notice: Ensure your kernel version is 5.7 or higher, BTF (BPF Type Format) is enabled, 
 * and the file '/sys/kernel/security/lsm' includes 'bpf'.
 */
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

/* Method to compute the checksum from the file and output it to sha256_output
 * Return 0 if no error, else return 1
 * 
 * */
int compute_sha256(const char *executable_path, char * sha256_output) {
	char command [512]
	snprintf(command, sizeof(command), "sha256sum %s", executable_path);
	FILE* file = popen(command, "r");
	if (!file) {
		perror("sha256 popen");
		return 1;
	}	
	if (fgets(output, 65, pipe) == NULL) {
		perror("sha256 pipe out")
		return 1;
	}
	pclose(file);
	return 0;
}

int main(int argc, char **argv)
{
	/* load the command line argument for the command line 
	 * argv[1] the path to the executable 
	 * argv[2] the path to the signature (Note: We only use existing key in the keyring)
  	 * argv[3] the path to the checksum file
	 * argv[4] the path that the executable should be retricted
	 * if not signed properly
	 * */


	if (argc == 5) {
		struct stat stats;
		if (stat(argv[1], &stats) != 0) {
        		perror("stat");
     		   	return 1;
    		}
		if (!S_ISREG(stats.st_mode) || access(argv[1], X_OK) != 0) {
			fprintf(stderr, "File does not exist or no permission to execute\n");
			return -1;
		}
		if (stat(argv[2], &stats) != 0) {
                        perror("stat");
                        return 1;
                }
		if (!S_ISREG(stats.st_mode) || access(argv[2], R_OK) != 0) {
			fprintf(stderr, "Signature does not exist or no permission to read\n");
			return -1;
		}
		if (stat(argv[3], &stats) != 0) {
                        perror("stat");
                        return 1;
                }

		if (!S_ISREG(stats.st_mode) || access(argv[3], R_OK) != 0) {
			fprintf(stderr, "Checksum does not exist or no permission to read\n");
			return -1;
		}
		if (stat(argv[4], &stats) != 0) {
                        perror("stat");
                        return 1;
                }

		if (!S_ISDIR(stats.st_mode)) {
			fprintf(stderr, "Restric directory does not exist\n");
			return -1;
		}



	} else if (argc == 2) {
		struct stat stats;
                stat(argv[1], &stats);

		if (!S_ISDIR(stats.st_mode)) {
			fprintf(stderr, "Restric directory does not exist\n");
			return -1;
		}

	} else {
		printf("Usage: lsm [path to execuatable] [path to signature] [path to checksum] [limit path]\n");
		printf("Usage: lsm [limit path]\n");
		return 0;
	}
	char checksum[65]
	if (compute_sha256(argv[1], checksum)) {
		perror("sha256");
		return -1;
	}
	printf(checksum);
	return 0;
	/* TODO: Add the part where we check if the signature 
         * fits with the executable
         *
         * */


	struct lsm_bpf *skel;
	int err;

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Open, load, and verify BPF application */
	skel = lsm_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		goto cleanup;
	}

	/* Attach lsm handler */
	err = lsm_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	       "to see output of the BPF programs.\n");

	for (;;) {
		/* trigger our BPF program */
		fprintf(stderr, ".");
		sleep(1);
	}

cleanup:
	lsm_bpf__destroy(skel);
	return -err;
}
