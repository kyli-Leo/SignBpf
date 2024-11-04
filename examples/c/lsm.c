// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2024 David Di */
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <bpf/libbpf.h>
#include "lsm.skel.h"

/* Notice: Ensure your kernel version is 5.7 or higher, BTF (BPF Type Format) is enabled, 
 * and the file '/sys/kernel/security/lsm' includes 'bpf'.
 */
//static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
//{
	//return vfprintf(stderr, format, args);
//}

/* Method to compute the checksum from the file and output it to sha256_output
 * Return 0 if no error, else return 1
 * 
 */
int compute_sha256(const char *executable_path, char *sha256_output) {
	char command [512];
	snprintf(command, sizeof(command), "sha256sum %s", executable_path);
	FILE* file = popen(command, "r");
	if (!file) {
		perror("sha256 popen");
		return 1;
	}	
	if (fgets(sha256_output, 65, file) == NULL) {
		perror("sha256 pipe out");
		return 1;
	}
	pclose(file);
	return 0;
}
/* Compare our checksum with actual checksum
*  Open the file to read the supposed checksum
*  Return 0 if they match, 1 if not.
*
*
*/

int compare_sha256(const char *actual_checksum_path, const char *computed_sha256) {
	char checksum[65];

	// Open the checksum file
	FILE *file = fopen(actual_checksum_path, "r");
	if (!file) {
		perror("checksum file open");
		return 1;
	}

	// Read the checksum file
	if (fgets(checksum, 65, file) == NULL) {
		perror("checksum file read");
		return 1;
	}
	fclose(file);

	// Compare the checksums
	if (strcmp(checksum, computed_sha256) != 0) {
		return 1;
	}

	return 0;
}

/* TODO: Finish the function that check if the checksum and signature match
*  Return 0 if they match, 1 if not.
*
*/

int checkSignature(const char *actual_checksum_path, const char *signature_path) {
	return 0;
}


int main(int argc, char **argv)
{
	/* load the command line argument for the command line 
	 * argv[1] the path that the executable should be retricted
	 * argv[2] the path to the signature (Note: We only use existing key in the keyring)
  	 * argv[3] the path to the checksum file
	 * argv[4] the path to the executable  
	 * if not signed properly
	 */

	int limit;
	if (argc >= 5) {
		struct stat stats;
		if (stat(argv[4], &stats) != 0) {
        		perror("stat");
     		   	return 1;
    	}
		if (!S_ISREG(stats.st_mode) || access(argv[4], X_OK) != 0) {
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
		if (stat(argv[1], &stats) != 0) {
            perror(" limit path stat");
            return 1;
        }

	} else {
		printf("Usage: lsm [path to restrict path] [path to signature] [path to checksum] [path to execuatable] [...] additional argument\n");
		return 0;
	}

	char checksum[65];
	if (compute_sha256(argv[4], checksum)) {
		perror("sha256");
		return -1;
	}
	if (!compare_sha256(argv[3], checksum)) {
		printf("The sha256 checksum matched\n");
		if (!checkSignature(argv[3], argv[2])) {
			limit = 0;
			printf("signature check passed\n");
		} else {
			limit = 1;
			printf("signature check failed\n");
		}
	} else {
		printf("The sha256 checksum does not match\n");
		limit = 1;
	}
	if (limit) {
		printf("Now executing the software with limit\n");
		int pipefd[2];
		if (pipe(pipefd) == -1) {
			perror("pipe");
			return 1;
    	}
		pid_t pid = fork();
		if (pid == -1) {
			perror("fork failed");
			close(pipefd[0]);
        	close(pipefd[1]);
			return 1;
		}
		if (pid == 0) {
			char buf;
			close(pipefd[1]); 
        	read(pipefd[0], &buf, 1);
			if (execvp(argv[4], &argv[4]) == -1) {
				perror("execvp");  
				close(pipefd[0]);
				return 1;
			}

		} else {
			close(pipefd[0]);
			struct lsm_bpf *skel;
			int err;

			/* Set up libbpf errors and debug info callback */
			//libbpf_set_print(libbpf_print_fn);


			/* Open, load, and verify BPF application */
			skel = lsm_bpf__open_and_load();
			if (!skel) {
				fprintf(stderr, "Failed to open and load BPF skeleton\n");
				kill(pid, SIGKILL);
				goto cleanup;
			}
			struct stat stats2;
			if (stat(argv[1], &stats2) != 0) {
				perror("stat 2");
				kill(pid, SIGKILL);
				goto cleanup;
			}
			__u64 restricted_inode = stats2.st_ino;  
			__u32 value = 1; 
			__u32 pid_u32 = (__u32)pid;

			err = bpf_map__update_elem(skel->maps.restricted_inodes_map, &restricted_inode, sizeof(restricted_inode), &value, sizeof(value), BPF_ANY);
			if (err) {
				fprintf(stderr, "Failed to update BPF map element\n");
				kill(pid, SIGKILL);
				goto cleanup;
			}

			err = bpf_map__update_elem(skel->maps.restricted_pid_map, &pid_u32, sizeof(pid_u32), &value, sizeof(value), BPF_ANY);
			if (err) {
				fprintf(stderr, "Failed to update BPF map element\n");
				kill(pid, SIGKILL);
				goto cleanup;
			}

			/* Attach lsm handler */
			err = lsm_bpf__attach(skel);
			if (err) {
				fprintf(stderr, "Failed to attach BPF skeleton\n");
				kill(pid, SIGKILL);
				goto cleanup;
			}
			write(pipefd[1], "", 1);
			close(pipefd[1]); 

			int status;
			waitpid(pid, &status, 0);  
			cleanup:
				close(pipefd[1]);
				lsm_bpf__destroy(skel);
				return -err;
		}

	} else {
		printf("Now executing the software without limit\n");
		if (execvp(argv[4], &argv[4]) == -1) {
			perror("execvp");  
			return 1;
		}
	}
}

	