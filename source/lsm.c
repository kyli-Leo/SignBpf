// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2024 David Di */
#include <search.h>
#include <pwd.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <signal.h>
#include <sys/resource.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/types.h>
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

/*
 * Clean input from file
 *
 * 
 */

void clean_line(char *line) {
    size_t length = strlen(line);
	// Remove trailing whitespace and newline
    while (length > 0 && (isspace((unsigned char)line[length - 1]))) {
        line[length - 1] = '\0';
		length -= 1;
    }
	// Remove leading whitespace and newline
    char *start = line;
    while (*start && (isspace((unsigned char)*start))) {
        start++;
    }
	if (start != line) {
        memmove(line, start, strlen(start) + 1);
    }
}

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
	char checksum[65]; // 64 characters + 1 null terminator

	// Open the checksum file
	FILE *file = fopen(actual_checksum_path, "r");
	if (!file) {
		perror("checksum file open");
		return 1;
	}

	// Read the checksum file
	if (fgets(checksum, 65, file) == NULL) {
		perror("checksum file read");
		fclose(file);
		return 1;
	}
	clean_line(checksum);
	fclose(file);

	// checksum[strcspn(checksum, "\n")] = '\0';
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
	char command[512];
    int result;
	const char *sudo_uid= getenv("SUDO_UID");
	uid_t userId = (uid_t)atoi(sudo_uid);
	struct passwd *pw = getpwuid(userId);
    if (!pw || !pw->pw_dir) {
        perror("pw");
        return 1;
    }
	const char * home_dir = pw->pw_dir;

    if (!home_dir) {
        perror("home_dir");
        return 1;
    }
	snprintf(command, sizeof(command), "gpg --homedir %s/.gnupg --verify %s %s", home_dir, signature_path, actual_checksum_path);
	result = system(command);

    if (result == 0) {
        printf("Signature is valid\n");
        return 0;
    } else {
        printf("Signature verification failed\n");
        return 1; 
    }
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
			return 1;
		}
		if (stat(argv[1], &stats) != 0) {
            perror(" limit path stat");
            return 1;
        }

		if (!S_ISREG(stats.st_mode) || access(argv[1], R_OK) != 0) {
			fprintf(stderr, "Limit file does not exist or no permission to read\n");
			return 1;
		}

	} else {
		printf("Usage: sudo ./lsm [path to restrict path] [path to signature] [path to checksum] [path to execuatable] [...] additional argument\n");
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
		} else {
			limit = 1;
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

			const char *sudo_uid= getenv("SUDO_UID");
			const char *sudo_gid = getenv("SUDO_GID");
			uid_t userId = (uid_t)atoi(sudo_uid);
			gid_t groupId = (gid_t)atoi(sudo_gid);
			if (setgid(groupId) != 0) {
				perror("setgid");
				close(pipefd[0]);
				return 1;
			}
			if (setuid(userId) != 0) {
				perror("setuid");
				close(pipefd[0]);
				return 1;
			}
			if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
				perror("prctl");
				close(pipefd[0]);
				return 1;
			}
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
			// libbpf_set_print(libbpf_print_fn);


			/* Open, load, and verify BPF application */
			skel = lsm_bpf__open_and_load();
			if (!skel) {
				fprintf(stderr, "Failed to open and load BPF skeleton\n");
				kill(pid, SIGKILL);
				goto cleanup;
			}
			struct stat stats2;
			__u32 value = 1; 
			__u32 pid_u32 = (__u32)pid;
			FILE *limit_file = fopen(argv[1], "r");;
			if (limit_file == NULL) {
				kill(pid, SIGKILL);
				goto cleanup;
			}
    		char buffer[2048];
			memset(buffer, '\0', sizeof(buffer));
			ENTRY **entry_pointers;  // Array to store ENTRY pointers
			size_t entry_count = 0;
			entry_pointers = malloc(sizeof(ENTRY *) * 1024);
			if (hcreate(1024) == 0) {
				perror("hcreate");
				kill(pid, SIGKILL);
				goto cleanup;
			}
			while (fgets(buffer, sizeof(buffer), limit_file) != NULL) {
				clean_line(buffer);
				if (stat(buffer, &stats2) != 0) {
					continue;
				}
				__u64 restricted_inode = stats2.st_ino; 
				err = bpf_map__update_elem(skel->maps.restricted_inodes_map, &restricted_inode, sizeof(restricted_inode), &value, sizeof(value), BPF_ANY);
				if (err) {
					fprintf(stderr, "Failed to update BPF map restricted inode\n");
					kill(pid, SIGKILL);
					goto cleanup;
				} 
				printf("Directory %s is added to the limit list\n", buffer);

				/* Add the path to hashtable to enable O(1) lookup*/
				char *inode_key = malloc(32); // Allocate space for inode key
				if (!inode_key) {
					perror("inode_key");
					kill(pid, SIGKILL);
					goto cleanup;
				}
				snprintf(inode_key, 32, "%llu", restricted_inode);
				ENTRY e, *ep;
				e.key = inode_key;
				e.data = strdup(buffer);
				ep = hsearch(e, ENTER);
				if (!ep) {
					perror("Hashtable enter");
					free(e.key);
					free(e.data);
					kill(pid, SIGKILL);
					goto cleanup;
				} else {
					entry_pointers[entry_count++] = ep;
				}

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
			__u64 key = 0, next_key = 0;
			char search_key[32];
			while (bpf_map__get_next_key(skel->maps.inode_access_map, &key, &next_key, sizeof(__u64)) == 0) {
				snprintf(search_key, 32, "%llu", next_key); 
    			ENTRY query, *found_entry;
    			query.key = search_key;
    			found_entry = hsearch(query, FIND);

				if (found_entry) {
					printf("Caution: The unverified programm tried to access path: %s which is prohibited!\n", (char *)found_entry->data);
				} else {
					printf("Caution: The unverified programm tried to access inode: %llu which is prohibited!\n", next_key);
				}

				key = next_key; 
			}
			cleanup:
				for (size_t i = 0; i < entry_count; i++) {
					free(entry_pointers[i]->key);
					free(entry_pointers[i]->data);
				}
				free(entry_pointers);  
				hdestroy();
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

	