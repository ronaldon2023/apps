// Author: ronaldon2023@gmail.com
/*
 * WebView Harness Wrapper for AFL++
 * This C wrapper reads input from a file and pipes it to a Python script
 *
 * Author: ronaldon2023@gmail.com
 * Date: August 2025
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <signal.h>
#include <fcntl.h>

#define MAX_INPUT_SIZE 1048576
#define PYTHON_SCRIPT "./targeted_webview_harness.py"

// Function to read the entire contents of a file into a buffer
size_t read_file(const char* filename, char* buffer, size_t max_size) {
    int fd = open(filename, O_RDONLY);
    if (fd == -1) {
        return 0; // File not found or couldn't be opened
    }

    size_t bytes_read = 0;
    ssize_t current_read;
    while ((current_read = read(fd, buffer + bytes_read, max_size - bytes_read)) > 0) {
        bytes_read += current_read;
        if (bytes_read >= max_size) {
            fprintf(stderr, "Warning: Input exceeded MAX_INPUT_SIZE, truncating.\n");
            break;
        }
    }

    close(fd);
    return bytes_read;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
        return 1;
    }

    char input_buffer[MAX_INPUT_SIZE];
    size_t bytes_read;
    int status;
    pid_t pid;
    int pipe_fd[2];

    // Read input from the file provided by AFL++
    bytes_read = read_file(argv[1], input_buffer, MAX_INPUT_SIZE - 1);
    if (bytes_read == 0) {
        fprintf(stderr, "Error: No input read from file\n");
        return 1;
    }

    // Null-terminate the input
    input_buffer[bytes_read] = '\0';

    // Create pipe to pass data to Python script
    if (pipe(pipe_fd) == -1) {
        fprintf(stderr, "Error: Failed to create pipe\n");
        return 1;
    }

    // Fork to run Python harness
    pid = fork();
    if (pid == -1) {
        fprintf(stderr, "Error: Failed to fork process\n");
        return 1;
    }

    if (pid == 0) {
        // Child process - execute Python harness
        close(pipe_fd[1]);
        if (dup2(pipe_fd[0], STDIN_FILENO) == -1) {
            fprintf(stderr, "Error: Failed to redirect stdin\n");
            exit(1);
        }
        close(pipe_fd[0]);
        execlp("python3", "python3", PYTHON_SCRIPT, input_buffer, NULL);
        fprintf(stderr, "Error: Failed to execute Python script\n");
        exit(1);
    } else {
        // Parent process
        close(pipe_fd[0]);
        if (write(pipe_fd[1], input_buffer, bytes_read) != bytes_read) {
            fprintf(stderr, "Error: Failed to write to pipe\n");
            close(pipe_fd[1]);
            return 1;
        }
        close(pipe_fd[1]);
        if (waitpid(pid, &status, 0) == -1) {
            fprintf(stderr, "Error: Failed to wait for child process\n");
            return 1;
        }
        if (WIFEXITED(status)) {
            int exit_code = WEXITSTATUS(status);
            if (exit_code != 0) {
                fprintf(stderr, "Python harness detected vulnerability, propagating crash\n");
                raise(SIGSEGV);
            }
            return 0;
        } else if (WIFSIGNALED(status)) {
            int signal_num = WTERMSIG(status);
            fprintf(stderr, "Python harness terminated by signal: %d, propagating crash\n", signal_num);
            raise(signal_num);
        } else {
            fprintf(stderr, "Python harness terminated abnormally\n");
            return 1;
        }
    }
    return 0;
}
