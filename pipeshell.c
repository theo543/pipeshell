#define _DEFAULT_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>
#include <limits.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>

#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>

struct str_list {
    char *text;
    struct str_list *next;
};

static void spaces(char **ptr) {
    while(**ptr != '\n' && **ptr != '\0' && isspace(**ptr)) {
        (*ptr)++;
    }
}

static uint8_t hex(char **ptr) {
    uint8_t number = 0;
    for(int x = 0;x < 2;x++) {
        char chr = **ptr;
        uint8_t digit;
        (*ptr)++;
        if(chr >= '0' && chr <= '9') {
            digit = chr - '0';
        } else if(chr >= 'A' && chr <= 'F') {
            digit = chr - 'A' + 10;
        } else if(chr >= 'a' && chr <= 'a') {
            digit = chr - 'a' + 10;
        } else {
            fprintf(stderr, "Syntax error: expected hex digit, got '%c'\n", chr);
            exit(EXIT_FAILURE);
        }
        number = number * 16 + digit;
    }
    return number;
}

static bool parse_int(char *start, char *end, int *out) {
    uint64_t number = 0;
    while(true) {
        if(end == NULL) {
            // end == NULL -> null terminated string
            if(*start == '\0') break;
        } else if(start == end) {
            break;
        }

        if(*start < '0' || *start > '9') {
            return false;
        }
        uint8_t new_digit = *start - '0';
        start++;
        if(number > UINT64_MAX / 10 || number * 10 + new_digit < number * 10) {
            return false;
        }
        number = number * 10 + new_digit;
    }
    assert((end == NULL && *start == '\0') || start == end);
    if(number > INT_MAX) {
        return false;
    }
    *out = number;
    return true;
}

struct token {
    union {
        char *text;
        int redirect_fd;
    };
    enum {
        TEXT,
        TO_FILE,
        TO_FILE_APPEND,
        FROM_FILE,
        PIPE,
    } kind;
};

static const char * const stringify_enum[] = {[TEXT] = "TEXT", [TO_FILE] = "TO_FILE", [TO_FILE_APPEND] = "TO_FILE_APPEND", [FROM_FILE] = "FROM_FILE", [PIPE] = "PIPE"};

static struct token token(char **ptr) {
    if(**ptr == '|') {
        (*ptr)++;
        return (struct token){.kind = PIPE};
    }

    if(**ptr == '"') {

        // quoted string token
        (*ptr)++;
        char *str_start = *ptr;

        // decode escapes directly into the original string to avoid allocation
        char *decode_out = str_start;
        while(**ptr != '"') {
            if(**ptr == '\n' || **ptr == '\0') {
                fprintf(stderr, "Syntax error: encountered end of line while reading quoted string\n");
                exit(EXIT_FAILURE);
            }
            if(**ptr != '\\') {
                *decode_out = **ptr;
                decode_out++;
                (*ptr)++;
                continue;
            }
            (*ptr)++;
            char escape = **ptr;
            (*ptr)++;
            char decoded;
            switch(escape) {
                case 'n':
                    decoded = '\n';
                    break;
                case '\\':
                    decoded = '\\';
                    break;
                case 'x':
                    decoded = hex(ptr);
                    break;
                default:
                    fprintf(stderr, "Syntax error: unknown escape \\%c, only \\n, \\\\, \\xXX are supported\n", escape);
                    exit(EXIT_FAILURE);
            }
            *decode_out = decoded;
            decode_out++;
        }

        // advance ptr past the quote
        assert(**ptr == '"');
        (*ptr)++;

        // decode_out is either the quote (for string with no escapes), or some character inside the quoted string
        // replace with null terminator, won't affect the next token
        assert(decode_out < *ptr);
        *decode_out = '\0';

        return (struct token){.kind = TEXT, .text = str_start};
    }

    char *str_start = *ptr;
    // either unquoted string token or redirect token
    while(**ptr != '>' && **ptr != '<' && **ptr != '|' && **ptr != '\0' && !isspace(**ptr)) {
        (*ptr)++;
    }

    bool is_unquoted_string = true;
    int redirect_fd;

    if(**ptr == '<' || **ptr == '>') {
        if(str_start == *ptr) {
            // token is a redirect with no explicit fd, use default
            // stdout is default for output redirect, stdin is default for input redirect
            redirect_fd = (**ptr == '>') ? 1 : 0;
            is_unquoted_string = false;
        } else {
            // token is either redirect with explicit fd, or an unquoted string followed by a redirect token
            // try to parse string as int, if it fails, token is not part of redirect
            is_unquoted_string = !parse_int(str_start, *ptr, &redirect_fd);
        }
    }

    if(is_unquoted_string) {
        // caller places the null terminator for this, doing it here might lose a token or newline
        return (struct token){.kind = TEXT, .text = str_start};
    }

    assert(**ptr == '>' || **ptr == '<');

    if(**ptr == '<') {
        // from file redirect token
        (*ptr)++;
        if(**ptr == '<') {
            fprintf(stderr, "Syntax error: << is not a valid redirect, did you mean <?\n");
            exit(EXIT_FAILURE);
        }
        return (struct token){.kind = FROM_FILE, .redirect_fd = redirect_fd};
    }

    // must be '>'
    assert(**ptr == '>');
    (*ptr)++;

    if(**ptr == '>') {
        (*ptr)++;
        if(**ptr == '>') {
            fprintf(stderr, "Syntax error: >>> is not a valid redirect, did you mean >>?\n");
            exit(EXIT_FAILURE);
        }
        return (struct token){.kind = TO_FILE_APPEND, .redirect_fd = redirect_fd};
    }

    return (struct token){.kind = TO_FILE, .redirect_fd = redirect_fd};
}

static void exit_command(char **args) {
    if(*args == NULL || *(args + 1) == NULL) {
        // default exit code 0
        exit(0);
    } else if(*(args + 2) != NULL) {
        // too many arguments
        fprintf(stderr, "exit: too many arguments\n");
        exit(2);
    } else {
        assert(*(args + 1) != NULL);
        assert(*(args + 2) == NULL);
        char *arg = *(args + 1);
        int exit_code;
        if(parse_int(arg, NULL, &exit_code)) {
            exit(exit_code);
        }
        fprintf(stderr, "exit: invalid exit code '%s'\n", arg);
        exit(3);
    }
}

struct proc_redirect {
    // Special case: NULL file_name before list of redirects for a process, target_fd stores number of arguments, and open_flags stores number of redirects

    int target_fd;
    int open_flags;
    char *file_name;
};

static void extend_buf(void **buf, size_t *len, size_t size) {
    assert(buf != NULL);
    size_t capacity = 0;
    if(*buf != NULL) {
        // capacity is always the smaller power of two >= len
        capacity = 1;
        while(capacity < *len) {
            capacity <<= 1;
        }
    } else {
        assert(*len == 0);
    }
    assert(*len <= capacity);
    if(*len == capacity) {
        if(capacity == 0) {
            capacity = 1;
        } else {
            capacity <<= 1;
        }
        *buf = reallocarray(*buf, capacity, size);
        if(*buf == NULL) {
            perror("reallocarray");
            exit(1);
        }
    }
    (*len) += 1;
    assert(*buf != NULL);
}

void dup2_(int fd1, int fd2) {
    if(dup2(fd1, fd2) < 0) {
        perror("dup2");
        exit(1);
    }
}

void close_(int fd) {
    if(close(fd) != 0) {
        perror("close");
        exit(1);
    }
}

void pipe_(int pipefd[2]) {
    if(pipe(pipefd) != 0) {
        perror("pipe");
        exit(1);
    }
}

void set_cloexec(int fd) {
    if(fcntl(fd, F_SETFD, FD_CLOEXEC) != 0) {
        perror("fcntl(.., F_SETFD, F_CLOEXEC)");
        exit(1);
    }
}

void clear_cloexec(int fd) {
    if(fcntl(fd, F_SETFD, 0) != 0) {
        perror("fcntl(.., F_SETFD, 0)");
        exit(1);
    }
}

int main(void){
    while(true) {
        if(isatty(STDIN_FILENO)) fprintf(stderr, "> ");
        char *command = NULL;
        size_t command_buf_capacity = 0;
        errno = 0;
        if(getline(&command, &command_buf_capacity, stdin) < 0) {
            if(errno == 0) {
                exit(0); // EOF
            }
            perror("getline");
            exit(EXIT_FAILURE);
        }
        assert(command != NULL);

        char *ptr = command;
        char **arg_ptr_buf = NULL;
        size_t arg_ptr_buf_len = 0;
        struct proc_redirect *proc_redirect_buf = NULL;
        size_t proc_redirect_buf_len = 0;
        int proc_argc = 0;
        char *pending_null = NULL;
        bool pending_redirect = false;
        int pending_redirect_fd;
        int pending_redirect_flags;
        int processes = 0;

        extend_buf((void**)&proc_redirect_buf, &proc_redirect_buf_len, sizeof(struct proc_redirect));
        int proc_redirect_header_idx = 0;

        while(true) {
            spaces(&ptr);

            bool last_iter;
            struct token tok;

            if(*ptr == '\n' || *ptr == '\0') {
                last_iter = true;
                tok = (struct token){.kind = PIPE};
            } else {
                last_iter = false;
                tok = token(&ptr);
            }

            // if the previous token was TEXT, it needs a null terminator
            // the terminator can't be set before parsing this current token, because it might overwrite a redirect or pipe character
            if(pending_null != NULL) {
                *pending_null = '\0';
                pending_null = NULL;
            }

            if(tok.kind == TEXT) {
                if(!pending_redirect) {
                    extend_buf((void**)&arg_ptr_buf, &arg_ptr_buf_len, sizeof(char**));
                    arg_ptr_buf[arg_ptr_buf_len - 1] = tok.text;
                    proc_argc++;                
                } else {
                    if(tok.kind != TEXT) {
                        fprintf(stderr, "Syntax error: expected text after redirect token, got %s\n", last_iter ? "end of line" : stringify_enum[tok.kind]);
                        exit(1);
                    }
                    extend_buf((void**)&proc_redirect_buf, &proc_redirect_buf_len, sizeof(struct proc_redirect));
                    proc_redirect_buf[proc_redirect_buf_len - 1] = (struct proc_redirect){.file_name = tok.text, .target_fd = pending_redirect_fd, .open_flags = pending_redirect_flags};
                    pending_redirect_fd = 0;
                    pending_redirect_flags = 0;
                    pending_redirect = false;
                }
                // *ptr is the character right after the text token
                // can't write null terminator now, must defer until after next token
                pending_null = ptr;
                continue;
            }

            if(tok.kind != PIPE) {
                // redirect token
                assert(tok.kind == TO_FILE || tok.kind == TO_FILE_APPEND || tok.kind == FROM_FILE);
                static const int redirect_flags[] = {[TO_FILE] = O_WRONLY | O_CREAT | O_TRUNC, [TO_FILE_APPEND] = O_WRONLY | O_CREAT | O_APPEND, [FROM_FILE] = O_RDONLY};
                pending_redirect_flags = redirect_flags[tok.kind];
                pending_redirect_fd = tok.redirect_fd;
                pending_redirect = true;
                continue;
            }

            assert(tok.kind == PIPE);

            if(proc_argc == 0) {
                if(last_iter && arg_ptr_buf_len == 0 && proc_redirect_buf_len == 1) {
                    // completely empty line, do nothing and go to next line
                    assert(processes == 0);
                    goto next_line;
                }
                fprintf(stderr, "Syntax error: no name given for process, expected at least one text token\n");
                exit(1);
            }

            // fill in proc_redirect header with number of arguments and redirects
            proc_redirect_buf[proc_redirect_header_idx] = (struct proc_redirect){.file_name = NULL, .target_fd = proc_argc, .open_flags = proc_redirect_buf_len - proc_redirect_header_idx - 1};
            proc_argc = 0;
            // allocate new header to be used for next process if any
            proc_redirect_header_idx = proc_redirect_buf_len;
            extend_buf((void**)&proc_redirect_buf, &proc_redirect_buf_len, sizeof(struct proc_redirect));

            // add terminator to argument list
            extend_buf((void**)&arg_ptr_buf, &arg_ptr_buf_len, sizeof(char**));
            arg_ptr_buf[arg_ptr_buf_len - 1] = NULL;

            processes++;

            if(last_iter) break;
        }

        // parsed the command, data is stored in proc_redirect buf and arg_ptr_buf, ready to spawn processes

        // special case: is command is 'exit' and not in a pipeline, run exit in this process
        if(processes == 1 && (strncmp(arg_ptr_buf[0], "exit", 4) == 0)) {
            exit_command(arg_ptr_buf);
        }

        int prev_process_pipe;
        struct proc_redirect *redirect = proc_redirect_buf;
        char **arg_start = arg_ptr_buf;

        for(int x = 0;x < processes;x++) {
            int pipe_fds[2] = {0, 0};
            if(x != processes - 1) {
                pipe_(pipe_fds);
                set_cloexec(pipe_fds[0]);
                set_cloexec(pipe_fds[1]);
            }
            int pid = fork();
            if(pid < 0) {
                perror("fork");
                break;
            } else if(pid != 0) {
                if(processes == 1) {
                    // no pipes
                } else if(x == 0) {
                    // first in pipe
                    prev_process_pipe = pipe_fds[0];
                    close_(pipe_fds[1]);
                } else if(x == processes - 1) {
                    // last in pipe
                    close_(prev_process_pipe);
                } else {
                    // middle of pipe
                    close_(prev_process_pipe);
                    prev_process_pipe = pipe_fds[0];
                    close_(pipe_fds[1]);
                }
                arg_start += redirect->target_fd + 1; // target_fd holds number of arguments
                assert(*(arg_start - 1) == NULL);
                redirect += redirect->open_flags + 1; // open_flags holds number of redirects
                continue;
            }
            // in forked process now
            if(x != 0) dup2_(prev_process_pipe, STDIN_FILENO);
            if(x != processes - 1) dup2_(pipe_fds[1], STDOUT_FILENO);
            assert(redirect->file_name == NULL);
            for(int y = 1;y <= redirect->open_flags;y++) {
                int fd;
                while((fd = open(redirect[y].file_name, redirect[y].open_flags | O_CLOEXEC, S_IROTH | S_IRGRP | S_IRUSR | S_IWUSR)) < 0) {
                    if(errno == EINTR) continue;
                    perror("open");
                    exit(1);
                }
                if(fd != redirect->target_fd) {
                    // copy onto target fd (copy won't have CLOEXEC bit)
                    dup2_(fd, redirect[y].target_fd);
                } else {
                    clear_cloexec(fd);
                }
            }
            execvp(*arg_start, arg_start);
            perror("execvp");
            exit(1);
        }

        while(1) {
            while(wait(NULL) > 0);
            if(errno == EINTR) continue;
            break;
        }

        next_line:
        free(command);
        if(arg_ptr_buf) free(arg_ptr_buf);
        if(proc_redirect_buf) free(proc_redirect_buf);
    }
}
