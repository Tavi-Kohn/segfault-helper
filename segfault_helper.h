//usr/bin/env gcc -x c segfault_helper.h -o libsegfault_helper.so -fpic -shared -g -ldw -std=c17 -Wall -Wextra -Wpedantic; exit 0

// The MIT License (MIT)

// Copyright (c) 2022 Tavi Kohn

//  Permission is hereby granted, free of charge, to any person obtaining a
//  copy of this software and associated documentation files (the "Software"),
//  to deal in the Software without restriction, including without limitation
//  the rights to use, copy, modify, merge, publish, distribute, sublicense,
//  and/or sell copies of the Software, and to permit persons to whom the
//  Software is furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in
//  all copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
//  OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
//  FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
//  DEALINGS IN THE SOFTWARE.

#ifndef SEGFAULT_HELPER_H
#define SEGFAULT_HELPER_H

// #define _POSIX_C_SOURCE 200809L
#define _GNU_SOURCE

// NOTE clang does not emit .debug_aranges section by default
// The flag -gdwarf-aranges must be passed to generate usable debug info

// NOTE this file must be compiled with -x c before the name segfault_helper.h so that the .h file is treated as a normal .c file and compiles correctly
// To compile a shared library for use with LD_PRELOAD
// gcc -x c segfault_helper.h -fpic -shared -g -ldw -Wall -Wextra -o libsegfault_helper.so

// #include <elfutils/libdw.h>
#include <elfutils/libdwfl.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

// Define an arbitrary identifier that will be searched for by name in the stack trace
#ifndef SEGFAULT_HELPER_ARBITRATY_IDENTIFIER
#define SEGFAULT_HELPER_ARBITRARY_IDENTIFIER K2a9Ek8KGwFRAYZ9n7EiPM9CfQ8oyP99jZFrCyifZCmCiNXZwU7mbgJUKCjWaKUx
#endif /* ARBITRARY_IDENTIFIER */

#define STRINGIFY_INNER(x) #x
#define CONCAT_INNER(x, y) x##y
#define STRINGIFY(x) STRINGIFY_INNER(x)
#define CONCAT(x, y) CONCAT_INNER(x, y)

#define SEGFAULT_HELPER_MAGIC_HANDLER_IDENTIFIER CONCAT(handle_, ARBITRARY_IDENTIFIER)
#define SEGFAULT_HELPER_MAGIC_HANDLER_STRING STRINGIFY(MAGIC_HANDLER_IDENTIFIER)

// The signal stack must be large enough to accomodate the DWARF parsing code
#ifndef SIGNAL_STACK_SIZE
#define SIGNAL_STACK_SIZE 1024 * 1024
#endif

// #ifndef CYCLE_DETECTION_DEPTH
// #define CYCLE_DETECTION_DEPTH 10
// #endif

#ifndef OUTPUT_FILE
#define OUTPUT_FILE stderr
#endif

#define SEGFAULT_HELPER_DEBUG_ENV_VAR = "SEGFAULT_HELPER_DEBUG"

// Should debug messages be printed
bool debug_print = false;

/**
 * @brief Initialize segfault helper
 * Sets up a signal handling stack and a signal handler for segfaults
 */
__attribute__((constructor)) void init_segfault_helper(void);
// TODO maybe use __attribute((weak)) to define an entry point

/**
 * @brief Signal handler function
 * Processes caught signals
 */
void handler(int, siginfo_t*, void*);

struct sigaction default_action;
struct sigaction action;
bool init_complete = false;

// Space allocated for handling signals on a separate stack
char signal_stack[SIGNAL_STACK_SIZE];

struct trim_opts {
    bool trim_by_name;  // Trim the stacktrace by searching for an identifier
    int skip_count;     // Trim *skip_count* many entries if the identifier was found
};

/**
 * @brief Callback for dumping Dwfl_Frame objects
 *
 * @param frame stack frame
 * @param arg stack frame trimming options
 * @return int Dwfl callback status code (DWARF_CB_OK or DWARF_CB_ABORT)
 */
static int getframes_callback(Dwfl_Frame* frame, void* arg) {
    struct trim_opts* state = (struct trim_opts*)arg;

    Dwfl_Thread* thread = dwfl_frame_thread(frame);
    Dwfl* session = dwfl_thread_dwfl(thread);
    Dwarf_Addr pc;
    if (dwfl_frame_pc(frame, &pc, NULL)) {
        Dwfl_Module* module = dwfl_addrmodule(session, pc);
        const char* module_filename;
        const char* module_name = dwfl_module_info(module, NULL, NULL, NULL, NULL, NULL, &module_filename, NULL);
        const char* function_name = dwfl_module_addrname(module, pc);
        Dwarf_Addr pc;
        dwfl_frame_pc(frame, &pc, NULL);

        // Determine if this frame should be trimmed
        if (state != NULL) {
            // Search for a known function name, and trim it
            if (state->trim_by_name) {
                if (strstr(function_name, SEGFAULT_HELPER_MAGIC_HANDLER_STRING) != NULL) {
                    state->trim_by_name = false;
                }
                return DWARF_CB_OK;
            }
            // Trim until state->skip_count is 0
            if (state->skip_count > 0) {
                state->skip_count--;
                return DWARF_CB_OK;
            }
        }

        // GElf_Off offset;
        // GElf_Sym symbol;
        // GElf_Word shndxp;
        // Dwarf_Addr bias;
        // dwfl_module_addrinfo(module, pc, &offset, &symbol, &shndxp, NULL, &bias);
        // fprintf(OUTPUT_FILE, "%lx %d %d\n", pc, bias, offset);
        // fprintf(OUTPUT_FILE, "in module '%s'\n", module_name);
        // fprintf(OUTPUT_FILE, "in module file '%s'\n", module_filename);
        fprintf(OUTPUT_FILE, "%-20s ", function_name);

        Dwfl_Line* line = dwfl_module_getsrc(module, pc);
        if (line != NULL) {
            int line_number;
            int column_number;
            Dwarf_Addr line_addr;
            const char* file_str = dwfl_lineinfo(line, &line_addr, &line_number, &column_number, NULL, NULL);
            fprintf(OUTPUT_FILE, "at %s:%d:%d", file_str, line_number, column_number);
        } else {
            fprintf(OUTPUT_FILE, "from %s", module_name);
        }
        fprintf(OUTPUT_FILE, "\n");
    }
    return DWARF_CB_OK;
}

static int getthreads_callback(Dwfl_Thread* thread, void* arg) {
    (void)(arg);                         // arg is not used, suppress unused parameter warnings
    struct trim_opts state = {true, 1};  // Skip all segfault_helper related frames, as well as 1 additional stack frame
    printf("Backtracing Thread %d\n", dwfl_thread_tid(thread));
    dwfl_thread_getframes(thread, getframes_callback, (void*)&state);
    return DWARF_CB_OK;
}

void print_backtrace() {
    // Fork so that one process can backtrace the other without additional permissions
    pid_t pid = fork();
    if (pid == 0) {
        // have the child do nothing until the parent finishes tracing it and exits
        while (true) wait(NULL);  // Hopefully calling wait here will suspend the process more efficiently?
    } else {
        const Dwfl_Callbacks callbacks = {
            .find_elf = dwfl_linux_proc_find_elf,
            .find_debuginfo = dwfl_standard_find_debuginfo,
            .section_address = dwfl_linux_kernel_module_section_address,
            .debuginfo_path = NULL,
        };
        Dwfl* session = dwfl_begin(&callbacks);
        if (dwfl_linux_proc_report(session, pid) != 0) {
            fprintf(OUTPUT_FILE, "Failed to get process report");
            return;
        }
        if (dwfl_report_end(session, NULL, NULL) != 0) {
            fprintf(OUTPUT_FILE, "Failed to complete report\n");
            return;
        }
        if (dwfl_linux_proc_attach(session, pid, false) != 0) {
            fprintf(OUTPUT_FILE, "Failed to trace process\n");
            return;
        }
        if (dwfl_getthreads(session, getthreads_callback, NULL) != 0) {
            fprintf(OUTPUT_FILE, "Failed to enumerate threads\n");
            return;
        }
        dwfl_end(session);
    }
}

// Make an arbitrary function name that can be string searched for
void SEGFAULT_HELPER_MAGIC_HANDLER_IDENTIFIER(int signal, siginfo_t* info, void* ucontext) { handler(signal, info, ucontext); }

void handler(int signal, siginfo_t* info, void* ucontext) {
    (void)(ucontext);  // ucontext is not used, suppress unused parameter warnings
    char* reason;
    switch (info->si_code) {
        case SEGV_MAPERR:
            reason = "Address not mapped to object";
            break;
        case SEGV_ACCERR:
            reason = "Invalid permissions for mapped object";
            break;
#ifdef SEGV_BNDERR
        case SEGV_BNDERR:
            reason = "Failed address bound checks";
            break;
#endif /* SEGV_BNDERR */
#ifdef SEGV_PKUERR
        case SEGV_PKUERR:
            reason = "Access was denied by memory protection keys";
            break;
#endif /* SEGV_PKUERR */
        default:
            reason = "Unknown reason";
    }
    fprintf(OUTPUT_FILE,
            "Caught Segfault attempting to access address %p (%ld) caused by "
            "\'%s\'\n",
            info->si_addr, (long)info->si_addr, reason);

    print_backtrace();
    fflush(OUTPUT_FILE);

    // Call the original signal handler
    sigaction(signal, &default_action, NULL);
    raise(signal);
}

__attribute__((constructor)) void init_segfault_helper(void) {
    if (!init_complete) {
        init_complete = true;
        if (getenv("SEGFAULT_HELPER_DEBUG") != NULL) {
            debug_print = true;
        } else {
            debug_print = false;
        }

        if (debug_print) {
            fprintf(stderr, "Initializing segfault helper\n");
        }

        // Set up a new stack just for signal handling
        stack_t stack = {
            .ss_sp = signal_stack,
            .ss_flags = 0,
            .ss_size = SIGNAL_STACK_SIZE,
        };
        if (sigaltstack(&stack, NULL) != 0) {
            fprintf(stderr, "Setting alternate signal stack failed: %s\n", strerror(errno));
        }

        // Set up signal handler to handle segfaults and provide information about the fault
        action.sa_sigaction = &SEGFAULT_HELPER_MAGIC_HANDLER_IDENTIFIER;
        action.sa_flags = SA_SIGINFO | SA_ONSTACK;
        sigaction(SIGSEGV, &action, &default_action);

        if (debug_print) {
            fprintf(stderr, "Segfault helper successfully initialized\n");
        }
    }
}

__attribute__((destructor)) void destructor(void) {
    // TODO maybe print that the current thread or process exited successfully
    if (debug_print) {
        fprintf(stderr, "Segfault helper destructor\n");
        fflush(stderr);
    }
}

#undef STRINGIFY_INNER
#undef STRINGIFY
#undef CONCAT_INNER
#undef CONCAT

#undef SIGNAL_STACK_SIZE
#undef OUTPUT_FILE

#endif  // SEGFAULT_HELPER_H
