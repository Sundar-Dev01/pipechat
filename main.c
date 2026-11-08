#include "pipe_chat.h"
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <ctype.h>


int main(void)
{
    int parent_to_child[2];
    int child_to_parent[2];
    pid_t child_pid;
    TicketRecord *tickets = NULL;
    IpcStatistics statistics = {0U, 0U, 0U, 0U, 0U, 0U};
    int next_ticket_id = 1001;
    char input[INPUT_LENGTH];
    size_t input_length = 0U;
    bool running = true;
    bool prompt_needed = true;

    (void)umask(0077);

    if (pipe(parent_to_child) < 0 || pipe(child_to_parent) < 0) {
        perror("pipe");
        return EXIT_FAILURE;
    }

    child_pid = fork();
    if (child_pid < 0) {
        perror("fork");
        return EXIT_FAILURE;
    }

    if (child_pid == 0) {
        (void)close(parent_to_child[1]);
        (void)close(child_to_parent[0]);
        child_process(parent_to_child[0], child_to_parent[1]);
    }

    (void)close(parent_to_child[0]);
    (void)close(child_to_parent[1]);

    (void)printf("\n============================================================\n");
    (void)printf("       PIPE CHAT - CUSTOMER SUPPORT SYSTEM\n");
    (void)printf("============================================================\n");
    (void)printf("Parent reception process : PID %ld\n", (long)getpid());
    (void)printf("Child support process    : PID %ld\n", (long)child_pid);
    (void)printf("IPC                      : Two unnamed pipes\n");
    (void)printf("Audit log                : %s (permission 0600)\n", LOG_PATH);
    (void)printf("Type /help to view commands.\n\n");
    (void)fflush(stdout);

    while (running) {
        struct pollfd descriptors[2];
        int poll_result;
        char ch;

        if (process_child_events(child_to_parent[0], tickets, &statistics) > 0) {
            prompt_needed = true;
        }

        if (prompt_needed) {
            (void)printf("pipe-chat> ");
            (void)fflush(stdout);
            prompt_needed = false;
        }

        descriptors[0].fd = STDIN_FILENO;
        descriptors[0].events = POLLIN;
        descriptors[0].revents = 0;
        descriptors[1].fd = child_to_parent[0];
        descriptors[1].events = POLLIN;
        descriptors[1].revents = 0;

        poll_result = poll(descriptors, 2U, -1);
        if (poll_result < 0) {
            if (errno == EINTR) continue;
            perror("poll");
            break;
        }

        if ((descriptors[1].revents & POLLIN) != 0) {
            (void)process_child_events(child_to_parent[0], tickets, &statistics);
            prompt_needed = true;
            continue;
        }

        if ((descriptors[0].revents & (POLLIN | POLLHUP)) != 0) {
            ssize_t amount = read(STDIN_FILENO, &ch, 1U);
            if (amount <= 0) {
                running = false;
                break;
            }

            if (ch != '\n' && ch != '\r') {
                if (input_length + 1U < sizeof(input)) {
                    input[input_length] = ch;
                    ++input_length;
                }
                continue;
            }

            input[input_length] = '\0';
            input_length = 0U;
            prompt_needed = true;

            if (input[0] == '\0') continue;

            if (strncmp(input, "/ticket ", 8U) == 0) {
                const char *issue = input + 8;
                int priority = detect_priority(issue);
                TicketRecord *record;
                RequestPacket request;

                if (issue[0] == '\0') {
                    (void)printf("Usage: /ticket <describe your issue>\n");
                    continue;
                }

                record = calloc(1U, sizeof(*record));
                if (record == NULL) {
                    (void)printf("Unable to allocate ticket record.\n");
                    continue;
                }

                record->id = next_ticket_id++;
                record->priority = priority;
                record->status = STATUS_OPEN;
                record->created_at = time(NULL);
                record->updated_at = record->created_at;
                (void)snprintf(record->issue, sizeof(record->issue),
                               "%.255s", issue);
                add_ticket_record(&tickets, record);

                (void)memset(&request, 0, sizeof(request));
                request.type = REQ_CREATE;
                request.ticket_id = record->id;
                request.priority = priority;
                (void)snprintf(request.issue, sizeof(request.issue),
                               "%s", record->issue);
                caesar_cipher(request.issue, CAESAR_ENCRYPT_SHIFT);

                if (send_request(parent_to_child[1], &request, &statistics) < 0) {
                    (void)printf("Failed to send ticket to support process.\n");
                    running = false;
                    continue;
                }

                (void)printf("\nTicket TK-%04d created successfully.\n",
                             record->id);
                display_ticket(record);
            } else if (strncmp(input, "/status ", 8U) == 0) {
                char *end_pointer;
                long id = strtol(input + 8, &end_pointer, 10);
                TicketRecord *record;

                if (*end_pointer != '\0' || id < 1L || id > 2147483647L) {
                    (void)printf("Usage: /status <numeric-ticket-id>\n");
                } else {
                    process_child_events(child_to_parent[0], tickets, &statistics);
                    record = find_ticket(tickets, (int)id);
                    if (record == NULL) {
                        (void)printf("Ticket TK-%04ld not found.\n", id);
                    } else {
                        display_ticket(record);
                    }
                }
            } else if (strcmp(input, "/tickets") == 0) {
                process_child_events(child_to_parent[0], tickets, &statistics);
                display_all_tickets(tickets);
            } else if (strcmp(input, "/stat") == 0) {
                process_child_events(child_to_parent[0], tickets, &statistics);
                display_statistics(tickets, &statistics);
            } else if (strcmp(input, "/help") == 0) {
                show_help();
            } else if (strcmp(input, "/start") == 0) {
                (void)printf("Reception process is active; support service is running.\n");
            } else if (strcmp(input, "/quit") == 0) {
                running = false;
            } else {
                (void)printf("Unknown command. Type /help for assistance.\n");
            }
        }
    }

    {
        RequestPacket shutdown_request;
        (void)memset(&shutdown_request, 0, sizeof(shutdown_request));
        shutdown_request.type = REQ_SHUTDOWN;
        (void)send_request(parent_to_child[1], &shutdown_request, &statistics);
    }

    (void)close(parent_to_child[1]);

    /* Receive remaining child events, including service shutdown notification. */
    for (;;) {
        struct pollfd descriptor;
        EventPacket event;
        int result;

        descriptor.fd = child_to_parent[0];
        descriptor.events = POLLIN;
        descriptor.revents = 0;

        if (poll(&descriptor, 1U, 1000) <= 0) break;
        result = read_full(child_to_parent[0], &event, sizeof(event));
        if (result <= 0) break;

        statistics.bytes_received += (unsigned long long)sizeof(event);
        ++statistics.responses_received;
        caesar_cipher(event.issue, CAESAR_DECRYPT_SHIFT);
        caesar_cipher(event.detail, CAESAR_DECRYPT_SHIFT);
        ++statistics.encrypted_messages;
        ++statistics.decrypted_messages;
        log_event(&event);
        if (event.ticket_id != 0) {
            TicketRecord *record = find_ticket(tickets, event.ticket_id);
            if (record != NULL) {
                record->status = event.status;
                record->updated_at = (time_t)event.updated_at;
                record->resolved_at = (time_t)event.resolved_at;
            }
        }
        (void)printf("\n[SERVICE] %s\n", event.detail);
        if (event.type == EVENT_SERVICE_STOPPED &&
            strstr(event.detail, "shutting down") != NULL) {
            break;
        }
    }

    (void)close(child_to_parent[0]);
    (void)waitpid(child_pid, NULL, 0);
    append_log("Pipe Chat session ended.");
    (void)printf("\nPipe Chat session closed. Audit log: %s\n", LOG_PATH);

    free_ticket_records(tickets);
    return EXIT_SUCCESS;
}
