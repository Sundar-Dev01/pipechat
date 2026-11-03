#define _POSIX_C_SOURCE 200809L

/*
 * PIPE CHAT - Customer Support Ticket Processing System
 * Linux C / Parent-child IPC using two unnamed pipes.
 *
 * Build: gcc -std=c11 -Wall -Wextra -Wpedantic -O2 pipe_chat.c -o pipe_chat
 * Run:   ./pipe_chat
 *
 * Data structures:
 *   1. Parent: linked list of all ticket records.
 *   2. Child: priority queue implemented as a sorted linked list (FIFO
 *      among tickets with the same priority).
 *   3. Fixed-size structures/arrays: IPC packets and terminal input.
 *
 * Security note: Caesar cipher is a learning demonstration only. It is
 * NOT secure encryption and must never protect real customer information.
 */

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define ISSUE_LENGTH 256
#define INPUT_LENGTH 320
#define LOG_PATH "pipe_chat.log"
#define HIGH_SECONDS 5
#define MEDIUM_SECONDS 7
#define LOW_SECONDS 15

typedef enum {
    REQ_CREATE = 1,
    REQ_SHUTDOWN
} RequestType;

typedef enum {
    EVENT_ACCEPTED = 1,
    EVENT_STATUS,
    EVENT_SERVICE_STOPPED
} EventType;

typedef enum {
    PRIORITY_LOW = 1,
    PRIORITY_MEDIUM = 2,
    PRIORITY_HIGH = 3
} Priority;

typedef enum {
    STATUS_OPEN = 1,
    STATUS_IN_PROGRESS,
    STATUS_RESOLVED
} TicketStatus;

typedef struct {
    int type;
    int ticket_id;
    int priority;
    char issue[ISSUE_LENGTH]; /* Caesar-encrypted in transit */
} RequestPacket;

typedef struct {
    int type;
    int ticket_id;
    int priority;
    int status;
    long created_at;
    long updated_at;
    long resolved_at;
    char issue[ISSUE_LENGTH];
    char detail[160];
} EventPacket;

typedef struct TicketRecord {
    int id;
    int priority;
    int status;
    time_t created_at;
    time_t updated_at;
    time_t resolved_at;
    char issue[ISSUE_LENGTH];
    struct TicketRecord *next;
} TicketRecord;

typedef struct QueueNode {
    int id;
    int priority;
    time_t created_at;
    char issue[ISSUE_LENGTH];
    struct QueueNode *next;
} QueueNode;

typedef struct {
    QueueNode *head;
    size_t count;
} PriorityQueue;

typedef struct {
    unsigned long long total_requests;
    unsigned long long responses_received;
    unsigned long long bytes_sent;
    unsigned long long bytes_received;
    unsigned long long encrypted_messages;
    unsigned long long decrypted_messages;
} IpcStatistics;

static void format_time(time_t value, char *buffer, size_t capacity)
{
    struct tm tm_value;

    if (value == (time_t)0) {
        (void)snprintf(buffer, capacity, "Not yet resolved");
        return;
    }
    if (localtime_r(&value, &tm_value) == NULL ||
        strftime(buffer, capacity, "%Y-%m-%d %H:%M:%S", &tm_value) == 0U) {
        (void)snprintf(buffer, capacity, "Time unavailable");
    }
}

static int read_full(int fd, void *buffer, size_t length)
{
    size_t offset = 0U;
    unsigned char *bytes = (unsigned char *)buffer;

    while (offset < length) {
        ssize_t amount = read(fd, bytes + offset, length - offset);
        if (amount == 0) return 0;
        if (amount < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        offset += (size_t)amount;
    }
    return 1;
}

/* Each fixed-size packet is smaller than PIPE_BUF on Linux. */
static int write_full_packet(int fd, const void *packet, size_t length)
{
    ssize_t amount;

    do {
        amount = write(fd, packet, length);
    } while (amount < 0 && errno == EINTR);

    return amount == (ssize_t)length ? 0 : -1;
}

static void caesar_cipher(char *text, int shift)
{
    size_t i;

    for (i = 0U; text[i] != '\0'; ++i) {
        unsigned char ch = (unsigned char)text[i];

        if (ch >= (unsigned char)'a' && ch <= (unsigned char)'z') {
            text[i] = (char)('a' + ((ch - (unsigned char)'a' +
                                    (unsigned int)shift) % 26U));
        } else if (ch >= (unsigned char)'A' && ch <= (unsigned char)'Z') {
            text[i] = (char)('A' + ((ch - (unsigned char)'A' +
                                    (unsigned int)shift) % 26U));
        }
    }
}

static int contains_keyword(const char *text, const char *keyword)
{
    char copy[ISSUE_LENGTH];
    size_t i;

    (void)snprintf(copy, sizeof(copy), "%s", text);
    for (i = 0U; copy[i] != '\0'; ++i) {
        if (copy[i] >= 'A' && copy[i] <= 'Z') {
            copy[i] = (char)(copy[i] - 'A' + 'a');
        }
    }
    return strstr(copy, keyword) != NULL;
}

static int detect_priority(const char *issue)
{
    if (contains_keyword(issue, "urgent") ||
        contains_keyword(issue, "critical") ||
        contains_keyword(issue, "emergency") ||
        contains_keyword(issue, "high")) {
        return PRIORITY_HIGH;
    }
    if (contains_keyword(issue, "medium") ||
        contains_keyword(issue, "moderate")) {
        return PRIORITY_MEDIUM;
    }
    return PRIORITY_LOW;
}

static const char *priority_text(int priority)
{
    if (priority == PRIORITY_HIGH) return "HIGH";
    if (priority == PRIORITY_MEDIUM) return "MEDIUM";
    return "LOW";
}

static const char *status_text(int status)
{
    if (status == STATUS_OPEN) return "OPEN";
    if (status == STATUS_IN_PROGRESS) return "IN PROGRESS";
    if (status == STATUS_RESOLVED) return "RESOLVED";
    return "UNKNOWN";
}

static int service_seconds(int priority)
{
    if (priority == PRIORITY_HIGH) return HIGH_SECONDS;
    if (priority == PRIORITY_MEDIUM) return MEDIUM_SECONDS;
    return LOW_SECONDS;
}

static void append_log(const char *message)
{
    int fd;
    char timestamp[32];
    char line[640];
    time_t now = time(NULL);
    struct tm tm_value;
    int length;

    if (localtime_r(&now, &tm_value) == NULL ||
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S",
                 &tm_value) == 0U) {
        (void)snprintf(timestamp, sizeof(timestamp), "unknown-time");
    }

    length = snprintf(line, sizeof(line), "[%s] %s\n", timestamp, message);
    if (length < 0) return;

    fd = open(LOG_PATH, O_WRONLY | O_CREAT | O_APPEND, S_IRUSR | S_IWUSR);
    if (fd >= 0) {
        (void)fchmod(fd, S_IRUSR | S_IWUSR);
        (void)write(fd, line, (size_t)length);
        (void)close(fd);
    }
}

static int send_event(int fd, int type, int id, int priority, int status,
                      time_t created, time_t updated, time_t resolved,
                      const char *issue, const char *detail)
{
    EventPacket event;

    (void)memset(&event, 0, sizeof(event));
    event.type = type;
    event.ticket_id = id;
    event.priority = priority;
    event.status = status;
    event.created_at = (long)created;
    event.updated_at = (long)updated;
    event.resolved_at = (long)resolved;
    if (issue != NULL) {
        (void)snprintf(event.issue, sizeof(event.issue), "%s", issue);
    }
    if (detail != NULL) {
        (void)snprintf(event.detail, sizeof(event.detail), "%s", detail);
    }

    /* Encrypt child-to-parent event text before transmitting it. */
    caesar_cipher(event.issue, 3);
    caesar_cipher(event.detail, 3);
    return write_full_packet(fd, &event, sizeof(event));
}

static void queue_insert(PriorityQueue *queue, const RequestPacket *request)
{
    QueueNode *node = malloc(sizeof(*node));
    QueueNode **position;

    if (node == NULL) return;

    node->id = request->ticket_id;
    node->priority = request->priority;
    node->created_at = time(NULL);
    (void)snprintf(node->issue, sizeof(node->issue), "%s", request->issue);
    node->next = NULL;

    /* Higher priority first; equal priorities retain FIFO order. */
    position = &queue->head;
    while (*position != NULL &&
           (*position)->priority >= node->priority) {
        position = &(*position)->next;
    }
    node->next = *position;
    *position = node;
    ++queue->count;
}

static QueueNode *queue_pop(PriorityQueue *queue)
{
    QueueNode *node = queue->head;

    if (node != NULL) {
        queue->head = node->next;
        node->next = NULL;
        --queue->count;
    }
    return node;
}

static void queue_destroy(PriorityQueue *queue)
{
    QueueNode *node;

    while ((node = queue_pop(queue)) != NULL) {
        free(node);
    }
}

static void child_process(int request_fd, int event_fd)
{
    PriorityQueue queue = { NULL, 0U };
    QueueNode *active = NULL;
    struct timespec deadline;
    bool running = true;
    bool active_ticket = false;

    (void)send_event(event_fd, EVENT_SERVICE_STOPPED, 0, 0, 0,
                     0, 0, 0, "", "Support service process is online.");

    while (running) {
        struct pollfd descriptor;
        int timeout = -1;
        int poll_result;

        if (active_ticket) {
            struct timespec now;
            long remaining_ms;

            (void)clock_gettime(CLOCK_MONOTONIC, &now);
            remaining_ms = (long)(deadline.tv_sec - now.tv_sec) * 1000L +
                           (long)(deadline.tv_nsec - now.tv_nsec) / 1000000L;
            timeout = remaining_ms <= 0L ? 0 :
                      (remaining_ms > 2147483647L ? 2147483647 :
                       (int)remaining_ms);
        }

        descriptor.fd = request_fd;
        descriptor.events = POLLIN;
        descriptor.revents = 0;
        poll_result = poll(&descriptor, 1U, timeout);

        if (poll_result < 0 && errno != EINTR) break;

        if (poll_result > 0 && (descriptor.revents & POLLIN) != 0) {
            RequestPacket request;
            int read_result = read_full(request_fd, &request, sizeof(request));

            if (read_result <= 0) {
                running = false;
            } else if (request.type == REQ_SHUTDOWN) {
                running = false;
            } else if (request.type == REQ_CREATE) {
                /* Reverse Caesar shift to recover the original customer issue. */
                caesar_cipher(request.issue, 23);
                queue_insert(&queue, &request);

                (void)send_event(event_fd, EVENT_ACCEPTED, request.ticket_id,
                                 request.priority, STATUS_OPEN, time(NULL),
                                 time(NULL), 0, request.issue,
                                 "Ticket received and added to priority queue.");
            }
        }

        if (running && active_ticket) {
            struct timespec now;
            (void)clock_gettime(CLOCK_MONOTONIC, &now);

            if (now.tv_sec > deadline.tv_sec ||
                (now.tv_sec == deadline.tv_sec &&
                 now.tv_nsec >= deadline.tv_nsec)) {
                time_t resolved = time(NULL);

                (void)send_event(event_fd, EVENT_STATUS, active->id,
                                 active->priority, STATUS_RESOLVED,
                                 active->created_at, resolved, resolved,
                                 active->issue,
                                 "Support request resolved successfully.");
                free(active);
                active = NULL;
                active_ticket = false;
            }
        }

        /* Start the next highest-priority ticket whenever the worker is idle. */
        if (running && !active_ticket && queue.head != NULL) {
            active = queue_pop(&queue);
            if (active != NULL) {
                time_t updated = time(NULL);
                (void)clock_gettime(CLOCK_MONOTONIC, &deadline);
                deadline.tv_sec += service_seconds(active->priority);
                active_ticket = true;

                (void)send_event(event_fd, EVENT_STATUS, active->id,
                                 active->priority, STATUS_IN_PROGRESS,
                                 active->created_at, updated, 0,
                                 active->issue,
                                 "Support engineer started processing this ticket.");
            }
        }
    }

    if (active != NULL) free(active);
    queue_destroy(&queue);
    (void)send_event(event_fd, EVENT_SERVICE_STOPPED, 0, 0, 0,
                     0, 0, 0, "", "Support service process is shutting down.");
    (void)close(request_fd);
    (void)close(event_fd);
    _exit(EXIT_SUCCESS);
}

static TicketRecord *find_ticket(TicketRecord *head, int id)
{
    TicketRecord *current = head;

    while (current != NULL) {
        if (current->id == id) return current;
        current = current->next;
    }
    return NULL;
}

static void add_ticket_record(TicketRecord **head, TicketRecord *record)
{
    TicketRecord **tail = head;

    while (*tail != NULL) tail = &(*tail)->next;
    *tail = record;
}

static void display_ticket(const TicketRecord *ticket)
{
    char created[32];
    char updated[32];
    char resolved[32];

    format_time(ticket->created_at, created, sizeof(created));
    format_time(ticket->updated_at, updated, sizeof(updated));
    format_time(ticket->resolved_at, resolved, sizeof(resolved));

    (void)printf("\n+----------------------------------------------------------+\n");
    (void)printf("|                    TICKET DETAILS                        |\n");
    (void)printf("+----------------------------------------------------------+\n");
    (void)printf("  Ticket ID       : TK-%04d\n", ticket->id);
    (void)printf("  Priority        : %s\n", priority_text(ticket->priority));
    (void)printf("  Status          : %s\n", status_text(ticket->status));
    (void)printf("  Issue           : %s\n", ticket->issue);
    (void)printf("  Created at      : %s\n", created);
    (void)printf("  Last updated    : %s\n", updated);
    (void)printf("  Resolved at     : %s\n", resolved);
    (void)printf("+----------------------------------------------------------+\n\n");
    (void)fflush(stdout);
}

static void display_all_tickets(TicketRecord *head)
{
    TicketRecord *current = head;

    if (current == NULL) {
        (void)printf("No tickets have been created in this session.\n");
        return;
    }

    (void)printf("\n%-10s %-9s %-15s %-22s %s\n",
                 "TICKET", "PRIORITY", "STATUS", "CREATED AT", "ISSUE");
    (void)printf("-------------------------------------------------------------------------------\n");

    while (current != NULL) {
        char created[32];
        format_time(current->created_at, created, sizeof(created));
        (void)printf("TK-%-7d %-9s %-15s %-22s %.55s\n",
                     current->id, priority_text(current->priority),
                     status_text(current->status), created, current->issue);
        current = current->next;
    }
    (void)printf("\n");
}

static void display_statistics(TicketRecord *head, const IpcStatistics *stats)
{
    TicketRecord *current = head;
    unsigned long total = 0UL;
    unsigned long high = 0UL;
    unsigned long medium = 0UL;
    unsigned long low = 0UL;
    unsigned long open = 0UL;
    unsigned long in_progress = 0UL;
    unsigned long resolved = 0UL;

    while (current != NULL) {
        ++total;
        if (current->priority == PRIORITY_HIGH) ++high;
        else if (current->priority == PRIORITY_MEDIUM) ++medium;
        else ++low;

        if (current->status == STATUS_OPEN) ++open;
        else if (current->status == STATUS_IN_PROGRESS) ++in_progress;
        else if (current->status == STATUS_RESOLVED) ++resolved;

        current = current->next;
    }

    (void)printf("\n============================================================\n");
    (void)printf("             PIPE CHAT - SESSION DASHBOARD\n");
    (void)printf("============================================================\n");
    (void)printf("TICKET SUMMARY\n");
    (void)printf("  Total tickets raised       : %lu\n", total);
    (void)printf("  High-priority tickets      : %lu\n", high);
    (void)printf("  Medium-priority tickets    : %lu\n", medium);
    (void)printf("  Low-priority tickets       : %lu\n", low);
    (void)printf("  Tickets resolved           : %lu\n", resolved);
    (void)printf("  Tickets open / queued      : %lu\n", open);
    (void)printf("  Tickets in progress        : %lu\n", in_progress);
    (void)printf("  Total pending              : %lu\n", open + in_progress);
    (void)printf("\nIPC COMMUNICATION SUMMARY\n");
    (void)printf("  Requests sent              : %llu\n", stats->total_requests);
    (void)printf("  Responses received         : %llu\n", stats->responses_received);
    (void)printf("  Bytes sent (Parent->Child) : %llu\n", stats->bytes_sent);
    (void)printf("  Bytes received (Child->Parent): %llu\n", stats->bytes_received);
    (void)printf("\nENCRYPTION SUMMARY\n");
    (void)printf("  Messages encrypted         : %llu\n", stats->encrypted_messages);
    (void)printf("  Messages decrypted         : %llu\n", stats->decrypted_messages);
    (void)printf("============================================================\n\n");
    (void)fflush(stdout);
}

static void log_event(const EventPacket *event)
{
    char line[640];
    char created[32];
    char updated[32];
    char resolved[32];

    if (event->ticket_id == 0) {
        (void)snprintf(line, sizeof(line), "SERVICE: %s", event->detail);
        append_log(line);
        return;
    }

    format_time((time_t)event->created_at, created, sizeof(created));
    format_time((time_t)event->updated_at, updated, sizeof(updated));
    format_time((time_t)event->resolved_at, resolved, sizeof(resolved));

    (void)snprintf(line, sizeof(line),
                   "TK-%04d | %s | %s | Created=%s | Updated=%s | Resolved=%s | Issue=%s | %s",
                   event->ticket_id, priority_text(event->priority),
                   status_text(event->status), created, updated, resolved,
                   event->issue, event->detail);
    append_log(line);
}

static int process_child_events(int event_fd, TicketRecord *tickets,
                                IpcStatistics *stats)
{
    struct pollfd descriptor;
    int processed = 0;

    descriptor.fd = event_fd;
    descriptor.events = POLLIN;
    descriptor.revents = 0;

    while (poll(&descriptor, 1U, 0) > 0 &&
           (descriptor.revents & POLLIN) != 0) {
        EventPacket event;
        TicketRecord *record;
        int result = read_full(event_fd, &event, sizeof(event));

        if (result <= 0) break;

        stats->bytes_received += (unsigned long long)sizeof(event);
        ++stats->responses_received;

        /* Decrypt child-to-parent event text after receiving the packet. */
        caesar_cipher(event.issue, 23);
        caesar_cipher(event.detail, 23);
        ++stats->encrypted_messages;
        ++stats->decrypted_messages;

        /* Acceptance also confirms the child decrypted the ticket request. */
        if (event.type == EVENT_ACCEPTED) {
            ++stats->decrypted_messages;
        }
        ++processed;

        log_event(&event);

        if (event.ticket_id == 0) {
            (void)printf("\n[SERVICE] %s\n", event.detail);
            continue;
        }

        record = find_ticket(tickets, event.ticket_id);
        if (record != NULL) {
            record->priority = event.priority;
            record->status = event.status;
            record->created_at = (time_t)event.created_at;
            record->updated_at = (time_t)event.updated_at;
            record->resolved_at = (time_t)event.resolved_at;
            (void)snprintf(record->issue, sizeof(record->issue), "%s",
                           event.issue);
        }

        (void)printf("\n[SUPPORT UPDATE] TK-%04d: %s\n",
                     event.ticket_id, event.detail);
        if (record != NULL) {
            (void)printf("  Current status: %s | Last updated: ",
                         status_text(record->status));
            {
                char updated[32];
                format_time(record->updated_at, updated, sizeof(updated));
                (void)printf("%s\n", updated);
            }
        }
    }
    return processed;
}

static int send_request(int request_fd, const RequestPacket *request,
                        IpcStatistics *stats)
{
    if (write_full_packet(request_fd, request, sizeof(*request)) < 0) {
        return -1;
    }
    stats->bytes_sent += (unsigned long long)sizeof(*request);
    ++stats->total_requests;
    if (request->type == REQ_CREATE) ++stats->encrypted_messages;
    return 0;
}

static void show_help(void)
{
    (void)printf("\nCOMMANDS\n");
    (void)printf("  /ticket <issue>  Create a new support ticket\n");
    (void)printf("  /status <id>     Display complete ticket information\n");
    (void)printf("  /tickets         List all tickets in this session\n");
    (void)printf("  /stat            Display detailed session statistics\n");
    (void)printf("  /start           Display service status\n");
    (void)printf("  /help            Display available commands\n");
    (void)printf("  /quit            Exit Pipe Chat\n\n");
    (void)printf("PRIORITY KEYWORDS\n");
    (void)printf("  HIGH   : urgent, critical, emergency, high\n");
    (void)printf("  MEDIUM : medium, moderate\n");
    (void)printf("  LOW    : default when no higher-priority keyword is found\n\n");
}

static void free_ticket_records(TicketRecord *head)
{
    while (head != NULL) {
        TicketRecord *next = head->next;
        free(head);
        head = next;
    }
}

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
                caesar_cipher(request.issue, 3);

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
        caesar_cipher(event.issue, 23);
        caesar_cipher(event.detail, 23);
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
