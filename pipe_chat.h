#ifndef PIPE_CHAT_H
#define PIPE_CHAT_H

#define _POSIX_C_SOURCE 200809L

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <time.h>

#define ISSUE_LENGTH 256
#define INPUT_LENGTH 320
#define LOG_PATH "pipe_chat.log"
#define HIGH_SECONDS 5
#define MEDIUM_SECONDS 7
#define LOW_SECONDS 15
#define CAESAR_ENCRYPT_SHIFT 3
#define CAESAR_DECRYPT_SHIFT 23

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
    char issue[ISSUE_LENGTH];
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

/* IPC */
int read_full(int fd, void *buffer, size_t length);
int write_full_packet(int fd, const void *packet, size_t length);
int send_request(int request_fd, const RequestPacket *request,
                 IpcStatistics *stats);

/* Caesar cipher and priority detection */
void caesar_cipher(char *text, int shift);
int contains_keyword(const char *text, const char *keyword);
int detect_priority(const char *issue);

/* Ticket and status helpers */
const char *priority_text(int priority);
const char *status_text(int status);
TicketRecord *find_ticket(TicketRecord *head, int id);
void add_ticket_record(TicketRecord **head, TicketRecord *record);
void display_ticket(const TicketRecord *ticket);
void display_all_tickets(TicketRecord *head);
void display_statistics(TicketRecord *head, const IpcStatistics *stats);
void free_ticket_records(TicketRecord *head);

/* Priority queue */
void queue_insert(PriorityQueue *queue, const RequestPacket *request);
QueueNode *queue_pop(PriorityQueue *queue);
void queue_destroy(PriorityQueue *queue);

/* Logging and timestamps */
void format_time(time_t value, char *buffer, size_t capacity);
void append_log(const char *message);
void log_event(const EventPacket *event);

/* Support child process and IPC events */
int service_seconds(int priority);
int send_event(int fd, int type, int id, int priority, int status,
               time_t created, time_t updated, time_t resolved,
               const char *issue, const char *detail);
void child_process(int request_fd, int event_fd);
int process_child_events(int event_fd, TicketRecord *tickets,
                         IpcStatistics *stats);
void show_help(void);

#endif
