#ifdef ENABLE_GCOV_DUMP
#include <gcov.h>
#endif
#include "pipe_chat.h"
#include <errno.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int service_seconds(int priority)
{
    if (priority == PRIORITY_HIGH) return HIGH_SECONDS;
    if (priority == PRIORITY_MEDIUM) return MEDIUM_SECONDS;
    return LOW_SECONDS;
}

int send_event(int fd, int type, int id, int priority, int status,
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
    caesar_cipher(event.issue, CAESAR_ENCRYPT_SHIFT);
    caesar_cipher(event.detail, CAESAR_ENCRYPT_SHIFT);
    return write_full_packet(fd, &event, sizeof(event));
}

void child_process(int request_fd, int event_fd)
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
                caesar_cipher(request.issue, CAESAR_DECRYPT_SHIFT);
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
    #ifdef ENABLE_GCOV_DUMP
    __gcov_dump();
    #endif
    _exit(EXIT_SUCCESS);
}
