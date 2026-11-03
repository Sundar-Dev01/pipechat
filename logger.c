#include "pipe_chat.h"
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

void format_time(time_t value, char *buffer, size_t capacity)
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

void append_log(const char *message)
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

void log_event(const EventPacket *event)
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
