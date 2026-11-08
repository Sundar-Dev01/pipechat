#include "pipe_chat.h"
#include <poll.h>
#include <stdio.h>
#include <string.h>

int process_child_events(int event_fd, TicketRecord *tickets,
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
        caesar_cipher(event.issue, CAESAR_DECRYPT_SHIFT);
        caesar_cipher(event.detail, CAESAR_DECRYPT_SHIFT);
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

        if (event.type == EVENT_ACCEPTED) {
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
    }
    return processed;
}

void show_help(void)
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
