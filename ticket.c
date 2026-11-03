#include "pipe_chat.h"
#include <stdio.h>
#include <stdlib.h>

const char *priority_text(int priority)
{
    if (priority == PRIORITY_HIGH) return "HIGH";
    if (priority == PRIORITY_MEDIUM) return "MEDIUM";
    return "LOW";
}

const char *status_text(int status)
{
    if (status == STATUS_OPEN) return "OPEN";
    if (status == STATUS_IN_PROGRESS) return "IN PROGRESS";
    if (status == STATUS_RESOLVED) return "RESOLVED";
    return "UNKNOWN";
}

TicketRecord *find_ticket(TicketRecord *head, int id)
{
    TicketRecord *current = head;

    while (current != NULL) {
        if (current->id == id) return current;
        current = current->next;
    }
    return NULL;
}

void add_ticket_record(TicketRecord **head, TicketRecord *record)
{
    TicketRecord **tail = head;

    while (*tail != NULL) tail = &(*tail)->next;
    *tail = record;
}

void display_ticket(const TicketRecord *ticket)
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

void display_all_tickets(TicketRecord *head)
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

void display_statistics(TicketRecord *head, const IpcStatistics *stats)
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

void free_ticket_records(TicketRecord *head)
{
    while (head != NULL) {
        TicketRecord *next = head->next;
        free(head);
        head = next;
    }
}
