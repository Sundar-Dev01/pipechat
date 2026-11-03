#include "pipe_chat.h"
#include <stdlib.h>
#include <stdio.h>

void queue_insert(PriorityQueue *queue, const RequestPacket *request)
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

QueueNode *queue_pop(PriorityQueue *queue)
{
    QueueNode *node = queue->head;

    if (node != NULL) {
        queue->head = node->next;
        node->next = NULL;
        --queue->count;
    }
    return node;
}

void queue_destroy(PriorityQueue *queue)
{
    QueueNode *node;

    while ((node = queue_pop(queue)) != NULL) {
        free(node);
    }
}
