# Pipe Chat – Modular Linux C Project

## Project structure

```text
pipe_chat_modular/
├── pipe_chat.h       # Shared macros, enums, structures and prototypes
├── main.c            # Parent process and command-line interface
├── ipc.c             # Pipe packet read/write and IPC byte accounting
├── crypto.c          # Caesar cipher and priority keyword detection
├── ticket.c          # Ticket linked list, display and statistics
├── queue.c           # Child-side priority queue (sorted linked list)
├── logger.c          # Timestamp formatting and audit logging
├── service.c         # Child support process and ticket processing
├── events.c          # Child-event reception and command help
└── Makefile          # Multi-file build
```

## Compile and run

```bash
make
./pipe_chat
```

Or compile directly:

```bash
gcc -std=c11 -Wall -Wextra -Wpedantic -O2 \
    main.c ipc.c crypto.c ticket.c queue.c logger.c service.c events.c \
    -o pipe_chat
```

## Commands

- `/ticket <issue>` – create a support ticket
- `/status <id>` – display complete ticket details and timestamps
- `/tickets` – list all tickets
- `/stat` – detailed ticket, IPC byte and encryption statistics
- `/start` – display service status
- `/help` – list commands
- `/quit` – exit

## Design preserved

This is a modular reorganization of the previous single-file implementation.
It retains the same parent/child two-pipe IPC architecture, ticket fields,
priority keyword detection, priority queue scheduling, processing durations,
bidirectional Caesar cipher demonstration, timestamps, audit log permissions,
and session statistics.

Data structures:
- Parent ticket registry: linked list.
- Child waiting-ticket scheduler: priority queue implemented as a sorted linked list,
  FIFO for equal priorities.
- IPC packet and command buffers: fixed-size arrays.

`pipe_chat.log` persists across runs; ticket records and session statistics are
in memory and reset when the program exits.

## Important security note

Caesar cipher is only a teaching demonstration and is not secure encryption.
Do not use it to protect actual customer data.
