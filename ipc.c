#include "pipe_chat.h"
#include <errno.h>
#include <unistd.h>

int read_full(int fd, void *buffer, size_t length)
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

int write_full_packet(int fd, const void *packet, size_t length)
{
    ssize_t amount;

    do {
        amount = write(fd, packet, length);
    } while (amount < 0 && errno == EINTR);

    return amount == (ssize_t)length ? 0 : -1;
}

int send_request(int request_fd, const RequestPacket *request,
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
