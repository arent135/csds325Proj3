/*
Alex Renteria
abr92
proj3.c
10/24/2026
*/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <inttypes.h>

struct packet {
    unsigned short interface;
    struct timeval timestamp;
    struct iphdr ip;
    size_t ip_header_length;
    size_t transport_header_length;

    union {
        struct tcphdr tcp;
        struct udphdr udp;
    } transport;
};

int readPacket(FILE *trace_file, struct packet *packet) {
    unsigned short interface;
    unsigned short padding;
    unsigned int seconds;
    unsigned int microseconds;

    size_t n = fread(&interface, 1, 2, trace_file);

    if (n == 0) {
        return feof(trace_file) ? 0 : -1;
    }

    if (n != 2) {
        return -1;
    }

    if (fread(&padding, 1, 2, trace_file) != 2 ||
        fread(&seconds, 1, 4, trace_file) != 4 ||
        fread(&microseconds, 1, 4, trace_file) != 4) {
        return -1;
    }

    packet->interface = ntohs(interface);
    packet->timestamp.tv_sec = ntohl(seconds);
    packet->timestamp.tv_usec = ntohl(microseconds);

    if (fread(&packet->ip, 1, 20, trace_file) != 20) {
        return -1;
    }

    packet->ip_header_length = packet->ip.ihl * 4;
    if (packet->ip_header_length < 20 || packet->ip_header_length > 60) {
        return -1;
    }

    size_t ip_options_length = packet->ip_header_length - 20;
    unsigned char ip_options[40];
    if (fread(ip_options, 1, ip_options_length, trace_file) !=
        ip_options_length) {
        return -1;
    }

    if (packet->ip.protocol == IPPROTO_UDP) {
        if (fread(&packet->transport.udp, 1, 8, trace_file) != 8) {
            return -1;
        }

        packet->transport_header_length = 8;

    } else if (packet->ip.protocol == IPPROTO_TCP) {
        if (fread(&packet->transport.tcp, 1, 20, trace_file) != 20) {
            return -1;
        }

        size_t tcp_len = packet->transport.tcp.doff * 4;
        if (tcp_len < 20 || tcp_len > 60) {
            return -1;
        }

        size_t options_len = tcp_len - 20;
        unsigned char options[40];

        if (fread(options, 1, options_len, trace_file) != options_len) {
            return -1;
        }

        packet->transport_header_length = tcp_len;
    } else {
        packet->transport_header_length = 0;
    }

    return 1;
}

void usage(char *program)
{
    fprintf(stderr,
            "Usage: %s [-p] [-c] [-n] "
            "[-r trace_file]\n",
            program);
}

int printMode(FILE *trace_file) {
    struct packet packet;
    int result;
    char source[INET_ADDRSTRLEN];
    char destination[INET_ADDRSTRLEN];

    while ((result = readPacket(trace_file, &packet)) == 1) {
        struct in_addr source_address = { .s_addr = packet.ip.saddr };
        struct in_addr destination_address = { .s_addr = packet.ip.daddr };
        unsigned int ip_length = ntohs(packet.ip.tot_len);

        if (ip_length < packet.ip_header_length +
                        packet.transport_header_length) {
            return -1;
        }

        if (inet_ntop(AF_INET, &source_address, source, sizeof(source)) == NULL ||
            inet_ntop(AF_INET, &destination_address, destination,
                      sizeof(destination)) == NULL) {
            return -1;
        }

        if (packet.ip.protocol == IPPROTO_UDP) {
            unsigned int payload_length =
                ip_length - packet.ip_header_length -
                packet.transport_header_length;

            printf("%ld.%06ld %s %s %u U %u %u %u\n",
                   (long)packet.timestamp.tv_sec,
                   (long)packet.timestamp.tv_usec,
                   source, destination, ip_length,
                   (unsigned int)ntohs(packet.transport.udp.source),
                   (unsigned int)ntohs(packet.transport.udp.dest),
                   payload_length);
        } else if (packet.ip.protocol == IPPROTO_TCP) {
            unsigned int payload_length =
                ip_length - packet.ip_header_length -
                packet.transport_header_length;

            printf("%ld.%06ld %s %s %u T %u %u %zu %u %u ",
                   (long)packet.timestamp.tv_sec,
                   (long)packet.timestamp.tv_usec,
                   source, destination, ip_length,
                   (unsigned int)ntohs(packet.transport.tcp.source),
                   (unsigned int)ntohs(packet.transport.tcp.dest),
                   packet.transport_header_length,
                   payload_length,
                   (unsigned int)ntohl(packet.transport.tcp.seq));

            if (packet.transport.tcp.ack) {
                printf("%u\n",
                       (unsigned int)ntohl(packet.transport.tcp.ack_seq));
            } else {
                printf("-\n");
            }
        } else {
            printf("%ld.%06ld %s %s %u %u\n",
                   (long)packet.timestamp.tv_sec,
                   (long)packet.timestamp.tv_usec,
                   source, destination, ip_length,
                   (unsigned int)packet.ip.protocol);
        }
    }

    return result;
}

int countMode(FILE *trace_file) {
    uint64_t counts[256] = {0};
    struct packet packet;
    int result;

    while ((result = readPacket(trace_file, &packet)) == 1) {
        if (counts[packet.ip.protocol] == UINT64_MAX) {
            return -1;
        }
        counts[packet.ip.protocol]++;
    }

    if (result != 0) {
        return result;
    }

    for (size_t protocol = 0; protocol < sizeof(counts) / sizeof(counts[0]);
         protocol++) {
        if (counts[protocol] != 0) {
            printf("%zu %llu\n", protocol,
                   (unsigned long long)counts[protocol]);
        }
    }

    return 0;
}

#define INITIAL_BUCKETS 1024

struct flow {
    uint32_t ip_a;
    uint32_t ip_b;
    unsigned short port_a;
    unsigned short port_b;
    unsigned char protocol;

    struct timeval first_seen;
    struct timeval last_seen;

    uint64_t a2b_packets;
    uint64_t b2a_packets;
    uint64_t a2b_bytes;
    uint64_t b2a_bytes;

    struct flow *next;
};

struct flow_table {
    struct flow **buckets;
    size_t bucket_count;
    size_t flow_count;
};

int compareEndpoints(uint32_t ip1, unsigned short port1,
                     uint32_t ip2, unsigned short port2)
{
    if (ip1 < ip2) return -1;
    if (ip1 > ip2) return 1;
    if (port1 < port2) return -1;
    if (port1 > port2) return 1;
    return 0;
}

/* Normalize endpoints so a flow hashes the same in either direction. */
size_t hashFlow(uint32_t src_ip, unsigned short src_port,
                uint32_t dst_ip, unsigned short dst_port,
                unsigned char protocol, size_t bucket_count)
{
    if (compareEndpoints(src_ip, src_port, dst_ip, dst_port) > 0) {
        uint32_t temp_ip = src_ip;
        unsigned short temp_port = src_port;

        src_ip = dst_ip;
        src_port = dst_port;

        dst_ip = temp_ip;
        dst_port = temp_port;
    }

    uint64_t hash = 14695981039346656037ULL;
    const uint32_t values[] = {
        src_ip, src_port, dst_ip, dst_port, protocol
    };

    for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); i++) {
        uint32_t value = values[i];

        for (int j = 0; j < 4; j++) {
            hash ^= (value >> (j * 8)) & 0xff;
            hash *= 1099511628211ULL;
        }
    }

    return (size_t)(hash % bucket_count);
}

/* Reuse existing flow nodes while rebuilding the bucket array. */
int resizeFlowTable(struct flow_table *table)
{
    if (table->bucket_count > SIZE_MAX / 2) {
        return -1;
    }

    size_t new_count = table->bucket_count * 2;

    if (new_count > SIZE_MAX / sizeof(struct flow *)) {
        return -1;
    }

    struct flow **new_buckets =
        calloc(new_count, sizeof(struct flow *));

    if (new_buckets == NULL) {
        return -1;
    }

    for (size_t i = 0; i < table->bucket_count; i++) {
        struct flow *current = table->buckets[i];

        while (current != NULL) {
            struct flow *next = current->next;

            size_t index = hashFlow(
                current->ip_a, current->port_a,
                current->ip_b, current->port_b,
                current->protocol, new_count
            );

            current->next = new_buckets[index];
            new_buckets[index] = current;

            current = next;
        }
    }

    free(table->buckets);
    table->buckets = new_buckets;
    table->bucket_count = new_count;

    return 0;
}

/* is_a_to_b reports the packet direction relative to the stored flow. */
struct flow *getFlow(struct flow_table *table,
                     uint32_t src_ip, unsigned short src_port,
                     uint32_t dst_ip, unsigned short dst_port,
                     unsigned char protocol,
                     struct timeval timestamp,
                     int *is_a_to_b)
{
    size_t index = hashFlow(
        src_ip, src_port, dst_ip, dst_port,
        protocol, table->bucket_count
    );

    for (struct flow *current = table->buckets[index];
         current != NULL;
         current = current->next) {

        if (current->protocol != protocol) {
            continue;
        }

        if (current->ip_a == src_ip &&
            current->port_a == src_port &&
            current->ip_b == dst_ip &&
            current->port_b == dst_port) {

            *is_a_to_b = 1;
            return current;
        }

        if (current->ip_a == dst_ip &&
            current->port_a == dst_port &&
            current->ip_b == src_ip &&
            current->port_b == src_port) {

            *is_a_to_b = 0;
            return current;
        }
    }

    if (table->flow_count >= table->bucket_count * 2) {
        if (resizeFlowTable(table) != 0) {
            return NULL;
        }

        index = hashFlow(
            src_ip, src_port, dst_ip, dst_port,
            protocol, table->bucket_count
        );
    }

    struct flow *new_flow = calloc(1, sizeof(struct flow));

    if (new_flow == NULL) {
        return NULL;
    }

    new_flow->ip_a = src_ip;
    new_flow->port_a = src_port;
    new_flow->ip_b = dst_ip;
    new_flow->port_b = dst_port;
    new_flow->protocol = protocol;

    new_flow->first_seen = timestamp;
    new_flow->last_seen = timestamp;

    new_flow->next = table->buckets[index];
    table->buckets[index] = new_flow;
    table->flow_count++;

    *is_a_to_b = 1;

    return new_flow;
}

static int compareFlows(const void *left, const void *right)
{
    const struct flow *first = *(const struct flow *const *)left;
    const struct flow *second = *(const struct flow *const *)right;
    uint32_t first_ip_a = ntohl(first->ip_a);
    uint32_t second_ip_a = ntohl(second->ip_a);
    uint32_t first_ip_b = ntohl(first->ip_b);
    uint32_t second_ip_b = ntohl(second->ip_b);

    if (first_ip_a != second_ip_a) {
        return first_ip_a < second_ip_a ? -1 : 1;
    }
    if (first->port_a != second->port_a) {
        return first->port_a < second->port_a ? -1 : 1;
    }
    if (first_ip_b != second_ip_b) {
        return first_ip_b < second_ip_b ? -1 : 1;
    }
    if (first->port_b != second->port_b) {
        return first->port_b < second->port_b ? -1 : 1;
    }
    if (first->protocol != second->protocol) {
        return first->protocol < second->protocol ? -1 : 1;
    }
    return 0;
}

static int updateFlow(struct flow *flow, int is_a_to_b,
                      struct timeval timestamp, unsigned int payload_length)
{
    if (timestamp.tv_sec > flow->last_seen.tv_sec ||
        (timestamp.tv_sec == flow->last_seen.tv_sec &&
         timestamp.tv_usec > flow->last_seen.tv_usec)) {
        flow->last_seen = timestamp;
    }

    uint64_t *packets = is_a_to_b
        ? &flow->a2b_packets : &flow->b2a_packets;
    uint64_t *bytes = is_a_to_b
        ? &flow->a2b_bytes : &flow->b2a_bytes;

    if (*packets == UINT64_MAX || UINT64_MAX - *bytes < payload_length) {
        return -1;
    }

    (*packets)++;
    *bytes += payload_length;
    return 0;
}

static int printFlows(const struct flow_table *table)
{
    if (table->flow_count > SIZE_MAX / sizeof(struct flow *)) {
        return -1;
    }

    struct flow **ordered_flows = NULL;
    if (table->flow_count != 0) {
        ordered_flows = malloc(table->flow_count * sizeof(*ordered_flows));
        if (ordered_flows == NULL) {
            return -1;
        }
    }

    size_t next_flow = 0;
    for (size_t i = 0; i < table->bucket_count; i++) {
        for (struct flow *flow = table->buckets[i];
             flow != NULL;
             flow = flow->next) {
            ordered_flows[next_flow++] = flow;
        }
    }

    if (table->flow_count > 1) {
        qsort(ordered_flows, table->flow_count, sizeof(*ordered_flows),
              compareFlows);
    }

    int result = 0;
    for (size_t i = 0; i < table->flow_count; i++) {
        const struct flow *flow = ordered_flows[i];
        struct in_addr address_a = { .s_addr = flow->ip_a };
        struct in_addr address_b = { .s_addr = flow->ip_b };

        char ip_a[INET_ADDRSTRLEN];
        char ip_b[INET_ADDRSTRLEN];
        if (inet_ntop(AF_INET, &address_a, ip_a, sizeof(ip_a)) == NULL ||
            inet_ntop(AF_INET, &address_b, ip_b, sizeof(ip_b)) == NULL) {
            result = -1;
            break;
        }

        double first_time =
            (double)flow->first_seen.tv_sec +
            (double)flow->first_seen.tv_usec / 1000000.0;
        double last_time =
            (double)flow->last_seen.tv_sec +
            (double)flow->last_seen.tv_usec / 1000000.0;

        printf("%s %hu %s %hu %c %.6f %.6f "
               "%" PRIu64 " %" PRIu64 " "
               "%" PRIu64 " %" PRIu64 "\n",
               ip_a, flow->port_a,
               ip_b, flow->port_b,
               flow->protocol == IPPROTO_UDP ? 'U' : 'T',
               first_time, last_time - first_time,
               flow->a2b_packets,
               flow->b2a_packets,
               flow->a2b_bytes,
               flow->b2a_bytes);
    }

    free(ordered_flows);
    return result;
}

int flowMode(FILE *trace_file)
{
    struct flow_table table = {0};
    table.bucket_count = INITIAL_BUCKETS;
    table.buckets = calloc(table.bucket_count, sizeof(*table.buckets));
    if (table.buckets == NULL) {
        return -1;
    }

    struct packet packet;
    int result;

    while ((result = readPacket(trace_file, &packet)) == 1) {
        if (packet.ip.protocol != IPPROTO_TCP &&
            packet.ip.protocol != IPPROTO_UDP) {
            continue;
        }

        unsigned int ip_length = ntohs(packet.ip.tot_len);
        if (ip_length < packet.ip_header_length +
                        packet.transport_header_length) {
            result = -1;
            break;
        }

        unsigned short src_port;
        unsigned short dst_port;
        if (packet.ip.protocol == IPPROTO_TCP) {
            src_port = ntohs(packet.transport.tcp.source);
            dst_port = ntohs(packet.transport.tcp.dest);
        } else {
            src_port = ntohs(packet.transport.udp.source);
            dst_port = ntohs(packet.transport.udp.dest);
        }

        int is_a_to_b;
        struct flow *flow = getFlow(
            &table, packet.ip.saddr, src_port,
            packet.ip.daddr, dst_port, packet.ip.protocol,
            packet.timestamp, &is_a_to_b
        );
        if (flow == NULL) {
            result = -1;
            break;
        }

        unsigned int payload_length =
            ip_length - packet.ip_header_length -
            packet.transport_header_length;
        if (updateFlow(flow, is_a_to_b, packet.timestamp, payload_length) != 0) {
            result = -1;
            break;
        }
    }

    if (result == 0) {
        result = printFlows(&table);
    }

    for (size_t i = 0; i < table.bucket_count; i++) {
        struct flow *current = table.buckets[i];

        while (current != NULL) {
            struct flow *next = current->next;
            free(current);
            current = next;
        }
    }

    free(table.buckets);

    return result;
}


int main(int argc, char *argv[]) {
    int opt;
    int mode = 0;
    char *trace_file = NULL;

    while ((opt = getopt(argc, argv, "pcnr:")) != -1) {
        switch (opt) {
        case 'p':
            if (mode != 0) {
                fprintf(stderr, "Error: multiple modes specified.\n");
                exit(1);
            }
            mode = 'p';
            break;

        case 'c':
            if (mode != 0) {
                fprintf(stderr, "Error: multiple modes specified.\n");
                exit(1);
            }
            mode = 'c';
            break;

        case 'n':
            if (mode != 0) {
                fprintf(stderr, "Error: multiple modes specified.\n");
                exit(1);
            }
            mode = 'n';
            break;

        case 'r':
            trace_file = optarg;
            break;

        default:
            usage(argv[0]);
            exit(1);
        }
    }

    if (mode == 0) {
        fprintf(stderr, "Error: must specify -p, -c, or -n.\n");
        exit(1);
    }

    if (trace_file == NULL) {
        fprintf(stderr, "Error: must give a trace file with -r.\n");
        exit(1);
    }

    FILE *input = fopen(trace_file, "rb");
    if (input == NULL) {
        perror(trace_file);
        exit(1);
    }

    int result;
    if (mode == 'p') {
        result = printMode(input);
    } else if (mode == 'c') {
        result = countMode(input);
    } else {
        result = flowMode(input);
    }

    if (fclose(input) != 0) {
        perror("Error closing packet trace");
        exit(1);
    }

    if (result != 0) {
        fprintf(stderr, "Error: failed to process packet trace.\n");
        exit(1);
    }

    exit(0);
}