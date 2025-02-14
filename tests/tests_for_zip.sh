#!/bin/bash

# === CONFIGURATION ===
ZIP_FILE="$1"
EXTRACT_DIR="/tmp/ex2_validation"
REQUIRED_FILES=("ex2_client.c" "ex2_server.c" "explanation.txt" "readme.txt")

# Docker Container Details
RESOLVER_IP="192.168.1.203"
TARGET_DOMAIN="www.example.cybercourse.com"
WANTED_TARGET_IP="6.6.6.6"
ATTACKER_AUTH_STARTUP_TIME=1

# === COLORS FOR OUTPUT ===
echo_red() { echo -e "\033[31m$*\033[0m"; }
echo_green() { echo -e "\033[32m$*\033[0m"; }

# === CLEANUP FUNCTION ===
cleanup() {
    echo "Cleaning up..."
    docker exec attacker-auth /bin/bash -c "rm -rf /tmp/test 2> /dev/null"
    docker exec attacker-client /bin/bash -c "rm -rf /tmp/test 2> /dev/null"
    rm -rf "$EXTRACT_DIR"
}

# === VALIDATE ZIP FILE ===
if [ ! -f "$ZIP_FILE" ]; then
    echo_red "Error: ZIP file not found."
    exit 1
fi

if [ "$ZIP_FILE" != "ex2.zip" ]; then
    echo_red "Error: ZIP file name is not 'ex2.zip'"
    exit 1
fi

echo "Extracting ZIP file..."
mkdir -p "$EXTRACT_DIR"
unzip -q "$ZIP_FILE" -d "$EXTRACT_DIR"
if [ $? -ne 0 ]; then
    echo_red "Error: Failed to extract ZIP file."
    cleanup
    exit 1
fi

# === VALIDATE REQUIRED FILES ===
echo "Validating required files..."
for file in "${REQUIRED_FILES[@]}"; do
    if [ ! -f "$EXTRACT_DIR/$file" ]; then
        echo_red "Error: Missing required file: $file"
        cleanup
        exit 1
    fi
done
echo_green "All required files are present."

# === VALIDATE EXPLANATION FILE ===
if [ ! -s "$EXTRACT_DIR/explanation.txt" ]; then
    echo_red "Error: explanation.txt is empty or missing content."
    cleanup
    exit 1
fi
echo_green "explanation.txt is valid."

# === VALIDATE README FILE ===
if ! grep -qE '^[0-9]+(,[0-9]+)?$' "$EXTRACT_DIR/readme.txt"; then
    echo_red "Error: readme.txt does not contain valid student IDs."
    cleanup
    exit 1
fi
echo_green "readme.txt is valid."

# === DEPLOY FILES TO DOCKER ===
echo "Copying files to Docker containers..."
docker cp "$EXTRACT_DIR/ex2_server.c" attacker-auth:/tmp/attackerAuthNS/
docker cp "$EXTRACT_DIR/ex2_client.c" attacker-client:/tmp/mclient/
if [ $? -ne 0 ]; then
    echo_red "Error: Failed to copy files to containers."
    cleanup
    exit 1
fi
echo_green "Files copied successfully."

# === COMPILE CODE WITH MEMORY LEAK CHECK ===
echo "Compiling the server and client with AddressSanitizer..."
docker exec -w "/tmp/attackerAuthNS/" attacker-auth /bin/bash -c "gcc -fsanitize=address -g -Wall -Wextra -Werror ex2_server.c -lldns -lpcap -o ex2_server"
if [ $? -ne 0 ]; then
    echo_red "Error: Failed to compile ex2_server.c"
    cleanup
    exit 1
fi

docker exec -w "/tmp/mclient/" attacker-client /bin/bash -c "gcc -fsanitize=address -g -Wall -Wextra -Werror ex2_client.c -lldns -lpcap -o ex2_client"
if [ $? -ne 0 ]; then
    echo_red "Error: Failed to compile ex2_client.c"
    cleanup
    exit 1
fi
echo_green "Compilation successful with memory leak checks enabled."

# === FLUSH CACHE ===
echo "Flushing resolver cache..."
docker exec bind9res rndc flush

# === START SERVER ===
echo "Starting the server..."
docker exec -w "/tmp/attackerAuthNS/" attacker-auth /bin/bash -c "./ex2_server > server_output 2>&1" &
SERVER_PID=$!
sleep $ATTACKER_AUTH_STARTUP_TIME

# === START CLIENT ===
echo "Starting the client..."
docker exec -w "/tmp/mclient/" attacker-client /bin/bash -c "./ex2_client > client_output 2>&1" &
CLIENT_PID=$!

# Wait for processes to complete
wait $SERVER_PID
SERVER_RET=$?
wait $CLIENT_PID
CLIENT_RET=$?
echo "Server and client finished."
echo "Server return code: $SERVER_RET"
echo "Client return code: $CLIENT_RET"

# === VALIDATE RESULTS ===
echo "Validating attack result..."
RESOLVED_TARGET_IP=$(docker exec client /bin/bash -c "dig @$RESOLVER_IP $TARGET_DOMAIN +short")
echo "Resolved IP: $RESOLVED_TARGET_IP"

TEST_PASSED=1

if [ "$RESOLVED_TARGET_IP" != "$WANTED_TARGET_IP" ]; then
    echo_red "Test failed: The target domain resolved to $RESOLVED_TARGET_IP instead of $WANTED_TARGET_IP"
    TEST_PASSED=0
fi

if [ $SERVER_RET -ne 0 ]; then
    echo_red "Test failed: Server did not exit cleanly."
    TEST_PASSED=0
fi

if [ $CLIENT_RET -ne 0 ]; then
    echo_red "Test failed: Client did not exit cleanly."
    TEST_PASSED=0
fi

SERVER_OUTPUT_LENGTH=$(docker exec attacker-auth /bin/bash -c "cat /tmp/attackerAuthNS/server_output | wc -l")
if [ $SERVER_OUTPUT_LENGTH -ne 0 ]; then
    echo_red "Test failed: Server output is not empty."
    TEST_PASSED=0
fi

CLIENT_OUTPUT_LENGTH=$(docker exec attacker-client /bin/bash -c "cat /tmp/mclient/client_output | wc -l")
if [ $CLIENT_OUTPUT_LENGTH -ne 0 ]; then
    echo_red "Test failed: Client output is not empty."
    TEST_PASSED=0
fi

# === DISPLAY RESULT ===
if [ $TEST_PASSED -eq 1 ]; then
    echo_green "[TEST PASSED]"
else
    echo_red "[TEST FAILED]"
fi

# === CLEANUP ===
cleanup