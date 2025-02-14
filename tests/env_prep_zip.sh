#!/bin/bash

# configuration
containers=("bind9res" "bind9root" "attacker-client" "attacker-auth" "client")
dns_port=53

# colors for output
echo_red() { echo -e "\033[31m$*\033[0m"; }
echo_green() { echo -e "\033[32m$*\033[0m"; }

# start necessary docker containers
echo "starting necessary docker containers..."
for container in "${containers[@]}"; do
    if ! docker ps -a --format '{{.Names}}' | grep -x "$container" >/dev/null; then
        echo_red "error: docker container $container does not exist."
        exit 1
    fi

    if ! docker ps --format '{{.Names}}' | grep -x "$container" >/dev/null; then
        echo "starting container: $container"
        docker start "$container"
    else
        echo "container $container is already running."
    fi
done
echo_green "all required containers are running."

# start bind9root and apply network delay
echo "starting bind9root and adding network delay..."
docker exec bind9root tc qdisc del dev eth0 root 2>/dev/null || true
docker exec bind9root tc qdisc add dev eth0 root netem delay 200ms
if [ $? -ne 0 ]; then
    echo_red "failed to add network delay on bind9root."
    exit 1
fi
echo_green "bind9root started with a 200ms network delay."

# start named daemons on bind9res and bind9root
echo "starting 'named' daemons on resolver and root server..."

start_named() {
    local container=$1
    docker exec "$container" /bin/bash -c "named -4"
    if [ $? -ne 0 ]; then
        echo_red "failed to start 'named' daemon on $container."
        exit 1
    fi
    echo_green "'named' daemon started successfully on $container."
}

start_named bind9res
start_named bind9root

# verify dns servers are listening on port 53
echo "verifying dns servers are listening on port 53..."

check_dns_listening() {
    local container=$1
    local port=$2
    docker exec "$container" /bin/bash -c "lsof -i :$port | grep LISTEN" &>/dev/null
    if [ $? -eq 0 ]; then
        echo_green "dns server is listening on port $port in $container."
    else
        echo_red "dns server is not listening on port $port in $container."
        exit 1
    fi
}

check_dns_listening bind9res $dns_port
check_dns_listening bind9root $dns_port

echo_green "both dns servers are actively listening on port 53."

# flush dns cache
echo "flushing dns resolver cache..."
docker exec bind9res rndc flush
if [ $? -ne 0 ]; then
    echo_red "failed to flush dns cache on bind9res."
    exit 1
fi
echo_green "dns cache flushed on resolver"

# verify docker containers' health
echo "verifying docker containers' health..."
for container in "${containers[@]}"; do
    status=$(docker inspect --format='{{.State.Status}}' "$container")
    if [ "$status" != "running" ]; then
        echo_red "error: container $container is not in 'running' state."
        exit 1
    fi
done
echo_green "all docker containers are healthy and running."

# summary
echo_green "environment is ready for testing. proceed with your test script."
