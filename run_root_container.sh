#!/bin/bash

docker start bind9root &&\
docker exec bind9root tc qdisc add dev eth0 root netem delay 200ms &&\
docker exec -it bind9root /bin/bash
