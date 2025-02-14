FROM ubuntu:24.04

RUN apt-get update &&\
    apt-get install -y\
    build-essential \
    libtool \
    make \
    tar \
    curl \
    vim \
    nmap \
    net-tools \
    libssl-dev \
    libcrypto++-dev \
    libc-dev \
    libc6-dev \
    libbsd-dev \
    libssl3 \
    libcrypto++-dev \
    libcurl4-openssl-dev \
    libidn11-dev \
    libxml2-dev \
    libbsd0 \
    lsof \
    iputils-ping \
    dnsutils \ 
    tcpdump \
    libpcap-dev \
    openssl \
    iproute2 \
    libldns-dev \
    gdb
    
# COPY ldns-1.8.4.tar.gz /tmp/
WORKDIR /tmp
# RUN tar -xvf ldns-1.8.4.tar.gz &&\
#    cd ldns-1.8.4 &&\
#    ./configure --with-examples --with-drill &&\
#    make &&\
#    make install
    
COPY resolv.conf /etc/resolv.conf

#EXPOSE 4442/tcp
#EXPOSE 4442/udp
