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
    iproute2

COPY bind-9.4.1.tar /tmp/
WORKDIR /tmp
RUN tar -xvf bind-9.4.1.tar &&\
    cd bind-9.4.1 &&\
    export LIBS="-lbsd -ldl" &&\
    ./configure --without-openssl --build=amd64-unknown-linux-gnu LDFLAGS="-L/usr/lib/x86_64-linux-gnu -lbsd -ldl" CFLAGS="-I/usr/include/bsd" &&\
    make clean &&\
    make LDFLAGS="-L/usr/lib/x86_64-linux-gnu -lbsd -ldl" CFLAGS="-I/usr/include/bsd" &&\
    make install
    
COPY named.conf /etc/named.conf
RUN chmod 644 /etc/named.conf

# COPY rndc.conf /etc/rndc.conf
# RUN chmod 644 /etc/rndc.conf

RUN mkdir /etc/bind/
COPY stub.zone /etc/bind/stub.zone
RUN chmod 644 /etc/bind/stub.zone

#EXPOSE 53/udp
#EXPOSE 53/tcp

# CMD /usr/local/sbin/named -4 -f

