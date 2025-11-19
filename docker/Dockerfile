# docker/Dockerfile
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \ 
    python3 python3-pip git clang llvm libbpf-dev linux-headers-generic \ 
    bpfcc-tools iproute2 && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY ebpf ./ebpf
COPY user ./user
COPY webui ./webui

RUN pip3 install bcc flask pyyaml

EXPOSE 8080

WORKDIR /app/user
CMD ["python3", "loader.py", "--iface", "eth0", "--policy", "./config/policy.yaml"]
