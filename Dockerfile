FROM ubuntu:18.04

# build essentials,
RUN apt-get update && apt-get install -y software-properties-common && \
    apt-add-repository -y universe && \
    apt-get update && \
    apt-get install -y \
    build-essential \
    gcc-multilib \
    libtool \
    automake \
    autoconf \
    bison \
    git \
    gcc \
    debootstrap \
    debian-archive-keyring \
    libtool-bin \
    python3 \
    python3-dev \ 
    python3-pip
    
    
# install QEMU 
RUN cp /etc/apt/sources.list /etc/apt/sources.list~ && sed -Ei 's/^# deb-src /deb-src /' /etc/apt/sources.list && \
    apt-get update && DEBIAN_FRONTEND=noninteractive apt-get build-dep -y qemu 

# Shellphish-AFL Deps
RUN bash -c "pip3 install https://github.com/angr/wheels/blob/master/shellphish_afl-1.2.1-py2.py3-none-manylinux1_x86_64.whl?raw=true && \
    pip3 install git+https://github.com/shellphish/driller && \
    pip3 install git+https://github.com/angr/tracer" 

# Shellphish-AFL Symlinks
RUN bash -c "ln -s /usr/local/bin/afl-cgc /usr/bin/afl-cgc && \
    ln -s /usr/local/bin/afl-multi-cgc /usr/bin/afl-multi-cgc && \
    ln -s /usr/local/bin/afl-unix /usr/bin/afl-unix && \
    ln -s /usr/local/bin/fuzzer-libs /usr/bin/fuzzer-libs && \
    ln -s /usr/local/bin/driller /usr/bin/driller" 

# Construct place for new phuzzers to live 
RUN mkdir /phuzzers 

# --- new fuzzer backends go here --- # 

# Install IJON Fuzzer
RUN cd /phuzzers && \
    git clone https://github.com/RUB-SysSec/ijon && \
    apt-get install clang -y && \
    cd ijon && make && cd llvm_mode && LLVM_CONFIG=llvm-config-6.0 CC=clang-6.0 make

# Install AFL++
RUN cd /phuzzers/ && \
    bash -c "$(wget -O - https://apt.llvm.org/llvm.sh)" && \
    git clone https://github.com/AFLplusplus/AFLplusplus && \
    cd AFLplusplus && \
    apt install build-essential libtool-bin python3-dev automake flex bison ipython3 \
    libglib2.0-dev libpixman-1-dev clang python3-setuptools llvm -y && \
    LLVM_CONFIG=llvm-config-11 make distrib && \
    make install -j 8

# Install the phuzzer framework 
COPY . ./phuzzer
RUN pip3 install ./phuzzer 
