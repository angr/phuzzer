FROM ubuntu:18.04

# build essentials, python3, qemu and other deps
RUN apt-get update && apt-get install -y software-properties-common
RUN apt-add-repository -y universe
RUN apt-get install -y \
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
        libtool-bin

# for QEMU compiling
RUN cp /etc/apt/sources.list /etc/apt/sources.list~
RUN sed -Ei 's/^# deb-src /deb-src /' /etc/apt/sources.list
RUN apt-get update

RUN DEBIAN_FRONTEND=noninteractive apt-get build-dep -y \
	qemu
RUN apt-get install -y \
	python3 \
	python3-pip 

# PHUZZER & DEPS
RUN pip3 install git+https://github.com/shellphish/shellphish-afl
RUN pip3 install git+https://github.com/shellphish/driller
RUN pip3 install git+https://github.com/angr/tracer

# Shellphish-AFL Symlinks
RUN ln -s /usr/local/bin/afl-cgc /usr/bin/afl-cgc
RUN ln -s /usr/local/bin/afl-multi-cgc /usr/bin/afl-multi-cgc
RUN ln -s /usr/local/bin/afl-unix /usr/bin/afl-unix
RUN ln -s /usr/local/bin/fuzzer-libs /usr/bin/fuzzer-libs
RUN ln -s /usr/local/bin/driller /usr/bin/driller

# Install IJON Phuzzer port
RUN git clone --single-branch --branch ijon-support https://github.com/angr/phuzzer && \
        pip3 install ./phuzzer

# Install IJON Fuzzer
RUN mkdir /phuzzers/ && cd /phuzzers && \
        git clone https://github.com/RUB-SysSec/ijon && \
        apt-get install clang -y && \
        cd ijon && make && cd llvm_mode && LLVM_CONFIG=llvm-config-6.0 CC=clang-6.0 make


# Install AFL++
RUN cd /phuzzers/ && \
        git clone https://github.com/AFLplusplus/AFLplusplus && \
        cd AFLplusplus && \
        apt install build-essential libtool-bin python3-dev automake flex bison ipython3 \
        libglib2.0-dev libpixman-1-dev clang python3-setuptools llvm -y && \
        make distrib && \
        make install

# Install Other Fuzzers...
