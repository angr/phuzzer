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

# AFL
# RUN git clone https://github.com/google/AFL.git /usr/bin/afl-unix
# RUN cd /usr/bin/afl-unix && make && make install

# PHUZZER & DEPS
RUN pip3 install git+https://github.com/shellphish/shellphish-afl
RUN pip3 install git+https://github.com/shellphish/driller
RUN pip3 install git+https://github.com/angr/tracer
RUN pip3 install git+https://github.com/angr/phuzzer

# Shellphish-AFL Symlinks
RUN ln -s /usr/local/bin/afl-cgc /usr/bin/afl-cgc
RUN ln -s /usr/local/bin/afl-multi-cgc /usr/bin/afl-multi-cgc
RUN ln -s /usr/local/bin/afl-unix /usr/bin/afl-unix
RUN ln -s /usr/local/bin/fuzzer-libs /usr/bin/fuzzer-libs
RUN ln -s /usr/local/bin/driller /usr/bin/driller
