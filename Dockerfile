FROM angr/angr:latest

RUN apt-get update && \
    apt-get install -y libtool-bin automake libc6-dev bison

USER angr
WORKDIR /home/angr/angr-dev

RUN bash -c "source ~/.virtualenvs/angr/bin/activate && \
    pip install https://github.com/angr/wheels/blob/master/shellphish_qemu-0.9.10-py3-none-manylinux1_x86_64.whl?raw=true && \
    pip install https://github.com/angr/wheels/blob/master/shellphish_afl-1.2.1-py2.py3-none-manylinux1_x86_64.whl?raw=true && \
    ./setup.sh -e angr tracer driller"

ADD --chown=angr:angr . /home/angr/angr-dev/phuzzer
RUN bash -c "source ~/.virtualenvs/angr/bin/activate &&  pip install -e ./phuzzer"

CMD bash
