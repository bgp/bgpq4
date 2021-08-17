ARG image=debian:buster
FROM $image

# From https://github.com/docker-library/postgres/blob/69bc540ecfffecce72d49fa7e4a46680350037f9/9.6/Dockerfile#L21-L24
RUN apt-get update && apt-get install -y locales && rm -rf /var/lib/apt/lists/* \
    && localedef -i en_US -c -f UTF-8 -A /usr/share/locale/locale.alias en_US.UTF-8
ENV LANG en_US.utf8

# Install dependencies
RUN apt-get update \
    && apt-get dist-upgrade -y \
    && apt-get install -y build-essential autoconf libtool automake markdown \
    && rm -rf /var/lib/apt/lists/*

# Add source code
ADD . /src
WORKDIR /src

# Run steps
RUN ./bootstrap
RUN ./configure
RUN make
RUN make check
RUN make distcheck

