ARG image=alpine:latest
FROM $image

# Install dependencies
RUN apk upgrade
RUN apk add autoconf automake file gcc gzip libtool make musl-dev

# Add source code
ADD . /src
WORKDIR /src

# Run steps
RUN ./bootstrap
RUN ./configure
RUN make
RUN make check
RUN make distcheck
