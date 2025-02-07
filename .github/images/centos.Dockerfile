ARG image=centos/centos:latest
FROM quay.io/$image

# Install dependencies
RUN dnf -y update
RUN dnf -y install autoconf automake gcc libtool make diffutils file gzip

# Add source code
ADD . /src
WORKDIR /src

# Run steps
RUN ./bootstrap
RUN ./configure
RUN make
RUN make check
RUN make distcheck
