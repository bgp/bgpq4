ARG image=centos/centos:latest
FROM quay.io/$image

# Install dependencies
RUN yum update -y
RUN yum install -y autoconf automake gcc libtool make diffutils file gzip

# Add source code
ADD . /src
WORKDIR /src

# Run steps
RUN ./bootstrap
RUN ./configure
RUN make
RUN make check
RUN make distcheck
