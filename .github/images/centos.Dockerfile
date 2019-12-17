ARG image=centos:8
FROM $image

# Install dependencies
RUN yum update -y
RUN yum groupinstall -y 'Development Tools'
RUN yum install -y autoconf automake findutils

# Add source code
ADD . /src
WORKDIR /src

# Run steps
RUN ./bootstrap
RUN ./configure
RUN make
RUN make check
RUN make distcheck

