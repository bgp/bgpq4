ARG image=centos/centos:latest
FROM quay.io/$image

# Install dependencies
RUN if command -v yum > /dev/null; then dnf=yum; fi; ${dnf:-dnf} update -y
RUN if command -v yum > /dev/null; then dnf=yum; fi; ${dnf:-dnf} install -y autoconf automake gcc libtool make diffutils file gzip

# Add source code
ADD . /src
WORKDIR /src

# Run steps
RUN ./bootstrap
RUN ./configure
RUN make
RUN make check
RUN make distcheck
