# to build the image locally tagged with the short commit hash:
# docker build -t bgpq4:$(git rev-parse --short HEAD) -f .github/images/alpine:3.Dockerfile .
ARG IMAGE=alpine:3
FROM $IMAGE as builder

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

FROM alpine:3
COPY --from=builder /src/bgpq4 /bgp/
WORKDIR /bgp
ENTRYPOINT [ "./bgpq4" ]