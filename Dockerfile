FROM alpine as builder

RUN apk --update --no-cache add build-base autoconf automake

COPY . /build
WORKDIR /build

RUN ./bootstrap
RUN ./configure
RUN make
RUN make install

FROM alpine
COPY --from=builder /build/bgpq4 /usr/local/bin

ENTRYPOINT ["/usr/local/bin/bgpq4"]
