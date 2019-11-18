# Build Geth in a stock Go builder container
FROM golang:1.10-alpine as builder

RUN apk add --no-cache make gcc musl-dev linux-headers

ADD . /go-ethereum
RUN cd /go-ethereum && rm -rf .git && make geth

# Pull Geth into a second stage deploy alpine container
FROM alpine:latest

RUN apk add --no-cache ca-certificates
COPY --from=builder /go-ethereum/build/bin/geth /usr/local/bin/

# Install tinylog
RUN cd /
RUN apk add make && apk add gcc g++ make libffi-dev openssl-dev
RUN wget http://b0llix.net/perp/distfiles/perp-2.07.tar.gz && tar -xzvf perp-2.07.tar.gz && rm perp-2.07.tar.gz
RUN cd perp-2.07 && make install

# Initilize
COPY --from=builder /go-ethereum/settings/uxchain_test_1.json /ucot_iot/settings/uxchain_test_1.json
RUN rm -f /ucot_iot/data/keystore/.DS_Store
RUN geth --datadir /ucot_iot/data init /ucot_iot/settings/uxchain_test_1.json

EXPOSE 25052 25052/udp 9003
# ENTRYPOINT ["geth"]