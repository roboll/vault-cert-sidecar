FROM alpine:3.4

RUN apk add --no-cache --update ca-certificates

ADD vault-cert-sidecar /vault-cert-sidecar
ENTRYPOINT ["/vault-cert-sidecar"]
