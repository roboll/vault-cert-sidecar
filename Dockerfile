FROM alpine:3.4

RUN apk add --no-cache --update ca-certificates

ADD kubelet-vault-registrar /kubelet-vault-registrar
ENTRYPOINT ["/kubelet-vault-registrar"]
