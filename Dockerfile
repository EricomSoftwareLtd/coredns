ARG DEBIAN_IMAGE=debian:stable-slim
ARG BASE=debian:stable-slim
FROM ${DEBIAN_IMAGE} AS build
SHELL [ "/bin/sh", "-ec" ]

RUN export DEBCONF_NONINTERACTIVE_SEEN=true \
           DEBIAN_FRONTEND=noninteractive \
           DEBIAN_PRIORITY=critical \
           TERM=linux ; \
    apt-get -qq update ; \
    apt-get -yyqq upgrade ; \
    apt-get -yyqq install ca-certificates libcap2-bin; \
    apt-get clean
COPY coredns /coredns
RUN setcap cap_net_bind_service=+ep /coredns

FROM ${BASE}
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY ./coredns /coredns
COPY ./Corefile.docker /Corefile
COPY ./ssl /ssl
# USER nonroot:nonroot
EXPOSE 10053 10053/udp
ENTRYPOINT ["/coredns"]
