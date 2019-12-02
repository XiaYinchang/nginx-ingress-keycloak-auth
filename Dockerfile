FROM alpine:3.8

ENV NAME keycloak-auth
ENV GOOS linux
ENV GOARCH amd64


COPY bin/keycloak-auth /opt/keycloak-auth

ENTRYPOINT [ "/opt/keycloak-auth" ]