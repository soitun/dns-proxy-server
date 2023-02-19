FROM debian:10-slim
COPY --from=ARTIFACTS /artifacts/binary/* /app/dns-proxy-server
WORKDIR /app
LABEL dps.container=true
VOLUME ["/var/run/docker.sock", "/var/run/docker.sock"]
CMD ["bash", "-c", "/app/dns-proxy-server"]
