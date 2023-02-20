FROM debian:9-slim AS BUILDER
# GLIB 2.24
ENV GRAALVM_URL='https://github.com/graalvm/graalvm-ce-builds/releases/download/vm-22.3.1/graalvm-ce-java19-linux-amd64-22.3.1.tar.gz'
ADD ${GRAALVM_URL} /graalvm/graalvm.tgz
RUN tar --strip 1 -zxvf /graalvm/graalvm.tgz -C /graalvm &&\
    /graalvm/bin/gu install native-image &&\
    apt-get update -y &&\
    apt-get install --force-yes -y build-essential libz-dev zlib1g-dev
ENV JAVA_HOME=/graalvm
COPY ./ /app
WORKDIR /app
RUN ./gradlew clean build -Dquarkus.package.type=native -i &&\
    cd build &&\
    ls -lha &&\
    mkdir -p artifacts &&\
    mv $(ls -p ./ | grep -v / | grep dns-proxy-server) ./artifacts/

FROM debian:10-slim
COPY --from=BUILDER /app/build/artifacts/* /app/dns-proxy-server
WORKDIR /app
LABEL dps.container=true
VOLUME ["/var/run/docker.sock", "/var/run/docker.sock"]
ENTRYPOINT "/app/dns-proxy-server"
