FROM docker.io/defreitas/tools_graalvm-22.3_java-19_debian-9:0.1.1 AS BUILDER
COPY ./ /app
WORKDIR /app
RUN ./gradlew clean build -Dquarkus.package.type=native -i &&\
    ./gradlew -Dquarkus.package.type=uber-jar -i -x check &&\
    cd build && ls -lha &&\
    mkdir -p ./artifacts/linux-amd64 && mkdir -p ./artifacts/jre &&\
    mv $(ls -p | grep -v / | grep dns-proxy-server) ./artifacts/linux-amd64 &&\
    mv $(ls | grep -E 'dns-proxy-server.*\.jar') ./artifacts/jre

ENTRYPOYINT cat
