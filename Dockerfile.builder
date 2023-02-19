FROM node:12-alpine AS FRONTEND
COPY app /app
WORKDIR /app
ENV PUBLIC_URL=/static
RUN npm install &&\
	npm run build &&\
	rm -f `find ./build -name *.map`

FROM ghcr.io/graalvm/graalvm-ce:22.3.1 AS COMPLETE
RUN gu install native-image
COPY ./ /cd
WORKDIR /cd
COPY --from=FRONTEND /app/build /cd/src/main/resources/META-INF/resources/static
RUN ./gradlew build -Dquarkus.package.type=uber-jar &&\
    ./gradlew build -Dquarkus.package.type=native &&\
    cd build &&\
    mkdir -p artifacts/binary &&\
    mv $(ls -p ./ | grep -v / | grep dns-proxy-server) ./artifacts/ &&\
    cd artifacts &&\
    mv $(ls -p ./ | grep -v / | grep -v jar) ./binary/
RUN ls -lha /cd/build/artifacts/**

FROM scratch AS ARTIFACTS
COPY --from=COMPLETE /cd/build/artifacts /artifacts

#FROM node:12-alpine AS FRONTEND
#COPY app /app
#WORKDIR /app
#ENV PUBLIC_URL=/static
#RUN npm install &&\
#	npm run build &&\
#	rm -f `find ./build -name *.map`
#
##FROM openjdk:17-jdk
#FROM ghcr.io/graalvm/graalvm-ce:22.3.1 AS COMPLETE
#RUN gu install native-image
#COPY ./ /cd
#WORKDIR /cd
#COPY --from=FRONTEND /app/build /cd/src/main/resources/META-INF/resources/static
#RUN ./gradlew build -Dquarkus.package.type=uber-jar &&\
#    ./gradlew build -Dquarkus.package.type=native &&\
#    cd build &&\
#    mkdir artifacts/binary &&\
#    mv $(ls -p ./ | grep -v / | grep dns-proxy-server) ./artifacts &&\
#    ls -lha ./artifacts/*
#
#FROM scratch AS ARTIFACTS
#COPY --from=COMPLETE /cd/build/artifacts /artifacts
#WORKDIR /artifacts
#
##RUN apt update &&\
##	apt install -y jq &&\
##	curl -s -L https://github.com/mageddo-projects/github-cli/releases/download/v1.8/github-cli.sh > /usr/bin/github-cli &&\
##	chmod +x /usr/bin/github-cli
##ENV GOPATH=/app
##ENV MG_WORK_DIR=/app/src/github.com/mageddo/dns-proxy-server
##LABEL dps.container=true
##WORKDIR /app/src/github.com/mageddo/dns-proxy-server
##COPY --from=BUILDER /app/build /static
##COPY ./builder.bash /bin/builder.bash
