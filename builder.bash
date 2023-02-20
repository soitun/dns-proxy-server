#!/bin/sh

set -e

REPO_DIR=`pwd`
APP_VERSION=$(cat gradle.properties | grep -oP 'version=\K(.+)')

echo "> builder.bash version=${APP_VERSION}, path=${REPO_DIR}"

copyFileFromService(){

  serviceName=$1
  from=$2
  to=$3

  docker-compose up --no-start --build --force-recreate $serviceName 1>&2
  id=$(docker ps -a | grep $serviceName | awk '{print $1}')
  docker cp "$id:$from" "$to"
}

generateDocs(){
  echo "> Generating docs version=${1}, target=${2}"
  mkdir -p "${2}"
  hugo --baseURL=http://mageddo.github.io/dns-proxy-server/$1 \
  --destination $2 \
  --ignoreCache --source docs/

  echo "> Generated docs version=$1, out files:"
  ls -lha $2
}

case $1 in

  validate-release )
    echo "> validate release, version=${APP_VERSION}, git=$(git rev-parse $APP_VERSION 2>/dev/null)"
    if git rev-parse "$APP_VERSION^{}" >/dev/null 2>&1; then
      echo "> Tag already exists $APP_VERSION"
      exit 3
    fi
  ;;

  deploy )

  echo "> Deploy started , current branch=$CURRENT_BRANCH"
  ./builder.bash validate-release

  if [ "$CURRENT_BRANCH" != "master" ]; then
    echo "> refusing to go ahead outside the master branch"
#    exit 8
  fi

  echo "> Building frontend files..."
  docker-compose build --progress=plain build-frontend
  copyFileFromService build-frontend /static ./src/main/resources/META-INF/resources/static

  touch ./src/main/resources/META-INF/resources/static/marroi

  echo "> Build, test and generate the binaries"
  mkdir -p "${REPO_DIR}/build"

  OS=linux
  ARCH=amd64
  SERVICE_NAME="build-${OS}-${ARCH}"
  BIN_FILE="${REPO_DIR}/build/dns-proxy-server-${OS}-${ARCH}-${APP_VERSION}"
  TAR_FILE=${BIN_FILE}.tgz

  VERSION=${APP_VERSION} docker-compose build --progress=plain ${SERVICE_NAME}
  copyFileFromService ${SERVICE_NAME} /app/dns-proxy-server ${BIN_FILE}
  cd $REPO_DIR/build/
  tar --exclude=*.tgz -czf $TAR_FILE $(basename ${BIN_FILE})

  echo "> Uploading the release artifacts"
  cd $REPO_DIR
  DESC=$(cat RELEASE-NOTES.md | awk 'BEGIN {RS="|"} {print substr($0, 0, index(substr($0, 3), "###"))}' | sed ':a;N;$!ba;s/\n/\\r\\n/g')
  github-cli release mageddo dns-proxy-server $APP_VERSION $CURRENT_BRANCH "${DESC}" $REPO_DIR/build/*.tgz

  echo "> Push docker images to docker hub"
#	docker-compose build prod-build-image-dps prod-build-image-dps-arm7x86 prod-build-image-dps-arm8x64 &&\
#	docker tag defreitas/dns-proxy-server:${APP_VERSION} defreitas/dns-proxy-server:latest &&\
  echo "$DOCKER_PASSWORD" | docker login -u "$DOCKER_USERNAME" --password-stdin &&\
  VERSION=${APP_VERSION} docker-compose push build-linux-amd64
#	docker-compose push prod-build-image-dps prod-build-image-dps-arm7x86 prod-build-image-dps-arm8x64 &&
#	docker push defreitas/dns-proxy-server:latest


  echo "> Generate the docs"
#  P=${2:-${PWD}/build}
#  echo "> Docs ${P}"
#
#  MINOR_VERSION=$(echo $APP_VERSION | awk -F '.' '{ print $1"."$2}');
#  rm -r "$2/docs" || echo "> build dir already clear"
#
#  TARGET="$2/docs/${MINOR_VERSION}"
#  generateDocs ${MINOR_VERSION} ${TARGET}
#
#  MINOR_VERSION=latest
#  TARGET="$2/docs/${MINOR_VERSION}"
#  generateDocs ${MINOR_VERSION} ${TARGET}

  ;;


esac
