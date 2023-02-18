#!/bin/sh

set -e

CUR_DIR=`pwd`
APP_VERSION=$(cat VERSION)

echo "> builder.bash version=${APP_VERSION}"

assemble(){
	echo "> Testing ..."
	go test -p 1 -cover -ldflags "-X github.com/mageddo/dns-proxy-server/flags.version=test" ./.../
	echo "> Tests completed"

	echo "> Building..."

	rm -rf build/
	mkdir -p build/

	cp -r /static build/
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

	upload-release )
		echo "> upload-release "
		DESC=$(cat RELEASE-NOTES.md | awk 'BEGIN {RS="|"} {print substr($0, 0, index(substr($0, 3), "###"))}' | sed ':a;N;$!ba;s/\n/\\r\\n/g')
		github-cli release mageddo dns-proxy-server $APP_VERSION $CURRENT_BRANCH "${DESC}" $PWD/build/*.tgz

	;;

	docs )

	P=${2:-${PWD}/build}
	echo "> Docs ${P}"

	VERSION=$(cat VERSION | awk -F '.' '{ print $1"."$2}');
	rm -r "$2/docs" || echo "> build dir already clear"

	TARGET="$2/docs/${VERSION}"
	generateDocs ${VERSION} ${TARGET}

	VERSION=latest
	TARGET="$2/docs/${VERSION}"
	generateDocs ${VERSION} ${TARGET}

	;;

	apply-version )
		echo "> Apply version"
		# updating files version
		sed -i -E "s/(dns-proxy-server.*)[0-9]+\.[0-9]+\.[0-9]+/\1$APP_VERSION/" docker-compose.yml

	;;

	assemble )
		echo "> assemble"
		assemble
	;;

	build )

		echo "> build"

		assemble

		if [ ! -z "$2" ]
		then
			builder.bash compile $2 $3
			exit 0
		fi

		# ARM
		builder.bash compile linux arm
		builder.bash compile linux arm64

		# LINUX
		# INTEL / AMD
		builder.bash compile linux 386
		builder.bash compile linux amd64

		echo "> Build success"

	;;

	compile )
		export GOOS=$2
		export GOARCH=$3
		echo "> Compiling os=${GOOS}, arch=${GOARCH}"
		go build -o $PWD/build/dns-proxy-server -ldflags "-X github.com/mageddo/dns-proxy-server/flags.version=$APP_VERSION"
		TAR_FILE=dns-proxy-server-${GOOS}-${GOARCH}-${APP_VERSION}.tgz
		cd $PWD/build/
		tar --exclude=*.tgz -czf $TAR_FILE *
	;;

	validate-release )
		echo "> validate release, version=${APP_VERSION}, git=$(git rev-parse $APP_VERSION 2>/dev/null)"
		if git rev-parse "$APP_VERSION^{}" >/dev/null 2>&1; then
			echo "> Tag already exists $APP_VERSION"
			exit 3
		fi
	;;

	deploy )

	echo "> Deploy"
	./builder.bash validate-release

	echo "> Build, test and generate the binaries to the output dir"



	EC=0
	docker-compose up --force-recreate --abort-on-container-exit prod-ci-deploy || EC=$?
	if [ "$EC" = "3" ]; then
		exit 0
	elif [ "$EC" -ne "0" ]; then
		exit $EC
	fi

	echo "> From the binaries, build the docker images then push them to docker hub"
	docker-compose build prod-build-image-dps prod-build-image-dps-arm7x86 prod-build-image-dps-arm8x64 &&\
	docker tag defreitas/dns-proxy-server:${APP_VERSION} defreitas/dns-proxy-server:latest &&\
	echo "$DOCKER_PASSWORD" | docker login -u "$DOCKER_USERNAME" --password-stdin &&\
	docker-compose push prod-build-image-dps prod-build-image-dps-arm7x86 prod-build-image-dps-arm8x64 &&
	docker push defreitas/dns-proxy-server:latest

	;;

	release )

		echo "> build started, current branch=$CURRENT_BRANCH"
		if [ "$CURRENT_BRANCH" = "master" ]; then
			echo "> deploying new version"
			builder.bash validate-release && builder.bash apply-version && builder.bash build && builder.bash upload-release

		else
			echo "> refusing to keep going outside the master branch"
		fi

	;;

esac
