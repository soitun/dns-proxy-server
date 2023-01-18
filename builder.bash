#!/bin/sh

set -e

CUR_DIR=`pwd`
APP_VERSION=$(cat VERSION)


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
	rm -r ${TARGET} || echo "not exists ${TARGET}"
	mkdir ${TARGET}
	hugo --baseURL=http://mageddo.github.io/dns-proxy-server/$1 \
	--destination $2 \
	--ignoreCache --source docs/
}

case $1 in

	docs )

	VERSION=$(cat VERSION | awk -F '.' '{ print $1"."$2}');
	TARGET=$PWD/.docs
	generateDocs ${VERSION} ${TARGET}

	;;

	assemble )
		assemble
	;;

	build )

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

	deploy-ci )

	EC=0
	docker-compose up --force-recreate --abort-on-container-exit prod-ci-deploy || EC=$?
	if [ "$EC" = "3" ]; then
		exit 0
	elif [ "$EC" -ne "0" ]; then
		exit $EC
	fi

	docker-compose build prod-build-image-dps prod-build-image-dps-arm7x86 prod-build-image-dps-arm8x64

	;;

	release )

		echo "> building new version"
		builder.bash build

	;;

esac
