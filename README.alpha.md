## Build project

Binary using Native Image
```bash
$ ./gradlew build nativeCompile &&\
 build/native/nativeCompile/dns-proxy-server
```

## x
```bash
docker-compose -f docker-compose-alpha.yml rm &&\
docker-compose -f docker-compose-alpha.yml build &&\
docker-compose -f docker-compose-alpha.yml run -T --rm arm7x86
```
