## Build project

Binary using Native Image
```bash
$ ./gradlew build nativeCompile &&\
 build/native/nativeCompile/dns-proxy-server
```


## Run a container  for testing

```
docker run --rm -it  --hostname nginx.dev -e 'HOSTNAMES=nginx.com.br' nginx:1.15 bash
```
## x
```bash
docker-compose -f docker-compose-alpha.yml rm &&\
docker-compose -f docker-compose-alpha.yml build &&\
docker-compose -f docker-compose-alpha.yml run -T --rm arm7x86
```

