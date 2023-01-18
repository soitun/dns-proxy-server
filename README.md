# A fork of dns-proxy-server

**Note from addshore**

It looks like the upstream mageddo/dns-proxy-server repository hasn't seen much activity in the past years.

I personally use this project and want to make some tweaks to it.

I will aim to maintain this fork to the best of my ability moving forward and hope that others can find the updates and possible fixes useful.

Also currently more than happy to fold any changes back into upstream if it becomes active.

You can find this fork on Docker Hub @ https://hub.docker.com/r/addshore/dns-proxy-server

`upstream-2.19.0*` tags are the same code as the last upstream release, just going via the new build and push path.

Any tag beyond `2.19.0` on this repository or docker images has come from this code base.

## Main features

DPS is a end user(developers, Server Administrators) DNS server tool to develop systems with docker solving
docker containers hostnames:

* Solve hostnames from local configuration database
* Solve hostnames from docker containers using docker **hostname** option or **HOSTNAMES** env
* Solve hostnames from a list of configured DNS servers(as a proxy) if no answer of two above
* Solve hostnames using wildcards
* Graphic interface to Create/List/Update/Delete **A/CNAME** records
* Solve host machine IP using `host.docker` hostname
* Access container by it’s container name / service name
* Specify from which network solve container IP 

![](https://i.imgur.com/aR9dl0O.png)

## Basic running it

```bash
$ docker run --rm --hostname dns.mageddo \
-v /var/run/docker.sock:/var/run/docker.sock \
-v /etc/resolv.conf:/etc/resolv.conf \
addshore/dns-proxy-server
```

then try it out

```bash
$ ping dns.mageddo
PING dns.mageddo (172.17.0.4) 56(84) bytes of data.
64 bytes from 172.17.0.4: icmp_seq=1 ttl=64 time=0.063 ms
64 bytes from 172.17.0.4: icmp_seq=2 ttl=64 time=0.074 ms
64 bytes from 172.17.0.4: icmp_seq=3 ttl=64 time=0.064 ms
```

## Documentation
* [Full documentation](http://mageddo.github.io/dns-proxy-server/) (from upstream)
* [Running it documentation](http://mageddo.github.io/dns-proxy-server/latest/en/1-getting-started/running-it/) (from upstream)
* [Examples](https://github.com/addshore/dns-proxy-server/tree/master/examples)
* [Coding at the DPS](http://mageddo.github.io/dns-proxy-server/latest/en/5-developing/) (from upstream)
