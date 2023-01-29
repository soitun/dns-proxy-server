package com.mageddo.dnsproxyserver.dns.server;

import lombok.SneakyThrows;

public class Main {
  @SneakyThrows
  public static void main(String[] args) {
    SimpleServer.start(8053, SimpleServer.Protocol.BOTH, null);
  }
}
