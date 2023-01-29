package com.mageddo.dnsproxyserver.dns.server;

import lombok.SneakyThrows;

import java.net.Inet4Address;

public class Main {
  @SneakyThrows
  public static void main(String[] args) {
    SimpleServer.start(8053, SimpleServer.Protocol.BOTH, Inet4Address.getByName("localhost"));
  }
}
