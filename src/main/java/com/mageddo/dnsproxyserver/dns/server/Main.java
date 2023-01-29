package com.mageddo.dnsproxyserver.dns.server;

import com.mageddo.dnsproxyserver.dagger.Factory;
import lombok.SneakyThrows;

public class Main {
  @SneakyThrows
  public static void main(String[] args) {

    Factory
        .factory()
        .dnsServerStarter()
        .start();
  }
}
