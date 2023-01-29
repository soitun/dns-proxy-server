package com.mageddo.dnsproxyserver.dns.server;

import com.mageddo.dnsproxyserver.dagger.Factory;
import lombok.SneakyThrows;

public class Main {
  @SneakyThrows
  public static void main(String[] args) {
    final var factory = Factory.factory();

    // start dns server
    factory.dnsServerStarter().start();

    // start webserver

    // configurations

    //  setup as default dns

    //  install as service

    Thread.currentThread().join();


  }
}
