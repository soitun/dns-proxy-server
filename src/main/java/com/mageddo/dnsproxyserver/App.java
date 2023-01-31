package com.mageddo.dnsproxyserver;

import com.mageddo.dnsproxyserver.dagger.Factory;

public class App {
  public static void main(String[] args) throws InterruptedException {
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
