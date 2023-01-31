package com.mageddo.dnsproxyserver;

import com.mageddo.dnsproxyserver.server.dns.ServerStarter;
import io.quarkus.runtime.Quarkus;
import io.quarkus.runtime.StartupEvent;
import io.quarkus.runtime.annotations.QuarkusMain;
import lombok.extern.slf4j.Slf4j;

import javax.enterprise.event.Observes;

@Slf4j
@QuarkusMain
public class App {
  public static void main(String[] args) {

    // start webserver

    // configurations

    //  setup as default dns

    //  install as service

    Quarkus.run(args);

  }

  void onStart(@Observes StartupEvent ev, ServerStarter dnsServer) {
    dnsServer.start();
  }
}
