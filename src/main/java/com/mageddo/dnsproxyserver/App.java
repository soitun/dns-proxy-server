package com.mageddo.dnsproxyserver;

import com.mageddo.dnsproxyserver.config.Configs;
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

    // configurations
    final var config = Configs.buildAndRegister(args);
    System.setProperty("quarkus.http.port", String.valueOf(config.getWebServerPort()));
    System.setProperty("quarkus.log.level", config.getLogLevel().name());

    // todo setup as default dns

    // install as service

    // start webserver
    // start dns server
    Quarkus.run(args);

  }

  void onStart(@Observes StartupEvent ev, ServerStarter dnsServer) {
    dnsServer.start();
  }
}
