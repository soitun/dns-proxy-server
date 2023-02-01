package com.mageddo.dnsproxyserver;

import com.mageddo.dnsproxyserver.config.Configs;
import com.mageddo.dnsproxyserver.config.entrypoint.FlagConfig;
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
    Configs.buildAndRegister(validateAndReturnProgramFlags(args));

    //  setup as default dns

    //  install as service

    // start webserver
    // start dns server
    Quarkus.run(args);

  }

  static FlagConfig validateAndReturnProgramFlags(String[] args) {
    final var flags = FlagConfig.parse(args);
    final var shouldExit = (Boolean) flags.getCommandLine().getExecutionResult();
    if (shouldExit == null || shouldExit) {
      flags.getCommandLine().getOut().flush();
      System.err.printf("%nexiting...%n");
      System.exit(0);
    }
    return flags;
  }

  void onStart(@Observes StartupEvent ev, ServerStarter dnsServer) {
    dnsServer.start();
  }
}
