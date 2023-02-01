package com.mageddo.dnsproxyserver.config.flags;

import lombok.SneakyThrows;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.Options;


public class Flags {

  @SneakyThrows
  public static Flags parse(String[] args) {
    final var options = new Options();
    options.addOption("version", "Shows the current version");
    options.addOption("web-server-port", "The web server port");
    options.addOption("server-port", "The DNS server to start into");
    options.addOption("default-dns", "This DNS server will be the default server for this machine");
    options.addOption("conf-path", "The config file path");
    options.addOption("service", """
      Setup as service, starting with machine at boot
         docker = start as docker service,
         normal = start as normal service,
         uninstall = uninstall the service from machine
      """
    );
    options.addOption(
      "service-publish-web-port", "Publish web port when running as service in docker mode"
    );
    options.addOption(
      "log-file",
      "Log to file instead of console, (true=log to default log file, /tmp/log.log=log to custom log location)"
    );
    options.addOption("log-level", "Log Level ERROR, WARNING, INFO, DEBUG");
    options.addOption(
      "register-container-names", "If must register container name / service name as host in DNS server"
    );
    options.addOption("host-machine-hostname", "The hostname to get host machine IP");
    options.addOption("domain", "Domain utilized to solver containers and services hostnames");
    options.addOption("dps-network", "Create a bridge network for DPS increasing compatibility");
    options.addOption(
      "dps-network-auto-connect", """
        Connect all running and new containers to the DPS network,
        this way you will probably not have resolution issues by acl (implies dps-network=true)
        """
    );
    options.addOption("version", "This message");

    final var parser = new DefaultParser();
    return new Flags(parser.parse(options, args));

  }
}
