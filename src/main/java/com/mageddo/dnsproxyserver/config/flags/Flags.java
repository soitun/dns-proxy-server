package com.mageddo.dnsproxyserver.config.flags;

import lombok.Getter;
import lombok.NoArgsConstructor;
import org.apache.commons.lang3.Validate;
import picocli.CommandLine;


@Getter
@NoArgsConstructor
public class Flags implements Runnable {

  @CommandLine.Option(names = {"-version", "--version"}, description = "Shows the current version")
  private Integer version;

  @CommandLine.Option(
    names = {"-web-server-port", "--web-server-port"},
    description = "The web server port",
    defaultValue = "5380"
  )
  private Integer webServerPort;

  @CommandLine.Option(
    names = {"-server-port", "--server-port"},
    description = "The DNS server to start into",
    defaultValue = "53"
  )
  private Integer serverPort;

  @CommandLine.Option(
    names = {"-default-dns", "--default-dns"},
    description = "This DNS server will be the default server for this machine",
    defaultValue = "true"
  )
  private Boolean defaultDns;

  @CommandLine.Option(
    names = {"-conf-path", "--conf-path"},
    description = "The config file path",
    defaultValue = "conf/config.json"
  )
  private String configPath;
  @CommandLine.Option(
    names = {"-service", "--service"},
    description = """
      Setup as service, starting with machine at boot
         docker = start as docker service,
         normal = start as normal service,
         uninstall = uninstall the service from machine
      """
  )
  private String service;

  @CommandLine.Option(
    names = {"-service-publish-web-port", "--service-publish-web-port"},
    description = "Publish web port when running as service in docker mode",
    defaultValue = "true"
  )
  private Boolean publishServicePort;

  @CommandLine.Option(
    names = {"-log-file", "--log-file"},
    description = "Log to file instead of console, (true=log to default log file, /tmp/log.log=log to custom log location)",
    defaultValue = "console"
  )
  private String logToFile;

  @CommandLine.Option(
    names = {"-log-level", "--log-level"},
    description = "Log Level ERROR, WARNING, INFO, DEBUG",
    defaultValue = "INFO"
  )
  private String logLevel;

  @CommandLine.Option(
    names = {"-register-container-names", "--register-container-names"},
    description = "If must register container name / service name as host in DNS server",
    defaultValue = "false"
  )
  private Boolean registerContainerNames;

  @CommandLine.Option(
    names = {"-host-machine-hostname", "--host-machine-hostname"},
    description = "The hostname to get host machine IP",
    defaultValue = "host.docker"
  )
  private String hostMachineHostname;

  @CommandLine.Option(
    names = {"-domain", "--domain"},
    description = "Domain utilized to solver containers and services hostnames",
    defaultValue = "docker"
  )
  private String domain;

  @CommandLine.Option(
    names = {"-dps-network", "--dps-network"},
    description = "Create a bridge network for DPS increasing compatibility",
    defaultValue = "false"
  )
  private Boolean dpsNetwork;


  @CommandLine.Option(
    names = {"-dps-network-auto-connect", "--dps-network-auto-connect"},
    description = "Connect all running and new containers to the DPS network, this way you will probably not have resolution issues by acl (implies dps-network=true)",
    defaultValue = "false"
  )
  private Boolean dpsNetworkAutoConnect;

  @CommandLine.Option(
    names = {"-help", "--help"},
    description = "This message",
    defaultValue = "false"
  )
  private Boolean help;

  public static Flags parse(String[] args) {
    final var commandLine = new CommandLine(new Flags());
    Validate.isTrue(commandLine.execute(args) == 0, "Execution Failed");
    return commandLine.getCommand();
  }

  @Override
  public void run() {
    // nop
  }
}
