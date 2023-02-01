package com.mageddo.dnsproxyserver.config.flags;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.mageddo.dnsproxyserver.utils.ConfigProps;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.apache.commons.lang3.Validate;
import picocli.CommandLine;
import picocli.CommandLine.Option;

import java.io.PrintWriter;
import java.util.concurrent.Callable;


@Getter
@NoArgsConstructor
public class Flags implements Callable<Boolean> {

  @Option(
      names = {"-version", "--version"}, description = "Shows the current version (default false)"
  )
  private boolean version;

  @Option(
      names = {"-web-server-port", "--web-server-port"},
      description = "The web server port (default 5380)",
      defaultValue = "5380"
  )
  private Integer webServerPort;

  @Option(
      names = {"-server-port", "--server-port"},
      description = "The DNS server to start into (default 53)",
      defaultValue = "53"
  )
  private Integer serverPort;

  @Option(
      names = {"-default-dns", "--default-dns"},
      description = "This DNS server will be the default server for this machine (default true)",
      defaultValue = "true"
  )
  private Boolean defaultDns;

  @Option(
      names = {"-conf-path", "--conf-path"},
      description = "The config file path (default conf/config.json)",
      defaultValue = "conf/config.json"
  )
  private String configPath;
  @Option(
      names = {"-service", "--service"},
      description = """
          Setup as service, starting with machine at boot
             docker = start as docker service,
             normal = start as normal service,
             uninstall = uninstall the service from machine
          (default <empty>)
          """
  )
  private String service;

  @Option(
      names = {"-service-publish-web-port", "--service-publish-web-port"},
      description = "Publish web port when running as service in docker mode (default true)",
      defaultValue = "true"
  )
  private Boolean publishServicePort;

  @Option(
      names = {"-log-file", "--log-file"},
      description = """
          Log to file instead of console,
          (true=log to default log file, /tmp/log.log=log to custom log location)
          (default console)
          """,
      defaultValue = "console"
  )
  private String logToFile;

  @Option(
      names = {"-log-level", "--log-level"},
      description = "Log Level ERROR, WARNING, INFO, DEBUG (default INFO)",
      defaultValue = "INFO"
  )
  private String logLevel;

  @Option(
      names = {"-register-container-names", "--register-container-names"},
      description = "If must register container name / service name as host in DNS server (default false)",
      defaultValue = "false"
  )
  private Boolean registerContainerNames;

  @Option(
      names = {"-host-machine-hostname", "--host-machine-hostname"},
      description = "The hostname to get host machine IP (default host.docker)",
      defaultValue = "host.docker"
  )
  private String hostMachineHostname;

  @Option(
      names = {"-domain", "--domain"},
      description = "Domain utilized to solver containers and services hostnames (default docker)",
      defaultValue = "docker"
  )
  private String domain;

  @Option(
      names = {"-dps-network", "--dps-network"},
      description = "Create a bridge network for DPS increasing compatibility (default false)",
      defaultValue = "false"
  )
  private Boolean dpsNetwork;


  @Option(
      names = {"-dps-network-auto-connect", "--dps-network-auto-connect"},
      description = """
          Connect all running and new containers to the DPS network,
          this way you will probably not have resolution issues by acl (implies dps-network=true)
          (default false)
           """,
      defaultValue = "false"
  )
  private Boolean dpsNetworkAutoConnect;

  @Option(
      names = {"-help", "--help"},
      description = "This message (default false)",
      defaultValue = "false",
      usageHelp = true
  )
  private Boolean help;

  @JsonIgnore
  private CommandLine commandLine;

  public static Flags parse(String[] args) {
    return parse(args, null);
  }

  public static Flags parse(String[] args, PrintWriter writer) {
    final var commandLine = new CommandLine(new Flags());
    if (writer != null) {
      commandLine.setOut(writer);
    }
    commandLine.setUsageHelpWidth(120);
    final var flags = (Flags) commandLine.getCommand();
    Validate.isTrue(commandLine.execute(args) == 0, "Execution Failed");
    flags.commandLine = commandLine;
    return flags;
  }

  /**
   * @return should exit program
   */
  @Override
  public Boolean call() {
    if (this.version) {
      this.commandLine.getOut().write(ConfigProps.getVersion());
      return true;
    }
    return false;
  }
}
