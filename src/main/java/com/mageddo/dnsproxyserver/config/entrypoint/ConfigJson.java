package com.mageddo.dnsproxyserver.config.entrypoint;

import java.nio.file.Path;

public interface ConfigJson {

  String getActiveEnv();

  Integer getWebServerPort();

  Integer getDnsServerPort();

  Boolean getDefaultDns();

  String getLogLevel();

  Path getLogFile();

  Boolean getRegisterContainerNames();

  String getHostMachineHostname();

  String getDomain();

  Boolean getDpsNetwork();

  Boolean getDpsNetworkAutoConnect();
}
