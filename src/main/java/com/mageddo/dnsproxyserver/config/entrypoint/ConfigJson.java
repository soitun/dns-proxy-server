package com.mageddo.dnsproxyserver.config.entrypoint;

public interface ConfigJson {

  String getActiveEnv();

  Integer getWebServerPort();

  Integer getDnsServerPort();

  Boolean getDefaultDns();

  String getLogLevel();

  String getLogFile();

  Boolean getRegisterContainerNames();

  String getHostMachineHostname();

  String getDomain();

  Boolean getDpsNetwork();

  Boolean getDpsNetworkAutoConnect();
}
