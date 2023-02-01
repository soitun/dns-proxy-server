package com.mageddo.dnsproxyserver.config;

import com.mageddo.dnsproxyserver.config.entrypoint.ConfigEnv;
import com.mageddo.dnsproxyserver.config.entrypoint.ConfigFlag;
import com.mageddo.dnsproxyserver.config.entrypoint.ConfigJson;
import com.mageddo.dnsproxyserver.config.entrypoint.JsonConfigs;

public class Configs {

  private static Config instance;

  public static Config build(ConfigFlag configFlag) {
    final var jsonConfig = JsonConfigs.loadConfig(configFlag.getConfigPath());
    return build(configFlag, ConfigEnv.fromEnv(), jsonConfig);
  }

  public static Config build(ConfigFlag configFlag, ConfigEnv configEnv, ConfigJson jsonConfig) {
    throw new UnsupportedOperationException();
  }

  public static Config buildAndRegister(String[] args) {
    return buildAndRegister(ConfigFlag.parse(args));
  }

  public static Config buildAndRegister(ConfigFlag flag) {
    return instance = build(flag);
  }
  public static Config getInstance() {
    return instance;
  }

}
