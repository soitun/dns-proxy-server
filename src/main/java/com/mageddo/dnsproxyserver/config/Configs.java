package com.mageddo.dnsproxyserver.config;

import com.mageddo.dnsproxyserver.config.entrypoint.ConfigurationV2;
import com.mageddo.dnsproxyserver.config.entrypoint.EnvConfig;
import com.mageddo.dnsproxyserver.config.entrypoint.FlagConfig;
import com.mageddo.dnsproxyserver.config.entrypoint.JsonConfigs;

public class Configs {

  private static Config instance;

  public static Config build(FlagConfig flagConfig) {
    final var jsonConfig = JsonConfigs.loadConfigV2(flagConfig.getConfigPath());
    return build(flagConfig, EnvConfig.fromEnv(), jsonConfig);
  }

  public static Config build(FlagConfig flagConfig, EnvConfig envConfig, ConfigurationV2 jsonConfig) {
    throw new UnsupportedOperationException();
  }

  public static Config buildAndRegister(FlagConfig flag) {
    return instance = build(flag);
  }

  public static Config getInstance() {
    return instance;
  }
}
