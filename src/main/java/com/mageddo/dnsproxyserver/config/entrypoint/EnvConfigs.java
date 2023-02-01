package com.mageddo.dnsproxyserver.config.entrypoint;

import com.mageddo.dnsproxyserver.config.Configs;

public class EnvConfigs {
  public static Configs fromEnv(){
    return Configs
      .builder()
      .build();
  }
}
