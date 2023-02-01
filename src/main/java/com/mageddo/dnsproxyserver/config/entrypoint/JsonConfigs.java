package com.mageddo.dnsproxyserver.config.entrypoint;

import java.nio.file.Path;

public class JsonConfigs {


  public static ConfigJsonV2 loadConfigV2(Path path){
    throw new UnsupportedOperationException();
  }

  /**
   * Parser v1 or v2 config json then return the interface.
   * @param configPath
   */
  // fixme missing config v1
  public static ConfigJson loadConfig(Path configPath) {
    throw new UnsupportedOperationException();
  }
}
