package com.mageddo.dnsproxyserver.quarkus;

import io.quarkus.runtime.configuration.ConfigUtils;

public class Quarkus {
  public static boolean isTest() {
    return ConfigUtils
      .getProfiles()
      .contains("test")
      ;
  }
}
