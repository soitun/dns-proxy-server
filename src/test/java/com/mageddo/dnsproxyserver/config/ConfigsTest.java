package com.mageddo.dnsproxyserver.config;

import org.junit.jupiter.api.Test;

class ConfigsTest {

  @Test
  void mustParseDefaultConfigs() {

    // arrange
    final var args = new String[]{};

    // act
    Configs.buildAndRegister(args);

    // assert
  }

}
