package com.mageddo.dnsproxyserver.config;

import org.junit.jupiter.api.Test;

import static com.mageddo.utils.TestUtils.readAndSortJson;
import static com.mageddo.utils.TestUtils.sortJson;
import static org.junit.jupiter.api.Assertions.assertEquals;

class ConfigsTest {

  @Test
  void mustParseDefaultConfigs() {

    // arrange
    final var args = new String[]{};

    // act
    final var config = Configs.buildAndRegister(args);

    // assert
    assertEquals(readAndSortJson("/configs-test/001.json"), sortJson(config));
  }

}
