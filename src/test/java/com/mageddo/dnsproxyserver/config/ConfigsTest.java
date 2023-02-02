package com.mageddo.dnsproxyserver.config;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;

import static com.mageddo.utils.TestUtils.readAndSortJson;
import static com.mageddo.utils.TestUtils.sortJson;
import static org.junit.jupiter.api.Assertions.assertEquals;

class ConfigsTest {

  @Test
  void mustParseDefaultConfigs(@TempDir Path tmpDir) {

    // arrange
    final var tmpConfigFile = tmpDir.resolve("tmpfile.json");
    final var args = new String[]{"--conf-path", tmpConfigFile.toString()};

    // act
    final var config = Configs.buildAndRegister(args);

    // assert
    assertEquals(readAndSortJson("/configs-test/001.json"), sortJson(config));
  }

}
