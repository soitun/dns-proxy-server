package com.mageddo.dnsproxyserver.config;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

import static com.mageddo.utils.TestUtils.readAndSortJson;
import static com.mageddo.utils.TestUtils.readString;
import static com.mageddo.utils.TestUtils.sortJson;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ConfigsTest {

  @Test
  void mustParseDefaultConfigsAndCreateConfigFile(@TempDir Path tmpDir) {

    // arrange
    final var tmpConfigFile = tmpDir.resolve("tmpfile.json");
    final var args = new String[]{"--conf-path", tmpConfigFile.toString()};
    assertFalse(Files.exists(tmpConfigFile));

    // act
    final var config = Configs.buildAndRegister(args);

    // assert
    final var expectedJsonConfig = readAndSortJson("/configs-test/001.json");
    assertEquals(expectedJsonConfig, sortJson(config));
    assertTrue(Files.exists(tmpConfigFile));

    assertEquals(expectedJsonConfig, sortJson(config));
    assertEquals(readString("/configs-test/002.json"), readString(tmpConfigFile));
  }

}
