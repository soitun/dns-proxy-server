package com.mageddo.dnsproxyserver.config.flags;

import com.mageddo.json.JsonUtils;
import org.junit.jupiter.api.Test;

import java.io.PrintWriter;
import java.io.StringWriter;

import static com.mageddo.utils.TestUtils.readAndSortJson;
import static com.mageddo.utils.TestUtils.readAsString;
import static org.junit.jupiter.api.Assertions.assertEquals;

class FlagsTest {

  @Test
  void mustParseDefaultConfigs() throws Exception {

    // arrange
    final var args = new String[]{};

    // act
    final var config = Flags.parse(args);

    // assert
    assertEquals(
        readAndSortJson("/flags-test/001.json"),
        JsonUtils.prettyInstance().writeValueAsString(config)
    );
  }

  @Test
  void mustPrintHelp() throws Exception {

    // arrange
    final var sw = new StringWriter();
    final var args = new String[]{"--help"};

    // act
    final var config = Flags.parse(args, new PrintWriter(sw));

    // assert
    assertEquals(
        readAsString("/flags-test/002.txt"),
        sw.toString()
    );

  }
}
