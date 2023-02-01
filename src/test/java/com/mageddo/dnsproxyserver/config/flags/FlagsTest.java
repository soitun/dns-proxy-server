package com.mageddo.dnsproxyserver.config.flags;

import com.mageddo.json.JsonUtils;
import org.junit.jupiter.api.Test;

import static com.mageddo.utils.TestUtils.readAndSortJson;
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
}
