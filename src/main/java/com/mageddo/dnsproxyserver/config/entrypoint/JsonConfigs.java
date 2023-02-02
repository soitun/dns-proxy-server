package com.mageddo.dnsproxyserver.config.entrypoint;

import com.mageddo.json.JsonUtils;
import lombok.SneakyThrows;

import java.nio.file.Path;

public class JsonConfigs {

  /**
   * Parser v1 or v2 config json then return the interface.
   *
   * @param configPath
   */
  @SneakyThrows
  public static ConfigJson loadConfig(Path configPath) {

    final var objectMapper = JsonUtils.instance();
    final var tree = objectMapper.readTree(configPath.toFile());
    final var version = tree.at("/version").asInt(-1);

    return switch (version) {
      case 1 -> objectMapper.treeToValue(tree, ConfigJsonV1.class);
      case 2 -> objectMapper.treeToValue(tree, ConfigJsonV2.class);
      default -> throw new IllegalArgumentException(String.format("Invalid version %d", version));
    };

  }
}
