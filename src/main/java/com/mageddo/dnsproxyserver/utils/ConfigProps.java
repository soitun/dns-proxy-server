package com.mageddo.dnsproxyserver.utils;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.Properties;

public class ConfigProps {
  private static final Properties resources = loadPropertiesResource("/application.properties");

  public static String getVersion(){
    return resources.getProperty("version", "unknown");
  }

  private static Properties loadPropertiesResource(String path) {
    final var in = ConfigProps.class.getResourceAsStream(path);
    final var properties = new Properties();
    try {
      properties.load(in);
      return properties;
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
  }

}
