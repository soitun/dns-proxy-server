package com.mageddo.dnsproxyserver.utils;

import java.util.Optional;

import static org.apache.commons.lang3.ObjectUtils.firstNonNull;

public class ObjectUtils {

  public static <T> T firstNonNullRequiring(T... args) {
    return Optional
      .ofNullable(firstNonNull(args))
      .orElseThrow(() -> new IllegalArgumentException("At least one argument shouldn't be null!"))
      ;
  }
}
