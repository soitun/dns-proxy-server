package com.mageddo.dnsproxyserver.utils;

import org.apache.commons.lang3.StringUtils;

import java.util.Optional;
import java.util.function.Supplier;

import static org.apache.commons.lang3.ObjectUtils.firstNonNull;

public class ObjectUtils {

  public static String firstNonBlankRequiring(String... args) {
    return Optional
      .ofNullable(StringUtils.firstNonBlank(args))
      .orElseThrow(throwError())
      ;
  }
  public static <T> T firstNonNullRequiring(T... args) {
    return Optional
      .ofNullable(firstNonNull(args))
      .orElseThrow(throwError())
      ;
  }

  static Supplier<IllegalArgumentException> throwError() {
    return () -> new IllegalArgumentException("At least one argument shouldn't be null!");
  }

}
