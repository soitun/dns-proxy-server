package com.mageddo.dnsproxyserver.quarkus;

import javax.enterprise.inject.Instance;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

public class Instances {
  public static  <T> List<T> toList(Instance<T> instance) {
    return instance
      .stream()
      .toList()
      ;
  }

  public static <T> Set<T> toSet(Instance<T> instance) {
    return instance
      .stream()
      .collect(Collectors.toSet())
      ;
  }
}
