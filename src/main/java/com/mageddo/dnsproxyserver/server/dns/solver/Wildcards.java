package com.mageddo.dnsproxyserver.server.dns.solver;

import java.util.ArrayList;
import java.util.List;

public class Wildcards {
  public static List<String> buildHostAndWildcards(String hostname) {

    final var query = "." + hostname;
    final var hostnames = new ArrayList<String>();
    hostnames.add(query.substring(1));

    int fromIndex = 0, actual = 0;
    while (true) {
      final var str = query.substring(fromIndex);
      actual = str.indexOf('.');

      if (actual == -1 || actual + 1 >= str.length()) {
        break;
      }
      hostnames.add(str.substring(actual));
      fromIndex += actual + 1;
    }
    return hostnames;
  }
}
