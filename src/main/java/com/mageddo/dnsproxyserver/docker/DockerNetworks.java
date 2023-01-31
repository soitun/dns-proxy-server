package com.mageddo.dnsproxyserver.docker;

import com.github.dockerjava.api.command.InspectContainerResponse;
import lombok.extern.slf4j.Slf4j;

import java.util.Arrays;

@Slf4j
public class DockerNetworks {
  public static String findBestIpMatching(InspectContainerResponse c, String... networksNames) {
    final var networks = c.getNetworkSettings().getNetworks();
    for (final var name : networksNames) {
      if (!networks.containsKey(name)) {
        continue;
      }
      final var ip = networks.get(name).getIpAddress();
      log.debug("status=foundIp, network={}, container={}, ip={}", name, c.getName(), ip);
      return ip;
    }
    log.debug("status=noIpFound, searchedNetworks={}, container={}", Arrays.toString(networksNames), c.getName());
    return null;
  }
}
