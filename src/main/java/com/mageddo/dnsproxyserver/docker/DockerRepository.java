package com.mageddo.dnsproxyserver.docker;

public interface DockerRepository {
  String findHostIp(String host);

  /**
   *
   * @param host
   * @return the host ip
   */
}
