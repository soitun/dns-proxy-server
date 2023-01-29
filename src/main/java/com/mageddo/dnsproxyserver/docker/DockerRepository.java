package com.mageddo.dnsproxyserver.docker;

public interface DockerRepository {

  /**
   *
   * @param host
   * @return the host ip
   */
  String findHost(String host);
}
