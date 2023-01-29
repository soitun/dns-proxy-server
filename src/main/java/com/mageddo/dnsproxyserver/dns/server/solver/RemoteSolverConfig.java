package com.mageddo.dnsproxyserver.dns.server.solver;

import lombok.Data;
import lombok.experimental.Accessors;

import java.io.UncheckedIOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;

@Data
@Accessors(chain = true)
public class RemoteSolverConfig {
  private byte[] ip;
  private short port;

  public InetSocketAddress toSocketAddress() {
    try {
      return new InetSocketAddress(InetAddress.getByAddress(this.ip), this.port);
    } catch (UnknownHostException e) {
      throw new UncheckedIOException(e);
    }
  }
}
