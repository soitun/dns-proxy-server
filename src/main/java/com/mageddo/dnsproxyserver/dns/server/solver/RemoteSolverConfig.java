package com.mageddo.dnsproxyserver.dns.server.solver;

import com.mageddo.dnsproxyserver.utils.Ips;
import lombok.Data;
import lombok.experimental.Accessors;

import java.net.InetSocketAddress;

@Data
@Accessors(chain = true)
public class RemoteSolverConfig {
  private byte[] ip;
  private short port;

  public InetSocketAddress toSocketAddress() {
    return new InetSocketAddress(Ips.toAddress(this.ip), this.port);
  }
}
