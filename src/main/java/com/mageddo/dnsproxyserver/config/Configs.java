package com.mageddo.dnsproxyserver.config;

import com.mageddo.dnsproxyserver.dns.server.solver.RemoteSolverConfig;
import com.mageddo.dnsproxyserver.dns.server.SimpleServer;

public class Configs {
  public static int findDnsServerPort() {
    return 8053;
  }

  public static SimpleServer.Protocol findDnsServerProtocol() {
    return SimpleServer.Protocol.BOTH;
  }

  public static RemoteSolverConfig findRemoverSolverConfig() {
    return new RemoteSolverConfig()
        .setIp(new byte[]{8, 8, 8, 8})
        .setPort((short) 53);
  }
}
