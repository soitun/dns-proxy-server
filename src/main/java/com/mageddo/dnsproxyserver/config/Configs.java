package com.mageddo.dnsproxyserver.config;

import com.mageddo.dnsproxyserver.server.dns.SimpleServer;
import com.mageddo.dnsproxyserver.server.dns.solver.RemoteSolverConfig;
import org.eclipse.microprofile.config.ConfigProvider;

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

  public static String findVersion() {
    return ConfigProvider
        .getConfig()
        .getValue("version", String.class)
        ;
  }
}
