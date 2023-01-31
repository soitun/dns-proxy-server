package com.mageddo.dnsproxyserver.server.dns;

import com.mageddo.dnsproxyserver.server.dns.solver.Solver;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import javax.inject.Inject;
import javax.inject.Singleton;
import java.net.InetAddress;
import java.util.List;

@Slf4j
@Singleton
@AllArgsConstructor(onConstructor = @__({@Inject}))
public class SimpleServer {

  public SimpleServer start(
      int port, Protocol protocol, List<Solver> solvers, InetAddress bindAddress
  ) {

    // fixme create tcp server
    final var udpServer = new UDPServer();
    solvers.forEach(udpServer::bind);
    udpServer.start(port, bindAddress);

    return new SimpleServer();
  }

  public enum Protocol {
    UDP,
    TCP,
    BOTH
  }

}
