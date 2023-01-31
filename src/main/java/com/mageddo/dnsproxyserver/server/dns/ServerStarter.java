package com.mageddo.dnsproxyserver.server.dns;

import com.mageddo.dnsproxyserver.config.Configs;
import com.mageddo.dnsproxyserver.server.dns.solver.Solver;
import com.mageddo.dnsproxyserver.server.dns.solver.Solvers;
import lombok.Getter;
import lombok.experimental.Accessors;

import javax.inject.Inject;
import java.util.List;
import java.util.Set;

@Getter
@Accessors(fluent = true)
public class ServerStarter {
  private final List<Solver> solvers;
  private final SimpleServer server;

  @Inject
  public ServerStarter(Set<Solver> solvers, SimpleServer server) {
    this.solvers = Solvers.sorted(solvers);
    this.server = server;
  }

  public ServerStarter start(){
    this.server.start(
        Configs.findDnsServerPort(),
        Configs.findDnsServerProtocol(),
        this.solvers,
        null
    );
    return this;
  }
}
