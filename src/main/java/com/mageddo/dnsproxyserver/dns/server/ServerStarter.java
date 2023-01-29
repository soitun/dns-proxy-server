package com.mageddo.dnsproxyserver.dns.server;

import com.mageddo.dnsproxyserver.config.Configs;
import com.mageddo.dnsproxyserver.dns.server.solver.Solver;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.experimental.Accessors;

import javax.inject.Inject;
import java.util.Set;

@Getter
@Accessors(fluent = true)
@AllArgsConstructor(onConstructor = @__({@Inject}))
public class ServerStarter {
  private final Set<Solver> solvers;
  private final SimpleServer server;

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
