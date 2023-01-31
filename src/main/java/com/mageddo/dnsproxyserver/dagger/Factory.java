package com.mageddo.dnsproxyserver.dagger;

import com.mageddo.dnsproxyserver.server.dns.ServerStarter;
import com.mageddo.dnsproxyserver.server.dns.solver.Solver;
import dagger.Component;

import javax.inject.Singleton;
import java.util.Set;

@Singleton
@Component(modules = {MainModule.class, DockerModule.class})
public interface Factory {

  ServerStarter dnsServerStarter();

  Set<Solver> solvers();

  static Factory factory() {
    return DaggerFactory
        .builder()
        .build()
        ;
  }
}
