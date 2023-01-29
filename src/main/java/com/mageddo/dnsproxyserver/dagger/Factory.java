package com.mageddo.dnsproxyserver.dagger;

import com.mageddo.dnsproxyserver.dns.server.ServerStarter;
import com.mageddo.dnsproxyserver.dns.server.solver.Solver;
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
