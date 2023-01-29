package com.mageddo.dnsproxyserver.dagger;

import com.mageddo.dnsproxyserver.config.Configs;
import com.mageddo.dnsproxyserver.dns.server.solver.RemoteSolver;
import com.mageddo.dnsproxyserver.dns.server.solver.Solver;
import dagger.Module;
import dagger.Provides;
import dagger.multibindings.ElementsIntoSet;
import org.xbill.DNS.Resolver;
import org.xbill.DNS.SimpleResolver;

import java.util.Set;

@Module
public interface MainModule {

  @ElementsIntoSet
  @Provides
  static Set<Solver> solvers(
      RemoteSolver remoteSolver
  ) {
    return Set.of(remoteSolver);
  }

  @Provides
  static Resolver simpleResolver() {
    return new SimpleResolver(Configs.findRemoverSolverConfig().toSocketAddress());
  }
}