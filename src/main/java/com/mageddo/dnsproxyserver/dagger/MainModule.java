package com.mageddo.dnsproxyserver.dagger;

import com.mageddo.dnsproxyserver.config.Configs;
import com.mageddo.dnsproxyserver.dns.server.solver.DockerSolver;
import com.mageddo.dnsproxyserver.dns.server.solver.RemoteSolver;
import com.mageddo.dnsproxyserver.dns.server.solver.Solver;
import com.mageddo.dnsproxyserver.docker.DockerRepository;
import com.mageddo.dnsproxyserver.docker.DockerRepositoryMock;
import dagger.Binds;
import dagger.Module;
import dagger.Provides;
import dagger.multibindings.ElementsIntoSet;
import org.xbill.DNS.Resolver;
import org.xbill.DNS.SimpleResolver;

import java.util.Set;

@Module
public interface MainModule {

  @Binds
  DockerRepository bind(DockerRepositoryMock m);

  @ElementsIntoSet
  @Provides
  static Set<Solver> solvers(
      RemoteSolver a, DockerSolver b
  ) {
    return Set.of(a, b);
  }

  @Provides
  static Resolver simpleResolver() {
    return new SimpleResolver(Configs.findRemoverSolverConfig().toSocketAddress());
  }
}