//package com.mageddo.dnsproxyserver.dagger;
//
//import com.mageddo.dnsproxyserver.config.Configs;
//import com.mageddo.dnsproxyserver.server.dns.solver.DockerSolver;
//import com.mageddo.dnsproxyserver.server.dns.solver.RemoteSolver;
//import com.mageddo.dnsproxyserver.server.dns.solver.Solver;
//import dagger.Module;
//import dagger.Provides;
//import dagger.multibindings.ElementsIntoSet;
//import org.xbill.DNS.Resolver;
//import org.xbill.DNS.SimpleResolver;
//
//import java.util.Set;
//
//@Module
//public interface MainModule {
//
//  @ElementsIntoSet
//  @Provides
//  static Set<Solver> solvers(
//      RemoteSolver a, DockerSolver b
//  ) {
//    return Set.of(a, b);
//  }
//
//  @Provides
//  static Resolver simpleResolver() {
//    return new SimpleResolver(Configs.findRemoverSolverConfig().toSocketAddress());
//  }
//}
