package com.mageddo.dnsproxyserver.quarkus;

import com.mageddo.dnsproxyserver.config.Config;
import org.xbill.DNS.Resolver;
import org.xbill.DNS.SimpleResolver;

import javax.enterprise.inject.Produces;

public class QuarkusConfig {

  @Produces
  public Resolver simpleResolver() {
    return new SimpleResolver(Config.findRemoverSolverConfig().toSocketAddress());
  }
}
