package com.mageddo.dnsproxyserver.dns.server.solver;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.xbill.DNS.Message;
import org.xbill.DNS.Resolver;

import javax.inject.Inject;
import java.io.IOException;
import java.io.UncheckedIOException;

@Slf4j
@AllArgsConstructor(onConstructor = @__({@Inject}))
public class RemoteSolver implements Solver {

  private final Resolver delegate;

  @Override
  public Message handle(Message req) {
    try {
      final var res = this.delegate.send(req);
      log.info("status=handled, req={}, res={}", req, res);
      return res;
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
  }
}
