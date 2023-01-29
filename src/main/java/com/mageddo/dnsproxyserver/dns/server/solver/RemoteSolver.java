package com.mageddo.dnsproxyserver.dns.server.solver;

import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.xbill.DNS.Message;
import org.xbill.DNS.Resolver;
import org.xbill.DNS.SimpleResolver;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;

@Slf4j
public class RemoteSolver implements Solver {

  private final Resolver delegate;

  @SneakyThrows
  public RemoteSolver() {
    this.delegate = new SimpleResolver(new InetSocketAddress(InetAddress.getByAddress(new byte[]{8,8,8,8}), 53));
  }

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
