package com.mageddo.dnsproxyserver.dns.server.solver;

import org.xbill.DNS.Message;

public interface Solver {
  Message handle(Message reqMsg);
}
