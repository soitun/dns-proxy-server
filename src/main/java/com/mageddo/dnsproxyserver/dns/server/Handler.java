package com.mageddo.dnsproxyserver.dns.server;

import org.xbill.DNS.Message;

public interface Handler {
  Message handle(Message message);
}
