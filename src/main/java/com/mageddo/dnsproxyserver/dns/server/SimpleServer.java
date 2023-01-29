package com.mageddo.dnsproxyserver.dns.server;

import lombok.extern.slf4j.Slf4j;
import org.xbill.DNS.Message;
import org.xbill.DNS.Rcode;

import java.net.InetAddress;

@Slf4j
public class SimpleServer {

  public static SimpleServer start(int port, Protocol protocol, InetAddress bindAddress) {

    final var udpServer = new UDPServer();
    udpServer.bind(message -> {
      log.info("status=new-msg, msg={}", message.toString());
      final var reply = new Message();
      final var header = message.getHeader();
      reply.setHeader(header);
      header.setRcode(Rcode.NOTAUTH);
      return reply;
    });
    udpServer.start(port, bindAddress);

    return new SimpleServer();
  }

  public enum Protocol {
    UDP,
    TCP,
    BOTH
  }

}
