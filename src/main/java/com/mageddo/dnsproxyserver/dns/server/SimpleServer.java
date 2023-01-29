package com.mageddo.dnsproxyserver.dns.server;

import com.mageddo.dnsproxyserver.dns.server.solver.RemoteSolver;
import lombok.extern.slf4j.Slf4j;

import java.net.InetAddress;

@Slf4j
public class SimpleServer {

  public static SimpleServer start(int port, Protocol protocol, InetAddress bindAddress) {

    // fixme create tcp server
    final var udpServer = new UDPServer();
//    udpServer.bind(message -> {
//      log.info("status=new-msg, msg={}", message.toString());
//      final var reply = new Message();
//      final var header = message.getHeader();
//      reply.setHeader(header);
//      header.setRcode(Rcode.NOTAUTH);
//      return reply;
//    });
    udpServer.bind(new RemoteSolver());
    udpServer.start(port, bindAddress);

    return new SimpleServer();
  }

  public enum Protocol {
    UDP,
    TCP,
    BOTH
  }

}
