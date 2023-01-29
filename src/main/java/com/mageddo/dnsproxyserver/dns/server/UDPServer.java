package com.mageddo.dnsproxyserver.dns.server;

import com.mageddo.dnsproxyserver.dns.server.solver.Solver;
import org.xbill.DNS.Message;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;

public class UDPServer {
  public static final short BUFFER_SIZE = 512;
  private final List<Solver> solvers;

  public UDPServer() {
    this.solvers = new ArrayList<>();
  }

  public UDPServer bind(Solver solver) {
    this.solvers.add(solver);
    return this;
  }

  public void start(int port, InetAddress bindAddress) {
    try {
      final var server = new DatagramSocket(port, bindAddress);
      final byte[] buff = new byte[BUFFER_SIZE];
      while (!server.isClosed()) {

        final var in = new DatagramPacket(buff, 0, buff.length);
        server.receive(in);
        final var response = this.handle(in).toWire();

        final var out = new DatagramPacket(response, response.length);
        out.setAddress(in.getAddress());
        out.setPort(in.getPort());

        server.send(out);


      }
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }

  }

  private Message handle(DatagramPacket packet) {
    for (Solver solver : this.solvers) {
      try {
        return solver.handle(new Message(packet.getData()));
      } catch (IOException e) {
        throw new UncheckedIOException(e);
      }
    }
    return null;
  }
}
