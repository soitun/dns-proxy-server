package com.mageddo.dnsproxyserver.dns.server;

import com.mageddo.dnsproxyserver.dns.server.solver.Solver;
import com.mageddo.dnsproxyserver.threads.ThreadPool;
import lombok.extern.slf4j.Slf4j;
import org.xbill.DNS.Message;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;

@Slf4j
public class UDPServer {
  public static final short BUFFER_SIZE = 512;
  private final List<Solver> solvers;
  private final ExecutorService pool;

  public UDPServer() {
    this.solvers = new ArrayList<>();
    this.pool = ThreadPool.create(5);
  }

  public UDPServer bind(Solver solver) {
    this.solvers.add(solver);
    return this;
  }

  public void start(int port, InetAddress bindAddress) {
    this.pool.submit(() -> this.start0(port, bindAddress));
    log.info("status=starting.., port={}, bindAddress={}", port, bindAddress);
  }

  private void start0(int port, InetAddress bindAddress) {
    try {
      final var server = new DatagramSocket(port, bindAddress);
      final byte[] buff = new byte[BUFFER_SIZE];
      while (!server.isClosed()) {

        final var in = new DatagramPacket(buff, 0, buff.length);
        server.receive(in);
        this.pool.submit(() -> this.handle(server, this.handle(in), in.getAddress(), in.getPort()));

      }
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
  }

  public void handle(DatagramSocket server, Message handle, InetAddress address, int port) {
    try {
      final var response = handle.toWire();
      final var out = new DatagramPacket(response, response.length);
      out.setAddress(address);
      out.setPort(port);

      server.send(out);

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
