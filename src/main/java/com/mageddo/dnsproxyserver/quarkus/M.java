package com.mageddo.dnsproxyserver.quarkus;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFileAttributes;

public class M {
  public static void main(String[] args) throws IOException {
    final var p = Paths.get("/var/run/docker.sock");
    final var permisions = Files.getPosixFilePermissions(p);
    System.out.println(permisions);

    final var attr = Files.readAttributes(p, PosixFileAttributes.class);
    System.out.println(attr.permissions());
  }
}
