package com.mageddo.os.linux.files;

public class Main {
  public static void main(String[] args) {
    {
      final var stat = new Stat.ByReference();
      final var res = Stats.INSTANCE.stat("/var/run/docker.sock", stat);
      System.out.println(res);
      System.out.println(stat.st_mode);
    }
    {
      final var stat = new Stat.ByReference();
      final var res = Stats.INSTANCE.stat("/home/typer/kill-quarkus-dev.sh", stat);
      System.out.println(res);
      System.out.println(stat.st_mode);
    }
  }
}
