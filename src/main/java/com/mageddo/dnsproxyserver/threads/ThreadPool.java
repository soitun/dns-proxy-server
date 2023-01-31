package com.mageddo.dnsproxyserver.threads;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;

public class ThreadPool {
  private static final ScheduledExecutorService pool = create(5);

  public static ScheduledExecutorService create(int size) {
    return Executors.newScheduledThreadPool(
        size,
        ThreadPool::createDaemonThread
    );
  }
  public static Thread createDaemonThread(Runnable r) {
    final var t = new Thread(r);
    t.setDaemon(true);
    return t;
  }
  public static ScheduledExecutorService main() {
    return pool;
  }
}
