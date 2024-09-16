package com.mageddo.dnsproxyserver.solver.remote;

public enum CircuitStatus {
  OPEN,
  CLOSED,
  HALF_OPEN;

  public static boolean isOpen(CircuitStatus status) {
    return OPEN == status;
  }
}
