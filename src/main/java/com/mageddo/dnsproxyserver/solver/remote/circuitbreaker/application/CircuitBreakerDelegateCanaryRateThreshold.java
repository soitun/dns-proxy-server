package com.mageddo.dnsproxyserver.solver.remote.circuitbreaker.application;

import com.mageddo.dnsproxyserver.solver.remote.CircuitStatus;
import com.mageddo.dnsproxyserver.solver.remote.Result;
import io.github.resilience4j.circuitbreaker.CircuitBreaker;

import java.util.function.Supplier;

public class CircuitBreakerDelegateCanaryRateThreshold implements CircuitBreakerDelegate {

  private final CircuitBreaker circuitBreaker;

  public CircuitBreakerDelegateCanaryRateThreshold(CircuitBreaker circuitBreaker) {
    this.circuitBreaker = circuitBreaker;
  }

  @Override
  public Result execute(Supplier<Result> sup) {
    return this.circuitBreaker.executeSupplier(sup);
  }

  @Override
  public CircuitStatus findStatus() {
    return null;
  }
}
