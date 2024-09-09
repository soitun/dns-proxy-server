package com.mageddo.dnsproxyserver.solver.remote.circuitbreaker.application;

import com.mageddo.commons.circuitbreaker.CircuitIsOpenException;
import com.mageddo.commons.concurrent.Threads;
import com.mageddo.concurrent.ThreadsV2;
import com.mageddo.dnsproxyserver.solver.remote.CircuitStatus;
import com.mageddo.dnsproxyserver.solver.remote.Result;
import com.mageddo.dnsproxyserver.solver.remote.mapper.Resilience4jStatusMapper;
import io.github.resilience4j.circuitbreaker.CallNotPermittedException;
import io.github.resilience4j.circuitbreaker.CircuitBreaker;
import lombok.extern.slf4j.Slf4j;

import java.time.Duration;
import java.util.function.Supplier;

@Slf4j
public class CircuitBreakerDelegateCanaryRateThreshold implements CircuitBreakerDelegate, AutoCloseable {

  private final CircuitBreaker circuitBreaker;
  private final Duration sleepDuration;
  private boolean open = true;

  public CircuitBreakerDelegateCanaryRateThreshold(CircuitBreaker circuitBreaker) {
    this(circuitBreaker, Duration.ofSeconds(1));
  }

  public CircuitBreakerDelegateCanaryRateThreshold(CircuitBreaker circuitBreaker, Duration sleepDuration) {
    this.circuitBreaker = circuitBreaker;
    this.sleepDuration = sleepDuration;
    this.startOpenCircuitHealthCheckWorker();
  }

  @Override
  public Result execute(Supplier<Result> sup) {
    try {
      return this.circuitBreaker.executeSupplier(sup);
    } catch (CallNotPermittedException e) {
      throw new CircuitIsOpenException(e);
    }
  }

  @Override
  public CircuitStatus findStatus() {
    return Resilience4jStatusMapper.toCircuitStatus(this.circuitBreaker.getState());
  }

  private void startOpenCircuitHealthCheckWorker() {
    Thread
      .ofVirtual()
      .start(() -> {
        while (ThreadsV2.isNotInterrupted() && this.open) {
          Threads.sleep(this.sleepDuration);
          this.healthCheckWhenInOpenState();
        }
      });
  }

  private void healthCheckWhenInOpenState() {
    final var status = this.findStatus();
    if (!CircuitStatus.isOpen(status)) {
      log.trace("status=notOpenStatus, status={}", status);
      return;
    }
    final var success = this.healthCheck();
    if (success) {
      this.circuitBreaker.transitionToHalfOpenState();
      this.log.debug("status=halfOpenStatus, circuitBreaker={}", this);
    }
  }

  private boolean healthCheck() {
    return true;// FIXME #533 implement
  }

  @Override
  public void close() throws Exception {
    this.open = false;
  }
}
