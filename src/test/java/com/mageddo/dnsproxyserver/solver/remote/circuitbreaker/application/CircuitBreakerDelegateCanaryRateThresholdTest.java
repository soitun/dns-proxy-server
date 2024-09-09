package com.mageddo.dnsproxyserver.solver.remote.circuitbreaker.application;

import com.mageddo.commons.circuitbreaker.CircuitCheckException;
import com.mageddo.commons.circuitbreaker.CircuitIsOpenException;
import com.mageddo.dnsproxyserver.solver.remote.Result;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import testing.templates.circuitbreaker.Resilience4jCircuitBreakerTemplates;
import testing.templates.solver.remote.ResultTemplates;

import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CircuitBreakerDelegateCanaryRateThresholdTest {

  CircuitBreakerDelegateCanaryRateThreshold delegate;

  @BeforeEach
  void beforeEach(){
    this.delegate = new CircuitBreakerDelegateCanaryRateThreshold(Resilience4jCircuitBreakerTemplates.fastFail());
  }

  @Test
  void mustExecuteSupplierWithSuccess(){
    // arrange
    final var counter = new AtomicInteger();

    // act
    final var result = this.delegate.execute(() -> {
      counter.incrementAndGet();
      return ResultTemplates.success();
    });

    // assert
    assertNotNull(result);
    assertTrue(result.hasSuccessMessage());
    assertEquals(1, counter.get());
  }


  @Test
  void mustThrowSpecificExceptionWhenGetOpenCircuit(){
    // arrange
    final Supplier<Result> sup = () -> {
      throw new CircuitCheckException("Mocked Error");
    };

    // act // assert
    assertThrows(CircuitCheckException.class, () -> this.delegate.execute(sup));
    assertThrows(CircuitIsOpenException.class, () -> this.delegate.execute(sup));

  }
}
