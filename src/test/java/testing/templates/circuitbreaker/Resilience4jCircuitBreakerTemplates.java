package testing.templates.circuitbreaker;

import io.github.resilience4j.circuitbreaker.CircuitBreaker;
import io.github.resilience4j.circuitbreaker.CircuitBreakerConfig;
import lombok.extern.slf4j.Slf4j;

import java.io.UncheckedIOException;
import java.time.Duration;

@Slf4j
public class Resilience4jCircuitBreakerTemplates {

  public static CircuitBreaker theDefault() {
    return CircuitBreaker.of(
      "defaultCircuitBreaker",
      CircuitBreakerConfig
        .custom()

        .failureRateThreshold(21f)
        .minimumNumberOfCalls(100)
        .permittedNumberOfCallsInHalfOpenState(10)

        .waitDurationInOpenState(Duration.ofDays(365))
        .recordExceptions(UncheckedIOException.class)

        .build()
    );
  }
}
