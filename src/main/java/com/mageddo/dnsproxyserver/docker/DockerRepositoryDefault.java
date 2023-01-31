package com.mageddo.dnsproxyserver.docker;

import com.github.dockerjava.api.DockerClient;
import com.github.dockerjava.api.command.InspectContainerResponse;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.time.StopWatch;

import javax.inject.Inject;
import javax.inject.Singleton;
import java.util.Objects;
import java.util.Set;
import java.util.function.Predicate;

import static com.mageddo.dnsproxyserver.docker.Docker.findContainerHostname;
import static com.mageddo.dnsproxyserver.docker.Docker.findHostnameFromEnv;

@Slf4j
@Singleton
@AllArgsConstructor(onConstructor = @__({@Inject}))
public class DockerRepositoryDefault implements DockerRepository {

  public static final String RUNNING_STATUS = "running";
  private final DockerClient dockerClient;

  @Override
  public String findHostIp(String host) {
    final var stopWatch = StopWatch.createStarted();
    final var activeContainers = this.dockerClient
      .listContainersCmd()
      .withStatusFilter(Set.of(RUNNING_STATUS))
      .withLimit(1024)
//      .withNetworkFilter()
      .exec();

    final var foundIp = activeContainers
      .stream()
      .map(it -> this.dockerClient.inspectContainerCmd(it.getId()).exec())
      .filter(matchingHostName(host))
      .map(c -> DockerNetworks.findBestIpMatching(c, buildNetworks(c)))
      .findFirst()
      .orElse(null);
    log.debug("status=findDone, host={}, found={}, time={}", host, foundIp, stopWatch.getTime());
    return foundIp;
  }

  String[] buildNetworks(InspectContainerResponse c) {
    return new String[]{"bridge"};
  }

  static Predicate<InspectContainerResponse> matchingHostName(String host) {
    return it -> {
      if (Objects.equals(findContainerHostname(it.getConfig()), host)) {
        return true;
      }
      return findHostnameFromEnv(it.getConfig().getEnv()).contains(host);
    };
  }
}
