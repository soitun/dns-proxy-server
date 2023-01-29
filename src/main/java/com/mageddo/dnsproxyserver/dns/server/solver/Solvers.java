package com.mageddo.dnsproxyserver.dns.server.solver;

import com.mageddo.dnsproxyserver.dns.server.solver.Solver;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Set;

public class Solvers {
  public static List<Solver> sorted(Set<Solver> source) {
    final var solvers = new ArrayList<>(source);
    solvers.sort(Comparator.comparing(Solver::priority));
    return solvers;
  }
}
