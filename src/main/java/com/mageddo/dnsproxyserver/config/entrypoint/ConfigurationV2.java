package com.mageddo.dnsproxyserver.config.entrypoint;

import com.mageddo.dnsproxyserver.config.EntryType;
import lombok.Data;
import lombok.experimental.Accessors;

import java.util.List;

@Data
@Accessors(chain = true)
public class ConfigurationV2 {
  private int version = 2;
  private List<String> remoteDnsServers; // dns servers formatted like 192.168.0.1:53

  private String activeEnv;
  private List<Env> envs;

  private int webServerPort;
  private int dnsServerPort;

  private Boolean defaultDns;

  private String logLevel;
  private String logFile;

  private Boolean registerContainerNames;

  private String hostMachineHostname;

  private String domain;

  private boolean dpsNetwork;

  private boolean dpsNetworkAutoConnect;

  @Data
  @Accessors(chain = true)
  public static class Env {
    private String name;
    private List<Hostname> hostnames;
  }

  @Data
  @Accessors(chain = true)
  public static class Hostname {
    private Long id;
    private String hostname;
    private String ip;
    private String target; // target hostname when type=CNAME

    private Integer ttl;
    private EntryType type;
  }

}
