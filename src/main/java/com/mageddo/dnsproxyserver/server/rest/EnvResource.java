package com.mageddo.dnsproxyserver.server.rest;

import com.mageddo.dnsproxyserver.config.ConfigDAO;
import lombok.AllArgsConstructor;

import javax.inject.Inject;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import java.util.Map;

@Path("/env")
@AllArgsConstructor(onConstructor = @__({@Inject}))
public class EnvResource {

  private final ConfigDAO configDAO;

  @GET
  @Path("/active")
  @Produces(MediaType.APPLICATION_JSON)
  public Object getActive() {
    return Map.of("name", this.configDAO.findActiveEnv().getName());
  }


}
