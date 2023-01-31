package com.mageddo.dnsproxyserver.server.rest;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

@Path("/env")
public class EnvResource {

  @GET
  @Path("/active")
  @Produces(MediaType.APPLICATION_JSON)
  public Object getActive(){
    throw new UnsupportedOperationException();
  }

//  curl 'http://localhost:5381/env/active' \
//    -H 'Accept: */*' \
//    -H 'Accept-Language: en-US,en;q=0.9,pt-BR;q=0.8,pt;q=0.7' \
//    -H 'Cache-Control: no-cache' \
//    -H 'Connection: keep-alive' \
//    -H 'Cookie: _elvis=xpto; _ga=GA1.1.2131204863.1674682362; _ga_JESVNT61CN=GS1.1.1674682362.1.1.1674683258.0.0.0; jenkins-timestamper-offset=10800000; Idea-c7d001=bafb52b8-0b93-4510-af77-e5452c3b8572; _mg_a=DPuBnTcBOVC6Y/ESa084YLLn0XYwKLxyD7CSzRJfWHce01NoCA2yOZDFlpV58a2v+hDZ90GAb+mtTeXcIIIsjSY=' \
//    -H 'Pragma: no-cache' \
//    -H 'Referer: http://localhost:5381/static/' \
//    -H 'Sec-Fetch-Dest: empty' \
//    -H 'Sec-Fetch-Mode: cors' \
//    -H 'Sec-Fetch-Site: same-origin' \
//    -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36' \
//    -H 'X-Requested-With: XMLHttpRequest' \
//    -H 'sec-ch-ua: "Not?A_Brand";v="8", "Chromium";v="108", "Google Chrome";v="108"' \
//    -H 'sec-ch-ua-mobile: ?0' \
//    -H 'sec-ch-ua-platform: "Linux"' \
//    --compressed

}
