package com.mageddo.dnsproxyserver.config.entrypoint;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import org.apache.commons.lang3.StringUtils;

import java.io.IOException;
import java.net.URI;

public class URIConverter {
  public static class Deserializer extends JsonDeserializer<URI> {

    @Override
    public URI deserialize(JsonParser jsonParser, DeserializationContext deserializationContext) throws IOException {
      final var v = jsonParser.getValueAsString(null);
      if(StringUtils.isBlank(v)){
        return null;
      }
      switch (StringUtils.lowerCase(v)){
        case "console":
          return URI.create("console://");
      }
      return URI.create(v);
    }
  }
}
