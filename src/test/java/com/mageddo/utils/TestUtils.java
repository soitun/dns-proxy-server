package com.mageddo.utils;

import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import lombok.SneakyThrows;
import lombok.experimental.UtilityClass;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.reflect.FieldUtils;
import org.mockito.Mockito;
import org.mockito.internal.util.MockUtil;

import java.io.InputStream;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.assertNotNull;

@UtilityClass
public class TestUtils {
  public static final ObjectMapper OBJECT_MAPPER = new ObjectMapper().enable(
          MapperFeature.SORT_PROPERTIES_ALPHABETICALLY)
      .enable(SerializationFeature.INDENT_OUTPUT);

  @SneakyThrows
  public static String readString(String path) {
    final InputStream resource = TestUtils.class.getResourceAsStream(path);
    assertNotNull(resource, "file not found: " + path);
    return IOUtils.toString(resource, "UTF-8");
  }
  @SneakyThrows
  public static String readAndSortJson(String path) {
    return sortJson(readString(path));
  }

  @SneakyThrows
  public static String sortJson(String json) {
    return OBJECT_MAPPER.writeValueAsString(OBJECT_MAPPER.readTree(json));
  }

  @SneakyThrows
  public static String sortJson(Object o) {
    return sortJson(OBJECT_MAPPER.writeValueAsString(o));
  }

  @SneakyThrows
  public static InputStream readAsStream(String path) {
    return TestUtils.class.getResourceAsStream(path);
  }

  @SneakyThrows
  public static Path readResource(String path) {
    final var f = TestUtils.class
        .getResource(path)
        .getFile();
    return Paths.get(f);
  }

  /**
   * Refactoring from mockito 3.4  to 5.0 looking at
   * https://github.com/mockito/mockito/blob/v3.4.8/src/main/java/org/mockito/internal/util/reflection/Fields.java
   */
  @SneakyThrows
  public static void resetMocks(Object jUnitInstance) {
    for (final Field field : FieldUtils.getAllFields(jUnitInstance.getClass())) {
      final var v = FieldUtils.readField(field, jUnitInstance, true);
      if (MockUtil.isMock(v)) {
        try {
          Mockito.reset(v);
        } catch (Throwable t) {
        }
      }
    }
  }

  @SneakyThrows
  public static String readString(Path path) {
    return Files.readString(path);
  }
}
