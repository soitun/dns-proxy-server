package com.mageddo.os.linux.jna;

import nativeimage.Reflection;

@Reflection(
  scanPackage = "com.mageddo.os.linux.struct",
  publicConstructors = true, declaredConstructors = true, declaredFields = true, publicFields = true,
  declaredMethods = true, publicMethods = true
)
public class ReflectConfig {
}
