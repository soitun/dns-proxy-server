package com.mageddo.os.linux.files;

import com.sun.jna.NativeLong;
import com.sun.jna.Structure;

import java.util.Arrays;
import java.util.List;


public class Stat extends Structure {

  /**
   * ID of device containing file
   */
  public NativeLong st_dev;

  /**
   * Inode number
   */
  public NativeLong st_ino;

  /**
   * File type and mode
   */
  public int st_mode;

  int st_nlink;       /* Number of hard links */
  int st_uid;         /* User ID of owner */
  int st_gid;         /* Group ID of owner */
  int st_rdev;        /* Device ID (if special file) */
  int st_size;        /* Total size, in bytes */
  int st_blksize;     /* Block size for filesystem I/O */
  int st_blocks;      /* Number of 512B blocks allocated */

               /* Since Linux 2.6, the kernel supports nanosecond
                  precision for the following timestamp fields.
                  For the details before Linux 2.6, see NOTES. */

  Timespec.ByValue st_atim;  /* Time of last access */
  Timespec.ByValue st_mtim;  /* Time of last modification */
  Timespec.ByValue st_ctim;  /* Time of last status change */

  @Override
  protected List<String> getFieldOrder() {
    return Arrays.asList("st_dev", "st_ino", "st_mode");
  }

  public static class ByReference extends Stat implements Structure.ByReference {
  }

  public static class ByValue extends Stat implements Structure.ByValue {
  }
}
