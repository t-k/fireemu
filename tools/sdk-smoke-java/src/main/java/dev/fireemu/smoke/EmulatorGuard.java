package dev.fireemu.smoke;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Refuses to start the smoke unless every emulator host variable the Java SDKs read, and the
 * one the smoke reads for Storage, names a loopback {@code host:port}.
 *
 * <p>The Java SDKs on the classpath read these variables (firebase-admin 9.11.0,
 * google-cloud-firestore 3.47.0, google-cloud-storage 2.73.0 sources):
 *
 * <ul>
 *   <li>{@code FIRESTORE_EMULATOR_HOST}: {@code com.google.cloud.firestore.FirestoreOptions}
 *       ({@code FIRESTORE_EMULATOR_SYSTEM_VARIABLE}, read in {@code Builder.build()}), which
 *       prefixes the value with {@code http://} and dials it in plaintext.
 *   <li>{@code FIREBASE_AUTH_EMULATOR_HOST}: {@code com.google.firebase.auth.internal.Utils}
 *       ({@code AUTH_EMULATOR_HOST}), formatted into
 *       {@code http://%s/identitytoolkit.googleapis.com/...} by {@code FirebaseUserManager}.
 *       While it is set the Admin SDK also swaps the app credentials for
 *       {@code EmulatorCredentials} and signs custom tokens with {@code EmulatorCryptoSigner}.
 *   <li>{@code FIREBASE_DATABASE_EMULATOR_HOST}:
 *       {@code com.google.firebase.database.util.EmulatorHelper}. {@code fireemu exec} exports it
 *       only when the Realtime Database runs, which it does not by default, and the smoke never
 *       opens the Realtime Database, so it may be absent; when it is present it is held to the
 *       same rule as the others.
 * </ul>
 *
 * <p>google-cloud-storage 2.73.0 reads no emulator variable at all (no {@code getenv} of a
 * host in the library), and firebase-admin's {@code StorageClient} builds
 * {@code StorageOptions} with no host. The smoke therefore routes Storage itself, from
 * {@code FIREBASE_STORAGE_EMULATOR_HOST} (the bare {@code host:port} {@code fireemu exec}
 * exports), and that variable is checked here as well. {@code STORAGE_EMULATOR_HOST} is not
 * read by any Java code on the classpath and is ignored.
 *
 * <p>A value is accepted only as {@code host:port} with no scheme, path, or userinfo, where
 * host is a literal loopback address ({@code 127.0.0.0/8} or {@code [::1]}) and port is a
 * decimal number from 1 to 65535. Host names, {@code localhost} included, are refused: the
 * guard does not trust name resolution.
 */
public final class EmulatorGuard {

  /** Variables read by the SDKs, then the one the smoke reads for Storage. */
  public static final List<String> VARIABLES =
      List.of(
          "FIRESTORE_EMULATOR_HOST",
          "FIREBASE_AUTH_EMULATOR_HOST",
          "FIREBASE_DATABASE_EMULATOR_HOST",
          "FIREBASE_STORAGE_EMULATOR_HOST");

  /** The subset of {@link #VARIABLES} that may be absent (see the class comment). */
  public static final List<String> OPTIONAL = List.of("FIREBASE_DATABASE_EMULATOR_HOST");

  /** A decimal octet without leading zeros; its range is checked after the match. */
  private static final String OCTET = "(0|[1-9][0-9]{0,2})";

  /**
   * {@code 127.a.b.c:port} or {@code [::1]:port}, the whole value. Groups 1 to 3 are the last
   * three octets (absent for IPv6) and group 4 the port, whose range is checked after the match.
   */
  private static final Pattern HOST_PORT =
      Pattern.compile(
          "(?:127\\." + OCTET + "\\." + OCTET + "\\." + OCTET + "|\\[::1\\]):([1-9][0-9]{0,4})");

  private EmulatorGuard() {}

  /** Thrown when a routing variable is missing or does not name a loopback host:port. */
  public static final class UnsafeEnvironmentException extends Exception {
    private static final long serialVersionUID = 1L;

    UnsafeEnvironmentException(String message) {
      super(message);
    }
  }

  /**
   * Checks every variable in {@link #VARIABLES} and returns the values present, in that order.
   *
   * @throws UnsafeEnvironmentException naming every variable that is missing or refused
   */
  public static Map<String, String> check(Map<String, String> env)
      throws UnsafeEnvironmentException {
    List<String> problems = new ArrayList<>();
    Map<String, String> accepted = new LinkedHashMap<>();
    for (String name : VARIABLES) {
      String value = env.get(name);
      if (value == null || value.isEmpty()) {
        if (!OPTIONAL.contains(name)) {
          problems.add(name + " is not set");
        }
      } else if (!isLoopbackHostPort(value)) {
        problems.add(name + " is not a loopback host:port without userinfo");
      } else {
        accepted.put(name, value);
      }
    }
    if (!problems.isEmpty()) {
      throw new UnsafeEnvironmentException(
          "refusing to run the Java Admin SDK smoke outside a local emulator: "
              + String.join("; ", problems));
    }
    return accepted;
  }

  /** Whether {@code value} is exactly {@code <loopback literal>:<port>}. */
  static boolean isLoopbackHostPort(String value) {
    Matcher m = HOST_PORT.matcher(value);
    if (!m.matches()) {
      return false;
    }
    for (int group = 1; group <= 3; group++) {
      String octet = m.group(group);
      if (octet != null && Integer.parseInt(octet) > 255) {
        return false;
      }
    }
    return Integer.parseInt(m.group(4)) <= 65535;
  }
}
