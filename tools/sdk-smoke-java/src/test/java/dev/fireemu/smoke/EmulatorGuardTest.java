package dev.fireemu.smoke;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.firebase.FirebaseApp;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/** Offline: no emulator, no network. */
class EmulatorGuardTest {

  /** The shape `fireemu exec` exports (crates/fireemu/src/main.rs, child_environment). */
  private static Map<String, String> execEnvironment() {
    Map<String, String> env = new HashMap<>();
    env.put("FIRESTORE_EMULATOR_HOST", "127.0.0.1:8080");
    env.put("FIREBASE_AUTH_EMULATOR_HOST", "127.0.0.1:9099");
    env.put("FIREBASE_DATABASE_EMULATOR_HOST", "127.0.0.1:9000");
    env.put("FIREBASE_STORAGE_EMULATOR_HOST", "127.0.0.1:9199");
    env.put("STORAGE_EMULATOR_HOST", "http://127.0.0.1:9199");
    env.put("GOOGLE_CLOUD_PROJECT", "demo-app");
    return env;
  }

  @Test
  void acceptsTheExecEnvironmentAndReturnsEveryVariableInOrder() throws Exception {
    Map<String, String> accepted = EmulatorGuard.check(execEnvironment());
    assertEquals(EmulatorGuard.VARIABLES, List.copyOf(accepted.keySet()));
    assertEquals("127.0.0.1:9199", accepted.get("FIREBASE_STORAGE_EMULATOR_HOST"));
  }

  @Test
  void theVariablesAreTheOnesTheSdksRead() {
    assertEquals(
        List.of(
            "FIRESTORE_EMULATOR_HOST",
            "FIREBASE_AUTH_EMULATOR_HOST",
            "FIREBASE_DATABASE_EMULATOR_HOST",
            "FIREBASE_STORAGE_EMULATOR_HOST"),
        EmulatorGuard.VARIABLES);
  }

  @Test
  void theDatabaseVariableMayBeAbsentBecauseExecOmitsItByDefault() throws Exception {
    assertEquals(List.of("FIREBASE_DATABASE_EMULATOR_HOST"), EmulatorGuard.OPTIONAL);
    for (String value : new String[] {null, ""}) {
      Map<String, String> env = execEnvironment();
      if (value == null) {
        env.remove("FIREBASE_DATABASE_EMULATOR_HOST");
      } else {
        env.put("FIREBASE_DATABASE_EMULATOR_HOST", value);
      }
      Map<String, String> accepted = EmulatorGuard.check(env);
      assertEquals(
          List.of(
              "FIRESTORE_EMULATOR_HOST",
              "FIREBASE_AUTH_EMULATOR_HOST",
              "FIREBASE_STORAGE_EMULATOR_HOST"),
          List.copyOf(accepted.keySet()));
    }
  }

  @Test
  void refusesWhenAnyRequiredVariableIsMissingOrEmpty() {
    for (String name : EmulatorGuard.VARIABLES) {
      if (EmulatorGuard.OPTIONAL.contains(name)) {
        continue;
      }
      for (String value : new String[] {null, ""}) {
        Map<String, String> env = execEnvironment();
        if (value == null) {
          env.remove(name);
        } else {
          env.put(name, value);
        }
        EmulatorGuard.UnsafeEnvironmentException e =
            assertThrows(
                EmulatorGuard.UnsafeEnvironmentException.class, () -> EmulatorGuard.check(env));
        assertTrue(e.getMessage().contains(name + " is not set"), e.getMessage());
      }
    }
  }

  @Test
  void refusesAnEmptyEnvironmentNamingEveryRequiredVariable() {
    EmulatorGuard.UnsafeEnvironmentException e =
        assertThrows(
            EmulatorGuard.UnsafeEnvironmentException.class, () -> EmulatorGuard.check(Map.of()));
    for (String name : EmulatorGuard.VARIABLES) {
      assertEquals(
          !EmulatorGuard.OPTIONAL.contains(name), e.getMessage().contains(name), e.getMessage());
    }
  }

  @Test
  void refusesEachVariableIndependently() {
    for (String name : EmulatorGuard.VARIABLES) {
      Map<String, String> env = execEnvironment();
      env.put(name, "10.0.0.1:8080");
      EmulatorGuard.UnsafeEnvironmentException e =
          assertThrows(
              EmulatorGuard.UnsafeEnvironmentException.class, () -> EmulatorGuard.check(env));
      assertTrue(
          e.getMessage().contains(name + " is not a loopback host:port"), e.getMessage());
    }
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "127.0.0.1:8080",
        "127.0.0.1:1",
        "127.0.0.1:65535",
        "127.255.255.254:9099",
        "127.0.0.0:80",
        "[::1]:9199",
      })
  void acceptsLoopbackLiterals(String value) {
    assertTrue(EmulatorGuard.isLoopbackHostPort(value), value);
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        // userinfo, including the capability form exec once exported in STORAGE_EMULATOR_HOST
        "user@127.0.0.1:8080",
        "user:pass@127.0.0.1:8080",
        "fireemu:secret@127.0.0.1:9199",
        "@127.0.0.1:8080",
        "user@[::1]:8080",
        "127.0.0.1:8080@evil.example",
        // scheme or path
        "http://127.0.0.1:9199",
        "127.0.0.1:9199/",
        "127.0.0.1:9199/path",
        // not loopback
        "10.0.0.1:8080",
        "0.0.0.0:8080",
        "128.0.0.1:8080",
        "126.255.255.255:8080",
        "firestore.googleapis.com:443",
        "storage.googleapis.com:443",
        "localhost:8080",
        "LOCALHOST:8080",
        "127.0.0.1.example:8080",
        "[::]:8080",
        "[::2]:8080",
        "[0:0:0:0:0:0:0:1]:8080",
        "::1:8080",
        "[::1]",
        "[::1]8080",
        "[::1]x8080",
        "[::1]::8080",
        "[::1:8080",
        // address forms some resolvers widen
        "127.1:8080",
        "0177.0.0.1:8080",
        "127.0.0.01:8080",
        "127.0.0.256:8080",
        "2130706433:8080",
        // port
        "127.0.0.1",
        "127.0.0.1:",
        "127.0.0.1:0",
        "127.0.0.1:65536",
        "127.0.0.1:99999",
        "127.0.0.1:08080",
        "127.0.0.1:+80",
        "127.0.0.1:-1",
        "127.0.0.1:8080:9090",
        // whitespace
        " 127.0.0.1:8080",
        "127.0.0.1:8080 ",
        "127.0.0.1:8080\n",
      })
  void refusesEverythingElse(String value) {
    assertFalse(EmulatorGuard.isLoopbackHostPort(value), value);
  }

  // Property checks with a fixed seed, so a failure reproduces.

  @Test
  void everyLoopbackIpv4WithAValidPortIsAccepted() {
    Random random = new Random(0x5eed);
    for (int i = 0; i < 10_000; i++) {
      String value =
          "127."
              + random.nextInt(256)
              + "."
              + random.nextInt(256)
              + "."
              + random.nextInt(256)
              + ":"
              + (1 + random.nextInt(65535));
      assertTrue(EmulatorGuard.isLoopbackHostPort(value), value);
    }
  }

  @Test
  void everyOtherFirstOctetIsRefused() {
    Random random = new Random(0x0c7e7);
    for (int first = 0; first < 256; first++) {
      if (first == 127) {
        continue;
      }
      String value =
          first + "." + random.nextInt(256) + "." + random.nextInt(256) + "." + random.nextInt(256)
              + ":" + (1 + random.nextInt(65535));
      assertFalse(EmulatorGuard.isLoopbackHostPort(value), value);
    }
  }

  @Test
  void anAcceptedValueWithUserinfoInsertedAnywhereIsRefused() {
    Random random = new Random(0xa7);
    String[] seeds = {"127.0.0.1:8080", "[::1]:9199", "127.3.2.1:1"};
    for (int i = 0; i < 5_000; i++) {
      String seed = seeds[random.nextInt(seeds.length)];
      int at = random.nextInt(seed.length() + 1);
      String user = random.nextBoolean() ? "u@" : "u:p@";
      String value = seed.substring(0, at) + user + seed.substring(at);
      assertFalse(EmulatorGuard.isLoopbackHostPort(value), value);
    }
  }

  @Test
  void everyPortOutsideTheRangeIsRefused() {
    for (int port : new int[] {0, 65536, 70000, 100000, Integer.MAX_VALUE}) {
      assertFalse(EmulatorGuard.isLoopbackHostPort("127.0.0.1:" + port), String.valueOf(port));
    }
  }

  @Test
  void theSmokeRefusesBeforeTouchingAnySdk() {
    Map<String, String> env = execEnvironment();
    env.put("FIRESTORE_EMULATOR_HOST", "firestore.googleapis.com:443");
    assertThrows(EmulatorGuard.UnsafeEnvironmentException.class, () -> JavaAdminSmoke.run(env));
    assertTrue(FirebaseApp.getApps().isEmpty(), "no FirebaseApp may be initialized");
  }
}
