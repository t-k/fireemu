// Prints the character classes the official database emulator's JavaScript reader (Rhino on
// Java) uses, for every code unit of the Basic Multilingual Plane, as ranges.
public class JavaChars {
  interface Test { boolean test(char c); }
  static void ranges(String name, Test t) {
    StringBuilder out = new StringBuilder(name);
    int start = -1;
    for (int c = 0; c <= 0x10000; c++) {
      boolean in = c <= 0xFFFF && t.test((char) c);
      if (in && start < 0) start = c;
      if (!in && start >= 0) { out.append(String.format(" %04X-%04X", start, c - 1)); start = -1; }
    }
    System.out.println(out);
  }
  public static void main(String[] a) {
    System.out.println("java " + System.getProperty("java.version"));
    ranges("identifier_start", Character::isJavaIdentifierStart);
    ranges("identifier_part", Character::isJavaIdentifierPart);
    ranges("space_separator", c -> Character.getType(c) == Character.SPACE_SEPARATOR);
    ranges("format", c -> Character.getType(c) == Character.FORMAT);
  }
}
