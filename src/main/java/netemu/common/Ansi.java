package netemu.common;

public final class Ansi {
    
    private Ansi() {}

    public static final String RESET  = "\u001B[0m";
    public static final String RED    = "\u001B[31m";
    public static final String GREEN  = "\u001B[32m";
    public static final String YELLOW = "\u001B[33m";
    public static final String BLUE   = "\u001B[34m";
    public static final String PURPLE = "\u001B[35m";
    public static final String CYAN   = "\u001B[36m";
    public static final String WHITE  = "\u001B[37m";
    public static final String BOLD   = "\u001B[1m";

    public static String red(String s)    { return RED + s + RESET; }
    public static String green(String s)  { return GREEN + s + RESET; }
    public static String yellow(String s) { return YELLOW + s + RESET; }
    public static String blue(String s)   { return BLUE + s + RESET; }
    public static String purple(String s) { return PURPLE + s + RESET; }
    public static String cyan(String s)   { return CYAN + s + RESET; }
    public static String bold(String s)   { return BOLD + s + RESET; }

    /**
     * Print a startup banner for a component. The whole banner is emitted as
     * one synchronized block so concurrent receiver/CLI threads can't break
     * the box.
     */
    public static void banner(String name, String color) {
        String top    = "╔" + "═".repeat(60) + "╗";
        String middle = "║  " + padRight(name, 56) + "  ║";
        String bot    = "╚" + "═".repeat(60) + "╝";
        synchronized (System.out) {
            System.out.println();
            System.out.println(color + top    + RESET);
            System.out.println(color + middle + RESET);
            System.out.println(color + bot    + RESET);
        }
    }

    private static String padRight(String s, int width) {
        if (s.length() >= width) return s.substring(0, width);
        StringBuilder sb = new StringBuilder(s);
        while (sb.length() < width) sb.append(' ');
        return sb.toString();
    }
}
