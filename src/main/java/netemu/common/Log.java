package netemu.common;

import java.time.LocalTime;
import java.time.format.DateTimeFormatter;

/**
 * Thread-safe console logger.
 *
 * Every print is serialized through a process-wide stdout lock so that
 * concurrent threads cannot interleave their output. Multi-line "tree"
 * entries (frame → packet → inner-message) must be emitted atomically via
 * {@link #event(String, String...)} so that the children always stay
 * attached to their parent line.
 *
 * Single-line entries (info/warn/error/security/rx/tx) print one line each.
 * Multi-line entries are preceded by a blank line so distinct events are
 * visually separated and easy to scan in a busy terminal.
 */
public final class Log {

    private static final DateTimeFormatter FMT = DateTimeFormatter.ofPattern("HH:mm:ss.SSS");
    /** Process-wide lock for stdout. Shared across every Log instance. */
    private static final Object STDOUT_LOCK = new Object();
    /** Width of the bracketed component name (longest component is "Router"). */
    private static final int PREFIX_WIDTH = 6;

    private final String prefix;
    private final String color;

    public Log(String name, String color) {
        this.prefix = "[" + pad(name, PREFIX_WIDTH) + "]";
        this.color = color;
    }

    private static String pad(String s, int width) {
        if (s.length() >= width) return s;
        StringBuilder sb = new StringBuilder(s);
        while (sb.length() < width) sb.append(' ');
        return sb.toString();
    }

    // ---- single-line entries -----------------------------------------------

    public void info(String msg) {
        synchronized (STDOUT_LOCK) {
            System.out.println(formatInfo(msg));
        }
    }

    public void warn(String msg) {
        synchronized (STDOUT_LOCK) {
            System.out.println(Ansi.YELLOW + timestamp() + " " + prefix + " WARN: " + msg + Ansi.RESET);
        }
    }

    public void error(String msg) {
        synchronized (STDOUT_LOCK) {
            System.out.println(Ansi.RED + timestamp() + " " + prefix + " ERROR: " + msg + Ansi.RESET);
        }
    }

    public void security(String msg) {
        synchronized (STDOUT_LOCK) {
            System.out.println(Ansi.RED + Ansi.BOLD + timestamp() + " " + prefix + " SECURITY: " + msg + Ansi.RESET);
        }
    }

    public void rx(String msg) { info("RX " + msg); }
    public void tx(String msg) { info("TX " + msg); }

    // ---- atomic multi-line entries -----------------------------------------

    /**
     * Print a multi-line "event" under the global lock so concurrent threads
     * can't interleave the lines. A blank line is emitted first as a visual
     * separator between distinct events.
     *
     * Example:
     * <pre>
     *   log.event("RX " + frame, "  └─ " + packet);
     * </pre>
     * produces (atomically, even if other threads are also logging):
     * <pre>
     *
     *   12:14:13.487 [Node1 ] RX Frame [N1 -> R1 | 14 bytes]
     *   12:14:13.487 [Node1 ]   └─ Packet [0x12 -> 0x22 | ICMP | 10 bytes]
     * </pre>
     */
    public void event(String first, String... rest) {
        synchronized (STDOUT_LOCK) {
            System.out.println();
            System.out.println(formatInfo(first));
            for (String line : rest) {
                System.out.println(formatInfo(line));
            }
        }
    }

    /**
     * Atomic multi-line event with the SECURITY level (bold red, "SECURITY:" prefix).
     * The first line gets the SECURITY prefix; subsequent lines are emitted as
     * security-level continuations so the whole alert reads as one unit.
     */
    public void securityEvent(String first, String... rest) {
        synchronized (STDOUT_LOCK) {
            System.out.println();
            System.out.println(Ansi.RED + Ansi.BOLD + timestamp() + " " + prefix + " SECURITY: " + first + Ansi.RESET);
            for (String line : rest) {
                System.out.println(Ansi.RED + Ansi.BOLD + timestamp() + " " + prefix + " SECURITY: " + line + Ansi.RESET);
            }
        }
    }

    /**
     * Print a raw block of text (no timestamp, no prefix) atomically under
     * the lock — useful for help banners, status tables, and box-drawn output
     * that should not be broken up by concurrent log lines.
     */
    public void block(String... lines) {
        synchronized (STDOUT_LOCK) {
            System.out.println();
            for (String line : lines) {
                System.out.println(line);
            }
        }
    }

    /**
     * Same as {@link #block(String...)} but tints the entire block in this
     * logger's component color so status tables match their owner.
     */
    public void blockColored(String... lines) {
        synchronized (STDOUT_LOCK) {
            System.out.println();
            for (String line : lines) {
                System.out.println(color + line + Ansi.RESET);
            }
        }
    }

    // ---- helpers -----------------------------------------------------------

    private String formatInfo(String msg) {
        return color + timestamp() + " " + prefix + " " + msg + Ansi.RESET;
    }

    private String timestamp() {
        return LocalTime.now().format(FMT);
    }
}
