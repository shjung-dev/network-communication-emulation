#!/usr/bin/env bash
# CS441 Network Emulator â€” Demo Launcher
# Works on macOS (Terminal.app) and Windows (Windows Terminal via Git Bash / WSL)
# Run from the project root: bash start-demo.sh
#
# Startup order (2s apart):
#   t=0s  LAN1      t=4s  Router
#   t=2s  LAN2      t=6s  Node1 [ATTACKER]
#   t=4s  LAN3      t=8s  Node2 [NORMAL]
#                   t=10s Node3 [FIREWALL]
#                   t=12s Node4 [NORMAL]

JAR="target/netemu-1.0-SNAPSHOT.jar"

# --- Preflight check ---
if [ ! -f "$JAR" ]; then
    echo "ERROR: JAR not found at $JAR"
    echo "Run 'mvn clean package' first."
    exit 1
fi

UNIX_ROOT="$(pwd)"

# --- OS detection ---
detect_os() {
    case "$(uname -s)" in
        Darwin*)               echo "macos"   ;;
        MINGW*|MSYS*|CYGWIN*)  echo "windows" ;;
        Linux*)
            if grep -qiE "microsoft|wsl" /proc/version 2>/dev/null; then
                echo "wsl"
            else
                echo "unknown"
            fi
            ;;
        *)
            [ -n "$WINDIR" ] && echo "windows" || echo "unknown"
            ;;
    esac
}

OS=$(detect_os)
echo "Detected OS : $OS"
echo "Project root: $UNIX_ROOT"
echo "Opening 8 terminals, 2s apart (~14s total)..."
echo ""

# ---------------------------------------------------------------------------
# macOS â€” open tabs one at a time with a 2s delay between each
# ---------------------------------------------------------------------------
if [ "$OS" = "macos" ]; then

    open_tab_macos() {
        local cmd="$1"
        osascript <<APPLESCRIPT
tell application "Terminal"
    activate
    tell application "System Events" to keystroke "t" using command down
    delay 0.4
    do script "cd '$UNIX_ROOT' && $cmd" in front window
end tell
APPLESCRIPT
    }

    # Tab 1: LAN1 â€” open in a fresh window (not a new tab)
    osascript -e "tell application \"Terminal\" to do script \"cd '$UNIX_ROOT' && java -cp $JAR netemu.lan.LAN1\""
    echo "[t=0s]  LAN1 opened"

    sleep 2
    open_tab_macos "java -cp $JAR netemu.lan.LAN2"
    echo "[t=2s]  LAN2 opened"

    sleep 2
    open_tab_macos "java -cp $JAR netemu.lan.LAN3"
    echo "[t=4s]  LAN3 opened"

    sleep 2
    open_tab_macos "java -cp $JAR netemu.device.Router"
    echo "[t=6s]  Router opened"

    sleep 2
    open_tab_macos "java -cp $JAR netemu.device.Node1"
    echo "[t=8s]  Node1 [ATTACKER] opened"

    sleep 2
    open_tab_macos "java -cp $JAR netemu.device.Node2"
    echo "[t=10s] Node2 [NORMAL] opened"

    sleep 2
    open_tab_macos "java -cp $JAR netemu.device.Node3"
    echo "[t=12s] Node3 [FIREWALL] opened"

    sleep 2
    open_tab_macos "java -cp $JAR netemu.device.Node4"
    echo "[t=14s] Node4 [NORMAL] opened"

# ---------------------------------------------------------------------------
# Windows (Git Bash / MSYS2) â€” open tabs one at a time with sleep between
# ---------------------------------------------------------------------------
elif [ "$OS" = "windows" ]; then

    WIN_ROOT=$(pwd -W 2>/dev/null || cygpath -w "$UNIX_ROOT" 2>/dev/null || echo "$UNIX_ROOT")
    WIN_JAR="target\\netemu-1.0-SNAPSHOT.jar"

    if command -v wt >/dev/null 2>&1; then
        WT_CMD="wt"
    elif command -v wt.exe >/dev/null 2>&1; then
        WT_CMD="wt.exe"
    else
        echo "ERROR: Windows Terminal (wt/wt.exe) was not found on PATH."
        echo "Install Windows Terminal or launch the demo components manually in separate terminals from:"
        echo "  $WIN_ROOT"
        echo ""
        echo "Commands to run manually:"
        echo "  java -cp $WIN_JAR netemu.lan.LAN1"
        echo "  java -cp $WIN_JAR netemu.lan.LAN2"
        echo "  java -cp $WIN_JAR netemu.lan.LAN3"
        echo "  java -cp $WIN_JAR netemu.device.Router"
        echo "  java -cp $WIN_JAR netemu.device.Node1"
        echo "  java -cp $WIN_JAR netemu.device.Node2"
        echo "  java -cp $WIN_JAR netemu.device.Node3"
        echo "  java -cp $WIN_JAR netemu.device.Node4"
        exit 1
    fi

    "$WT_CMD" --title "LAN1" cmd /k "cd /d \"$WIN_ROOT\" && java -cp $WIN_JAR netemu.lan.LAN1"
    echo "[t=0s]  LAN1 opened"

    sleep 2
    "$WT_CMD" -w 0 new-tab --title "LAN2" cmd /k "cd /d \"$WIN_ROOT\" && java -cp $WIN_JAR netemu.lan.LAN2"
    echo "[t=2s]  LAN2 opened"

    sleep 2
    "$WT_CMD" -w 0 new-tab --title "LAN3" cmd /k "cd /d \"$WIN_ROOT\" && java -cp $WIN_JAR netemu.lan.LAN3"
    echo "[t=4s]  LAN3 opened"

    sleep 2
    "$WT_CMD" -w 0 new-tab --title "Router" cmd /k "cd /d \"$WIN_ROOT\" && java -cp $WIN_JAR netemu.device.Router"
    echo "[t=6s]  Router opened"

    sleep 2
    "$WT_CMD" -w 0 new-tab --title "Node1 [ATTACKER]" cmd /k "cd /d \"$WIN_ROOT\" && java -cp $WIN_JAR netemu.device.Node1"
    echo "[t=8s]  Node1 [ATTACKER] opened"

    sleep 2
    "$WT_CMD" -w 0 new-tab --title "Node2 [NORMAL]" cmd /k "cd /d \"$WIN_ROOT\" && java -cp $WIN_JAR netemu.device.Node2"
    echo "[t=10s] Node2 [NORMAL] opened"

    sleep 2
    "$WT_CMD" -w 0 new-tab --title "Node3 [FIREWALL]" cmd /k "cd /d \"$WIN_ROOT\" && java -cp $WIN_JAR netemu.device.Node3"
    echo "[t=12s] Node3 [FIREWALL] opened"

    sleep 2
    "$WT_CMD" -w 0 new-tab --title "Node4 [NORMAL]" cmd /k "cd /d \"$WIN_ROOT\" && java -cp $WIN_JAR netemu.device.Node4"
    echo "[t=14s] Node4 [NORMAL] opened"

# ---------------------------------------------------------------------------
# WSL â€” same as Windows but use wslpath and wt.exe
# ---------------------------------------------------------------------------
elif [ "$OS" = "wsl" ]; then

    WIN_ROOT=$(wslpath -w "$UNIX_ROOT")
    WIN_JAR="target\\netemu-1.0-SNAPSHOT.jar"

    wt.exe --title "LAN1" cmd /k "cd /d \"$WIN_ROOT\" && java -cp $WIN_JAR netemu.lan.LAN1"
    echo "[t=0s]  LAN1 opened"

    sleep 2
    wt.exe -w 0 new-tab --title "LAN2" cmd /k "cd /d \"$WIN_ROOT\" && java -cp $WIN_JAR netemu.lan.LAN2"
    echo "[t=2s]  LAN2 opened"

    sleep 2
    wt.exe -w 0 new-tab --title "LAN3" cmd /k "cd /d \"$WIN_ROOT\" && java -cp $WIN_JAR netemu.lan.LAN3"
    echo "[t=4s]  LAN3 opened"

    sleep 2
    wt.exe -w 0 new-tab --title "Router" cmd /k "cd /d \"$WIN_ROOT\" && java -cp $WIN_JAR netemu.device.Router"
    echo "[t=6s]  Router opened"

    sleep 2
    wt.exe -w 0 new-tab --title "Node1 [ATTACKER]" cmd /k "cd /d \"$WIN_ROOT\" && java -cp $WIN_JAR netemu.device.Node1"
    echo "[t=8s]  Node1 [ATTACKER] opened"

    sleep 2
    wt.exe -w 0 new-tab --title "Node2 [NORMAL]" cmd /k "cd /d \"$WIN_ROOT\" && java -cp $WIN_JAR netemu.device.Node2"
    echo "[t=10s] Node2 [NORMAL] opened"

    sleep 2
    wt.exe -w 0 new-tab --title "Node3 [FIREWALL]" cmd /k "cd /d \"$WIN_ROOT\" && java -cp $WIN_JAR netemu.device.Node3"
    echo "[t=12s] Node3 [FIREWALL] opened"

    sleep 2
    wt.exe -w 0 new-tab --title "Node4 [NORMAL]" cmd /k "cd /d \"$WIN_ROOT\" && java -cp $WIN_JAR netemu.device.Node4"
    echo "[t=14s] Node4 [NORMAL] opened"

# ---------------------------------------------------------------------------
# Unsupported
# ---------------------------------------------------------------------------
else
    echo "ERROR: Unsupported OS. Please open 8 terminals manually."
    echo ""
    echo "Run these in order, one per terminal:"
    echo "  java -cp $JAR netemu.lan.LAN1"
    echo "  java -cp $JAR netemu.lan.LAN2"
    echo "  java -cp $JAR netemu.lan.LAN3"
    echo "  java -cp $JAR netemu.device.Router"
    echo "  java -cp $JAR netemu.device.Node1"
    echo "  java -cp $JAR netemu.device.Node2"
    echo "  java -cp $JAR netemu.device.Node3"
    echo "  java -cp $JAR netemu.device.Node4"
    exit 1
fi

echo ""
echo "All 8 terminals launched."
echo "Wait for all 'DHCP: ACK' messages before running demo commands."
