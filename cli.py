"""PacketPulse CLI: Terminal runner, Cyberpunk Braille Radar, and 3D WebGL HUD launcher."""

from __future__ import annotations
import argparse
import sys
import time

from packetpulse.engine import PacketPulse
from packetpulse.models import Hop


# ANSI Styling
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
MAGENTA = "\033[95m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


def print_banner():
    banner = rf"""{CYAN}{BOLD}
    ____             __      __  ____        __            
   / __ \____ ______/ /_____/ /_/ __ \__  __/ /_______     
  / /_/ / __ `/ ___/ //_/ _  __/ /_/ / / / / / ___/ _ \    
 / ____/ /_/ / /__/ ,< /  __/ / ____/ /_/ / (__  )  __/    
/_/    \__,_/\___/_/|_|\___/_/_/    \__,_/_/____/\___/     
    {MAGENTA}Real-Time Network Hop & Protocol Telemetry Engine{RESET}
"""
    print(banner)


def render_hop_row(hop: Hop):
    hop_str = f"{hop.hop_num:02d}"
    if hop.timed_out:
        print(f" {DIM}{hop_str}{RESET}  │ {RED}* * * Request timed out{RESET}")
        return

    rtt_color = GREEN if (hop.rtt_ms or 0) < 50 else (YELLOW if (hop.rtt_ms or 0) < 120 else RED)
    rtt_str = f"{rtt_color}{hop.rtt_ms:>6.1f} ms{RESET}" if hop.rtt_ms is not None else "     *    "
    jitter_str = f"{hop.jitter_ms:>5.1f} ms" if hop.jitter_ms is not None else "    -   "

    ip_str = f"{hop.ip:<15}" if hop.ip else " " * 15
    loc_str = f"{hop.city}, {hop.country}" if hop.city and hop.country else "Unknown"
    loc_str = (loc_str[:22] + "..") if len(loc_str) > 24 else f"{loc_str:<24}"
    asn_str = (hop.asn[:24] + "..") if hop.asn and len(hop.asn) > 26 else (hop.asn or "Direct")

    dest_indicator = f" {GREEN}🎯 [TARGET]{RESET}" if hop.is_destination else ""
    print(f" {BOLD}{hop_str}{RESET}  │ {CYAN}{ip_str}{RESET} │ {rtt_str} │ {DIM}Δ{RESET} {jitter_str} │ {loc_str} │ {DIM}{asn_str}{RESET}{dest_indicator}")


def main():
    parser = argparse.ArgumentParser(description="PacketPulse: Real-Time Network Hop & Protocol Telemetry")
    parser.add_argument("--target", "-t", default="google.com", help="Target domain or IP address (default: google.com)")
    parser.add_argument("--max-hops", "-m", type=int, default=20, help="Maximum number of hops (default: 20)")
    parser.add_argument("--timeout", type=float, default=1.5, help="Socket timeout per hop in seconds (default: 1.5)")
    parser.add_argument("--simulated", "-s", action="store_true", help="Force high-fidelity simulated backbone trace")
    parser.add_argument("--mode", choices=["auto", "raw", "system", "simulated"], default="auto", help="Traceroute execution mode")
    parser.add_argument("--tui", action="store_true", help="Launch Cyberpunk Braille Terminal Radar HUD")
    parser.add_argument("--web", action="store_true", help="Launch 3D WebGL Spatial Earth HUD on localhost:8080")
    parser.add_argument("--port", "-p", type=int, default=8080, help="Web server port (default: 8080)")
    parser.add_argument("--benchmark", "-b", action="store_true", help="Execute multi-thread stress benchmarks and issue performance scorecard")
    parser.add_argument("--audit", "-a", action="store_true", help="Execute OWASP security audit, SAST checks, and issue security scorecard")

    args = parser.parse_args()

    # Route to Security Audit
    if args.audit:
        from packetpulse.security import SecurityAuditor
        print_banner()
        auditor = SecurityAuditor(verbose=True)
        auditor.run_all()
        return

    # Route to Benchmarks
    if args.benchmark:
        from packetpulse.benchmark import PerformanceBenchmarker
        print_banner()
        bm = PerformanceBenchmarker(verbose=True)
        bm.run_all()
        return

    # Route to Web HUD
    if args.web:
        from packetpulse.web import start_web_server
        print_banner()
        start_web_server(port=args.port, open_browser=False)
        return

    # Route to Terminal Radar HUD (TUI)
    if args.tui:
        from packetpulse.tui import PacketPulseHUD
        mode = "simulated" if args.simulated else args.mode
        hud = PacketPulseHUD(target=args.target, mode=mode, max_hops=args.max_hops)
        hud.run()
        return

    # Standard CLI Streaming Output
    print_banner()

    mode = "simulated" if args.simulated else args.mode
    engine = PacketPulse(mode=mode)
    dest_ip = engine.tracer._resolve_target(args.target)

    print(f"  {BOLD}Target Destination:{RESET} {CYAN}{args.target}{RESET} -> [{dest_ip}]")
    print(f"  {BOLD}Tracing Mode:{RESET}       {MAGENTA}{mode}{RESET}")
    print(f"  {BOLD}Max Hops:{RESET}           {args.max_hops}")
    print("─" * 90)
    print(f" {BOLD}HOP{RESET} │ {BOLD}{'IP ADDRESS':<15}{RESET} │ {BOLD}{'RTT':<9}{RESET} │ {BOLD}{'JITTER':<8}{RESET} │ {BOLD}{'LOCATION':<24}{RESET} │ {BOLD}AUTONOMOUS SYSTEM (ASN){RESET}")
    print("─" * 90)

    try:
        telemetry = engine.trace(
            target=args.target,
            max_hops=args.max_hops,
            timeout=args.timeout,
            on_hop=render_hop_row,
        )
    except ValueError as e:
        print(f"\n{RED}Security Validation Error: {e}{RESET}\n")
        sys.exit(1)

    print("─" * 90)
    print(f"\n{BOLD}🎯 TELEMETRY SUMMARY:{RESET}")
    print(f"  • Total Hops Traversed:   {BOLD}{len(telemetry.hops)}{RESET}")
    print(f"  • Destination Reached:    {GREEN if telemetry.reached_destination else RED}{telemetry.reached_destination}{RESET}")
    print(f"  • Average Route Jitter:   {BOLD}{telemetry.avg_jitter_ms} ms{RESET}")
    print(f"  • Total Scan Elapsed:     {BOLD}{telemetry.total_time_ms:.1f} ms{RESET}")
    print(f"  • Packet Loss:            {BOLD}{telemetry.packet_loss_pct}%{RESET}\n")


if __name__ == "__main__":
    main()
