"""PacketPulse Cyberpunk ANSI & Braille Terminal Radar HUD.
Subpixel polar radar plotting, real-time RTT sparklines, and packet telemetry.
"""

from __future__ import annotations
import math
import os
import sys
import time
from typing import List, Optional, Tuple

from .engine import PacketPulse
from .models import Hop, RouteTelemetry

# ANSI Truecolor and styling
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
CYAN = "\033[38;2;0;240;255m"
NEON_GREEN = "\033[38;2;0;255;136m"
AMBER = "\033[38;2;255;184;0m"
CRIMSON = "\033[38;2;255;0;60m"
PURPLE = "\033[38;2;180;100;255m"
DARK_GRAY = "\033[38;2;45;55;72m"
LIGHT_GRAY = "\033[38;2;160;174;192m"


class BrailleRadarCanvas:
    """Subpixel terminal canvas utilizing 2x4 Unicode Braille dot patterns for circular radar."""

    def __init__(self, cols: int = 44, rows: int = 22):
        self.cols = cols
        self.rows = rows
        self.pixel_width = cols * 2
        self.pixel_height = rows * 4
        self.grid = [[0 for _ in range(self.pixel_width)] for _ in range(self.pixel_height)]
        self.color_grid = [[None for _ in range(cols)] for _ in range(rows)]

    def clear(self):
        for r in range(self.pixel_height):
            for c in range(self.pixel_width):
                self.grid[r][c] = 0
        for r in range(self.rows):
            for c in range(self.cols):
                self.color_grid[r][c] = None

    def set_pixel(self, x: int, y: int, color: str = CYAN):
        if 0 <= x < self.pixel_width and 0 <= y < self.pixel_height:
            self.grid[y][x] = 1
            cell_x = x // 2
            cell_y = y // 4
            self.color_grid[cell_y][cell_x] = color

    def draw_line(self, x0: int, y0: int, x1: int, y1: int, color: str = CYAN):
        """Bresenham's line algorithm for radar sweep & trajectory vectors."""
        dx = abs(x1 - x0)
        dy = abs(y1 - y0)
        sx = 1 if x0 < x1 else -1
        sy = 1 if y0 < y1 else -1
        err = dx - dy

        cx, cy = x0, y0
        while True:
            self.set_pixel(cx, cy, color)
            if cx == x1 and cy == y1:
                break
            e2 = 2 * err
            if e2 > -dy:
                err -= dy
                cx += sx
            if e2 < dx:
                err += dx
                cy += sy

    def draw_circle(self, cx: int, cy: int, radius: int, color: str = DARK_GRAY):
        """Midpoint circle algorithm for range rings."""
        x = radius
        y = 0
        err = 0

        while x >= y:
            for px, py in [
                (cx + x, cy + y), (cx + y, cy + x),
                (cx - y, cy + x), (cx - x, cy + y),
                (cx - x, cy - y), (cx - y, cy - x),
                (cx + y, cy - x), (cx + x, cy - y)
            ]:
                self.set_pixel(px, py, color)

            y += 1
            err += 1 + 2 * y
            if 2 * (err - x) + 1 > 0:
                x -= 1
                err += 1 - 2 * x

    def render_rows(self) -> List[str]:
        output_lines = []
        dot_offsets = [
            (0, 0, 0x01), (0, 1, 0x02), (0, 2, 0x04),
            (1, 0, 0x08), (1, 1, 0x10), (1, 2, 0x20),
            (0, 3, 0x40), (1, 3, 0x80),
        ]
        for r in range(self.rows):
            line = ""
            for c in range(self.cols):
                code = 0
                for dx, dy, bit in dot_offsets:
                    px = c * 2 + dx
                    py = r * 4 + dy
                    if 0 <= py < self.pixel_height and 0 <= px < self.pixel_width:
                        if self.grid[py][px]:
                            code |= bit

                char = chr(0x2800 + code) if code > 0 else " "
                col = self.color_grid[r][c] or DARK_GRAY
                line += f"{col}{char}{RESET}"
            output_lines.append(line)
        return output_lines


def generate_sparkline(values: List[float], max_val: Optional[float] = None) -> str:
    """Generate high-density UTF-8 sparkline for RTT latency history."""
    if not values:
        return f"{DIM}--------{RESET}"
    bars = [" ", "â–‚", "â–ƒ", "â–„", "â–…", "â–†", "â–‡", "â–ˆ"]
    m = max_val if max_val is not None else (max(values) if values else 1.0)
    if m <= 0:
        m = 1.0

    rendered = []
    for v in values:
        idx = min(len(bars) - 1, int((v / m) * (len(bars) - 1)))
        col = NEON_GREEN if v < 40 else (AMBER if v < 100 else CRIMSON)
        rendered.append(f"{col}{bars[idx]}{RESET}")
    return "".join(rendered)


class PacketPulseHUD:
    """Interactive Dual Terminal HUD for real-time packet trajectory and telemetry."""

    def __init__(self, target: str = "google.com", mode: str = "simulated", max_hops: int = 15):
        self.target = target
        self.mode = mode
        self.max_hops = max_hops
        self.engine = PacketPulse(mode=mode)
        self.canvas = BrailleRadarCanvas(cols=42, rows=20)
        self.sweep_angle = 0.0
        self.telemetry: Optional[RouteTelemetry] = None
        self.current_hop_idx = 0

    def load_telemetry(self):
        """Execute trace and store telemetry."""
        self.telemetry = self.engine.trace(
            target=self.target,
            max_hops=self.max_hops,
            timeout=1.5,
        )

    def draw_radar_frame(self) -> List[str]:
        """Render a single animated frame of the radar."""
        self.canvas.clear()
        cx = self.canvas.pixel_width // 2
        cy = self.canvas.pixel_height // 2
        max_r = min(cx, cy) - 2

        # Draw concentric distance rings (30ms, 80ms, 150ms)
        self.canvas.draw_circle(cx, cy, int(max_r * 0.33), DARK_GRAY)
        self.canvas.draw_circle(cx, cy, int(max_r * 0.66), DARK_GRAY)
        self.canvas.draw_circle(cx, cy, max_r, DARK_GRAY)

        # Crosshairs
        self.canvas.draw_line(cx - max_r, cy, cx + max_r, cy, DARK_GRAY)
        self.canvas.draw_line(cx, cy - max_r, cx, cy + max_r, DARK_GRAY)

        # Draw rotating sweep beam
        sweep_x = int(cx + max_r * math.cos(self.sweep_angle))
        sweep_y = int(cy + max_r * math.sin(self.sweep_angle))
        self.canvas.draw_line(cx, cy, sweep_x, sweep_y, CYAN)

        # Draw Hops as blips on radar
        if self.telemetry and self.telemetry.hops:
            total_hops = len(self.telemetry.hops)
            for i, hop in enumerate(self.telemetry.hops[:self.current_hop_idx + 1]):
                if hop.timed_out:
                    continue
                rtt = hop.rtt_ms or 10.0
                norm_dist = min(1.0, max(0.1, rtt / 150.0))
                # Angle distributed around radar circle
                angle = (i / max(1, total_hops)) * 2 * math.pi - (math.pi / 2)
                hx = int(cx + norm_dist * max_r * math.cos(angle))
                hy = int(cy + norm_dist * max_r * math.sin(angle))

                # Highlight destination with crimson, intermediate hops with neon green/amber
                col = CRIMSON if hop.is_destination else (NEON_GREEN if rtt < 50 else AMBER)
                # Plot 2x2 blip for visibility
                self.canvas.set_pixel(hx, hy, col)
                self.canvas.set_pixel(hx + 1, hy, col)
                self.canvas.set_pixel(hx, hy + 1, col)
                self.canvas.set_pixel(hx + 1, hy + 1, col)

        return self.canvas.render_rows()

    def render_screen(self) -> str:
        """Compose the full dual-pane cyberpunk terminal HUD."""
        radar_lines = self.draw_radar_frame()
        lines = []

        # Header Bar
        lines.append(f"{CYAN}{BOLD}â•”â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•—{RESET}")
        lines.append(f"{CYAN}{BOLD}â•‘  âš¡ PACKETPULSE // SUBPIXEL NETWORK RADAR & TELEMETRY COMMAND HUD                          â•‘{RESET}")
        lines.append(f"{CYAN}{BOLD}â•šâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•{RESET}")

        dest_ip = self.telemetry.destination_ip if self.telemetry else "RESOLVING..."
        status_line = (
            f" {BOLD}TARGET:{RESET} {CYAN}{self.target}{RESET} [{dest_ip}]  â”‚ "
            f"{BOLD}MODE:{RESET} {PURPLE}{self.mode.upper()}{RESET}  â”‚ "
            f"{BOLD}SWEEP:{RESET} {math.degrees(self.sweep_angle) % 360:05.1f}Â°"
        )
        lines.append(status_line)
        lines.append(f"{DARK_GRAY}{'â”€' * 95}{RESET}")

        # Side-by-side: Left = Braille Radar, Right = Telemetry & Hop Stream
        active_hops = self.telemetry.hops[:self.current_hop_idx + 1] if self.telemetry else []
        rtts = [h.rtt_ms for h in active_hops if h.rtt_ms is not None]
        sparkline = generate_sparkline(rtts)

        avg_rtt = sum(rtts) / len(rtts) if rtts else 0.0
        avg_jitter = self.telemetry.avg_jitter_ms if self.telemetry else 0.0
        loss_pct = self.telemetry.packet_loss_pct if self.telemetry else 0.0

        side_panels = [
            f"{BOLD}â–º TELEMETRY METRICS{RESET}",
            f"  {LIGHT_GRAY}Hops Active:{RESET}   {BOLD}{len(active_hops)}/{len(self.telemetry.hops) if self.telemetry else '?'}{RESET}",
            f"  {LIGHT_GRAY}Avg Latency:{RESET}   {NEON_GREEN if avg_rtt < 50 else AMBER}{avg_rtt:.1f} ms{RESET}",
            f"  {LIGHT_GRAY}Avg Jitter:{RESET}    {BOLD}{avg_jitter:.1f} ms{RESET}",
            f"  {LIGHT_GRAY}Packet Loss:{RESET}   {NEON_GREEN if loss_pct == 0 else CRIMSON}{loss_pct:.1f}%{RESET}",
            f"  {LIGHT_GRAY}RTT Profile:{RESET}   {sparkline}",
            f"{DARK_GRAY}{'â”€' * 46}{RESET}",
            f"{BOLD}â–º RECENT HOP ROUTE{RESET}",
        ]

        # Add recent 10 hops to side panel
        recent_hops = active_hops[-10:] if active_hops else []
        for h in recent_hops:
            if h.timed_out:
                side_panels.append(f"  {DIM}{h.hop_num:02d}{RESET} {CRIMSON}* TIMEOUT *{RESET}")
            else:
                dest = f" {NEON_GREEN}â˜…{RESET}" if h.is_destination else ""
                rtt_c = NEON_GREEN if (h.rtt_ms or 0) < 50 else (AMBER if (h.rtt_ms or 0) < 100 else CRIMSON)
                loc= fnÚ˜Ú]_KÚ˜Ûİ[_HˆYˆ˜Ú]H[ÙH•˜[œÚ]›ÙH‚ˆØÈH
ØÖÎŒMH
È‹‹ˆŠHYˆ[ŠØÊHˆMˆ[ÙHˆÛØÎMŸH‚ˆÚYWÜ[™[Ë˜\[™
ˆˆĞ“Ó^ÚšÜÛ[NŒ™^Ô‘TÑUHĞÖPSŸ^Úš\M^Ô‘TÑUHÜØß^ÚœÛ\ÎKŒYŸ[\ŞÔ‘TÑUHÑS_^ÛØß^Ô‘TÑU^Ù\İHŠB‚ˆÈYÚYH[™[ÈÈX]Ú˜Y\ˆZYÚˆÚ[H[ŠÚYWÜ[™[ÊH[Š˜Y\—Û[™\ÊN‚ˆÚYWÜ[™[Ë˜\[™
ˆŠB‚ˆ›Üˆ—Û[™K×Û[™H[ˆš\
˜Y\—Û[™\ËÚYWÜ[™[ÊN‚ˆ[™\Ë˜\[™
ˆˆÜ—Û[™_H8¥ ˆÜ×Û[™_HŠB‚ˆ[™\Ë˜\[™
ˆÑT’×ÑÔV_^Éø¥ 	È
ˆM_^Ô‘TÑUHŠBˆ[™\Ë˜\[™
ˆˆÑS_PÛÛ›ÛÎˆ™\ÜÈİ›
ĞÈÈ^]˜Y\ˆQËÈ™Yœ™\Ú[™È]MH”ŞÔ‘TÑUHŠB‚ˆ™]\›ˆ—ˆ‹š›Ú[Š[™\ÊB‚ˆYˆ[ŠÙ[‹œ˜[Y\Îˆ[H
N‚ˆˆˆ”[ˆ\›Z[˜[[š[X][ÛˆÛÜˆˆˆ‚ˆÈYHİ\œÛÜ‚ˆŞ\Ëœİİ]Üš]J—ÌÖÏÌ[ŠBˆŞ\Ëœİİ]™›\Ú

B‚ˆN‚ˆÈš\œİ˜XÙBˆÙ[‹›ØYİ[[Y]J
Bˆİ[ÚÜÈH[ŠÙ[‹[[Y]KšÜÊHYˆÙ[‹[[Y]H[ÙHB‚ˆ›Üˆˆ[ˆ˜[™ÙJœ˜[Y\ÊN‚ˆÙ[‹œİÙY\Ø[™ÛH
ÏHŒ‚ˆYˆÙ[‹˜İ\œ™[ÚÜÚYİ[ÚÜÈHH[™ˆ	HˆOH‚ˆÙ[‹˜İ\œ™[ÚÜÚY
ÏHB‚ˆÈ[İ™Hİ\œÛÜˆÈÜYˆØÜ™Y[—ÜİˆH—ÌÖÒˆ
ÈÙ[‹œ™[™\—ÜØÜ™Y[Š
BˆŞ\Ëœİİ]Üš]JØÜ™Y[—ÜİŠBˆŞ\Ëœİİ]™›\Ú

Bˆ[YKœÛY\
ŒJHÈŒMH”Âˆ^Ù\Ù^X›Ø\™[\œ\‚ˆ\ÜÂˆš[˜[N‚ˆÈ™\İÜ™Hİ\œÛÜ‚ˆŞ\Ëœİİ]Üš]J—ÌÖÏÌZˆŠBˆŞ\Ëœİİ]™›\Ú

B‚‚™Yˆ[—İZJ\™Ù]ˆİˆH™ÛÛÙÛK˜ÛÛH‹[ÙNˆİˆHœÚ[][]Y‹œ˜[Y\Îˆ[HJN‚ˆˆˆ‘[HÚ[È][˜ÚRKˆˆˆ‚ˆYHXÚÙ][ÙRQ
\™Ù]]\™Ù][ÙO[[ÙJBˆYœ[Šœ˜[Y\ÏYœ˜[Y\ÊB‚‚šYˆ×Û˜[YW×ÈOH—×ÛXZ[—×È‚ˆ\™Ù]HŞ\Ë˜\™İ–ÌWHYˆ[ŠŞ\Ë˜\™İŠHˆH[ÙH™ÛÛÙÛK˜ÛÛH‚ˆ[—İZJ\™Ù]]\™Ù]
B