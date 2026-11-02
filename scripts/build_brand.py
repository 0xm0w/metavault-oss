#!/usr/bin/env python3
"""MetaVault OSS brand system -- v0.3 clean-room rebuild.

Nothing here is traced from a bitmap. The mark is authored as parametric
geometry on a 512-unit grid and emitted twice from the same contour list:

  * SVG  -- exact fillet arcs (``A`` commands), even-odd / non-zero fills and a
            mask for the hinge gaps;
  * PNG  -- the same contours flattened and rasterised with a winding-number
            accumulator at 4-16x supersampling, then box-filtered down.

Optical sizes
-------------
A single drawing cannot be both detailed at 512 px and crisp at 16 px, so the
mark ships five hand-tuned tiers that share one silhouette:

  full   >= 96 px   chip with "AI" + pin-1 marker, fine pins
  mid    40-95 px   heavier frame, bigger chip, bolder "AI", no marker
  small  28-39 px   drawn on a 32-px grid (16 units/px): chip + die window
  tiny   20-27 px   drawn on a 24-px grid: chip + die window, 2 pins a side
  micro  < 20 px    drawn on a 16-px grid (32 units/px): solid chip + pins

Run:  python scripts/build_brand.py
"""
from __future__ import annotations

import math
import os
import struct
import sys

import numpy as np
from PIL import Image, ImageDraw

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
B = os.path.join(ROOT, "brand")
FONT = os.path.join(B, "src", "inter-var.ttf")
GRID = 512

INK = (12, 12, 14)
ACCENT = (130, 80, 252)
PAPER = (251, 251, 253)
NIGHT = (15, 13, 23)
SNOW = (244, 244, 246)

for sub in ("icons", "app", os.path.join("app", "mac.iconset")):
    os.makedirs(os.path.join(B, sub), exist_ok=True)


# =============================================================================
# geometry primitives -- every shape is a closed contour: (svg_d, points)
# =============================================================================
def _f(v: float) -> str:
    s = f"{v:.2f}".rstrip("0").rstrip(".")
    return "0" if s in ("-0", "") else s


def fillet(verts, radii=0.0, steps=18):
    """Polygon with a circular fillet of radius ``r_i`` at every vertex."""
    n = len(verts)
    if not isinstance(radii, (list, tuple)):
        radii = [radii] * n
    corners = []
    for i in range(n):
        px, py = verts[i]
        ax, ay = verts[i - 1]
        cx, cy = verts[(i + 1) % n]
        r = radii[i]
        ux, uy = ax - px, ay - py
        vx, vy = cx - px, cy - py
        lu, lv = math.hypot(ux, uy), math.hypot(vx, vy)
        if r <= 0 or lu == 0 or lv == 0:
            corners.append(((px, py), None))
            continue
        ux, uy, vx, vy = ux / lu, uy / lu, vx / lv, vy / lv
        theta = math.acos(max(-1.0, min(1.0, ux * vx + uy * vy)))
        if theta < 1e-6 or abs(math.pi - theta) < 1e-6:
            corners.append(((px, py), None))
            continue
        t = r / math.tan(theta / 2)
        tmax = min(lu, lv) / 2
        if t > tmax:
            t = tmax
            r = t * math.tan(theta / 2)
        t1 = (px + ux * t, py + uy * t)
        t2 = (px + vx * t, py + vy * t)
        bx, by = ux + vx, uy + vy
        bl = math.hypot(bx, by)
        d = r / math.sin(theta / 2)
        cen = (px + bx / bl * d, py + by / bl * d)
        turn = (px - ax) * (cy - py) - (py - ay) * (cx - px)
        corners.append(((t1, t2, cen, r, 1 if turn > 0 else 0), True))

    d_parts, pts = [], []
    for k, (c, rounded) in enumerate(corners):
        if not rounded:
            x, y = c
            d_parts.append(("M" if k == 0 else "L") + f"{_f(x)},{_f(y)}")
            pts.append((x, y))
            continue
        t1, t2, cen, r, sweep = c
        d_parts.append(("M" if k == 0 else "L") + f"{_f(t1[0])},{_f(t1[1])}")
        d_parts.append(f"A{_f(r)},{_f(r)} 0 0 {sweep} {_f(t2[0])},{_f(t2[1])}")
        a1 = math.atan2(t1[1] - cen[1], t1[0] - cen[0])
        a2 = math.atan2(t2[1] - cen[1], t2[0] - cen[0])
        da = (a2 - a1 + math.pi) % (2 * math.pi) - math.pi
        for s in range(steps + 1):
            a = a1 + da * s / steps
            pts.append((cen[0] + r * math.cos(a), cen[1] + r * math.sin(a)))
    return "".join(d_parts) + "Z", pts


def rrect(x0, y0, x1, y1, r=0.0):
    return fillet([(x0, y0), (x1, y0), (x1, y1), (x0, y1)], r)


def rrect_c(cx, cy, w, h, r=0.0):
    return rrect(cx - w / 2, cy - h / 2, cx + w / 2, cy + h / 2, r)


def _line_x(p, q, y):
    (x0, y0), (x1, y1) = p, q
    return x0 + (x1 - x0) * (y - y0) / (y1 - y0)


def glyph_ai(cx, cy, cap, stem, wa, apex, bar, bar_lift, gap, wi, r=3.0):
    """Geometric 'AI' monogram, optically centred on (cx, cy)."""
    total = wa + gap + wi
    x0 = cx - total / 2
    yt, yb = cy - cap / 2, cy + cap / 2
    # A: outer legs, then inner legs offset by the (horizontal) stem width
    lo = ((x0, yb), (x0 + (wa - apex) / 2, yt))
    ro = ((x0 + wa, yb), (x0 + (wa + apex) / 2, yt))
    li = ((x0 + stem, yb), (x0 + stem + (wa - apex) / 2, yt))
    ri = ((x0 + wa - stem, yb), (x0 + wa - stem + (wa + apex) / 2 - wa, yt))
    bar_bot = yb - bar_lift
    bar_top = bar_bot - bar
    outer = fillet(
        [lo[0], lo[1], ro[1], ro[0],
         ri[0], (_line_x(*ri, bar_bot), bar_bot),
         (_line_x(*li, bar_bot), bar_bot), li[0]],
        [r * 0.6, r, r, r * 0.6, r * 0.6, 0, 0, r * 0.6])
    # counter: triangle (or trapezoid if the legs never meet below the apex)
    sl = (li[1][0] - li[0][0]) / (li[1][1] - li[0][1])
    sr = (ri[1][0] - ri[0][0]) / (ri[1][1] - ri[0][1])
    y_meet = li[0][1] + (ri[0][0] - li[0][0]) / (sl - sr)
    y_cap = yt + stem * 0.95
    xl, xr = _line_x(*li, bar_top), _line_x(*ri, bar_top)
    if y_meet >= y_cap:
        counter = fillet([(xl, bar_top), (_line_x(*li, y_meet), y_meet),
                          (xr, bar_top)], [0.8, 0.8, 0.8])
    else:
        counter = fillet([(xl, bar_top), (_line_x(*li, y_cap), y_cap),
                          (_line_x(*ri, y_cap), y_cap), (xr, bar_top)], 0.8)
    xi = x0 + wa + gap
    i_bar = rrect(xi, yt, xi + wi, yb, r * 0.6)
    return [outer, counter, i_bar]


# =============================================================================
# the mark -- one parametric drawing, four optical tiers
# =============================================================================
def _px(grid, **spec):
    """Scale a tier authored in whole pixels on a ``grid``-px canvas to 512u."""
    u = GRID / grid

    def sc(v):
        if isinstance(v, (int, float)):
            return v * u
        if isinstance(v, tuple):
            return tuple(sc(x) for x in v)
        if isinstance(v, list):
            return [sc(x) for x in v]
        if isinstance(v, dict):
            return {k: (x if k == "n" else sc(x)) for k, x in v.items()}
        return v

    return {k: sc(v) for k, v in spec.items()}


TIERS = {
    "full": dict(
        body=(72, 64, 440, 416, 88), frame=40, inner_r=48,
        feet=[(124, 400, 188, 448, 18), (324, 400, 388, 448, 18)],
        hinge=dict(cx=(92, 420), cy=240, w=48, h=136, gap=12),
        chip=dict(cx=256, cy=240, s=172, r=30),
        pins=dict(n=3, w=20, len=28, pitch=48, cap=10),
        letters=dict(cap=80, stem=22, wa=86, apex=26, bar=18, bar_lift=14,
                     gap=12, wi=22, r=3),
        dot=(194, 178, 7), die=None),
    "mid": dict(
        body=(72, 64, 440, 416, 88), frame=46, inner_r=44,
        feet=[(120, 400, 192, 452, 20), (320, 400, 392, 452, 20)],
        hinge=dict(cx=(95, 417), cy=240, w=54, h=140, gap=16),
        chip=dict(cx=256, cy=240, s=184, r=32),
        pins=dict(n=3, w=24, len=24, pitch=54, cap=10),
        letters=dict(cap=94, stem=29, wa=100, apex=30, bar=24, bar_lift=14,
                     gap=12, wi=29, r=4),
        dot=None, die=None),
    # 32-px grid -> 16 units per pixel; every edge lands on a pixel boundary
    "small": dict(
        body=(48, 32, 464, 416, 96), frame=48, inner_r=48,
        feet=[(112, 384, 192, 464, 24), (320, 384, 400, 464, 24)],
        hinge=dict(cx=(72, 440), cy=224, w=80, h=160, gap=16),
        chip=dict(cx=256, cy=224, s=160, r=32),
        pins=dict(n=2, w=32, len=32, pitch=64, cap=8),
        letters=None, dot=None, die=(64, 12)),
    # 24-px grid -> 21.33 units per pixel
    "tiny": _px(
        24,
        body=(2, 1, 22, 19, 4), frame=2, inner_r=2,
        feet=[(5, 18, 9, 23, 1), (15, 18, 19, 23, 1)],
        hinge=dict(cx=(3, 21), cy=10, w=4, h=6, gap=1),
        chip=dict(cx=12, cy=10, s=8, r=1.5),
        pins=dict(n=2, w=2, len=2, pitch=4, cap=0),
        letters=None, dot=None, die=(2, 0.4)),
    # 16-px grid -> 32 units per pixel
    "micro": dict(
        body=(64, 32, 448, 416, 96), frame=64, inner_r=32,
        feet=[(128, 384, 192, 480, 16), (320, 384, 384, 480, 16)],
        hinge=dict(cx=(80, 432), cy=224, w=96, h=192, gap=0, r=16),
        chip=dict(cx=256, cy=224, s=128, r=16),
        pins=dict(n=2, w=32, len=32, pitch=96, cap=0),
        letters=None, dot=None, die=None),
}


def tier_for(px: float) -> str:
    if px >= 96:
        return "full"
    if px >= 40:
        return "mid"
    if px >= 28:
        return "small"
    if px >= 20:
        return "tiny"
    return "micro"


def mark(tier: str):
    """Return paint layers: [(color_key, [(rule, contours)], cut_contours)]."""
    p = TIERS[tier]
    x0, y0, x1, y1, r = p["body"]
    t = p["frame"]
    frame = ("evenodd", [rrect(x0, y0, x1, y1, r),
                         rrect(x0 + t, y0 + t, x1 - t, y1 - t, p["inner_r"])])
    feet = [("nonzero", [rrect(*f)]) for f in p["feet"]]

    c = p["chip"]
    cx, cy, s = c["cx"], c["cy"], c["s"]
    chip_c = [rrect_c(cx, cy, s, s, c["r"])]
    if p["dot"]:
        dx, dy, dr = p["dot"]
        chip_c.append(rrect_c(dx, dy, dr * 2, dr * 2, dr))
    if p["die"]:
        ds, dr = p["die"]
        chip_c.append(rrect_c(cx, cy, ds, ds, dr))
    if p["letters"]:
        chip_c += glyph_ai(cx, cy, **p["letters"])
    chip = ("evenodd", chip_c)

    pn = p["pins"]
    pins = []
    half = s / 2
    ov = 6  # pins tuck under the chip edge so the SVG never shows a seam
    offs = [(k - (pn["n"] - 1) / 2) * pn["pitch"] for k in range(pn["n"])]
    w2, ln, cr = pn["w"] / 2, pn["len"], pn["cap"]
    for o in offs:
        # top, bottom, left, right -- fillet only on the outer end
        pins.append(fillet([(cx + o - w2, cy - half - ln), (cx + o + w2, cy - half - ln),
                            (cx + o + w2, cy - half + ov), (cx + o - w2, cy - half + ov)],
                           [cr, cr, 0, 0]))
        pins.append(fillet([(cx + o - w2, cy + half - ov), (cx + o + w2, cy + half - ov),
                            (cx + o + w2, cy + half + ln), (cx + o - w2, cy + half + ln)],
                           [0, 0, cr, cr]))
        pins.append(fillet([(cx - half - ln, cy + o - w2), (cx - half + ov, cy + o - w2),
                            (cx - half + ov, cy + o + w2), (cx - half - ln, cy + o + w2)],
                           [cr, 0, 0, cr]))
        pins.append(fillet([(cx + half - ov, cy + o - w2), (cx + half + ln, cy + o - w2),
                            (cx + half + ln, cy + o + w2), (cx + half - ov, cy + o + w2)],
                           [0, cr, cr, 0]))
    pin_paths = [("nonzero", [pc]) for pc in pins]

    h = p["hinge"]
    hinges, cuts = [], []
    for hx in h["cx"]:
        hinges.append(("nonzero", [rrect_c(hx, h["cy"], h["w"], h["h"],
                                           h.get("r", h["w"] / 2))]))
        if h["gap"]:
            g = h["gap"]
            cuts.append(rrect_c(hx, h["cy"], h["w"] + 2 * g, h["h"] + 2 * g,
                                h["w"] / 2 + g))

    return [("ink", [frame] + feet + [chip] + pin_paths, cuts),
            ("accent", hinges, [])]


# =============================================================================
# rasteriser -- winding-number accumulation, supersampled, box-filtered
# =============================================================================
def _signed_area(pts):
    a = 0.0
    for i in range(len(pts)):
        x0, y0 = pts[i - 1]
        x1, y1 = pts[i]
        a += x0 * y1 - x1 * y0
    return a / 2


def _cover(paths, W, H, xf):
    """Boolean coverage of a list of (rule, contours) at supersampled size."""
    out = np.zeros((H, W), dtype=bool)
    for rule, contours in paths:
        wind = np.zeros((H, W), dtype=np.int16)
        for _, pts in contours:
            im = Image.new("1", (W, H), 0)
            ImageDraw.Draw(im).polygon([xf(x, y) for x, y in pts], fill=1)
            m = np.asarray(im, dtype=bool)
            if rule == "evenodd":
                wind += m
            else:
                wind += np.where(m, 1 if _signed_area(pts) > 0 else -1, 0).astype(np.int16)
        out |= (wind % 2 == 1) if rule == "evenodd" else (wind != 0)
    return out


def _reduce(mask, ss):
    H, W = mask.shape
    return mask.reshape(H // ss, ss, W // ss, ss).mean(axis=(1, 3))


def render(size, scale=1.0, colors=None, bg=None, tile_r=None, tier=None,
           mono=None):
    """Rasterise the mark. ``scale`` = mark height as a fraction of ``size``."""
    colors = colors or {"ink": INK, "accent": ACCENT}
    if mono:
        colors = {"ink": mono, "accent": mono}
    tier = tier or tier_for(size * scale)
    ss = 16 if size <= 64 else 8 if size <= 256 else 4
    W = size * ss
    k = size * scale / GRID * ss
    off = W / 2 - GRID / 2 * k

    def xf(x, y):
        return (x * k + off, y * k + off)

    rgb = np.zeros((size, size, 3))
    alpha = np.zeros((size, size))
    if bg is not None:
        if tile_r is None:
            cov = np.ones((size, size))
        else:
            cov = _reduce(_cover([("nonzero", [rrect(0, 0, W, W, tile_r * W)])],
                                 W, W, lambda x, y: (x, y)), ss)
        rgb[:] = np.array(bg) / 255.0
        rgb *= cov[..., None]
        alpha = cov.copy()
    for key, paths, cuts in mark(tier):
        m = _cover(paths, W, W, xf)
        if cuts:
            m &= ~_cover([("nonzero", [c]) for c in cuts], W, W, xf)
        a = _reduce(m, ss)
        col = np.array(colors[key]) / 255.0
        rgb = rgb * (1 - a[..., None]) + col * a[..., None]
        alpha = alpha * (1 - a) + a
    out = np.zeros((size, size, 4), dtype=np.uint8)
    safe = np.where(alpha > 0, alpha, 1)
    out[..., :3] = np.clip(rgb / safe[..., None] * 255 + 0.5, 0, 255)
    out[..., 3] = np.clip(alpha * 255 + 0.5, 0, 255)
    return Image.fromarray(out, "RGBA")


def save(im, *rel):
    path = os.path.join(B, *rel)
    im.save(path, optimize=True)
    return path


# =============================================================================
# SVG emitter -- same contours, exact arcs
# =============================================================================
def svg_mark_group(tier="full", colors=None, uid="mv", transform=None):
    colors = colors or {"ink": INK, "accent": ACCENT}
    hexc = {k: "#%02x%02x%02x" % v for k, v in colors.items()}
    defs, body = [], []
    for key, paths, cuts in mark(tier):
        attrs = f' fill="{hexc[key]}"'
        if cuts:
            mid = f"{uid}-cut"
            d = "".join(c[0] for c in cuts)
            defs.append(f'<mask id="{mid}" maskUnits="userSpaceOnUse" x="0" y="0" '
                        f'width="{GRID}" height="{GRID}"><rect width="{GRID}" '
                        f'height="{GRID}" fill="#fff"/><path d="{d}"/></mask>')
            attrs += f' mask="url(#{mid})"'
        inner = []
        for rule, contours in paths:
            fr = ' fill-rule="evenodd"' if rule == "evenodd" else ""
            inner.append(f'<path{fr} d="{"".join(c[0] for c in contours)}"/>')
        body.append(f"<g{attrs}>" + "".join(inner) + "</g>")
    tr = f' transform="{transform}"' if transform else ""
    return "".join(defs), f"<g{tr}>" + "".join(body) + "</g>"


def write_svg(rel, inner_defs, inner_body, vb=f"0 0 {GRID} {GRID}", title="MetaVault OSS"):
    defs = f"<defs>{inner_defs}</defs>" if inner_defs else ""
    with open(os.path.join(B, rel), "w", encoding="utf-8", newline="\n") as fh:
        fh.write(f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="{vb}">'
                 f"<title>{title}</title>{defs}{inner_body}</svg>\n")


# =============================================================================
# wordmark -- Inter outlines (wght 640) + GPOS pair kerning, vector + raster
# =============================================================================
def _gpos_kern(font, left, right):
    """Default-master pair kerning between two glyph names (PairPos f1/f2)."""
    if "GPOS" not in font:
        return 0
    gpos = font["GPOS"].table
    idx = set()
    for fr in gpos.FeatureList.FeatureRecord:
        if fr.FeatureTag == "kern":
            idx.update(fr.Feature.LookupListIndex)
    for li in sorted(idx):
        lk = gpos.LookupList.Lookup[li]
        for st in lk.SubTable:
            if lk.LookupType == 9:
                st = st.ExtSubTable
            if getattr(st, "LookupType", 2) != 2 or left not in st.Coverage.glyphs:
                continue
            if st.Format == 1:
                ps = st.PairSet[st.Coverage.glyphs.index(left)]
                for pv in ps.PairValueRecord:
                    if pv.SecondGlyph == right and pv.Value1:
                        return getattr(pv.Value1, "XAdvance", 0) or 0
            elif st.Format == 2:
                c1 = st.ClassDef1.classDefs.get(left, 0)
                c2 = st.ClassDef2.classDefs.get(right, 0)
                v = st.Class1Record[c1].Class2Record[c2].Value1
                if v and getattr(v, "XAdvance", 0):
                    return v.XAdvance
    return 0


def wordmark_contours(text, px, wght=640, tracking=-0.012):
    """Contours (svg_d, pts) for ``text`` at cap-relative size ``px`` (em)."""
    from fontTools.pens.basePen import BasePen
    from fontTools.ttLib import TTFont

    font = TTFont(FONT)
    upm = font["head"].unitsPerEm
    gs = font.getGlyphSet(location={"wght": wght, "opsz": 32})
    cmap = font.getBestCmap()
    s = px / upm
    asc = font["hhea"].ascent

    class Flat(BasePen):
        def __init__(self, ox):
            super().__init__(gs)
            self.ox, self.cur, self.contours, self.d = ox, [], [], []

        def _pt(self, p):
            return ((p[0] + self.ox) * s, (asc - p[1]) * s)

        def _moveTo(self, p):
            self.cur = [self._pt(p)]
            self.d.append("M" + ",".join(_f(v) for v in self._pt(p)))

        def _lineTo(self, p):
            self.cur.append(self._pt(p))
            self.d.append("L" + ",".join(_f(v) for v in self._pt(p)))

        def _qCurveToOne(self, p1, p2):
            a, b, c = self._getCurrentPoint(), p1, p2
            for i in range(1, 9):
                t = i / 8
                x = (1 - t) ** 2 * a[0] + 2 * (1 - t) * t * b[0] + t * t * c[0]
                y = (1 - t) ** 2 * a[1] + 2 * (1 - t) * t * b[1] + t * t * c[1]
                self.cur.append(self._pt((x, y)))
            q1, q2 = self._pt(p1), self._pt(p2)
            self.d.append(f"Q{_f(q1[0])},{_f(q1[1])} {_f(q2[0])},{_f(q2[1])}")

        def _curveToOne(self, p1, p2, p3):
            a = self._getCurrentPoint()
            for i in range(1, 13):
                t = i / 12
                mt = 1 - t
                x = mt**3 * a[0] + 3 * mt * mt * t * p1[0] + 3 * mt * t * t * p2[0] + t**3 * p3[0]
                y = mt**3 * a[1] + 3 * mt * mt * t * p1[1] + 3 * mt * t * t * p2[1] + t**3 * p3[1]
                self.cur.append(self._pt((x, y)))
            c1, c2, c3 = self._pt(p1), self._pt(p2), self._pt(p3)
            self.d.append(f"C{_f(c1[0])},{_f(c1[1])} {_f(c2[0])},{_f(c2[1])} "
                          f"{_f(c3[0])},{_f(c3[1])}")

        def _closePath(self):
            self.d.append("Z")
            self.contours.append(self.cur)
            self.cur = []

        _endPath = _closePath

    out, x = [], 0.0
    names = [cmap[ord(ch)] for ch in text]
    for i, name in enumerate(names):
        pen = Flat(x)
        gs[name].draw(pen)
        d = "".join(pen.d)
        # one svg_d per glyph; keep flattened contours for the rasteriser
        out.append((d, pen.contours))
        x += gs[name].width + tracking * upm
        if i + 1 < len(names):
            x += _gpos_kern(font, name, names[i + 1])
    width = (x - tracking * upm) * s
    capH = font["OS/2"].sCapHeight * s
    top = (asc - font["OS/2"].sCapHeight) * s
    return out, width, capH, top


def _scan_nonzero(contours, W, H, xf):
    """Non-zero scanline fill; handles self-intersecting font contours."""
    segs = []
    for pts in contours:
        p = np.array([xf(x, y) for x, y in pts], dtype=float)
        q = np.roll(p, -1, axis=0)
        segs.append(np.hstack([p, q]))
    e = np.vstack(segs)
    e = e[e[:, 1] != e[:, 3]]
    up = e[:, 1] > e[:, 3]
    d = np.where(up, -1, 1)
    y0 = np.minimum(e[:, 1], e[:, 3])
    y1 = np.maximum(e[:, 1], e[:, 3])
    out = np.zeros((H, W), dtype=bool)
    r0 = max(0, int(math.floor(y0.min())))
    r1 = min(H, int(math.ceil(y1.max())) + 1)
    for r in range(r0, r1):
        yc = r + 0.5
        act = (y0 <= yc) & (y1 > yc)
        if not act.any():
            continue
        a = e[act]
        xs = a[:, 0] + (yc - a[:, 1]) * (a[:, 2] - a[:, 0]) / (a[:, 3] - a[:, 1])
        order = np.argsort(xs)
        xs, ds = xs[order], d[act][order]
        wind = np.cumsum(ds)
        for i in range(len(xs) - 1):
            if wind[i] != 0:
                c0 = max(0, int(math.ceil(xs[i] - 0.5)))
                c1 = min(W, int(math.ceil(xs[i + 1] - 0.5)))
                if c1 > c0:
                    out[r, c0:c1] = True
    return out


def render_text(glyphs, w, h, ox, oy, color, ss=4):
    W, H = w * ss, h * ss
    contours = [c for _, cs in glyphs for c in cs]
    m = _scan_nonzero(contours, W, H, lambda x, y: ((x + ox) * ss, (y + oy) * ss))
    a = _reduce(m, ss)
    out = np.zeros((h, w, 4), dtype=np.uint8)
    out[..., :3] = color
    out[..., 3] = np.clip(a * 255 + 0.5, 0, 255)
    return Image.fromarray(out, "RGBA")


# =============================================================================
# build
# =============================================================================
def build():
    hexd = lambda c: "#%02x%02x%02x" % c  # noqa: E731

    # ---- master vectors -----------------------------------------------------
    d, g = svg_mark_group("full", uid="mv")
    write_svg("mark.svg", d, g)
    d, g = svg_mark_group("full", {"ink": SNOW, "accent": ACCENT}, uid="mvi")
    write_svg("mark-inverse.svg", d, g)
    # favicon.svg: paper tile, mark at 80%; tier "mid" because it renders tiny
    d, g = svg_mark_group("mid", uid="fv", transform="translate(51.2 51.2) scale(.8)")
    write_svg(os.path.join("icons", "favicon.svg"), d,
              f'<rect width="512" height="512" rx="116" fill="{hexd(PAPER)}"/>{g}')

    # ---- transparent favicon rung ----------------------------------------
    for s in (16, 32, 48, 64, 96, 128, 256):
        save(render(s), "icons", f"favicon-{s}.png")
    frames = [render(s) for s in (16, 24, 32, 48)]
    frames[-1].save(os.path.join(B, "icons", "favicon.ico"), format="ICO",
                    sizes=[(s, s) for s in (16, 24, 32, 48)], append_images=frames[:-1])

    # ---- opaque tiles: apple-touch, PWA, maskable ---------------------------
    save(render(180, 0.78, bg=PAPER), "icons", "apple-touch-icon.png")
    save(render(192, 0.78, bg=PAPER), "icons", "icon-192.png")
    save(render(512, 0.78, bg=PAPER), "icons", "icon-512.png")
    save(render(512, 0.62, bg=PAPER), "icons", "maskable-512.png")

    # ---- silhouettes ---------------------------------------------------------
    save(render(512, mono=(255, 255, 255)), "icons", "mark-white.png")
    save(render(512, mono=INK), "icons", "mark-black.png")

    # ---- desktop app ---------------------------------------------------------
    # Docks and taskbars are often dark, so app icons ship on a paper squircle.
    # <= 32 px keeps the mark at 100% so the pixel-grid tiers stay crisp.
    def app_icon(s):
        if s <= 32:
            return render(s, 1.0, bg=PAPER, tile_r=0.19)
        return render(s, 0.76, bg=PAPER, tile_r=0.225)

    for s in (1024, 512, 256, 128, 64, 32):
        save(app_icon(s), "app", f"icon-{s}.png")
    ico = [app_icon(s) for s in (16, 24, 32, 48, 64, 96, 128, 256)]
    ico[-1].save(os.path.join(B, "app", "app-icon.ico"), format="ICO",
                 sizes=[(s, s) for s in (16, 24, 32, 48, 64, 96, 128, 256)],
                 append_images=ico[:-1])
    for s, n in [(16, "icon_16x16.png"), (32, "icon_16x16@2x.png"), (32, "icon_32x32.png"),
                 (64, "icon_32x32@2x.png"), (128, "icon_128x128.png"),
                 (256, "icon_128x128@2x.png"), (256, "icon_256x256.png"),
                 (512, "icon_256x256@2x.png"), (512, "icon_512x512.png"),
                 (1024, "icon_512x512@2x.png")]:
        save(app_icon(s), "app", "mac.iconset", n)
    save(render(32, mono=(255, 255, 255)), "app", "tray.png")
    save(render(64, mono=(255, 255, 255)), "app", "tray@2x.png")
    save(render(32, mono=INK), "app", "tray-light.png")
    save(render(64, mono=INK), "app", "tray-light@2x.png")

    # ---- wordmark + lockups --------------------------------------------------
    em = 200.0
    glyphs, ww, capH, top = wordmark_contours("MetaVault", em)
    pad = 6
    wm_w, wm_h = int(math.ceil(ww)) + 2 * pad, int(math.ceil(capH)) + 2 * pad
    wd = "".join(gd for gd, _ in glyphs)
    with open(os.path.join(B, "wordmark.svg"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write(f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {wm_w} {wm_h}">'
                 f'<title>MetaVault</title><path fill="{hexd(INK)}" '
                 f'transform="translate({pad} {_f(pad - top)})" d="{wd}"/></svg>\n')
    render_text(glyphs, wm_w, wm_h, pad, pad - top, INK).save(
        os.path.join(B, "wordmark.png"), optimize=True)

    # lockup: mark box H, cap height = 0.36 H, gap = 0.14 H
    H = 200
    k = H / GRID
    cap_target = 0.36 * H
    ts = cap_target / capH
    gap = 0.14 * H
    lw = int(math.ceil(H + gap + ww * ts)) + 4
    tx, ty = H + gap, (H - cap_target) / 2 - top * ts
    for mode, ink in (("light", INK), ("dark", SNOW)):
        cols = {"ink": ink, "accent": ACCENT}
        dd, gg = svg_mark_group("full", cols, uid=f"lk{mode}", transform=f"scale({_f(k)})")
        if mode == "light":
            write_svg("logo-horizontal.svg", dd,
                      gg + f'<path fill="{hexd(ink)}" transform="translate({_f(tx)} {_f(ty)}) '
                      f'scale({ts:.5f})" d="{wd}"/>', vb=f"0 0 {lw} {H}")
        canvas = Image.new("RGBA", (lw, H), (0, 0, 0, 0))
        canvas.alpha_composite(render(H, colors=cols), (0, 0))
        scaled = [(None, [[(x * ts, y * ts) for x, y in c] for c in cs]) for _, cs in glyphs]
        txt = render_text(scaled, lw, H, tx, ty, ink)
        canvas.alpha_composite(txt)
        canvas.save(os.path.join(B, "logo-horizontal.png" if mode == "light"
                                 else "logo-horizontal-dark.png"), optimize=True)

    # ---- QA: per-tier contact strip for the preview --------------------------
    strip = Image.new("RGBA", (5 * 136, 136), PAPER + (255,))
    for i, t in enumerate(("full", "mid", "small", "tiny", "micro")):
        strip.alpha_composite(render(128, tier=t), (i * 136 + 4, 4))
    strip.save(os.path.join(B, "src", "tiers.png"), optimize=True)

    for rel in ("icons/favicon.ico", "app/app-icon.ico"):
        with open(os.path.join(B, rel), "rb") as fh:
            n = struct.unpack("<HHH", fh.read(6))[2]
        print(f"{rel}: {n} frames")
    print("done ->", B)


if __name__ == "__main__":
    sys.exit(build())
