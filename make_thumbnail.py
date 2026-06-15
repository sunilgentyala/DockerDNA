"""
Generates thumbnail.png (1200x630) for DockerDNA social sharing.
Run: python make_thumbnail.py
Requires: pip install Pillow
"""
from PIL import Image, ImageDraw, ImageFont
import os, math

W, H = 1200, 630
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "thumbnail.png")

# ── colour palette ───────────────────────────────────────────────
BG      = (5,   7,  12)
BG2     = (10,  14,  22)
BORDER  = (30,  35,  50)
BLUE    = (37,  99, 235)   # blue-600
BLUE_L  = (96, 165, 250)   # blue-400
INDIGO  = (99, 102, 241)   # indigo-500
CYAN    = (6,  182, 212)   # cyan-500
CYAN_L  = (103, 232, 249)  # cyan-300
TEXT    = (226, 232, 240)  # slate-200
MUTED   = (148, 163, 184)  # slate-400
DIM     = (71,  85, 105)   # slate-600
WHITE   = (255, 255, 255)

FONT_DIR = r"C:\Windows\Fonts"

def font(name, size):
    candidates = {
        "bold":  ["arialbd.ttf", "calibrib.ttf", "segoeuib.ttf"],
        "black": ["ariblk.ttf",  "Arial Black.ttf", "segoeuib.ttf"],
        "reg":   ["arial.ttf",   "segoeui.ttf",  "calibri.ttf"],
        "mono":  ["consola.ttf", "cour.ttf",     "lucon.ttf"],
    }
    for fname in candidates.get(name, candidates["reg"]):
        p = os.path.join(FONT_DIR, fname)
        if os.path.exists(p):
            return ImageFont.truetype(p, size)
    return ImageFont.load_default()

def h_grad(draw, x, y, w, h, c1, c2, c3=None):
    for i in range(w):
        t = i / max(w-1, 1)
        if c3 and t > 0.5:
            t2 = (t-0.5)*2
            c  = tuple(int(c2[k]+(c3[k]-c2[k])*t2) for k in range(3))
        else:
            t2 = (t*2) if c3 else t
            c  = tuple(int(c1[k]+(c2[k]-c1[k])*t2) for k in range(3))
        draw.line([(x+i, y), (x+i, y+h)], fill=c)

def lerp_c(c1, c2, t):
    return tuple(int(c1[k]+(c2[k]-c1[k])*t) for k in range(3))

def rr(draw, x, y, w, h, r, fill=None, outline=None, ow=1):
    draw.rounded_rectangle([x, y, x+w, y+h], radius=r,
                           fill=fill, outline=outline, width=ow)

def pill_label(draw, x, y, w, h, text, fc, bg, tf):
    rr(draw, x, y, w, h, h//2, fill=bg, outline=fc)
    tw = draw.textlength(text, font=tf)
    draw.text((x+(w-tw)//2, y+(h-tf.size)//2 - 1), text, font=tf, fill=fc)

# ═══════════════════════════════════════════════════════════════════
img  = Image.new("RGB", (W, H), BG)
draw = ImageDraw.Draw(img)

# ── dot grid (blueprint feel) ─────────────────────────────────────
for gx in range(24, W, 36):
    for gy in range(24, H, 36):
        draw.ellipse([gx-1, gy-1, gx+1, gy+1], fill=(37, 99, 235, 14))

# ── ambient glow blobs ────────────────────────────────────────────
def blob(cx, cy, rx, ry, color, alpha=0.07):
    b = Image.new("RGB", (W, H), BG)
    bd = ImageDraw.Draw(b)
    bd.ellipse([cx-rx, cy-ry, cx+rx, cy+ry], fill=color)
    Image.blend(img, b, alpha)
    img.paste(Image.blend(img, b, alpha))

blob(200, 280, 280, 200, (10, 30, 80))
blob(900, 150, 230, 160, (5,  50, 80))
blob(1050,520, 200, 140, (15, 10, 60))

# ── top accent bar: blue → indigo → cyan ─────────────────────────
h_grad(draw, 0, 0, W, 5, BLUE, INDIGO, CYAN)

# ══════════════ LEFT PANEL: DNA HELIX + BRAND ═════════════════════

# ── DNA double helix (painted as two sinusoids + rungs) ──────────
HX, HY, HW, HH = 80, 52, 240, 360
CX = HX + HW // 2
STEPS = 300

# Helix: strand1 follows sin, strand2 is offset by pi
def helix_x(cx, phase, amp, step, total):
    t = step / total
    return cx + int(amp * math.sin(2 * math.pi * t * 2 + phase))

def helix_y(hy, step, total):
    return hy + int(step / total * HH)

AMP = 62

# Draw rungs first (behind strands)
rung_count = 10
for ri in range(rung_count + 1):
    t  = ri / rung_count
    sy = HY + int(t * HH)
    x1 = CX + int(AMP * math.sin(2 * math.pi * t * 2))
    x2 = CX + int(AMP * math.sin(2 * math.pi * t * 2 + math.pi))
    rung_c = lerp_c(BLUE, CYAN, t)
    a = int(0.4 * 255)
    rr_col = tuple(int(rung_c[k] * 0.35) for k in range(3))
    draw.line([(x1, sy), (x2, sy)], fill=rr_col, width=2)

# Draw strand 1 (blue → indigo)
prev = None
for s in range(STEPS + 1):
    t  = s / STEPS
    sx = helix_x(CX, 0, AMP, s, STEPS)
    sy = helix_y(HY, s, STEPS)
    c  = lerp_c(BLUE_L, INDIGO, t)
    if prev:
        draw.line([prev, (sx, sy)], fill=c, width=3)
    prev = (sx, sy)

# Draw strand 2 (indigo → cyan)
prev = None
for s in range(STEPS + 1):
    t  = s / STEPS
    sx = helix_x(CX, math.pi, AMP, s, STEPS)
    sy = helix_y(HY, s, STEPS)
    c  = lerp_c(INDIGO, CYAN_L, t)
    if prev:
        draw.line([prev, (sx, sy)], fill=c, width=3)
    prev = (sx, sy)

# ── small Docker container boxes flanking helix ───────────────────
def docker_box(x, y, w=38, h=26):
    rr(draw, x, y, w, h, 4, fill=(12, 18, 35), outline=(37, 99, 235, 160))
    rr(draw, x+3, y+3, w-6, 5, 2, fill=(37, 99, 235, 80))
    for col in range(3):
        rr(draw, x+3+col*12, y+11, 10, 11, 2, fill=(10, 30, 65))

docker_box(HX - 50, HY + 40)
docker_box(HX + HW + 10, HY + 90)
docker_box(HX - 48, HY + 160)
docker_box(HX + HW + 8,  HY + 230)
docker_box(HX - 50, HY + 295)

# ── Brand wordmark ────────────────────────────────────────────────
fW  = font("black", 80)
fWs = font("black", 80)
WX  = 360

docker_w  = draw.textlength("Docker", font=fW)
draw.text((WX, 58), "Docker", font=fW, fill=TEXT)
draw.text((WX + docker_w, 58), "DNA", font=fWs, fill=BLUE_L)

# gradient underline
wl = int(draw.textlength("DockerDNA", font=fW))
h_grad(draw, WX, 155, wl, 4, BLUE, INDIGO, CYAN)

# tagline
fTag = font("reg", 21)
draw.text((WX, 175), "Cryptographic Container Lineage", font=fTag, fill=MUTED)
fSub = font("reg", 16)
draw.text((WX, 205), "& Deterministic Structural Auditing Framework", font=fSub, fill=DIM)

# ── vertical divider ─────────────────────────────────────────────
draw.line([(355, 58), (355, 555)], fill=BORDER, width=1)

# ══════════════ RIGHT PANEL: STATS + FEATURES ════════════════════
RX = 385

# ── compliance pill ──────────────────────────────────────────────
fBadge = font("bold", 13)
badge_txt = "SLSA v1.0 Level 3  ·  NIST SP 800-190  ·  CIS Docker v1.6"
bw = int(draw.textlength(badge_txt, font=fBadge)) + 40
rr(draw, RX, 62, bw, 34, 17, fill=(5, 20, 45), outline=(37, 99, 235, 180))
draw.ellipse([RX+14, 73, RX+22, 81], fill=CYAN)
draw.text((RX+30, 70), badge_txt, font=fBadge, fill=CYAN_L)

# ── big 3 stats ───────────────────────────────────────────────────
fBig   = font("black", 68)
fUnit  = font("bold",  16)
fNote  = font("reg",   13)

stats = [
    ("<142ms", "Analysis",   "Time",    BLUE_L),
    ("99.2%",  "Detection",  "Accuracy", CYAN),
    ("38.4%",  "Compression","Ratio",    INDIGO),
]
sx = RX
for val, l1, l2, color in stats:
    vw = int(draw.textlength(val, font=fBig))
    draw.text((sx, 108), val, font=fBig, fill=color)
    draw.text((sx+vw+8, 118), l1, font=fUnit, fill=MUTED)
    draw.text((sx+vw+8, 140), l2, font=fUnit, fill=MUTED)
    sx += vw + 90 + int(draw.textlength("  ", font=fUnit))
    if sx > W - 100:
        break

# draw divider under stats
draw.line([(RX, 210), (W-60, 210)], fill=BORDER, width=1)

# ── feature grid (3 cols × 3 rows) ───────────────────────────────
features = [
    (BLUE_L,  "Layer Fingerprint",    "SHA-256 per layer",    CYAN,   "Merkle DAG",        "Tamper-proof chain"),
    (INDIGO,  "Delta Compression",    "38.4% avg savings",    BLUE_L, "SBOM Generation",   "CycloneDX 1.5"),
    (CYAN,    "Drift Detection",       "Behavioral delta",    INDIGO, "Provenance Graph",  "SLSA v1.0 L3"),
    (BLUE_L,  "Reg Compliance",       "NIST + CIS checks",    CYAN,   "Supply Chain Sec.", "Sigstore verify"),
]

fFeat = font("bold", 16)
fFsub = font("reg",  13)
col1x = RX
col2x = RX + 390
rowY  = 230
rowH  = 70

for i, (c1, t1, s1, c2, t2, s2) in enumerate(features):
    ry = rowY + i * rowH
    # col1
    draw.ellipse([col1x+3, ry+6, col1x+11, ry+14], fill=c1)
    draw.text((col1x+20, ry), t1, font=fFeat, fill=TEXT)
    draw.text((col1x+20, ry+22), s1, font=fFsub, fill=DIM)
    # col2
    if col2x + 20 < W - 40:
        draw.ellipse([col2x+3, ry+6, col2x+11, ry+14], fill=c2)
        draw.text((col2x+20, ry), t2, font=fFeat, fill=TEXT)
        draw.text((col2x+20, ry+22), s2, font=fFsub, fill=DIM)

# ══════════════ BOTTOM BAR ════════════════════════════════════════
draw.rectangle([0, 548, W, H], fill=BG2)
draw.line([(0, 548), (W, 548)], fill=BORDER, width=1)

fName = font("bold", 17)
fCred = font("reg",  13)
fUrl  = font("bold", 13)

draw.text((72, 570), "Sunil Gentyala", font=fName, fill=TEXT)
draw.text((72, 597), "IEEE Senior Member  ·  CISM  ·  ISACA  ·  HCL America Inc., Dallas TX",
          font=fCred, fill=MUTED)

# credential pills
pills = [
    ("IEEE Sr. Member", BLUE_L, (8,  20, 45)),
    ("CISM",            CYAN,   (5,  25, 38)),
    ("ISACA",           INDIGO, (20, 12, 50)),
]
px = 410
fPill = font("reg", 12)
for label, fc, bg in pills:
    fw = int(draw.textlength(label, font=fPill)) + 22
    rr(draw, px, 566, fw, 28, 5, fill=bg, outline=fc)
    draw.text((px + fw//2, 570), label, font=fPill, fill=fc, anchor="mt")
    px += fw + 10

# URL right-aligned
u1 = "github.com/sunilgentyala/DockerDNA"
u2 = "sunilgentyala.github.io/DockerDNA"
u1w = int(draw.textlength(u1, font=fUrl))
u2w = int(draw.textlength(u2, font=fCred))
draw.text((W-48-u1w, 570), u1, font=fUrl,  fill=BLUE_L)
draw.text((W-48-u2w, 597), u2, font=fCred, fill=DIM)

# ── bottom accent bar ─────────────────────────────────────────────
h_grad(draw, 0, H-5, W, 5, BLUE, INDIGO, CYAN)

# ── save ─────────────────────────────────────────────────────────
img.save(OUT, "PNG", optimize=True)
print(f"Saved: {OUT}  ({W}x{H})")
