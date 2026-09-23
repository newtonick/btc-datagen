/* SeedSigner demo QR site.
 *
 * Static QRs (seeds, descriptors, addresses, messages, BBQR) arrive from the
 * Python build as bare module matrices (packed bits, row-major, 1 = dark, no
 * quiet zone), and this file just blits those modules onto a canvas.
 *
 * The animated transaction QRs are different: they are generated here, frame by
 * frame, by the WASM build of cUR (site/ssqr.js). A UR animation is a
 * *fountain*, pure fragments 1..N and then an endless stream of fresh XOR
 * combinations, and no finite list of frames can be that. Shipping a list
 * meant the animation eventually replayed the same mixed parts, sequence
 * numbers and all, which no real encoder does.
 *
 * Two rendering rules matter for whether a SeedSigner can actually read the
 * screen, and both are easy to get wrong:
 *
 *   1. Integer module scaling only. A fractional scale gives some modules one
 *      more pixel than their neighbours, and that asymmetry wrecks decoding.
 *      We size the canvas in *device* pixels and pick scale = floor(avail/grid).
 *   2. One scale for a whole animation. Frames within a set can differ by a QR
 *      version, so we lock to the largest frame and centre the smaller ones.
 *      Otherwise the symbol visibly resizes mid-scan and the camera re-hunts.
 *
 * The views mirror distinct device features, which is why signing and address
 * verification are kept apart: in the SIGNING flow the device verifies change
 * addresses on board and you never scan an address at it. Verify Address is a
 * separate SeedSigner tool, so it gets its own view.
 */
'use strict';

const QUIET_ZONE = 4;           // modules; spec minimum, vs Sparrow's on-screen 2
// The handmade card runs a tighter margin: the guide strip already sits between
// the quiet zone and the grid, so a full 4-module zone on top of that left a
// conspicuous empty band between the hand-written label and the code. The
// printed templates carry no quiet zone at all and still scan.
const HAND_QUIET = 3;
const TAU = Math.PI * 2;

// "Handmade" SeedQR palette. Warm paper and a soft dark grey rather than pure
// black, a felt pen never lays down #000. Contrast stays enormous (grey ~3%
// luminance against ~87% paper), so decoders are unaffected.
const PAPER = '#f0e4c4';   // aged, well off white and towards yellow
const GRID_INK = 'rgba(86, 72, 44, 0.28)';        // per-module, dotted
const ZONE_INK = 'rgba(74, 62, 38, 0.55)';        // zone boundaries, solid
const GUIDE_INK = 'rgba(105, 95, 72, 0.72)';      // the A-F / 1-6 guides
const GUIDE_RULE = 'rgba(120, 108, 82, 0.40)';    // strip borders around them
// Room outside the quiet zone for the row/column guides, in modules. Added to
// the canvas rather than taken out of the quiet zone: the quiet zone has to stay
// clear paper for the symbol to be found reliably.
const GUTTER_MODULES = 2.6;

/* One marker colour per key: different people, different pens. In a multisig
 * demo it also means each cosigner's card is instantly distinguishable, which is
 * useful rather than merely decorative.
 *
 * Every entry is LOW LIGHTNESS on purpose. A decoder binarizes on luminance, so
 * a marker colour is only safe while it stays dark against ~94% paper, a yellow
 * or orange highlighter would look plausible and scan terribly.
 *
 * The hand-written label uses the SAME marker, which is what a person would
 * actually do: you label the card with the pen already in your hand. */
const MARKER_COLORS = {
  graphite: { h: 35, s: 10, l: 30 },                 // near-black Sharpie
  blue: { h: 221, s: 55, l: 34 },
  green: { h: 150, s: 45, l: 26 },
  maroon: { h: 353, s: 52, l: 34 },
  purple: { h: 275, s: 42, l: 34 },
  teal: { h: 193, s: 48, l: 27 },
  brown: { h: 25, s: 45, l: 28 },
};

/* Assigned explicitly, not hashed. alice/bob/carol are the 2-of-3 cosigners and
 * so the trio a demo actually exercises, they have to be unmistakably
 * different from each other, and hashing happened to hand alice and carol the
 * same purple. Their hues are spread wide on purpose (275 / 221 / 150).
 * Graphite is kept in the set, just moved off bob onto dave. */
const SEED_MARKERS = {
  alice: 'purple',
  bob: 'blue',
  carol: 'maroon',
  dave: 'graphite',
  erin: 'brown',
  frank: 'teal',
  grace: 'green',
};

const MARKER_FALLBACK = Object.keys(MARKER_COLORS);

function markerFor(seedName) {
  const named = SEED_MARKERS[seedName];
  if (named) return MARKER_COLORS[named];
  // Any seed added later still gets a stable colour.
  let h = 0;
  for (let i = 0; i < seedName.length; i++) {
    h = Math.imul(h ^ seedName.charCodeAt(i), 0x01000193) >>> 0;
  }
  return MARKER_COLORS[MARKER_FALLBACK[h % MARKER_FALLBACK.length]];
}

/* Paper grain, built once into a small tile and repeated.
 *
 * Regenerating noise per draw would be wasteful, and doing it per pixel on a
 * 1000px canvas is not free. The amplitude is well short of anything a
 * binarizer would trip over, paper sits around 90% lightness and the darkest
 * ink at ~19%, but grit is what stops a flat fill reading as a screen, so it's
 * pushed until it's actually visible on a phone rather than merely present. */
let paperGrain = null;
function grainPattern(ctx) {
  if (paperGrain) return paperGrain;
  const size = 128;
  const tile = document.createElement('canvas');
  tile.width = size;
  tile.height = size;
  const tctx = tile.getContext('2d');
  const img = tctx.createImageData(size, size);
  for (let i = 0; i < size * size; i++) {
    const n = Math.random() - 0.5;
    const light = n > 0;
    img.data[i * 4] = light ? 255 : 120;
    img.data[i * 4 + 1] = light ? 252 : 104;
    img.data[i * 4 + 2] = light ? 240 : 72;
    img.data[i * 4 + 3] = Math.abs(n) * 78;
  }
  tctx.putImageData(img, 0, 0);
  paperGrain = ctx.createPattern(tile, 'repeat');
  return paperGrain;
}

/* Soft crease down the middle in each axis, a backup card that has lived folded
   in a safe, rather than a freshly generated rectangle. Each crease is a narrow
   shadow with a highlight on one side, which is what sells a fold. */
function drawCreases(ctx, w, h) {
  const crease = (x0, y0, x1, y1, len) => {
    const g = ctx.createLinearGradient(x0, y0, x1, y1);
    g.addColorStop(0.00, 'rgba(120, 100, 60, 0)');
    g.addColorStop(0.42, 'rgba(120, 100, 60, 0.05)');
    g.addColorStop(0.50, 'rgba(88, 70, 38, 0.10)');
    g.addColorStop(0.58, 'rgba(255, 253, 244, 0.55)');
    g.addColorStop(1.00, 'rgba(120, 100, 60, 0)');
    ctx.fillStyle = g;
    ctx.fillRect(0, 0, w, h);
  };
  const vx = w * 0.5;
  const hy = h * 0.5;
  crease(vx - w * 0.07, 0, vx + w * 0.07, 0);
  crease(0, hy - h * 0.07, 0, hy + h * 0.07);
}

/* Handmade-look tuning, in one place so the scannability sweep can drive it.
   `floor`/`range` are fractions of a full half-cell radius. */
const HAND = {
  // Marker ink: a mid grey. Distinctly lighter than the PRINTED registration
  // blocks, because on a real template those are pre-printed and the dots are
  // whatever pen the owner had. That contrast is half the story the look tells.
  inkL: 30,        // marker ink lightness, %
  inkVary: 12,     // +/- half of this, %
  printL: 19,      // pre-printed blocks: near-black, not pure black
  offset: 0.10,    // dab centre wander, +/- half of this, as a fraction of a cell
  // Sharpie nib vs the little box you're told to fill: the nib usually wins, so
  // most dabs OVERFLOW their cell and neighbours merge into blobs. Width is in
  // cells, so anything over 1.0 is spilling out.
  // Biased deliberately upward. QR codes tolerate marks that are too BIG far
  // better than dots that are too small: an oversized dab still cannot reach a
  // neighbouring cell's sample point, whereas an undersized one fails to cover
  // its own. So err fat.
  widthMin: 0.95,
  widthRange: 0.35,   // 0.95 .. 1.30 cells wide
  strokeMin: 0.10,    // nib drag length, in cells
  strokeRange: 0.30,
  // Printed ink flakes off paper that has been folded and handled. Applied only
  // to the registration blocks, since those are the printed part.
  //
  // Kept deliberately light. Finder patterns are STRUCTURAL, not error
  // corrected: a decoder finds the symbol at all by scanning for the 1:1:3:1:1
  // dark/light ratio through them. Data modules can lose ink and be
  // reconstructed; a finder pattern eaten away past recognition means the
  // symbol is never located in the first place. Specks are small and sparse so
  // they read as wear without disturbing that ratio.
  // Pushed up until the wear actually reads on a phone. The safe direction is
  // BIGGER-BUT-GREY: a factorial over {print darkness} x {speck colour} x {speck
  // size} showed only one failing combination, large AND paper-white, which
  // punches holes that binarize as light. Large grey specks decode fine; so do
  // small white ones. These are large and grey.
  flakeChance: 0.72,  // fraction of printed cells showing any wear
  flakeMax: 4,        // specks per affected cell
  flakeSizeMin: 0.12, // speck diameter, as a fraction of a cell
  flakeSize: 0.34,    // ...plus up to this much more
  flakeLMin: 26,      // speck lightness %, far below paper's ~90
  flakeLRange: 11,
};

/* Deterministic per-module wobble, so hand-filled dots don't look stamped: each
 * dot gets its own size, a slight offset, and a slightly different ink density.
 * Same module always yields the same wobble, so nothing shimmers on reflow and
 * the scannability test stays reproducible.
 *
 * On the bounds: going LARGE is safe, even a dot overflowing its cell can't
 * reach a neighbouring cell's centre, which is where a decoder samples, so the
 * only theoretical limit is the small end.
 *
 * A sweep at the tightest size we render (320px-wide phone, dpr 3) had zbar
 * still decoding with the floor as low as 0.40 and ink as light as 65%
 * lightness. So these settings have wide margin *on a clean synthetic render*.
 * Do not read that as licence to push them: a real camera, off-axis and
 * under bad light, is far less forgiving than zbar on a pristine PNG, and the
 * hardware is the only test that counts. These values keep the handmade look
 * while staying conservative. */
function jitter(x, y) {
  const h = Math.imul((x * 73856093) ^ (y * 19349663), 0x45d9f3b) >>> 0;
  const g = Math.imul(h ^ 0x9e3779b9, 0x85ebca6b) >>> 0;
  return {
    dx: (((h & 0xff) / 255) - 0.5) * HAND.offset,
    dy: ((((h >> 8) & 0xff) / 255) - 0.5) * HAND.offset,
    w: HAND.widthMin + (((h >> 16) & 0xff) / 255) * HAND.widthRange,
    inkD: ((((h >> 24) & 0xff) / 255) - 0.5) * HAND.inkVary,
    len: HAND.strokeMin + ((g & 0xff) / 255) * HAND.strokeRange,
    ang: (((g >> 8) & 0xff) / 255) * TAU,
  };
}

/* Zone size for the printed transcription templates.
 *
 * Straight from the device's own transcribe screen (`modules_per_zone =
 * (size == 21) ? 7 : 5`) and matching the printed PDFs in the SeedSigner repo
 * (docs/seed_qr/printable_templates/grid_NxN.pdf) exactly:
 *
 *   21x21 -> 7 per zone, 3 zones, rows A-C, columns 1-3
 *   25x25 -> 5 per zone, 5 zones, rows A-E, columns 1-5
 *   29x29 -> 5 per zone, 6 zones, rows A-F, columns 1-6  (last zone only 4 wide)
 *
 * The zone count is a ceiling, so the final zone can be a partial one; guides
 * are centred on each zone's ACTUAL extent rather than assuming full width. */
function zoneSize(modules) {
  return modules === 21 ? 7 : 5;
}

function zoneRanges(modules) {
  const per = zoneSize(modules);
  const ranges = [];
  for (let start = 0; start < modules; start += per) {
    ranges.push([start, Math.min(start + per, modules)]);
  }
  return ranges;
}

/* Fine mottling for the PRINTED blocks, so they don't read as flat digital
 * black. Same idea as the paper grain, tuned for dark ink: a sparse two-tone
 * speckle in both directions, tiled from one small canvas.
 *
 * This replaced an earlier approach that drew discrete pale splotches. Those
 * looked like damage rather than print, and were actively risky: large light
 * blobs in a finder pattern binarize as holes, and finder patterns are
 * STRUCTURAL, a decoder locates the symbol by scanning for their 1:1:3:1:1
 * ratio, with no error correction to fall back on. Fine noise softens the fill
 * without ever producing a light region big enough to matter, and a camera's
 * own defocus averages it away entirely.
 *
 * Tiled from the canvas origin, so neighbouring printed cells line up and a
 * block still reads as one continuous piece of ink. */
let inkGrain = null;
function inkNoisePattern(ctx) {
  if (inkGrain) return inkGrain;
  const size = 96;
  const tile = document.createElement('canvas');
  tile.width = size;
  tile.height = size;
  const tctx = tile.getContext('2d');
  const img = tctx.createImageData(size, size);
  for (let i = 0; i < size * size; i++) {
    const n = Math.random() - 0.5;
    const lighter = n > 0;
    img.data[i * 4] = lighter ? 168 : 26;
    img.data[i * 4 + 1] = lighter ? 158 : 24;
    img.data[i * 4 + 2] = lighter ? 136 : 20;
    img.data[i * 4 + 3] = Math.abs(n) * HAND.inkNoise;
  }
  tctx.putImageData(img, 0, 0);
  inkGrain = ctx.createPattern(tile, 'repeat');
  return inkGrain;
}

/* Is this module part of a fixed registration pattern, a finder "eye" or the
 * alignment block?
 *
 * Ported verbatim from the device's own zoomed-transcription screen
 * (seedsigner-lvgl-screens, seed_transcribe_zoomed_qr_is_registration) so the
 * "handmade" SeedQR here looks like what a transcriber actually sees. Those
 * blocks stay SOLID SQUARES: printed SeedQR templates come with them
 * pre-printed in normal square form, and full-cell squares let neighbouring
 * cells tile into one connected shape. Only DATA modules are the round dots the
 * transcriber fills in by hand. (The `qrcode` library's CircleModuleDrawer
 * makes the same split: square eyes, round data.)
 *
 * Alignment position follows the same square-off: module 16 for a 25-module QR,
 * 20 for 29; version-1 21-module QRs have no alignment pattern at all.
 */
function isRegistrationModule(x, y, size) {
  const finder = (x < 7 && y < 7)
    || (x >= size - 7 && y < 7)
    || (x < 7 && y >= size - 7);
  const align = size === 25 ? 16 : (size === 29 ? 20 : -1);
  const alignment = align >= 0
    && x >= align && x < align + 5
    && y >= align && y < align + 5;
  return finder || alignment;
}

const VIEWS = ['home', 'sign', 'seed', 'verify', 'message'];

const state = {
  index: null,
  mode: 'home',
  scenario: null,
  scenarioData: null,
  format: 'ur',
  density: {},                  // per-format sticky density
  fps: 5,
  seedName: null,
  seedVariant: 'compact',
  descriptorUr: 'crypto-output',
  verifyWallet: null,
  verifyDescriptorUr: 'crypto-output',
  verifyAddress: { branch: 'receive', index: 0 },
  onlySeedName: null,
  onlySeedVariant: 'compact',
  messageName: null,
  // Native SegWit by default: the common case, and the one the landing
  // scenario uses. Outputs are deliberately NOT a filter, the shape is in
  // each row's title, so leaving it out keeps the list short enough to scan.
  filters: { network: 'main', sig_type: 'all', script_type: 'P2WPKH', inputs: 'all' },
  // Adversarial / malformed transactions are hidden until their PR's toggle is
  // enabled in the picker. Each hardening PR (#1013, #1032, ...) has its own
  // toggle so the sets stay isolated. Holds the set of enabled PR ids.
  showPR: new Set(),
};

const $ = (id) => document.getElementById(id);

/* ---------- data helpers -------------------------------------------------- */

function unpack(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function getJSON(path) {
  const res = await fetch(path, { cache: 'no-cache' });
  if (!res.ok) throw new Error(`${path}: ${res.status}`);
  return res.json();
}

function prepare(payload) {
  // Decode once, up front, decoding inside the animation loop would stutter.
  return {
    count: payload.count,
    maxModules: payload.max_modules,
    maxVersion: payload.max_version,
    frames: payload.frames.map((f) => ({ m: f.m, v: f.v, bits: unpack(f.b) })),
  };
}

/* A live ur:crypto-psbt fountain, dressed up to look like a payload.
 *
 * Same duck type as `prepare()` output, maxModules for the canvas, a frame at
 * `frames[i]`, so QrPlayer does not need to know which kind it is holding.
 * The difference is that `frames` is a growing cache rather than a fixed list,
 * and `count` is the number of PURE fragments rather than a total, because
 * there is no total.
 *
 * Frames are cached rather than regenerated on each draw: a canvas relayout
 * (rotate the phone, open fullscreen) redraws the current frame, and pulling a
 * *new* part from the encoder for a redraw would silently skip a frame every
 * time the layout changed.
 */
class UrFountain {
  constructor(ssqr, psbtBytes, spec) {
    this.ssqr = ssqr;
    this.encoder = new ssqr.UrPsbtEncoder(psbtBytes, spec.max_fragment);
    this.count = spec.count;
    this.maxModules = spec.modules;
    this.maxVersion = spec.version;
    this.frames = [];
    this.onGrow = null;
  }

  /* Generate up to and including index `i`. Sequential by construction: the
     player only ever advances by one. */
  ensure(i) {
    while (this.frames.length <= i) {
      const part = this.encoder.next().toUpperCase();
      const frame = this.ssqr.qrEncode(part);
      // The build-time ceiling (LAYOUT_CEILING_SEQ in tools/build_site.py) is
      // computed from an actual part at a six-digit sequence number, so this
      // should never fire. If it ever does, one visible resize beats a QR
      // clipped by a canvas that is too small for it.
      if (frame.m > this.maxModules) {
        this.maxModules = frame.m;
        this.maxVersion = frame.v;
        if (this.onGrow) this.onGrow();
      }
      this.frames.push({ m: frame.m, v: frame.v, bits: frame.bits });
    }
    return this.frames[i];
  }

  /* Keep the cache bounded. A demo left running overnight would otherwise
     accumulate a frame object per displayed part forever; 4096 frames is
     roughly 13 minutes at 5 fps, far past any scan, and re-generating an
     evicted frame is not possible (the fountain never goes back), so eviction
     is only safe for frames already behind the playhead. */
  trim(currentIndex) {
    const KEEP = 4096;
    if (this.frames.length <= KEEP) return;
    // Null out old entries rather than splicing: indexes are the sequence
    // number, and shifting them would renumber the whole animation.
    for (let i = 0; i < currentIndex - KEEP; i++) this.frames[i] = null;
  }

  free() {
    this.encoder.free();
    this.frames = [];
  }
}

const sats = (n) => n.toLocaleString('en-US') + ' sats';

/* "alice" -> "Alice's key". What someone would actually scrawl on a backup,
   rather than a spec line. Names already ending in s take the bare apostrophe. */
function possessive(name) {
  const titled = name.charAt(0).toUpperCase() + name.slice(1);
  return `${titled}${titled.endsWith('s') ? "'" : "'s"} key`;
}

/* Draw the label a character at a time, each one nudged and tilted slightly.
 *
 * A single rotation applied to the whole string still reads as typeset text
 * that happens to be crooked. Hand lettering is irregular letter BY letter:
 * baselines drift, individual characters lean different ways, and the slant
 * isn't consistent. Wander is deterministic per character index, so redraws
 * (resize, font load, unfolding the sheet) don't make the label twitch.
 *
 * Called inside a save()/restore() with the origin already at the label centre
 * and `ctx.font` set by the caller. */
function drawHandLabel(ctx, text, size) {
  ctx.textAlign = 'left';
  ctx.textBaseline = 'middle';
  const chars = [...text];
  const widths = chars.map((ch) => ctx.measureText(ch).width);
  const total = widths.reduce((a, b) => a + b, 0);

  let x = -total / 2;
  chars.forEach((ch, i) => {
    const h = Math.imul(i + 1, 0x9e3779b1) >>> 0;
    const dy = (((h & 0xff) / 255) - 0.5) * size * 0.10;        // baseline drift
    const rot = ((((h >> 8) & 0xff) / 255) - 0.5) * 0.10;       // +/- ~3 degrees
    const shear = ((((h >> 16) & 0xff) / 255) - 0.5) * 0.22;    // lean, per letter
    const w = widths[i];
    ctx.save();
    ctx.translate(x + w / 2, dy);
    ctx.rotate(rot);
    ctx.transform(1, 0, shear, 1, 0, 0);
    ctx.fillText(ch, -w / 2, 0);
    ctx.restore();
    x += w;
  });
}

/* ---------- QR player ----------------------------------------------------- */

class QrPlayer {
  constructor() {
    this.payload = null;
    this.canvas = null;
    this.frame = 0;
    this.playing = true;
    this.fps = 5;
    this.accum = 0;
    this.last = 0;
    this.onFrame = null;
    requestAnimationFrame((t) => this._tick(t));
  }

  setCanvas(canvas) {
    if (this._observer) this._observer.disconnect();
    this.canvas = canvas;
    // Watch the card rather than relying on callers to re-layout at the right
    // moment. A canvas inside a `hidden` section measures 0 wide, and laying
    // out against that silently yields a 1-device-pixel-per-module QR; this way
    // the correct layout happens as soon as the section is actually shown.
    if (canvas && window.ResizeObserver) {
      this._observer = new ResizeObserver(() => this.layout());
      this._observer.observe(canvas.parentElement);
    }
    this.layout();
  }

  setPayload(payload) {
    this.payload = payload;
    this.frame = 0;
    this.accum = 0;
    this.layout();
  }

  get isAnimated() {
    return !!this.payload && this.payload.count > 1;
  }

  /* Size the canvas to whole device pixels per module, then draw. */
  layout() {
    const { canvas, payload } = this;
    if (!canvas || !payload) return;

    const dpr = window.devicePixelRatio || 1;
    const quiet = this.renderStyle === 'handmade' ? HAND_QUIET : QUIET_ZONE;
    const grid = payload.maxModules + quiet * 2;

    let availCss;
    if (canvas.id === 'fs-canvas') {
      availCss = Math.min(window.innerWidth, window.innerHeight) - 16;
    } else {
      const card = canvas.parentElement;
      const cs = getComputedStyle(card);
      availCss = card.clientWidth
        - parseFloat(cs.paddingLeft) - parseFloat(cs.paddingRight);
    }

    // Nothing to measure against yet (container hidden or not laid out). Draw
    // nothing rather than committing to a garbage scale; the ResizeObserver
    // will call back once the container has a real width.
    if (!(availCss > 0)) return;

    // The guides live OUTSIDE the quiet zone, so they cost canvas rather than
    // symbol size.
    const gutterModules = this.renderStyle === 'handmade' ? GUTTER_MODULES : 0;
    const scale = Math.max(1, Math.floor((availCss * dpr) / (grid + gutterModules)));
    const devPx = grid * scale;
    const gutter = Math.round(gutterModules * scale);

    // The hand-written label is drawn INTO the canvas rather than sitting in the
    // card as HTML. As a sibling element it was a second surface: the canvas had
    // grain and creases, the card padding did not, and the join between them was
    // a visible rectangle that broke the illusion of one sheet of paper. Giving
    // the canvas a taller band keeps every textured pixel on one surface without
    // shrinking the symbol (which growing the quiet zone would have done).
    const band = this.label ? Math.round(scale * 6.4) : 0;
    canvas.width = devPx + gutter;
    canvas.height = devPx + gutter + band;
    canvas.style.width = `${(devPx + gutter) / dpr}px`;
    canvas.style.height = `${(devPx + gutter + band) / dpr}px`;
    this.scale = scale;
    this.band = band;
    this.gutter = gutter;
    this.draw();
  }

  draw() {
    const { canvas, payload } = this;
    if (!canvas || !payload || !this.scale) return;
    // A fountain generates on demand; a pre-rendered payload just indexes.
    const f = payload.ensure ? payload.ensure(this.frame) : payload.frames[this.frame];
    const scale = this.scale;
    const handmade = this.renderStyle === 'handmade';
    // Declared up here because both the label and the dabs need it, and the
    // label is drawn first.
    const mk = this.marker || MARKER_COLORS.graphite;
    const ctx = canvas.getContext('2d');
    ctx.imageSmoothingEnabled = false;

    // Paper tint and ink, not white and pure black. Contrast stays enormous, so
    // decoders are unbothered, but it reads as a physical card. This lives
    // INSIDE the canvas on purpose: a CSS filter or rotation on the canvas would
    // resample it and undo the crisp whole-pixel module grid.
    ctx.fillStyle = handmade ? PAPER : '#ffffff';
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    const band = this.band || 0;
    if (handmade) {
      ctx.fillStyle = grainPattern(ctx);
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      drawCreases(ctx, canvas.width, canvas.height);
      if (this.label) {
        // Same marker as the dabs, nudged a little brighter, because thin
        // letter strokes read lighter than dense blobs of the same ink.
        const ink = `hsl(${mk.h} ${Math.min(100, mk.s + 12)}% ${mk.l + 4}%)`;
        const maxWidth = canvas.width * 0.86;
        const write = (text, y, targetSize, tilt) => {
          ctx.save();
          ctx.translate(canvas.width / 2, y);
          ctx.rotate(tilt);
          ctx.fillStyle = ink;
          let size = Math.round(targetSize);
          ctx.font = `${size}px "Permanent Marker", cursive`;
          // Shrink to fit rather than run off the edge of the card.
          const measured = ctx.measureText(text).width;
          if (measured > maxWidth) {
            size = Math.max(10, Math.floor(size * (maxWidth / measured)));
          }
          drawHandLabel(ctx, text, size);
          ctx.restore();
        };
        write(this.label, band * 0.33, scale * 3.4, -0.019);
        // The master fingerprint, which is what actually tells two backups
        // apart, a name is a convenience, the fingerprint is the identity, and
        // writing it on the card is standard practice. SeedSigner's own
        // fingerprint templates give it a box in the header for exactly this.
        if (this.fingerprint) {
          write(this.fingerprint, band * 0.78, scale * 2.8, 0.012);
        }
      }
    }

    // Centre this frame inside the locked grid of the largest frame, then shift
    // past the label band (top) and the guide gutter (top + left).
    const quiet = handmade ? HAND_QUIET : QUIET_ZONE;
    const off = quiet + ((payload.maxModules - f.m) >> 1);
    const gutter = this.gutter || 0;
    const originX = gutter;
    const originY = band + gutter;
    const bits = f.bits;
    const radius = scale / 2;

    // Transcription grid, drawn BENEATH the modules so the dabs stay solid. The
    // device draws it on top (a transcriber needs to see cell edges), but here
    // that would eat into the dark area a camera depends on.
    //
    // Two weights, copying the printed templates: DOTTED hairlines at every
    // module, SOLID heavier lines at each zone boundary. lineWidth is in DEVICE
    // pixels, a hardcoded 1 is a third of a CSS pixel on a dpr-3 phone, which
    // is why the grid was invisible on a real handset while looking fine in
    // dpr-1 screenshots, so it scales with the module size.
    if (handmade && scale >= 4) {
      const a = originY + off * scale;
      const b = originY + (off + f.m) * scale;
      const la = originX + off * scale;
      const lb = originX + (off + f.m) * scale;
      const hair = Math.max(1, Math.round(scale / 10));

      ctx.strokeStyle = GRID_INK;
      ctx.lineWidth = hair;
      ctx.setLineDash([hair, hair * 2]);
      for (let i = 0; i <= f.m; i++) {
        const gx = Math.round(originX + (off + i) * scale) + 0.5;
        const gy = Math.round(originY + (off + i) * scale) + 0.5;
        ctx.beginPath(); ctx.moveTo(gx, a); ctx.lineTo(gx, b); ctx.stroke();
        ctx.beginPath(); ctx.moveTo(la, gy); ctx.lineTo(lb, gy); ctx.stroke();
      }
      ctx.setLineDash([]);

      ctx.strokeStyle = ZONE_INK;
      ctx.lineWidth = Math.max(1, Math.round(scale / 7));
      const per = zoneSize(f.m);
      for (let i = 0; i <= f.m; i += per) {
        const gx = Math.round(originX + (off + i) * scale) + 0.5;
        const gy = Math.round(originY + (off + i) * scale) + 0.5;
        ctx.beginPath(); ctx.moveTo(gx, a); ctx.lineTo(gx, b); ctx.stroke();
        ctx.beginPath(); ctx.moveTo(la, gy); ctx.lineTo(lb, gy); ctx.stroke();
      }
      // Close the far edges, which a stride of `per` misses when the last zone
      // is a partial one (29x29).
      const ex = Math.round(originX + (off + f.m) * scale) + 0.5;
      const ey = Math.round(originY + (off + f.m) * scale) + 0.5;
      ctx.beginPath(); ctx.moveTo(ex, a); ctx.lineTo(ex, b); ctx.stroke();
      ctx.beginPath(); ctx.moveTo(la, ey); ctx.lineTo(lb, ey); ctx.stroke();

      // Row/column guides, laid out like the printed templates: a header strip
      // of numbered cells across the top, a lettered strip down the left, an
      // empty corner cell, thin rules boxing them in.
      //
      // They sit FLUSH against the grid, which technically intrudes on the
      // symbol's quiet zone, exactly as the printed PDFs do, since those carry
      // no quiet zone at all and rely on the surrounding paper. The guides are
      // light grey hairlines and there is a wide paper margin outside them, so
      // detection is unaffected; attaching them to the grid is what makes them
      // read as part of the template rather than floating labels.
      if (gutter > 0) {
        const gridL = originX + off * scale;
        const gridT = originY + off * scale;
        const gridR = originX + (off + f.m) * scale;
        const gridB = originY + (off + f.m) * scale;
        const stripL = gridL - gutter;
        const stripT = gridT - gutter;

        ctx.strokeStyle = GUIDE_RULE;
        ctx.lineWidth = Math.max(1, Math.round(scale / 12));
        // Box around strips + grid, then the rules closing each strip off.
        ctx.strokeRect(Math.round(stripL) + 0.5, Math.round(stripT) + 0.5,
                       Math.round(gridR - stripL), Math.round(gridB - stripT));
        ctx.beginPath();
        ctx.moveTo(stripL, Math.round(gridT) + 0.5);
        ctx.lineTo(gridR, Math.round(gridT) + 0.5);
        ctx.stroke();
        ctx.beginPath();
        ctx.moveTo(Math.round(gridL) + 0.5, stripT);
        ctx.lineTo(Math.round(gridL) + 0.5, gridB);
        ctx.stroke();

        ctx.fillStyle = GUIDE_INK;
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.font = `${Math.round(scale * 1.35)}px -apple-system, "Segoe UI", Roboto, sans-serif`;
        zoneRanges(f.m).forEach(([zStart, zEnd], k) => {
          const mid = (zStart + zEnd) / 2;
          ctx.fillText(String(k + 1), gridL + mid * scale, stripT + gutter / 2);
          ctx.fillText(String.fromCharCode(65 + k), stripL + gutter / 2, gridT + mid * scale);
          if (k > 0) {
            const dx = Math.round(gridL + zStart * scale) + 0.5;
            const dy = Math.round(gridT + zStart * scale) + 0.5;
            ctx.beginPath(); ctx.moveTo(dx, stripT); ctx.lineTo(dx, gridT); ctx.stroke();
            ctx.beginPath(); ctx.moveTo(stripL, dy); ctx.lineTo(gridL, dy); ctx.stroke();
          }
        });
      }
    }

    // Registration blocks are PRINTED, so they get flat, much blacker ink than
    // the owner's marker dabs. That difference is doing real explanatory work:
    // it shows at a glance which parts came with the template and which parts a
    // person filled in.
    const printInk = handmade ? `hsl(35 8% ${HAND.printL}%)` : '#000000';
    ctx.fillStyle = printInk;
    ctx.lineCap = 'round';
    ctx.lineJoin = 'round';

    for (let r = 0; r < f.m; r++) {
      const rowBase = r * f.m;
      for (let c = 0; c < f.m; c++) {
        const i = rowBase + c;
        if (!((bits[i >> 3] >> (7 - (i & 7))) & 1)) continue;
        const x = originX + (off + c) * scale;
        const y = originY + (off + r) * scale;
        if (handmade && !isRegistrationModule(c, r, f.m)) {
          // One dab of a marker per cell: a short round-capped drag rather than
          // a perfect circle, so the mark has a direction and a blobby edge the
          // way a felt tip actually leaves. Wider than its cell more often than
          // not, so neighbours run together.
          const j = jitter(c, r);
          const cx = x + radius + j.dx * scale;
          const cy = y + radius + j.dy * scale;
          const hx = Math.cos(j.ang) * j.len * scale * 0.5;
          const hy = Math.sin(j.ang) * j.len * scale * 0.5;
          ctx.strokeStyle = `hsl(${mk.h} ${mk.s}% ${mk.l + j.inkD}%)`;
          ctx.lineWidth = j.w * scale;
          ctx.beginPath();
          ctx.moveTo(cx - hx, cy - hy);
          ctx.lineTo(cx + hx, cy + hy);
          ctx.stroke();
        } else {
          ctx.fillStyle = printInk;
          ctx.fillRect(x, y, scale, scale);
          if (handmade) {
            ctx.fillStyle = inkNoisePattern(ctx);
            ctx.fillRect(x, y, scale, scale);
          }
        }
      }
    }
    if (this.onFrame) this.onFrame(this.frame, payload.count);
    if (this.onRendered) this.onRendered(canvas);
  }

  /* A UR fountain never wraps; a BBQR set always does.
   *
   * A real UR encoder emits pure fragments 1..N and then mixed XOR parts N+1,
   * N+2, … forever, never returning to part 1, so for a fountain the frame
   * index just keeps climbing and the encoder keeps producing. BBQR has no
   * fountain coding and a BBQR sender really does loop its fixed set of
   * slices, so that case wraps modulo the count.
   */
  advance(delta = 1) {
    if (!this.payload) return;
    if (this.payload.ensure) {
      this.frame = Math.max(0, this.frame + delta);
      this.payload.trim(this.frame);
    } else {
      const { count } = this.payload;
      this.frame = ((this.frame + delta) % count + count) % count;
    }
    this.draw();
  }

  _tick(ts) {
    requestAnimationFrame((t) => this._tick(t));
    if (!this.payload || !this.playing || this.payload.count < 2) {
      this.last = ts;
      return;
    }
    if (!this.last) this.last = ts;
    this.accum += ts - this.last;
    this.last = ts;
    const period = 1000 / this.fps;
    if (this.accum >= period) {
      // Drop whole periods rather than catching up frame-by-frame, so a
      // backgrounded tab doesn't fast-forward through the animation on return.
      this.accum = this.accum % period;
      this.advance(1);
    }
  }
}

const player = new QrPlayer();
const seedPlayer = new QrPlayer();
const descriptorPlayer = new QrPlayer();
const verifyDescriptorPlayer = new QrPlayer();
const verifyAddressPlayer = new QrPlayer();
const onlySeedPlayer = new QrPlayer();
const messagePlayer = new QrPlayer();
const messageSeedPlayer = new QrPlayer();
const verifySeedPlayer = new QrPlayer();
const allPlayers = [player, seedPlayer, descriptorPlayer,
                    verifyDescriptorPlayer, verifyAddressPlayer,
                    onlySeedPlayer, messagePlayer, messageSeedPlayer,
                    verifySeedPlayer];

/* ---------- small UI builders --------------------------------------------- */

function buildSegmented(container, options, current, onPick) {
  container.innerHTML = '';
  options.forEach((opt) => {
    const b = document.createElement('button');
    b.type = 'button';
    b.textContent = opt.label;
    b.setAttribute('aria-pressed', String(opt.value === current));
    b.addEventListener('click', () => onPick(opt.value));
    container.appendChild(b);
  });
}

function buildChooser(container, options, isActive, onPick) {
  container.innerHTML = '';
  options.forEach((opt) => {
    const b = document.createElement('button');
    b.type = 'button';
    b.textContent = opt.label;
    b.setAttribute('aria-pressed', String(isActive(opt.value)));
    b.addEventListener('click', () => onPick(opt.value));
    container.appendChild(b);
  });
}

function scriptLabel(scriptType) {
  const friendly = state.index.script_labels[scriptType];
  return friendly ? `${friendly} (${scriptType})` : scriptType;
}

/* Descriptor UR type picker, shared by both paths. */
function buildDescriptorSeg(segId, urs, current, onPick) {
  buildSegmented($(segId),
    Object.keys(urs).map((t) => ({ value: t, label: urs[t].label })),
    current, onPick);
}

/* ---------- signing path: the transaction step ---------------------------- */

function formatSpec(fmt) { return state.index.formats[fmt]; }

function densityFor(fmt) {
  // Sticky per format: UR defaults to its higher-density option, BBQR to Low.
  if (!state.density[fmt]) state.density[fmt] = formatSpec(fmt).default_density;
  return state.density[fmt];
}

function renderFormatControls() {
  const fmts = Object.keys(state.index.formats);
  buildSegmented($('format-seg'),
    fmts.map((f) => ({ value: f, label: formatSpec(f).label })),
    state.format,
    (v) => { state.format = v; loadQr(); });

  const spec = formatSpec(state.format);
  buildSegmented($('density-seg'),
    spec.densities.map((d) => ({ value: d, label: state.index.density_labels[d] })),
    densityFor(state.format),
    (v) => { state.density[state.format] = v; loadQr(); });

  $('qr-note').textContent = spec.note;
}

/* The WASM module, loaded once and shared by the animated QRs and the scanner.
   Dynamic import keeps it off the critical path for the seed and address views,
   which never touch it. */
let ssqrPromise = null;
function loadSsqr() {
  if (!ssqrPromise) {
    ssqrPromise = import('./ssqr.js').then(async (mod) => { await mod.ready(); return mod; });
  }
  return ssqrPromise;
}

async function loadQr() {
  const density = densityFor(state.format);
  const ref = state.scenario.qr[state.format][density];
  renderFormatControls();

  // Release the previous fountain's encoder before replacing it; WASM memory is
  // not garbage collected on our behalf.
  if (player.payload && typeof player.payload.free === 'function') player.payload.free();

  if (ref.runtime) {
    const ssqr = await loadSsqr();
    const fountain = new UrFountain(ssqr, unpack(state.scenarioData.psbt_base64), ref);
    fountain.onGrow = () => player.layout();
    player.setPayload(fountain);
  } else {
    player.setPayload(prepare(await getJSON(ref.file)));
  }
  updatePlaybackControls();
}

function updatePlaybackControls() {
  const animated = player.isAnimated;
  $('fps-control').hidden = !animated;
  $('playpause').hidden = !animated;
  $('step-frame').hidden = !animated;
  $('playpause').textContent = player.playing ? 'Pause' : 'Play';
  $('step-frame').disabled = player.playing;
}

function onFrameChange(i, count) {
  const payload = player.payload;
  const modules = payload.maxModules;
  // For a fountain, `count` is the number of PURE fragments, not a total;
  // there is no total. Past that point the sequence number is the only honest
  // thing to show, so "12 / 15" gives way to a bare part number.
  const fountain = !!payload.ensure;
  let label;
  let fsLabel;
  if (count === 1) {
    label = `Single static frame · ${modules}×${modules} modules`;
    fsLabel = '';
  } else if (fountain && i >= count) {
    // Every part past N is a fresh XOR of a random fragment subset, forever.
    label = `Fountain part ${i + 1} (mixed) · ${modules}×${modules} modules`;
    fsLabel = `part ${i + 1}`;
  } else {
    label = `Part ${i + 1} of ${count} · ${modules}×${modules} modules`;
    fsLabel = `${i + 1} / ${count}`;
  }
  $('qr-progress').textContent = label;
  $('fs-progress').textContent = fsLabel;
}

/* Split an address so CSS can ellipsize the head and always show the tail.
   The last characters are the ones you check against the device screen, so
   they must survive; see .addr-trunc in styles.css. Tapping expands it. */
const ADDR_TAIL = 8;

function truncatedAddr(address) {
  if (address.length <= ADDR_TAIL + 8) return `<div class="addr">${address}</div>`;
  const head = address.slice(0, -ADDR_TAIL);
  const tail = address.slice(-ADDR_TAIL);
  return `<div class="addr addr-trunc" title="${address}" role="button" tabindex="0"
    ><span class="addr-head">${head}</span><span class="addr-tail">${tail}</span></div>`;
}

function renderTxSummary() {
  const s = state.scenarioData.summary;
  const rows = s.outputs.map((o) => {
    const cls = o.kind === 'external' ? 'pill-external' : 'pill-change';
    const label = o.kind === 'external' ? 'recipient'
      : (o.kind === 'change' ? 'change' : 'self-transfer');
    return `<tr><th class="kv-wide"><span class="pill ${cls}">${label}</span>${truncatedAddr(o.address)}</th>
            <td class="num">${sats(o.value)}</td></tr>`;
  }).join('');

  $('tx-summary').innerHTML = `
    <p class="qr-note" style="margin-top:0">${state.scenario.blurb}</p>
    <table class="kv">
      <tr><th>Inputs</th><td class="num">${s.num_inputs} · ${sats(s.input_amount)}</td></tr>
      ${rows}
      <tr><th>Network fee</th><td class="num">${sats(s.fee)}</td></tr>
      <tr><th>PSBT size</th><td class="num">${state.scenarioData.psbt_bytes.toLocaleString()} bytes</td></tr>
    </table>
    ${state.scenario.summary_note
      ? `<p class="qr-note qr-note-warn">${state.scenario.summary_note}</p>` : ''}
    <p class="qr-note">Signable, but unbroadcastable, these UTXOs do not exist.</p>`;
}

/* ---------- signing path: the seed step ----------------------------------- */

async function renderSeedStep() {
  const seeds = state.scenario.signing_seeds;
  if (!state.seedName || !seeds.includes(state.seedName)) state.seedName = seeds[0];

  const multi = seeds.length > 1;
  // Stage direction: what the person would actually be doing at this point.
  $('seed-hint').textContent = multi
    ? `You retrieve your handmade SeedQR. ${state.scenario.threshold}-of-${seeds.length} `
      + `multisig, sign with any ${state.scenario.threshold}, one at a time.`
    : 'You retrieve your handmade SeedQR.';

  const chooser = $('seed-chooser');
  chooser.hidden = !multi;
  if (multi) {
    buildChooser(chooser, seeds.map((n) => ({ value: n, label: n })),
      (v) => v === state.seedName,
      (v) => { state.seedName = v; renderSeedStep(); });
  } else {
    chooser.innerHTML = '';
  }

  const entry = state.index.seeds.find((s) => s.name === state.seedName);
  const data = await getJSON(entry.file);

  buildSegmented($('seedqr-seg'), [
    { value: 'compact', label: 'CompactSeedQR' },
    { value: 'standard', label: `SeedQR (${data.words}w)` },
  ], state.seedVariant, (v) => { state.seedVariant = v; renderSeedStep(); });

  seedPlayer.label = possessive(data.name);
  seedPlayer.marker = markerFor(data.name);
  seedPlayer.fingerprint = data.master_fingerprint.toUpperCase();
  seedPlayer.setPayload(prepare(data[state.seedVariant].qr));

  const wordList = data.mnemonic.split(' ');
  const wordRows = Math.ceil(wordList.length / 3);
  const words = wordList.map((w, i) => `<span><i>${i + 1}</i>${w}</span>`).join('');
  $('seed-words').innerHTML = `
    <div class="words" style="grid-template-rows: repeat(${wordRows}, auto)">${words}</div>
    <table class="kv" style="margin-top:10px">
      <tr><th>Master fingerprint</th><td class="mono">${data.master_fingerprint}</td></tr>
    </table>`;
}

/* ---------- signing path: the wallet descriptor step ---------------------- */

/* Multisig only, and NOT address verification: without the wallet policy the
   device can't tell that a change output is its own, so it can't show you a
   verified change amount while you review the transaction. */
async function renderDescriptorStep() {
  if (!state.scenario.needs_descriptor) return;

  const entry = state.index.wallets.find((w) => w.name === state.scenario.wallet);
  const data = await getJSON(entry.file);

  // A fixed build never reaches this step (it rejects the psbt during parse), so
  // for a test scenario the descriptor is here to reproduce the OLD flow: load it
  // on a pre-fix build to reach change verification and watch how it behaves.
  $('descriptor-hint').textContent = state.scenario.test
    ? `This wallet's descriptor, so a build from before the fix reaches its change `
      + `verification. A fixed build rejects the transaction first and never asks for it.`
    : `So the device can verify this ${entry.policy} wallet's own change output.`;

  const urs = data.descriptor_urs;
  if (!Object.keys(urs).includes(state.descriptorUr)) {
    state.descriptorUr = Object.keys(urs)[0];
  }
  buildDescriptorSeg('descriptor-seg', urs, state.descriptorUr,
    (v) => { state.descriptorUr = v; renderDescriptorStep(); });

  descriptorPlayer.setPayload(prepare(urs[state.descriptorUr].qr));
  $('descriptor-meta').textContent =
    `${entry.policy} ${entry.script_label} · single-frame ur:${state.descriptorUr}`;
  $('descriptor-text').innerHTML = `<div class="addr">${data.descriptor}</div>`;
}

/* ---------- signing path: which steps apply ------------------------------- */

/* Every applicable step is on the page at once and the user just scrolls. A
   "next step" button was only ever re-implementing the scrollbar; the numbered
   section headings already say what order to do things in. The descriptor step
   is the one that genuinely comes and goes, since it only applies to a multisig
   transaction that has change to recognise. */
function renderFlow() {
  const isTest = !!state.scenario.test;
  $('step-descriptor').hidden = !state.scenario.needs_descriptor;
  // A test scenario is rejected on device during the parse, before any signature
  // exists, so there is nothing to read back. Hide that step and show the banner
  // that says what the device should do instead.
  $('step-scan').hidden = isTest;
  renderTestBanner();
  renumberSteps('view-sign');
}

/* The what-to-load / what-should-happen note for a PR test scenario. Empty and
   hidden for every ordinary demo transaction. */
/* How the fixed device should react, phrased by outcome: most abort to a warning
   screen, but some parse with no warning and only classify the output. */
function outcomePhrase(s) {
  const scr = s.expected_screen;
  switch (s.outcome) {
    case 'error': return `should abort to the <b>${scr}</b>`;
    case 'spend':
    case 'change':
      return `should parse with no warning, and show the output <b>${scr.toLowerCase()}</b>`;
    default: return `should route to “<b>${scr}</b>”`;
  }
}

function renderTestBanner() {
  const banner = $('test-banner');
  const s = state.scenario;
  if (!s.test) { banner.hidden = true; banner.innerHTML = ''; return; }
  const seed = s.signing_seeds[0];
  const group = (state.index.test_pr_groups || []).find((g) => g.pr === s.pr);
  const tag = group ? group.label : `PR #${s.pr}`;
  banner.innerHTML = `
    <strong>Test transaction (${tag}), not a demo</strong>
    <p>${s.blurb}</p>
    <p class="test-banner-do">Load <b>${seed}</b>'s seed below. On a device with the
      fix, this ${outcomePhrase(s)}.</p>`;
  banner.hidden = false;
}

/* Steps that come and go with the wallet policy, the descriptor, in both the
   signing and the verify flows, mean numbers have to be assigned at render
   time. Hardcoding them left single-sig showing "1, 2, 4", which reads as a
   missing step rather than an omitted one. */
function renumberSteps(viewId) {
  let n = 0;
  document.querySelectorAll(`#${viewId} > .step`).forEach((step) => {
    if (step.hidden) return;
    const badge = step.querySelector('.step-num');
    if (badge) badge.textContent = String(++n);
  });
}

/* ---------- signing path: reading the signature back ---------------------- */

let scanner = null;

/* Signatures collected across successive scans.
 *
 * A multisig needs one cosigner at a time: load alice's seed, sign, read it
 * back; load bob's seed, sign the SAME transaction, read that back. Each scan
 * carries only the signature the device just made, so judging each one in
 * isolation reported "partly signed" forever and the demo could never reach a
 * complete transaction, the one thing a multisig demo exists to show.
 *
 * Accumulating them here is exactly what a coordinator like Sparrow does when
 * it combines PSBTs. Only signatures that have VERIFIED are kept, and they are
 * keyed by public key per input, so re-scanning the same cosigner adds nothing
 * rather than counting twice.
 */
let collected = { scenarioId: null, inputs: [] };

function resetCollected() {
  collected = { scenarioId: null, inputs: [] };
}

/** Merge a scan's valid signatures in; returns how many were new. */
function collectSignatures(report) {
  if (collected.scenarioId !== state.scenario.id
      || collected.inputs.length !== report.inputs.length) {
    collected = {
      scenarioId: state.scenario.id,
      inputs: report.inputs.map(() => new Map()),
    };
  }
  let added = 0;
  for (const inp of report.inputs) {
    const seen = collected.inputs[inp.index];
    for (const sig of inp.sigs) {
      if (sig.valid && !seen.has(sig.pubkey)) {
        seen.set(sig.pubkey, sig);
        added++;
      }
    }
  }
  return added;
}

/* Tear the camera down and put the step back to its resting state. Called on
   every navigation as well as by the Stop button, a camera left running
   because someone tapped Home is both a battery drain and, at a demo table
   where a stranger is holding the phone, a bad look. */
function resetScanUi() {
  if (scanner) { scanner.stop(); scanner = null; }
  const start = $('scan-start');
  start.hidden = false;
  start.disabled = false;
  start.textContent = 'Start camera';
  $('scan-stage').hidden = true;
  $('scan-progress').hidden = true;
  $('scan-cells').innerHTML = '';
  $('scan-note').textContent = '';
  const result = $('scan-result');
  result.hidden = true;
  result.innerHTML = '';
}

async function startScan() {
  const start = $('scan-start');
  start.disabled = true;
  start.textContent = 'Starting camera…';
  $('scan-result').hidden = true;

  const { SignedPsbtScanner } = await import('./scan.js');
  scanner = new SignedPsbtScanner({
    video: $('scan-video'),
    onProgress: renderScanProgress,
    onComplete: onScanComplete,
    onError: showScanError,
  });

  if (!await scanner.start()) {          // start() already reported why
    scanner = null;
    start.disabled = false;
    start.textContent = 'Start camera';
    return;
  }
  start.hidden = true;
  $('scan-stage').hidden = false;
  $('scan-progress').hidden = false;
  renderScanProgress(scanner.snapshot());

  // The Start button sits at the bottom of a long scrolling page, so tapping it
  // leaves the preview mostly below the fold, you end up aiming a camera you
  // cannot see. Pull the stage to the top (clear of the sticky banner, via
  // scroll-margin-top) so the preview and the percentage are both on screen.
  $('scan-stage').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function renderScanProgress(p) {
  $('scan-pct').textContent = `${Math.round(p.percent * 100)}%`;
  $('scan-count').textContent = p.expected
    ? `${p.received} of ${p.expected} parts`
      // Named separately because it is a genuinely different event: the decoder
      // solved that fragment out of XOR'd frames rather than ever seeing it.
      + (p.reconstructed ? ` · ${p.reconstructed} rebuilt from mixed frames` : '')
    : 'looking for the first frame…';

  const cells = $('scan-cells');
  if (p.expected && cells.childElementCount !== p.expected) {
    cells.innerHTML = '';
    for (let i = 0; i < p.expected; i++) {
      const cell = document.createElement('div');
      cell.className = 'scan-cell';
      cells.appendChild(cell);
    }
  }
  // A COUNT meter, not a positional map: cell i lights when the decoder holds
  // i+1 fragments, whichever they turn out to be.
  //
  // Marking only the fragments read directly off the screen was the first
  // attempt, and against real hardware it displayed nothing at all. A device's
  // UR animation shows the pure fragments once, under a second at 5 fps for a
  // small transaction, and then stays in the fountain forever. Unless the
  // camera happens to lock on in that first second, every frame you catch is a
  // mixed one, so the decoder is recovering fragments steadily while not one of
  // them was ever seen in pure form. The bar sat empty next to a rising
  // percentage. cUR reports how many fragments it holds but not which, and a
  // segmented meter is not read positionally anyway.
  for (let i = 0; i < cells.childElementCount; i++) {
    cells.children[i].classList.toggle('is-read', i < p.received);
  }
  $('scan-note').textContent = p.note || '';
}

async function onScanComplete(psbtBytes) {
  scanner = null;
  $('scan-stage').hidden = true;
  $('scan-progress').hidden = true;

  const { verifySignedPsbt } = await import('./psbt.js');
  try {
    renderScanResult(await verifySignedPsbt(psbtBytes, state.scenarioData.verify));
  } catch (e) {
    showScanError(`That decoded, but it is not a PSBT this page can read: ${e.message}`);
  }
  // The preview just disappeared from where the eye was; bring the verdict to
  // the same place rather than leaving the page scrolled to empty space.
  $('scan-result').scrollIntoView({ behavior: 'smooth', block: 'center' });
}

function scanResultBox(cls, mark, headline, detail, rows, footer, again) {
  const box = $('scan-result');
  box.className = `scan-result ${cls}`;
  box.innerHTML = `
    <div class="scan-verdict">
      <span class="scan-verdict-mark" aria-hidden="true">${mark}</span>
      <strong>${headline}</strong>
    </div>
    <p class="qr-note">${detail}</p>
    ${rows ? `<table class="kv">${rows}</table>` : ''}
    ${footer || ''}
    <button id="scan-again" class="btn btn-block" style="margin-top:12px">${again}</button>`;
  box.hidden = false;
  $('scan-again').addEventListener('click', () => { resetScanUi(); startScan(); });
}

/* "alice, bob and carol", an Oxford-comma-free list, because at three
   cosigners this is read aloud at a demo table rather than parsed. */
function nameList(names) {
  if (names.length <= 1) return names[0] || '';
  return `${names.slice(0, -1).join(', ')} and ${names[names.length - 1]}`;
}

function renderScanResult(report) {
  const added = report.txMatches ? collectSignatures(report) : 0;

  // Counts come from everything collected so far, not just this scan, so a
  // multisig adds up across cosigners. Capped per input at the threshold: three
  // cosigners signing a 2-of-3 is 9 signatures against 6 needed, and "9 of 6"
  // is not a thing anybody wants to read.
  const needed = report.inputs.reduce((n, i) => n + i.needed, 0);
  const have = report.inputs.map((i) =>
    (collected.inputs[i.index] ? collected.inputs[i.index].size : 0));
  const valid = report.inputs.reduce((n, i) => n + Math.min(have[i.index], i.needed), 0);
  const threshold = report.inputs.length ? report.inputs[0].needed : 1;
  const enough = report.txMatches && report.inputs.every((i) => have[i.index] >= i.needed);

  const seeds = new Set();
  for (const perInput of collected.inputs) {
    for (const sig of perInput.values()) if (sig.seed) seeds.add(sig.seed);
  }
  const who = nameList([...seeds]);

  let cls = '', mark = '·', headline, detail;
  if (!report.txMatches) {
    // The interesting failure. Every signature in it may be perfectly valid,
    // just not over the transaction this page sent, which is the whole thing a
    // hardware signer exists to make impossible to fake.
    cls = 'scan-bad';
    mark = '✗';
    headline = 'That is a different transaction';
    detail = 'The device returned a transaction that is not the one shown above.';
  } else if (report.anyInvalid) {
    cls = 'scan-bad';
    mark = '✗';
    headline = 'A signature did not check out';
    detail = 'This is the right transaction, but a signature on it failed verification.';
  } else if (enough) {
    cls = 'scan-ok';
    mark = '✓';
    headline = 'Signed, and the signature is real';
    // The headline already makes the verification claim, so the body closes the
    // loop instead: this is the point where a real transfer ends, and without
    // saying so the demo stops one step short of the thing it is explaining.
    const cosigners = state.scenario.signing_seeds.length;
    // The headline already makes the verification claim, so the body closes the
    // loop instead: this is where a real transfer ends, and without saying so
    // the demo stops one step short of the thing it is explaining. No "but this
    // one is fake" line, the sticky banner and the transaction summary both
    // carry that, and a third copy is the kind of text nobody reads.
    detail = `${threshold > 1
      ? `${who} together complete the ${threshold}-of-${cosigners}. `
      : (who ? `Signed by ${who}. ` : '')}After scanning in the signature, your
      wallet software would then broadcast the transaction to the network.`;
  } else if (valid > 0) {
    mark = '◐';
    headline = 'Partly signed';
    // Rescanning the same cosigner is the obvious thing to try when nothing
    // seems to be happening, so name it rather than silently showing the same
    // numbers a second time.
    detail = added === 0
      ? `That signature was already counted, ${who} has signed. Load a DIFFERENT
         cosigner's seed on the device, scan the transaction above again, and read
         the new signature back here.`
      : `${who} ${seeds.size > 1 ? 'have' : 'has'} signed. Load the next cosigner's
         seed, scan the transaction above again, and read that signature back here
         too, they add up.`;
  } else {
    headline = 'Not signed yet';
    detail = 'This is the transaction that was sent, unchanged and with no signatures on it.';
  }

  // Deliberately NOT an "inputs signed" row. It counted inputs that had reached
  // threshold, so a 2-of-3 signed by one cosigner read "inputs signed: 0 of 3"
  // directly above "valid signatures: 3", two true statements that look like a
  // contradiction. Signatures are the unit the user is accumulating, so count
  // only those, and say how many are outstanding rather than making them
  // subtract.
  const rows = `
    <tr><th>Valid signatures</th><td class="num">${valid} of ${needed}</td></tr>
    ${valid < needed
      ? `<tr><th>Still needed</th><td class="num">${needed - valid}</td></tr>`
      : ''}`;

  // The transaction id sits OUTSIDE the table. In it, the numeric column asks to
  // be as narrow as its content while a 64-character txid asks for everything
  // going, the auto table layout splits the difference and wraps the id into a
  // ragged column two characters wide. Nothing in a two-column key/value table
  // handles both a short right-aligned number and a long identifier.
  const footer = `<p class="scan-txid"><span>Transaction</span>${truncatedAddr(report.txid)}</p>`;

  scanResultBox(cls, mark, headline, detail, rows, footer, 'Scan again');
}

function showScanError(message) {
  if (scanner) { scanner.stop(); scanner = null; }
  $('scan-stage').hidden = true;
  $('scan-progress').hidden = true;
  scanResultBox('scan-bad', '✗', 'Camera', message, '', '', 'Try again');
}

/* ---------- "verify an address" view -------------------------------------- */

/* A separate SeedSigner tool from signing: you point Verify Address at an
   address and the device tells you whether it belongs to a wallet it knows.
   During signing the device checks its own change on board instead, which is
   why this isn't a step of that flow.
 *
 * The ADDRESS comes first, matching the device: you scan the address, and only
 * then does the device need to know what to check it against. And the
 * descriptor step is multisig-only, a single-sig address is verified against a
 * loaded seed, and there is no single-sig wallet descriptor to scan, because
 * SeedSigner does not support importing one. Offering it anyway sent people
 * looking for a device screen that does not exist. */
async function renderVerifyView() {
  const wallets = state.index.wallets.filter((w) => w.network === state.filters.network);
  const select = $('verify-wallet');
  if (!state.verifyWallet || !wallets.some((w) => w.name === state.verifyWallet)) {
    state.verifyWallet = wallets[0].name;
  }
  select.innerHTML = '';
  wallets.forEach((w) => {
    const o = document.createElement('option');
    o.value = w.name;
    o.textContent = `${w.policy} · ${scriptLabel(w.script_type)}`;
    o.selected = w.name === state.verifyWallet;
    select.appendChild(o);
  });

  const entry = wallets.find((w) => w.name === state.verifyWallet);
  const data = await getJSON(entry.file);

  // Step 2 is whatever the device asks for after the address scan, and that
  // differs by policy: a single-sig address is derived from the seed, while a
  // multisig address only means something against the wallet policy, no single
  // seed can answer for it.
  const isMultisig = entry.sig_type === 'multisig';
  $('verify-step-descriptor').hidden = !isMultisig;
  $('verify-step-seed').hidden = isMultisig;

  if (!isMultisig) {
    await renderHandmadeSeed(entry.cosigners[0], {
      player: verifySeedPlayer,
      hintId: 'verify-seed-hint',
      segId: 'verify-seedqr-seg',
      wordsId: 'verify-seed-words',
      hint: 'So the device can derive this wallet’s addresses and see whether '
        + 'the one you scanned is among them.',
      rerender: renderVerifyView,
    });
  }

  if (isMultisig) {
    const urs = data.descriptor_urs;
    if (!Object.keys(urs).includes(state.verifyDescriptorUr)) {
      state.verifyDescriptorUr = Object.keys(urs)[0];
    }
    buildDescriptorSeg('verify-descriptor-seg', urs, state.verifyDescriptorUr,
      (v) => { state.verifyDescriptorUr = v; renderVerifyView(); });

    $('verify-descriptor-hint').textContent =
      `So the device knows what a ${entry.policy} address of this wallet should look like.`;
    verifyDescriptorPlayer.setPayload(prepare(urs[state.verifyDescriptorUr].qr));
    $('verify-descriptor-meta').textContent =
      `${entry.policy} ${entry.script_label} · ur:${state.verifyDescriptorUr}`;
    $('verify-descriptor-text').innerHTML = `<div class="addr">${data.descriptor}</div>`;
  }

  const options = [];
  ['receive', 'change'].forEach((branch) => {
    data.addresses[branch].forEach((item) => {
      options.push({ value: `${branch}:${item.index}`, label: `${branch} ${item.index}` });
    });
  });
  const currentKey = `${state.verifyAddress.branch}:${state.verifyAddress.index}`;
  buildChooser($('verify-address-chooser'), options,
    (v) => v === currentKey,
    (v) => {
      const [branch, index] = v.split(':');
      state.verifyAddress = { branch, index: Number(index) };
      renderVerifyView();
    });

  const chosen = data.addresses[state.verifyAddress.branch]
    .find((a) => a.index === state.verifyAddress.index);
  verifyAddressPlayer.setPayload(prepare(chosen.qr));
  $('verify-address-meta').textContent = chosen.address;
  renumberSteps('view-verify');
}

/* ---------- standalone "load a seed" view --------------------------------- */

async function renderOnlySeedView() {
  const seeds = state.index.seeds;
  if (!state.onlySeedName || !seeds.some((s) => s.name === state.onlySeedName)) {
    state.onlySeedName = seeds[0].name;
  }
  buildChooser($('only-seed-chooser'),
    seeds.map((s) => ({ value: s.name, label: `${s.name} · ${s.words}w` })),
    (v) => v === state.onlySeedName,
    (v) => { state.onlySeedName = v; renderOnlySeedView(); });

  const entry = seeds.find((s) => s.name === state.onlySeedName);
  const data = await getJSON(entry.file);

  buildSegmented($('only-seedqr-seg'), [
    { value: 'compact', label: 'CompactSeedQR' },
    { value: 'standard', label: `SeedQR (${data.words}w)` },
  ], state.onlySeedVariant, (v) => { state.onlySeedVariant = v; renderOnlySeedView(); });

  const variant = data[state.onlySeedVariant];
  onlySeedPlayer.label = possessive(data.name);
  onlySeedPlayer.marker = markerFor(data.name);
  onlySeedPlayer.fingerprint = data.master_fingerprint.toUpperCase();
  onlySeedPlayer.setPayload(prepare(variant.qr));
  $('only-seed-note').textContent = state.onlySeedVariant === 'compact'
    ? `${data.words === 24 ? 32 : 16} bytes of entropy, a smaller, easier scan.`
    : `${variant.payload.length} digits, numeric mode.`;

  const wordList = data.mnemonic.split(' ');
  const wordRows = Math.ceil(wordList.length / 3);
  const words = wordList.map((w, i) => `<span><i>${i + 1}</i>${w}</span>`).join('');
  $('only-seed-words').innerHTML = `
    <div class="words" style="grid-template-rows: repeat(${wordRows}, auto)">${words}</div>
    <table class="kv" style="margin-top:10px">
      <tr><th>Master fingerprint</th><td class="mono">${data.master_fingerprint}</td></tr>
    </table>`;
}

/* ---------- "sign a message" view ---------------------------------------- */

/* Two steps, in the device's order: scan the message, then load the seed.
 *
 * The seed used to be a one-line note under the QR ("Load seed alice first"),
 * which is the same mistake as leaving it out, signing needs the key on board,
 * the device asks for a seed immediately after the scan, and a demo that stops
 * at the message stops before anything happens. It gets the same handmade
 * SeedQR treatment as the signing flow, for the same reason. */
async function renderMessageView() {
  const msgs = state.index.messages.filter((m) => m.network === state.filters.network);
  if (!state.messageName || !msgs.some((m) => m.name === state.messageName)) {
    state.messageName = msgs[0].name;
  }
  buildChooser($('message-chooser'),
    msgs.map((m) => ({ value: m.name, label: m.label })),
    (v) => v === state.messageName,
    (v) => { state.messageName = v; renderMessageView(); });

  const entry = msgs.find((m) => m.name === state.messageName);
  const data = await getJSON(entry.file);

  messagePlayer.setPayload(prepare(data.qr));
  $('message-meta').textContent =
    `${entry.chars} characters · ${scriptLabel(entry.script_type)}`;

  $('message-detail').innerHTML = `
    <table class="kv">
      <tr><th class="kv-wide">Message</th><td></td></tr>
      <tr><td colspan="2">${data.message}</td></tr>
      <tr><th>Derivation</th><td class="mono">${data.derivation}</td></tr>
      <tr><th class="kv-wide">Signing address</th><td>${truncatedAddr(data.address)}</td></tr>
    </table>`;

  await renderHandmadeSeed(data.seed, {
    player: messageSeedPlayer,
    hintId: 'message-seed-hint',
    segId: 'message-seedqr-seg',
    wordsId: 'message-seed-words',
    hint: `The device asks which seed to sign with, this message is signed by ${data.seed}.`,
    rerender: renderMessageView,
  });
  renumberSteps('view-message');
}

/* Render a "load the seed" step: handmade SeedQR, type picker, word list.
 *
 * Three views need this now, signing, message signing, and verifying a
 * single-sig address, because on the device they all reach the same point:
 * whatever you scanned, it cannot do anything until a key is on board. Shared
 * rather than copied, so the SeedQR presentation (which carries a fair amount
 * of deliberate design: the handmade look, the folded sheet, the per-key ink)
 * cannot drift between them. */
async function renderHandmadeSeed(seedName, opts) {
  const seedEntry = state.index.seeds.find((s) => s.name === seedName);
  const seed = await getJSON(seedEntry.file);

  $(opts.hintId).textContent = opts.hint;

  buildSegmented($(opts.segId), [
    { value: 'compact', label: 'CompactSeedQR' },
    { value: 'standard', label: `SeedQR (${seed.words}w)` },
  ], state.seedVariant, (v) => { state.seedVariant = v; opts.rerender(); });

  const player = opts.player;
  player.label = possessive(seed.name);
  player.marker = markerFor(seed.name);
  player.fingerprint = seed.master_fingerprint.toUpperCase();
  player.setPayload(prepare(seed[state.seedVariant].qr));

  const wordList = seed.mnemonic.split(' ');
  const wordRows = Math.ceil(wordList.length / 3);
  const words = wordList.map((w, i) => `<span><i>${i + 1}</i>${w}</span>`).join('');
  $(opts.wordsId).innerHTML = `
    <div class="words" style="grid-template-rows: repeat(${wordRows}, auto)">${words}</div>
    <table class="kv" style="margin-top:10px">
      <tr><th>Master fingerprint</th><td class="mono">${seed.master_fingerprint}</td></tr>
    </table>`;
}

/* ---------- the folded sheet ---------------------------------------------- */

/* The card starts folded in half and unfolds upward. The two stand-in faces are
   painted from a snapshot of the canvas, because a canvas element can only live
   in one place in the DOM and the fold needs its top and bottom halves to move
   independently. Once the flap is flat the stand-ins fade out and the real
   canvas, which was never display:none, only covered, is what you scan. */
function refreshFold(fold, canvas, meta) {
  if (!fold || !canvas.width) return;
  // Match the stage to the CANVAS box, not the container's.
  //
  // Integer module scaling means the canvas is usually a few percent narrower
  // than the space available, and the card centres it. The stand-in faces size
  // their background to the stage, so a stage spanning the full container
  // stretched the snapshot ~5% too large, the QR visibly popped down to size
  // the instant the real canvas took over at the end of the unfold, and popped
  // back up when re-folding.
  const stage = fold.querySelector('.fold-stage');
  const foldBox = fold.getBoundingClientRect();
  const canvasBox = canvas.getBoundingClientRect();
  stage.style.left = `${canvasBox.left - foldBox.left}px`;
  stage.style.top = `${canvasBox.top - foldBox.top}px`;
  stage.style.width = `${canvasBox.width}px`;
  stage.style.height = `${canvasBox.height}px`;

  const url = canvas.toDataURL();
  fold.querySelectorAll('.fold-upper, .fold-front').forEach((face) => {
    face.style.backgroundImage = `url(${url})`;
  });
  if (!meta) return;
  // The outside of the folded sheet carries the same identifying marks, in the
  // same pen, so a closed card still tells you which key it is.
  const note = fold.querySelector('.fold-back-note');
  if (!note) return;
  note.style.color = `hsl(${meta.marker.h} ${Math.min(100, meta.marker.s + 12)}% ${meta.marker.l + 4}%)`;
  handwrite(note.querySelector('.fold-back-name'), meta.label, 0);
  handwrite(note.querySelector('.fold-back-fp'), meta.fingerprint, 7);
}

/* DOM equivalent of drawHandLabel: one span per character, each nudged, tilted
   and sheared a little. A single rotation on the whole line still reads as type
   that happens to be crooked, the irregularity has to be per letter. */
function handwrite(el, text, salt) {
  el.textContent = '';
  [...text].forEach((ch, i) => {
    const span = document.createElement('span');
    span.textContent = ch === ' ' ? '\u00a0' : ch;
    const h = Math.imul(i + 1 + salt * 31, 0x9e3779b1) >>> 0;
    const dy = ((((h & 0xff) / 255) - 0.5) * 0.16).toFixed(3);
    const rot = ((((h >> 8) & 0xff) / 255) - 0.5) * 8;
    const skew = ((((h >> 16) & 0xff) / 255) - 0.5) * 14;
    span.style.transform = `translateY(${dy}em) rotate(${rot.toFixed(2)}deg) skewX(${skew.toFixed(2)}deg)`;
    el.appendChild(span);
  });
}

function setupFolds() {
  document.querySelectorAll('.fold').forEach((fold) => {
    // The button opens; it must not also reach the stage's toggle below, or the
    // two would cancel out and the sheet would never open.
    fold.querySelector('.fold-open').addEventListener('click', (e) => {
      e.stopPropagation();
      fold.classList.add('is-open');
    });
    // Tapping the sheet itself toggles it. This lives on the stage rather than
    // the card because the card is permanently visibility:hidden, and hidden
    // elements receive no pointer events.
    fold.querySelector('.fold-stage').addEventListener('click', () => {
      fold.classList.toggle('is-open');
    });
  });
}

/* Re-fold everything, so the next person at the demo table starts from a folded
   sheet rather than inheriting the last one's. */
function lockFolds() {
  document.querySelectorAll('.fold').forEach((f) => f.classList.remove('is-open'));
}

/* ---------- view routing -------------------------------------------------- */

/* Each view change is a real history entry, so the phone's Back gesture returns
 * to the landing page instead of leaving the site.
 *
 * Every navigation used replaceState, which keeps the URL shareable but leaves
 * the history stack one entry deep, so Back from three steps into the signing
 * flow exited to whatever was open before. On a phone Back is the primary way
 * out of anything, and a page that answers it by closing itself reads as a
 * crash.
 *
 * `push` is false when the navigation IS the history moving (popstate) or when
 * restoring state on first load; pushing there would either loop or bury the
 * entry the user came from.
 */
/* The URL is DERIVED from the current view, never accumulated into.
 *
 * It used to be accumulated: selectScenario() wrote `?tx=` unconditionally,
 * including while the landing page was showing, so merely opening the root
 * rewrote the URL to `?tx=<default>`. Refreshing then landed on the signing
 * view instead of the menu, and that made Back unfixable in principle rather
 * than merely broken, because the history entry the user started from no longer
 * described the page they had started on. No amount of pushState fixes a stack
 * whose entries lie.
 *
 * `tx` implies the signing view rather than sitting alongside `do=sign`, which
 * keeps the shareable deep link short (`?tx=<id>`), that shape is documented
 * and already in use.
 */
function syncUrl({ push = false } = {}) {
  const url = new URL(window.location);
  url.searchParams.delete('do');
  url.searchParams.delete('tx');
  if (state.mode === 'sign') {
    if (state.scenario) url.searchParams.set('tx', state.scenario.id);
  } else if (state.mode !== 'home') {
    url.searchParams.set('do', state.mode);
  }
  // Only a genuine change earns an entry; re-selecting the current view would
  // otherwise stack duplicates that Back has to chew through one at a time.
  if (url.href === window.location.href) return;
  if (push) history.pushState({ mode: state.mode }, '', url);
  else history.replaceState({ mode: state.mode }, '', url);
}

/** Which view a URL describes. The one place that decides, so a deep link, a
    fresh load and a popstate cannot disagree about it. */
function modeFromUrl(params) {
  return params.get('do') || (params.get('tx') ? 'sign' : 'home');
}

async function setMode(mode, { push = true } = {}) {
  if (!VIEWS.includes(mode)) mode = 'home';
  lockFolds();
  resetScanUi();
  state.mode = mode;
  VIEWS.forEach((v) => { $(`view-${v}`).hidden = v !== mode; });

  if (mode === 'seed') await renderOnlySeedView();
  if (mode === 'verify') await renderVerifyView();
  if (mode === 'message') await renderMessageView();

  syncUrl({ push });
  window.scrollTo({ top: 0, behavior: 'auto' });
}

/* Back/forward: rebuild the view from the URL, without writing history again.
   selectScenario skips its own URL write here, setMode is about to derive the
   whole URL a line later, and letting both write means a transient state where
   the URL describes neither the old view nor the new one. */
async function onPopState() {
  const params = new URL(window.location).searchParams;
  const tx = params.get('tx');
  if (tx && (!state.scenario || state.scenario.id !== tx)) {
    await selectScenario(tx, { updateUrl: false });
  }
  await setMode(modeFromUrl(params), { push: false });
}

/* ---------- scenario selection -------------------------------------------- */

async function selectScenario(id, { updateUrl = true } = {}) {
  const scenario = state.index.scenarios.find((s) => s.id === id);
  if (!scenario) return;
  state.scenario = scenario;
  state.scenarioData = await getJSON(`data/scenario/${id}.json`);
  lockFolds();
  // A result from the previous transaction would be about a different txid, and
  // signatures collected for it mean nothing here. Note this is NOT in
  // resetScanUi(): "Scan again" must keep what has been collected so far, which
  // is the entire point of collecting it.
  resetScanUi();
  resetCollected();

  // The blurb lives behind the "What's in this transaction?" accordion, above
  // the fold it was three lines of prose between the QR and the next step.
  $('scenario-title').textContent = scenario.title;

  renderFlow();
  await loadQr();
  renderTxSummary();
  await renderSeedStep();
  await renderDescriptorStep();
  renderFlow();

  // Replace, never push: picking a different transaction is a parameter change
  // within the signing view, so Back should return to the menu rather than walk
  // backwards through every transaction that was browsed. And on the landing
  // page this writes nothing at all, syncUrl only emits `tx` when the signing
  // view is the one actually showing.
  if (updateUrl) syncUrl();
}

/* ---------- picker -------------------------------------------------------- */

function uniq(list) { return [...new Set(list)]; }

/* Scenarios matching the current filters, optionally ignoring one of them so
   that filter's own option list can be built from what's actually reachable. */
function matchingScenarios(ignore) {
  const f = state.filters;
  return state.index.scenarios.filter((s) =>
    !s.test                          // test scenarios are listed in their own group
    && s.network === f.network
    && (ignore === 'sig_type' || f.sig_type === 'all' || s.sig_type === f.sig_type)
    && (ignore === 'script_type' || f.script_type === 'all' || s.script_type === f.script_type)
    && (ignore === 'inputs' || f.inputs === 'all' || s.num_inputs === Number(f.inputs)));
}

/* Picking "Multisig" should land on the multisig people actually use, not on
   whatever the previous single-sig choice was, which would otherwise filter to
   nothing and look broken. */
function defaultScriptFor(sigType) {
  if (sigType === 'multisig') return 'P2WSH';
  if (sigType === 'single-sig') return 'P2WPKH';
  return state.filters.script_type;
}

function renderFilters() {
  const idx = state.index;
  const inNetwork = idx.scenarios.filter((s) => s.network === state.filters.network);
  const forSig = state.filters.sig_type === 'all'
    ? inNetwork
    : inNetwork.filter((s) => s.sig_type === state.filters.sig_type);

  // Only offer input counts that exist for the rest of the selection. The sweep
  // runs on two script types only, so most combinations have just the one count,
  // and listing the others would be dead options.
  const counts = uniq(matchingScenarios('inputs').map((s) => s.num_inputs))
    .sort((a, b) => a - b);
  if (state.filters.inputs !== 'all' && !counts.includes(Number(state.filters.inputs))) {
    state.filters.inputs = 'all';
  }

  const defs = [
    { key: 'network', label: 'Network',
      options: [{ value: 'main', label: 'Mainnet' }, { value: 'test', label: 'Testnet' }] },
    { key: 'sig_type', label: 'Signing',
      options: [{ value: 'all', label: 'All' },
                ...uniq(inNetwork.map((s) => s.sig_type))
                  .map((v) => ({ value: v, label: idx.sig_type_labels[v] || v }))] },
    // Human name alongside the abbreviation: "Native SegWit (P2WPKH)". The
    // abbreviation alone is jargon; the name alone loses precision.
    { key: 'script_type', label: 'Script type',
      options: [{ value: 'all', label: 'All' },
                ...uniq(forSig.map((s) => s.script_type))
                  .map((v) => ({ value: v, label: scriptLabel(v) }))] },
    { key: 'inputs', label: 'Inputs',
      options: [{ value: 'all', label: 'All' },
                ...counts.map((n) => ({ value: String(n), label: `${n} input${n === 1 ? '' : 's'}` }))] },
  ];

  const box = $('filters');
  box.innerHTML = '';
  defs.forEach((def) => {
    const wrap = document.createElement('div');
    wrap.className = 'control';
    const label = document.createElement('label');
    label.textContent = def.label;
    const select = document.createElement('select');
    select.className = 'btn btn-block';
    def.options.forEach((opt) => {
      const o = document.createElement('option');
      o.value = opt.value;
      o.textContent = opt.label;
      o.selected = state.filters[def.key] === opt.value;
      select.appendChild(o);
    });
    select.addEventListener('change', () => {
      state.filters[def.key] = select.value;
      if (def.key === 'sig_type') {
        state.filters.script_type = defaultScriptFor(select.value);
      }
      // Rebuild the controls too: changing one filter changes what the others
      // can offer.
      renderFilters();
      renderScenarioList();
    });
    wrap.append(label, select);
    box.appendChild(wrap);
  });
}

function scenarioItem(s) {
  const b = document.createElement('button');
  b.type = 'button';
  b.className = 'scenario-item' + (s.test ? ' is-test' : '');
  b.setAttribute('aria-current', String(state.scenario && s.id === state.scenario.id));
  if (s.test) {
    // A test row leads with what to load and the screen it should trigger, the
    // only two things you need to run it on device.
    b.innerHTML = `<strong>${s.title}</strong>
      <span>Load ${s.signing_seeds[0]} · expects “${s.expected_screen}”</span>`;
  } else {
    // Just the input count, spelled out. Frame count and PSBT size were noise at
    // this size; the size now lives in "What's in this transaction?", where
    // there is room to read it.
    const stress = s.tags.includes('stress test') ? ' · stress test' : '';
    b.innerHTML = `<strong>${s.title}</strong>
      <span>${s.num_inputs} input${s.num_inputs === 1 ? '' : 's'}${stress}</span>`;
  }
  b.addEventListener('click', () => { closePicker(); selectScenario(s.id); });
  return b;
}

function groupHead(text, sub) {
  const wrap = document.createElement('div');
  wrap.className = 'list-group-head';
  const h = document.createElement('p');
  h.className = 'list-group-title';
  h.textContent = text;
  wrap.appendChild(h);
  if (sub) {
    const p = document.createElement('p');
    p.className = 'list-group-sub';
    p.textContent = sub;
    wrap.appendChild(p);
  }
  return wrap;
}

function renderScenarioList() {
  const list = $('scenario-list');
  list.innerHTML = '';

  // Each enabled PR's test scenarios sit in their own labelled group above the
  // demo transactions. They match on network only (a small curated set; hiding
  // them behind the script-type/inputs filters would just make a toggle look
  // broken). The groups render in the order the index lists the PRs.
  let shownAnyTest = false;
  (state.index.test_pr_groups || []).forEach((g) => {
    if (!state.showPR.has(g.pr)) return;
    const tests = state.index.scenarios.filter(
      (s) => s.test && s.pr === g.pr && s.network === state.filters.network);
    if (!tests.length) return;
    shownAnyTest = true;
    list.appendChild(groupHead(g.label, g.blurb));
    tests.forEach((s) => list.appendChild(scenarioItem(s)));
  });
  if (shownAnyTest) list.appendChild(groupHead('Demo transactions'));

  const matches = matchingScenarios();
  if (!matches.length) {
    list.insertAdjacentHTML('beforeend',
      '<p class="empty">No transactions match those filters.</p>');
    return;
  }
  matches.forEach((s) => list.appendChild(scenarioItem(s)));
}

/* One "show test scenarios" checkbox per hardening PR, built from the index so a
   new PR needs no markup change. */
function renderPickerToggles() {
  const box = $('picker-toggles');
  box.innerHTML = '';
  (state.index.test_pr_groups || []).forEach((g) => {
    const label = document.createElement('label');
    label.className = 'picker-toggle';
    const cb = document.createElement('input');
    cb.type = 'checkbox';
    cb.checked = state.showPR.has(g.pr);
    cb.addEventListener('change', () => {
      if (cb.checked) state.showPR.add(g.pr); else state.showPR.delete(g.pr);
      renderScenarioList();
    });
    const span = document.createElement('span');
    span.innerHTML = `Show <b>${g.label}</b> <small>test scenarios</small>`;
    label.append(cb, span);
    box.appendChild(label);
  });
}

function openPicker() {
  renderPickerToggles();
  renderFilters();
  renderScenarioList();
  $('picker').hidden = false;
  // It scrolls as a full page now, so start it at the top rather than wherever a
  // previous visit left it.
  $('picker').scrollTop = 0;
}
function closePicker() { $('picker').hidden = true; }

/* ---------- fullscreen ---------------------------------------------------- */

function openFullscreen() {
  $('fs').hidden = false;
  player.setCanvas($('fs-canvas'));
}
function closeFullscreen() {
  $('fs').hidden = true;
  player.setCanvas($('qr-canvas'));
}

/* ---------- boot ---------------------------------------------------------- */

function wireControls() {
  $('home').addEventListener('click', goHome);
  document.querySelectorAll('[data-goto]').forEach((b) => {
    b.addEventListener('click', () => setMode(b.dataset.goto));
  });
  $('only-seed-chooser');
  $('verify-wallet').addEventListener('change', (e) => {
    state.verifyWallet = e.target.value;
    renderVerifyView();
  });

  $('open-picker').addEventListener('click', openPicker);
  $('picker-close').addEventListener('click', closePicker);
  $('picker').addEventListener('click', (e) => { if (e.target.id === 'picker') closePicker(); });
  // The per-PR test toggles are built and wired in renderPickerToggles().

  $('qr-expand').addEventListener('click', openFullscreen);
  $('fs-close').addEventListener('click', closeFullscreen);

  $('scan-start').addEventListener('click', startScan);
  $('scan-cancel').addEventListener('click', resetScanUi);

  // Tap a truncated address to see all of it. Delegated from the document
  // because the summary table is rebuilt on every scenario change, and a
  // listener per row would leak one per selection.
  document.addEventListener('click', (e) => {
    const addr = e.target.closest && e.target.closest('.addr-trunc');
    if (addr) addr.classList.toggle('is-open');
  });
  // A backgrounded tab keeps a camera open, and on a phone that means the
  // indicator light stays on after someone has switched away from the page.
  document.addEventListener('visibilitychange', () => {
    if (document.hidden && scanner) resetScanUi();
  });

  $('playpause').addEventListener('click', () => {
    player.playing = !player.playing;
    updatePlaybackControls();
  });
  $('step-frame').addEventListener('click', () => player.advance(1));

  const slider = $('fps-slider');
  slider.addEventListener('input', () => {
    state.fps = parseFloat(slider.value);
    player.fps = state.fps;
    $('fps-value').textContent = `${state.fps} fps`;
  });

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') { closeFullscreen(); closePicker(); }
  });

  window.addEventListener('popstate', () => { onPopState(); });

  let resizeTimer;
  const relayout = () => allPlayers.forEach((p) => p.layout());
  window.addEventListener('resize', () => {
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(relayout, 120);
  });
  window.addEventListener('orientationchange', () => setTimeout(relayout, 250));
}

/* The banner title is the way back to the landing page. */
async function goHome() {
  await setMode('home');
}

async function main() {
  player.setCanvas($('qr-canvas'));
  player.onFrame = onFrameChange;
  seedPlayer.renderStyle = 'handmade';
  seedPlayer.onRendered = (c) => refreshFold($('seed-fold'), c, seedPlayer);
  seedPlayer.setCanvas($('seed-canvas'));
  descriptorPlayer.setCanvas($('descriptor-canvas'));
  verifyDescriptorPlayer.setCanvas($('verify-descriptor-canvas'));
  verifyAddressPlayer.setCanvas($('verify-address-canvas'));
  onlySeedPlayer.renderStyle = 'handmade';
  onlySeedPlayer.onRendered = (c) => refreshFold($('only-seed-fold'), c, onlySeedPlayer);
  onlySeedPlayer.setCanvas($('only-seed-canvas'));
  messagePlayer.setCanvas($('message-canvas'));
  messageSeedPlayer.renderStyle = 'handmade';
  messageSeedPlayer.onRendered = (c) =>
    refreshFold($('message-seed-fold'), c, messageSeedPlayer);
  messageSeedPlayer.setCanvas($('message-seed-canvas'));
  verifySeedPlayer.renderStyle = 'handmade';
  verifySeedPlayer.onRendered = (c) =>
    refreshFold($('verify-seed-fold'), c, verifySeedPlayer);
  verifySeedPlayer.setCanvas($('verify-seed-canvas'));

  wireControls();
  setupFolds();
  // The hand-written label is canvas text, and canvas does NOT participate in
  // font loading: setting ctx.font never triggers a fetch. Once the label moved
  // off the DOM and into the canvas, nothing on the page referenced Permanent
  // Marker any more, so the browser never downloaded it, document.fonts.ready
  // resolved immediately, and every label silently painted in a serif fallback.
  // Ask for the face explicitly, then redraw.
  if (document.fonts && document.fonts.load) {
    document.fonts.load('16px "Permanent Marker"')
      .then(() => allPlayers.forEach((pl) => pl.layout()))
      .catch(() => {});
  }

  state.index = await getJSON('data/index.json');
  const d = state.index.defaults;
  state.format = d.format;
  state.fps = d.fps;
  state.seedVariant = d.seedqr || state.seedVariant;
  player.fps = d.fps;
  $('fps-slider').value = d.fps;
  $('fps-value').textContent = `${d.fps} fps`;
  $('foot-build').textContent =
    `${state.index.scenarios.length} transactions · ${state.index.wallets.length} wallets · `
    + `${state.index.seeds.length} seeds`;

  const params = new URL(window.location).searchParams;
  const fallback = state.index.scenarios.find((s) => s.is_default) || state.index.scenarios[0];
  const start = state.index.scenarios.find((s) => s.id === params.get('tx')) || fallback;
  state.filters.network = start.network;
  // A ?tx= link straight to a test scenario means that PR's group should already
  // be enabled, so "Change" lands somewhere that includes the current one.
  if (start.test && start.pr) state.showPR.add(start.pr);
  // updateUrl:false, a default transaction is preloaded so the signing view is
  // instant when it IS opened, but preloading must not announce itself in the
  // URL. Writing `?tx=` here is what made a refresh of the root land on the
  // signing view.
  await selectScenario(start.id, { updateUrl: false });
  // A ?tx= link means someone wants that transaction, not the landing page.
  // push:false, the first view IS the entry the browser already has. Pushing
  // here would put a duplicate on the stack, so the first Back would appear to
  // do nothing.
  await setMode(modeFromUrl(params), { push: false });
}

// Test hook: lets the scannability harness force a render style on the seed QRs.
window.__tuneHandmade = (patch) => {
  Object.assign(HAND, patch);
  [seedPlayer, onlySeedPlayer, messageSeedPlayer, verifySeedPlayer].forEach((p) => p.draw());
};
window.__setStyle = (style) => {
  [seedPlayer, onlySeedPlayer, messageSeedPlayer, verifySeedPlayer].forEach((p) => { p.renderStyle = style; p.draw(); });
};

main().catch((err) => {
  document.body.insertAdjacentHTML('afterbegin',
    `<p style="padding:16px;color:#b00">Failed to load site data: ${err.message}.
     Did you run <code>bash tools/wasm/build.sh</code> and
     <code>python -m tools.build_site</code>, and start the dev server?</p>`);
  console.error(err);
});
