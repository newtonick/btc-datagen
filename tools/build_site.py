"""Build the static GitHub Pages demo site into site/dist/.

Everything the browser needs is precomputed here, because Pages is static and
PSBT construction needs embit. Static QR codes ship as **bare module matrices**
(packed bits, no quiet zone) rather than payload text, so the browser never has
to encode those itself and the on-screen white border stays a front-end concern.

The animated transaction QRs are the exception, and deliberately so. They are
generated in the browser by the WASM build of cUR (tools/wasm/), because a
pre-generated frame list cannot be a fountain: a real UR encoder emits pure
fragments 1..N and then mixed XOR parts forever, never repeating and never
returning to part 1, and the only way to reproduce that is to run the encoder.
Shipping the base64 PSBT plus a fragment size instead of a few hundred rendered
frames also cuts the largest scenario from ~296 KB to ~53 KB.

That trade means there IS now a second QR encoder to keep honest;
tools/wasm/roundtrip_test.mjs is the gate that does it.

Layout:
    site/dist/
      index.html app.js ssqr.js psbt.js scan.js styles.css  (copied from site/)
      vendor/ssqr.{js,wasm} vendor/noble-secp256k1.js       (built / fetched)
      data/index.json                     scenario + wallet + seed catalog
      data/scenario/<id>.json             base64 PSBT, detail, verification data
      data/qr/<id>.bbqr.<density>.json    BBQR frame matrices (lazy-loaded)
      data/seed/<name>.json               SeedQR + CompactSeedQR matrices
      data/wallet/<name>.json             descriptor QR + address QRs

Prerequisite:  bash tools/wasm/build.sh   (once; needs Docker)

Run:  python -m tools.build_site            (both networks)
      python -m tools.build_site --network main
      python -m tools.build_site --quick    (skip the big input-count sweep)
"""
import argparse
import hashlib
import json
import os
import shutil
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from embit.psbt import SIGHASH
from urtypes.crypto import PSBT as URPSBT

from common import bbqr, scenarios as scenario_defs, script_types
from common.attack_psbt import build_test_psbt
from common.fixtures import load_seeds, load_wallets, wallet_cosigners
from common.psbt import build_psbt, summarize
from common.qr import qr_matrix, qr_matrix_bytes
from common.seedqr import standard_seedqr_digits, compact_seedqr_bytes
from common.ur2.ur import UR
from common.ur2.ur_encoder import UREncoder

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SITE_SRC = os.path.join(ROOT, "site")
DIST = os.path.join(SITE_SRC, "dist")
STATIC_FILES = ["index.html", "app.js", "styles.css", "seedsigner-logo.svg",
                # ES modules, loaded on demand by app.js: the WASM wrapper, the
                # PSBT reader/verifier, and the camera scanner.
                "ssqr.js", "psbt.js", "scan.js",
                # Self-hosted rather than pulled from a font CDN: this thing gets
                # opened on conference wifi, and a webfont that fails to load
                # would silently drop the handwritten label back to a system
                # serif, the exact failure the font is there to avoid.
                "permanent-marker.woff2",
                # Custom domain. Ships inside the artifact so the domain travels
                # with the build rather than living only in repo settings.
                "CNAME"]
# Copied wholesale: font + library licence texts, and the built/fetched
# third-party bundle (see tools/wasm/).
STATIC_DIRS = ["licenses", "vendor"]

# The site cannot run without these; there is no pre-rendered fallback for the
# animated transaction QRs any more.
WASM_ARTIFACTS = ["vendor/ssqr.js", "vendor/ssqr.wasm", "vendor/noble-secp256k1.js"]

MIN_FRAGMENT_BYTES = 10          # Sparrow MIN_FRAGMENT_LENGTH
DEFAULT_FPS = 5                  # Sparrow ANIMATION_PERIOD_MILLIS = 200ms
DEFAULT_SEEDQR = "compact"       # CompactSeedQR: smaller symbol, easier scan

# Sequence number used to size the animation's canvas.
#
# Every fountain part carries the same fragment length, so the ONLY thing that
# grows the payload, and with it the QR version, is the sequence number: as a
# decimal in the URI path, and as a CBOR integer inside the part (1 byte below
# 24, 2 below 256, 3 below 65536, 5 beyond). The front end has to lock one
# module scale for a whole animation (see site/app.js), so it needs the ceiling
# up front rather than discovering it three minutes in.
#
# 999,999 parts is 55 hours at 5 fps and already sits in the widest CBOR band,
# so this is the practical maximum rather than a guess. The front end still
# re-layouts if a frame ever exceeds it, which costs one visible resize instead
# of a clipped QR.
LAYOUT_CEILING_SEQ = 999_999

# Sparrow's two density presets per format. "normal" is the HIGHER-density
# option (more data per frame); "low" packs less in and is easier to scan.
FORMATS = {
    "ur": {
        "label": "UR",
        "note": "ur:crypto-psbt, what Sparrow sends by default.",
        "densities": {"normal": 400, "low": 80},     # bytes of CBOR per fragment
        "default_density": "normal",
    },
    "bbqr": {
        "label": "BBQR",
        "note": "BBQR, Coldcard-Q style. Denser per frame, so Low is the sane default.",
        "densities": {"normal": 2000, "low": 1000},  # CHARS of encoded body per part
        "default_density": "low",
    },
}
DEFAULT_FORMAT = "ur"

DENSITY_LABELS = {"normal": "Normal", "low": "Low"}

# Message-signing payloads. SeedSigner's format is
#   signmessage {derivation_path} ascii:{message}
# and its type detection is `startswith("signmessage")`, lowercase, so unlike
# the UR payloads these must NOT be upper-cased for alphanumeric density.
MESSAGE_DEFS = [
    {"name": "short", "script_type": "P2WPKH", "path_suffix": "/0/0",
     "label": "Short message",
     "message": "Signed on a SeedSigner with a published test key."},
    {"name": "long", "script_type": "P2WPKH", "path_suffix": "/0/0",
     "label": "Long message (pages on device)",
     "message": ("This is a deliberately long test message, so the SeedSigner has to "
                 "page through it on a small screen before you confirm what you are "
                 "actually signing. Reading the whole thing is the point of the "
                 "exercise: a signer that shows you only the first line is a signer "
                 "that can be lied to. None of this is real -- the key is public.")},
    {"name": "legacy", "script_type": "P2PKH", "path_suffix": "/0/0",
     "label": "Legacy address path",
     "message": "Message signing from a legacy P2PKH path."},
]
MESSAGE_SEED = "alice"

WARNING = ("TEST DATA ONLY, every key on this site is published and deterministic. "
           "These transactions are synthetic and spend UTXOs that do not exist. "
           "Never send real funds to any address here.")


# --- QR payload generation ---------------------------------------------------

def ur_runtime_spec(raw_psbt: bytes, max_fragment_bytes: int) -> dict:
    """What the browser needs to run the ur:crypto-psbt fountain itself.

    No frames, the browser has the PSBT and the fragment size, and generates
    parts on demand with the same cUR codec the ESP32 firmware runs. What Python
    contributes is the two numbers the front end cannot compute without
    encoding: how many pure fragments there are (so the progress line can say
    "part 3 of 15" and switch to "fountain part" past the end), and the module
    ceiling to lock the canvas scale to.

    The ceiling is measured, not estimated: it rasterizes an actual part at
    LAYOUT_CEILING_SEQ, which is the widest a part can get short of a 32-bit
    sequence number. Part 1 is measured too, because a single-part UR has no
    fountain header at all and is therefore *smaller*, not larger.
    """
    ur = UR("crypto-psbt", URPSBT(raw_psbt).to_cbor())
    encoder = UREncoder(ur, max_fragment_bytes, 0, MIN_FRAGMENT_BYTES)

    if encoder.is_single_part():
        _b64, version, modules = qr_matrix(encoder.next_part())
        return {"runtime": True, "max_fragment": max_fragment_bytes,
                "min_fragment": MIN_FRAGMENT_BYTES, "count": 1,
                "modules": modules, "version": version}

    seq_len = encoder.fountain_encoder.seq_len()
    _b64, v_first, m_first = qr_matrix(encoder.next_part())
    ceiling = UREncoder(ur, max_fragment_bytes, LAYOUT_CEILING_SEQ, MIN_FRAGMENT_BYTES)
    _b64, v_max, m_max = qr_matrix(ceiling.next_part())
    return {
        "runtime": True,
        "max_fragment": max_fragment_bytes,
        "min_fragment": MIN_FRAGMENT_BYTES,
        "count": seq_len,
        "modules": max(m_first, m_max),
        "version": max(v_first, v_max),
    }


def bbqr_parts(raw_psbt: bytes, max_fragment_chars: int) -> list:
    """BBQR parts. Unlike UR this really is a fixed set of slices that a sender
    loops, BBQR has no fountain coding, so pre-rendering it is faithful."""
    parts, _encoding = bbqr.encode(raw_psbt, "P", max_fragment_chars)
    return parts


def frames_payload(parts: list) -> dict:
    """Rasterize each part to a bare module matrix.

    Frames in one set can differ by a QR version (the last slice is often
    smaller). The front end locks its scale to `max_modules` and centers smaller
    frames, so the symbol never resizes mid-scan.
    """
    frames = []
    for part in parts:
        b64, version, modules = qr_matrix(part)
        frames.append({"m": modules, "v": version, "b": b64})
    return {
        "count": len(frames),
        "max_modules": max(f["m"] for f in frames),
        "max_version": max(f["v"] for f in frames),
        "frames": frames,
    }


def _single(b64: str, version: int, modules: int) -> dict:
    return {"count": 1, "max_modules": modules, "max_version": version,
            "frames": [{"m": modules, "v": version, "b": b64}]}


def text_qr(payload: str, uppercase: bool = True) -> dict:
    return _single(*qr_matrix(payload, uppercase=uppercase))


def address_qr(address: str) -> dict:
    """Address QRs ship verbatim, see the note in common.qr.qr_matrix about
    why upper-casing a Bitcoin address is not an option."""
    return text_qr(address, uppercase=False)


def bytes_qr(payload: bytes) -> dict:
    """A byte-mode QR (CompactSeedQR)."""
    return _single(*qr_matrix_bytes(payload))


# --- verification data for the scan-back step --------------------------------

def verification_data(psbt, signers: list, threshold: int) -> dict:
    """Everything the browser needs to check a signature the device hands back.

    The browser does the elliptic-curve work (site/psbt.js, via
    @noble/secp256k1) but NOT the sighash construction. That is deliberate:
    computing a sighash means implementing BIP143, BIP341 and the legacy
    algorithm in JavaScript, three separate chances to be subtly wrong, in a
    place where being subtly wrong means confidently displaying a green tick.
    embit already knows how, so the message digest for every input is computed
    here and shipped.

    That shapes what the check MEANS, and the UI says so: it verifies the
    signature against the sighash of *the transaction this page sent*. If the
    device had signed anything else, a different amount, a different
    recipient, the signature would not verify against this digest. That is the
    property a demo is actually trying to show.

    Taproot key-path spends verify against the TWEAKED output key sitting in the
    scriptPubKey, not the internal key in the PSBT's derivation fields, so the
    x-only key is pulled straight out of the script.
    """
    by_fingerprint = {s.fingerprint: s.name for s in signers}
    taproot = psbt.inputs[0].is_taproot
    sighash_type = SIGHASH.DEFAULT if taproot else SIGHASH.ALL

    inputs = []
    for i, inp in enumerate(psbt.inputs):
        if taproot:
            # A P2TR scriptPubKey is OP_1 <32-byte x-only key>.
            xonly = inp.utxo.script_pubkey.data[2:34]
            keys = [{"pubkey": xonly.hex(),
                     "fingerprint": der.fingerprint.hex(),
                     "seed": by_fingerprint.get(der.fingerprint.hex(), "?")}
                    for _pk, (_leaves, der) in inp.taproot_bip32_derivations.items()]
        else:
            keys = [{"pubkey": pk.sec().hex(),
                     "fingerprint": der.fingerprint.hex(),
                     "seed": by_fingerprint.get(der.fingerprint.hex(), "?")}
                    for pk, der in inp.bip32_derivations.items()]
        inputs.append({"sighash": psbt.sighash(i, sighash=sighash_type).hex(),
                       "keys": keys})

    return {
        "txid": psbt.tx.txid().hex(),
        # The exact bytes the returned PSBT's global unsigned transaction must
        # equal. Comparing these is what proves the device signed THIS
        # transaction rather than a plausible-looking one.
        "unsigned_tx": psbt.tx.serialize().hex(),
        "taproot": taproot,
        # Signatures required per input before the transaction is complete.
        "threshold": threshold or 1,
        "inputs": inputs,
    }


# --- writers -----------------------------------------------------------------

def write_json(path: str, obj) -> int:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(obj, f, separators=(",", ":"))
    return os.path.getsize(path)


def build_scenario(scenario, wallets, seeds) -> tuple:
    """Returns (index_entry, files_written_bytes)."""
    wallet = wallets[scenario.wallet]
    signers = wallet_cosigners(wallet, seeds)

    # Adversarial / malformed test scenarios forge the PSBT (or, for the
    # wrong-seed case, ship an honest one the decoy seed cannot sign). The
    # builders live in common/attack_psbt, one per `attack` kind.
    if scenario.attack:
        psbt = build_test_psbt(scenario.attack, signers, scenario.script_type,
                               wallet["network"], scenario.num_inputs,
                               threshold=wallet["threshold"])
    else:
        psbt = build_psbt(signers, scenario.script_type, scenario.num_inputs,
                          scenario.output_shape, threshold=wallet["threshold"])
    raw = psbt.serialize()
    b64 = psbt.to_string()
    summary = summarize(psbt, wallet["network"])

    info = script_types.get(scenario.script_type)
    # Which seed the "Load the seed" step presents. Test scenarios override it (the
    # wrong-seed case is entirely about loading a decoy).
    signing_seeds = [scenario.load_seed] if scenario.load_seed else wallet["cosigners"]

    # The descriptor step earns its place whenever the device would ask for it.
    # A fixed build rejects a test scenario during parse, before any descriptor,
    # but a build from BEFORE the PR still walks the multisig change-verification
    # flow, so the wallet descriptor is offered for every multisig test scenario
    # to let a tester reproduce that older behavior. For ordinary demos it needs
    # an on-device change output to check against.
    if scenario.attack:
        needs_descriptor = info.is_multisig
    else:
        has_own_output = any(o["kind"] in ("change", "self_transfer")
                             for o in summary["outputs"])
        needs_descriptor = info.is_multisig and has_own_output

    written = 0
    variant_index = {"ur": {}, "bbqr": {}}

    # UR is generated in the browser, so the index carries parameters rather
    # than a file reference, a few dozen bytes instead of up to 296 KB.
    for density, cap in FORMATS["ur"]["densities"].items():
        variant_index["ur"][density] = ur_runtime_spec(raw, cap)

    for density, cap in FORMATS["bbqr"]["densities"].items():
        payload = frames_payload(bbqr_parts(raw, cap))
        rel = f"data/qr/{scenario.id}.bbqr.{density}.json"
        written += write_json(os.path.join(DIST, rel), payload)
        variant_index["bbqr"][density] = {
            "file": rel,
            "count": payload["count"],
            "modules": payload["max_modules"],
            "version": payload["max_version"],
        }

    # A test scenario is rejected by the device before it ever produces a
    # signature, so there is nothing to scan back and no verification data.
    verify = None if scenario.attack else verification_data(psbt, signers, wallet["threshold"])

    written += write_json(os.path.join(DIST, f"data/scenario/{scenario.id}.json"), {
        "id": scenario.id,
        "psbt_base64": b64,
        "psbt_bytes": len(raw),
        "summary": summary,
        "verify": verify,
    })

    entry = {
        "id": scenario.id,
        "title": scenario.title,
        "blurb": scenario.blurb,
        "wallet": scenario.wallet,
        "script_type": scenario.script_type,
        "script_label": info.label,
        "sig_type": info.sig_type,
        "network": scenario.network,
        "num_inputs": scenario.num_inputs,
        "output_shape": scenario.output_shape,
        "tags": scenario.tags,
        "is_default": scenario.is_default,
        "psbt_bytes": len(raw),
        "signing_seeds": signing_seeds,
        "threshold": wallet["threshold"],
        "needs_descriptor": needs_descriptor,
        "summary": summary,
        # Set only where the summary table's psbt-claim view needs annotating
        # (PR #995's amount lies); null for every other scenario.
        "summary_note": scenario.summary_note,
        "qr": variant_index,
        # Present (and truthy) only on adversarial / malformed test scenarios.
        "test": bool(scenario.attack),
        "pr": scenario.pr,
        "attack": scenario.attack,
        "expected": scenario.expected,
        "expected_screen": scenario.expected_screen,
        "outcome": scenario.outcome,
    }
    return entry, written


def build_seed_files(seeds) -> tuple:
    entries, written = [], 0
    for name, seed in seeds.items():
        words = seed["mnemonic"].split()
        digits = standard_seedqr_digits(words)
        entropy = compact_seedqr_bytes(words)
        assert entropy.hex() == seed["entropy_hex"], f"{name}: compact entropy mismatch"
        written += write_json(os.path.join(DIST, f"data/seed/{name}.json"), {
            "name": name,
            "mnemonic": seed["mnemonic"],
            "words": seed["words"],
            "master_fingerprint": seed["master_fingerprint"],
            "standard": {"payload": digits, "qr": text_qr(digits)},
            "compact": {"payload_hex": entropy.hex(), "qr": bytes_qr(entropy)},
        })
        entries.append({"name": name, "words": seed["words"],
                        "master_fingerprint": seed["master_fingerprint"],
                        "file": f"data/seed/{name}.json"})
    return entries, written


def build_wallet_files(wallets) -> tuple:
    entries, written = [], 0
    for name, wallet in wallets.items():
        info = script_types.get(wallet["script_type"])
        addresses = {}
        for branch, items in wallet["addresses"].items():
            addresses[branch] = [
                {**item, "qr": address_qr(item["address"])} for item in items
            ]
        written += write_json(os.path.join(DIST, f"data/wallet/{name}.json"), {
            "name": name,
            "descriptor": wallet["descriptor"],
            # SeedSigner imports a descriptor from either UR type, and it isn't
            # settled which one Sparrow emits, so ship both and let the UI pick.
            "descriptor_urs": {
                "crypto-output": {
                    "label": "crypto-output",
                    "payload": wallet["ur_crypto_output"],
                    "qr": text_qr(wallet["ur_crypto_output"]),
                },
                "crypto-account": {
                    "label": "crypto-account",
                    "payload": wallet["ur_crypto_account"],
                    "qr": text_qr(wallet["ur_crypto_account"]),
                },
            },
            "addresses": addresses,
            "cosigner_keys": wallet["cosigner_keys"],
        })
        entries.append({
            "name": name, "policy": wallet["policy"], "network": wallet["network"],
            "script_type": wallet["script_type"], "script_label": info.label,
            "sig_type": info.sig_type, "threshold": wallet["threshold"],
            "cosigners": wallet["cosigners"], "derivation": wallet["derivation"],
            "file": f"data/wallet/{name}.json",
        })
    return entries, written


def build_message_files(seeds, wallets, networks) -> tuple:
    """Message-signing payloads: `signmessage {path} ascii:{message}`.

    Not upper-cased, SeedSigner detects these with a lowercase
    `startswith("signmessage")`, so the alphanumeric-mode trick used for UR
    payloads would make them undetectable.
    """
    entries, written = [], 0
    for network in networks:
        for md in MESSAGE_DEFS:
            info = script_types.get(md["script_type"])
            base = scenario_defs.WALLET_FOR_SCRIPT_TYPE[md["script_type"]]
            wallet_name = base if network == "main" else f"{base}_testnet"
            wallet = wallets[wallet_name]
            account_path = wallet["derivation"]
            full_path = f"{account_path}{md['path_suffix']}"
            payload = f"signmessage {full_path} ascii:{md['message']}"

            signers = wallet_cosigners(wallet, seeds)
            address = wallet["addresses"]["receive"][0]["address"]

            name = md["name"] if network == "main" else f"{md['name']}_testnet"
            written += write_json(os.path.join(DIST, f"data/message/{name}.json"), {
                "name": name,
                "payload": payload,
                "message": md["message"],
                "derivation": full_path,
                "address": address,
                "seed": wallet["cosigners"][0],
                "qr": text_qr(payload, uppercase=False),
            })
            entries.append({
                "name": name, "label": md["label"], "network": network,
                "script_type": md["script_type"], "script_label": info.label,
                "derivation": full_path, "seed": wallet["cosigners"][0],
                "chars": len(md["message"]),
                "file": f"data/message/{name}.json",
            })
    return entries, written


def copy_static():
    for name in STATIC_FILES:
        src = os.path.join(SITE_SRC, name)
        if os.path.exists(src):
            shutil.copy2(src, os.path.join(DIST, name))
    for name in STATIC_DIRS:
        src = os.path.join(SITE_SRC, name)
        if os.path.isdir(src):
            shutil.copytree(src, os.path.join(DIST, name), dirs_exist_ok=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--network", choices=["main", "test", "both"], default="both")
    ap.add_argument("--quick", action="store_true",
                    help="skip input counts above 5 (fast iteration on the UI)")
    args = ap.parse_args()

    # Fail here rather than shipping a site whose central feature is a blank
    # canvas. There is no pre-rendered fallback for the animated QRs any more.
    missing = [a for a in WASM_ARTIFACTS if not os.path.exists(os.path.join(SITE_SRC, a))]
    if missing:
        sys.exit(f"missing build artifact(s): {', '.join(missing)}\n"
                 f"Run `bash tools/wasm/build.sh` first (needs Docker).")

    networks = ("main", "test") if args.network == "both" else (args.network,)
    seeds = load_seeds()
    wallets = load_wallets()
    all_scenarios = scenario_defs.all_scenarios(networks)
    if args.quick:
        all_scenarios = [s for s in all_scenarios if s.num_inputs <= 5]
    # Adversarial / malformed transactions for exercising PR #1013 on device.
    # Mainnet-only and hidden behind a picker toggle, so they never intrude on
    # the demo, but they build alongside everything else. Skipped by --network test.
    if "main" in networks:
        all_scenarios = all_scenarios + scenario_defs.test_scenarios()

    # Build into a staging directory and swap at the end, so the previous build
    # keeps serving throughout. Wiping DIST up front left the dev server with no
    # index.html for the ~2 minutes of a full build, anyone testing on a phone
    # in that window just got a directory listing.
    global DIST
    final = DIST
    staging = final + ".building"
    if os.path.exists(staging):
        shutil.rmtree(staging)
    os.makedirs(staging)
    DIST = staging

    started = time.time()
    total_bytes = 0
    scenario_entries = []
    for i, scenario in enumerate(all_scenarios, 1):
        entry, written = build_scenario(scenario, wallets, seeds)
        scenario_entries.append(entry)
        total_bytes += written
        # For UR, `count` is the number of PURE fragments, the animation itself
        # is unbounded, so this is "how long before it goes fountain", not a
        # frame total.
        biggest = max(entry["qr"][f][d]["count"]
                      for f in entry["qr"] for d in entry["qr"][f])
        print(f"  [{i:>3}/{len(all_scenarios)}] {scenario.id:<44s} "
              f"{entry['psbt_bytes']:>7,}B  up to {biggest:>3} parts")

    seed_entries, w = build_seed_files(seeds)
    total_bytes += w
    wallet_entries, w = build_wallet_files(wallets)
    total_bytes += w
    message_entries, w = build_message_files(seeds, wallets, networks)
    total_bytes += w

    total_bytes += write_json(os.path.join(DIST, "data/index.json"), {
        "warning": WARNING,
        "defaults": {"format": DEFAULT_FORMAT, "fps": DEFAULT_FPS, "network": "main",
                     "seedqr": DEFAULT_SEEDQR},
        "formats": {k: {"label": v["label"], "note": v["note"],
                        "default_density": v["default_density"],
                        "densities": list(v["densities"])}
                    for k, v in FORMATS.items()},
        "density_labels": DENSITY_LABELS,
        # Human-friendly names for the pickers. "P2SH-P2WPKH" means nothing to
        # someone at a demo table; "Nested SegWit" does.
        "script_labels": {name: info.label for name, info in
                          script_types.SCRIPT_TYPES.items()},
        "sig_type_labels": {script_types.SINGLE_SIG: "Single sig",
                            script_types.MULTISIG: "Multisig"},
        "output_shape_labels": scenario_defs.OUTPUT_SHAPE_LABELS,
        # One picker toggle per hardening PR; only present when test scenarios
        # were built (mainnet). The front end renders a checkbox + group per entry.
        "test_pr_groups": scenario_defs.TEST_PR_GROUPS if "main" in networks else [],
        "scenarios": scenario_entries,
        "seeds": seed_entries,
        "wallets": wallet_entries,
        "messages": message_entries,
    })

    copy_static()

    # Swap the finished build in. Rename is near-instant, so the window where the
    # site is unavailable is a moment rather than the length of a build.
    DIST = final
    previous = final + ".previous"
    if os.path.exists(previous):
        shutil.rmtree(previous)
    if os.path.exists(final):
        os.rename(final, previous)
    os.rename(staging, final)
    shutil.rmtree(previous, ignore_errors=True)

    elapsed = time.time() - started
    print(f"\nBuilt {len(scenario_entries)} scenarios, {len(seed_entries)} seeds, "
          f"{len(wallet_entries)} wallets, {len(message_entries)} messages")
    print(f"  {total_bytes / 1_048_576:.1f} MiB of data in {elapsed:.1f}s -> {DIST}")


if __name__ == "__main__":
    main()
