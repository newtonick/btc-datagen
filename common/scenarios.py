"""The demo transaction matrix.

Static hosting means every PSBT has to exist before anyone loads the page, so
"configurable" is a bounded matrix presented as pickers rather than arbitrary
runtime construction. The matrix is deliberately shaped rather than a full cross
product (which would be ~340 cases, most of them redundant):

  * a **full cross** of all seven script types x all four output shapes at the
    default input count: this is the "what does each wallet type look like"
    axis, and it's the one people actually poke at;
  * an **input-count sweep** on the two representative types only, because input
    count is really a QR-payload-size axis and doesn't interact with script type
    in any way a demo reveals. 30 inputs is the usual stress test; 100 is the
    extreme.

Both are built for both networks.
"""
from dataclasses import dataclass, field

from common import script_types
from common.attack_psbt import PR995_CLAIMED_INPUT_VALUE, PR995_REAL_INPUT_VALUE
from common.psbt import FEE, IN_VALUE

DEFAULT_NUM_INPUTS = 3

# Wallet fixture to use for each script type (base name; `_testnet` is appended
# for the test network).
WALLET_FOR_SCRIPT_TYPE = {
    "P2WPKH": "ss_native_segwit",
    "P2SH-P2WPKH": "ss_nested_segwit",
    "P2TR": "ss_taproot",
    "P2PKH": "ss_legacy",
    "P2WSH": "2of3_p2wsh",
    "P2SH-P2WSH": "2of3_p2sh_p2wsh",
    "P2SH": "2of3_p2sh",
}

# Input counts swept on the two representative script types.
SWEEP_SCRIPT_TYPES = ["P2WPKH", "P2WSH"]
SWEEP_INPUT_COUNTS = [1, 2, 5, 20, 30, 100]

OUTPUT_SHAPE_LABELS = {
    "change": "Send with change",
    "full_spend": "Full spend (no change)",
    "self_transfer": "Self-transfer",
    "multi_recipient": "Three recipients + change",
}

OUTPUT_SHAPE_BLURBS = {
    "change": "One external recipient, the remainder back to the wallet as change, "
              "plus the network fee.",
    "full_spend": "Sweeps the whole balance to one external recipient, no change "
                  "output at all.",
    "self_transfer": "Pays back to the wallet's own receive address rather than a "
                     "third party. SeedSigner counts both outputs as change.",
    "multi_recipient": "A batched payment: three separate external recipients plus "
                       "change.",
}


@dataclass
class Scenario:
    id: str
    wallet: str
    script_type: str
    num_inputs: int
    output_shape: str
    network: str
    title: str
    blurb: str
    is_default: bool = False
    tags: list = field(default_factory=list)
    # Adversarial / malformed test scenarios. None on the ordinary demo
    # transactions. `pr` groups them by the SeedSigner PR they exercise (each PR
    # gets its own picker toggle); `attack` selects the forgery builder;
    # `load_seed` overrides which seed the "Load the seed" step presents (the
    # point of the wrong-seed case); `expected*` describe what the device should
    # do so the sample is useful to run on hardware.
    pr: str = None                     # "1013" | "1032" | "1044" | "1040" | "995"
    attack: str = None
    load_seed: str = None
    expected: str = None
    expected_screen: str = None
    # What the device does with this psbt, so the banner can phrase it correctly:
    #   refuse  aborts to a warning screen (expected_screen names it)
    #   error   aborts to the generic error screen (unsupported input)
    #   spend   parses fine; the output is shown as a payment out, not change
    #   change  parses fine; the output is shown as change (correctly, or as a
    #           documented limit; expected_screen says which)
    outcome: str = None
    # Free-text note rendered under the site's "What's in this transaction?"
    # table. Only #995's amount lies need it: that table repeats the psbt's own
    # claim, which for those is exactly the fee a vulnerable device displays.
    summary_note: str = None


def _make(script_type, shape, num_inputs, network, is_default=False):
    info = script_types.get(script_type)
    base_wallet = WALLET_FOR_SCRIPT_TYPE[script_type]
    wallet = base_wallet if network == "main" else f"{base_wallet}_testnet"
    suffix = "" if network == "main" else "-testnet"
    sid = f"{base_wallet}-{shape}-{num_inputs}in{suffix}"
    inputs_label = f"{num_inputs} input" + ("s" if num_inputs != 1 else "")
    title = f"{info.label}: {OUTPUT_SHAPE_LABELS[shape]}"
    blurb = f"{inputs_label}. {OUTPUT_SHAPE_BLURBS[shape]}"
    tags = [info.sig_type, info.label]
    if num_inputs >= 20:
        tags.append("stress test")
    return Scenario(id=sid, wallet=wallet, script_type=script_type,
                    num_inputs=num_inputs, output_shape=shape, network=network,
                    title=title, blurb=blurb, is_default=is_default, tags=tags)


def all_scenarios(networks=("main", "test")) -> list:
    out, seen = [], set()
    for network in networks:
        # Full cross at the default input count.
        for script_type in script_types.SCRIPT_TYPES:
            for shape in OUTPUT_SHAPE_LABELS:
                is_default = (network == "main" and script_type == "P2WPKH"
                              and shape == "change")
                s = _make(script_type, shape, DEFAULT_NUM_INPUTS, network, is_default)
                out.append(s)
                seen.add(s.id)
        # Input-count sweep on the representative types.
        for script_type in SWEEP_SCRIPT_TYPES:
            for n in SWEEP_INPUT_COUNTS:
                s = _make(script_type, "change", n, network)
                if s.id not in seen:
                    out.append(s)
                    seen.add(s.id)
    return out


def default_scenario(scenarios: list) -> Scenario:
    return next(s for s in scenarios if s.is_default)


# --- adversarial / malformed test scenarios ----------------------------------
#
# Hidden behind per-PR "show test scenarios" toggles in the picker. These are NOT
# part of the demo; each exists to run against a build of the named PR on real
# hardware and watch the device reject it. Deliberately small and curated, and
# mainnet only (the checks are network-agnostic and the demo defaults to mainnet).

# The seed the forgeries impersonate: the honest signer of the single-sig test
# wallets and a cosigner of the multisig one, so "load this seed" is unambiguous.
TEST_VICTIM_SEED = "alice"
# A seed that is NOT a key in the native-segwit test wallet, for "Seed Can't Sign".
TEST_DECOY_SEED = "bob"

# One picker toggle per PR, in listing order. `blurb` heads the group so a tester
# knows what the whole set probes.
TEST_PR_GROUPS = [
    {
        "pr": "1013",
        "label": "PR #1013: ownership scan",
        "url": "https://github.com/seedsigner/seedsigner/pull/1013",
        "blurb": ("Re-derive every claim of this seed's fingerprint and reject a psbt "
                  "that names our fingerprint on a key the seed cannot derive."),
    },
    {
        "pr": "1032",
        "label": "PR #1032: change output ownership",
        "url": "https://github.com/seedsigner/seedsigner/pull/1032",
        "blurb": ("An output counts as change only when the script rebuilt from this "
                  "seed matches what the output commits to. Contradictions and "
                  "malformed derivation bookkeeping are refused."),
    },
    {
        "pr": "1044",
        "label": "PR #1044: every claim held to the script",
        "url": "https://github.com/seedsigner/seedsigner/pull/1044",
        "blurb": ("A multisig output may claim this seed more than once. Every claim is "
                  "now held to the committed script, so a decoy key of ours is refused "
                  "wherever the psbt lists it, not only when it is listed first."),
    },
    {
        "pr": "1040",
        "label": "PR #1040: fingerprint consistency",
        "url": "https://github.com/seedsigner/seedsigner/pull/1040",
        "blurb": ("A key's derivation entry and the global xpub that derives it both name "
                  "a fingerprint. When they disagree the psbt contradicts itself and is "
                  "refused; an all-zero fingerprint is a missing value, not a second answer."),
    },
    {
        "pr": "995",
        "label": "PR #995: input amounts",
        "url": "https://github.com/seedsigner/seedsigner/pull/995",
        "blurb": ("Fee is inputs minus outputs, so an input amount the device cannot prove "
                  "lets a coordinator display any fee it likes. Legacy inputs are the worst "
                  "case: their signatures commit no amount, so the lie survives signing and "
                  "the difference burns as miner fee."),
    },
]

# script_type -> (short family name, wallet fixture base name), for PR #1013.
TEST_SCRIPT_FAMILIES = [
    ("P2WPKH", "Native SegWit"),
    ("P2TR", "Taproot"),
    ("P2WSH", "Multisig (2-of-3)"),
]

_ATTACK_DEFS = {  # PR #1013
    "fake_change": {
        "label": "Fake change attack",
        "expected_screen": "Suspicious Transaction / Likely an Attack!",
        "expected": "Device should refuse it as likely an attack.",
        # Single-key families (native segwit, taproot): the scriptPubKey is
        # repointed at the attacker, so the funds really leave.
        "blurb": ("An output is dressed up as change back to your own wallet, but the "
                  "key it names is one your seed does not own, so the funds actually "
                  "leave to an attacker. The device re-derives the key and the claim "
                  "collapses."),
        # Multisig: the real change script is left in place (the funds return to
        # your own 2-of-3); only the ownership claim is forged. This is the case
        # 0.8.7 misses, because it checks the script, not the claimed key.
        "blurb_multisig": ("The output really is your own change, back to your 2-of-3, "
                           "so no funds move. But the psbt annotates it with a key your "
                           "seed cannot derive, a false ownership claim that nothing in "
                           "0.8.7 objects to."),
    },
    "bad_input": {
        "label": "Malformed input ownership",
        "expected_screen": "Transaction Problem",
        "expected": "Device should reject it as a malformed transaction.",
        "blurb": ("An input claims your fingerprint on a key your seed does not derive. "
                  "It gains an attacker nothing (it is unsignable either way), so the "
                  "device treats it as broken data rather than an attack."),
    },
    "wrong_seed": {
        "label": "Wrong seed loaded",
        "expected_screen": "Seed Can't Sign",
        "expected": "Device should say this seed can't sign it.",
        "blurb": ("A perfectly ordinary, honest transaction, for a wallet this seed is "
                  "not part of. Load the decoy seed and the device finds no input it "
                  "can sign."),
    },
}


def _make_test(attack, script_type, family):
    info = script_types.get(script_type)
    base_wallet = WALLET_FOR_SCRIPT_TYPE[script_type]
    d = _ATTACK_DEFS[attack]
    slug = script_type.lower().replace("-", "_")
    sid = f"test-{attack.replace('_', '-')}-{slug}"
    # Some forgeries behave differently for multisig (see fake_change: single-key
    # families redirect the funds, multisig does not), so a per-family blurb wins.
    blurb = d["blurb_multisig"] if (info.is_multisig and "blurb_multisig" in d) else d["blurb"]
    load_seed = TEST_DECOY_SEED if attack == "wrong_seed" else TEST_VICTIM_SEED
    return Scenario(
        id=sid, wallet=base_wallet, script_type=script_type,
        num_inputs=DEFAULT_NUM_INPUTS, output_shape="change", network="main",
        title=f"⚠ {d['label']} ({family})", blurb=blurb, is_default=False,
        tags=["test", d["label"], info.label],
        pr="1013", attack=attack, load_seed=load_seed,
        expected=d["expected"], expected_screen=d["expected_screen"], outcome="refuse",
    )


# PR #1032, #1044, and #1040: one def list per PR. Each entry pins the forgery
# builder (common/attack_psbt.build_test_psbt), the wallet it runs on, and the
# expected outcome. Most refuse to a warning screen; some parse fine but classify
# the output (spend, or change: correctly, or for a documented limitation).
# `screen` is the label a tester looks for; `outcome` tells the banner how to
# phrase it.
_ATTACK_SCREEN = "Suspicious Transaction / Likely an Attack!"
_PROBLEM_SCREEN = "Transaction Problem"
_ERROR_SCREEN = "Generic error screen"
_SPEND_RESULT = "Shown as a payment, not change"
_CHANGE_RESULT = "Shown as change (a limitation)"
_CHANGE_OK_RESULT = "Shown as change (correct)"

_REFUSE = "Device should refuse it as likely an attack."
_MALFORMED = "Device should reject it as a malformed transaction."
_ERROR = "Device should abort to the generic error screen."
_SPEND = "Device should show the output as a payment out, not change."
_CHANGE = "Without a descriptor the device shows it as change; load the descriptor to catch it."
_CHANGE_OK = "Device should parse it and show the output as change."
_CHANGE_NO_XPUBS = "With no global xpubs there is nothing to compare, so the device shows it as change."
_UNVERIFIED = "Device should discard it: the input amounts cannot be confirmed."

# Icon by outcome: a warning triangle where the device stops, an arrow where the
# output leaves as a spend, an info mark where it is (mis)counted as change.
_ICON = {"refuse": "⚠", "error": "⚠", "spend": "→", "change": "ℹ"}

_PR1032_DEFS = [
    # --- refusals: ownership contradictions (attack warning) -----------------
    {"kind": "contradiction_singlesig", "script_type": "P2WPKH", "family": "Native SegWit",
     "label": "Fake change pays another key", "outcome": "refuse",
     "screen": _ATTACK_SCREEN, "expected": _REFUSE,
     "blurb": ("It is labeled as change back to this seed, but the scriptPubKey pays a "
               "key you do not own, so the funds really leave.")},
    {"kind": "contradiction_pays_us_claims_other", "script_type": "P2WPKH", "family": "Native SegWit",
     "label": "Change claims a stranger's key", "outcome": "refuse",
     "screen": _ATTACK_SCREEN, "expected": _REFUSE,
     "blurb": ("It really is your change and the script pays your key, but the derivation "
               "entry claims a stranger's fingerprint. Any wrong ownership claim is refused.")},
    {"kind": "contradiction_taproot_claims_other", "script_type": "P2TR", "family": "Taproot",
     "label": "Taproot change claims a stranger", "outcome": "refuse",
     "screen": _ATTACK_SCREEN, "expected": _REFUSE,
     "blurb": ("The taproot version of the above: the output pays your internal key, but "
               "the entry claims a stranger's fingerprint.")},
    {"kind": "contradiction_multisig", "script_type": "P2WSH", "family": "Multisig (2-of-3)",
     "label": "Fake change to a foreign multisig", "outcome": "refuse",
     "screen": _ATTACK_SCREEN, "expected": _REFUSE,
     "blurb": ("It is labeled as change back to this seed, but it pays an attacker's "
               "2-of-3 that holds none of your keys, so the funds really leave.")},
    {"kind": "contradiction_multisig_unclaimed", "script_type": "P2WSH", "family": "Multisig (2-of-3)",
     "label": "Change hidden behind relabeled fingerprints", "outcome": "refuse",
     "screen": _ATTACK_SCREEN, "expected": _REFUSE,
     "blurb": ("It really is your own change output, but every derivation fingerprint is "
               "relabeled to a stranger's, hiding that it belongs to you.")},
    {"kind": "contradiction_multisig_decoy_first", "script_type": "P2WSH", "family": "Multisig (2-of-3)",
     "label": "Decoy key listed first", "outcome": "refuse",
     "screen": _ATTACK_SCREEN, "expected": _REFUSE,
     "blurb": ("A genuine multisig change output, plus a decoy entry, a key you own that "
               "is not in the script, listed first. The recorded key is not in the "
               "committed script.")},
    {"kind": "contradiction_multisig_bad_script", "script_type": "P2WSH", "family": "Multisig (2-of-3)",
     "label": "Supplied script is not the committed one", "outcome": "refuse",
     "screen": _ATTACK_SCREEN, "expected": _REFUSE,
     "blurb": ("Only the scriptPubKey is repointed at a stranger's 2-of-3; the supplied "
               "witness script and every entry are kept, so the script no longer hashes "
               "to what the output commits to.")},

    # --- refusals: malformed derivation bookkeeping ("Transaction Problem") ---
    {"kind": "surplus_singlesig", "script_type": "P2WPKH", "family": "Native SegWit",
     "label": "Surplus derivation paths (single-key)", "outcome": "refuse",
     "screen": _PROBLEM_SCREEN, "expected": _MALFORMED,
     "blurb": ("It is a valid change output back to this seed, but it lists two "
               "derivation paths for a single-key script.")},
    {"kind": "surplus_multisig", "script_type": "P2WSH", "family": "Multisig (2-of-3)",
     "label": "Surplus derivation paths (multisig)", "outcome": "refuse",
     "screen": _PROBLEM_SCREEN, "expected": _MALFORMED,
     "blurb": ("It is a valid 2-of-3 change output, but it lists four derivation paths "
               "for a script that has only three keys.")},
    {"kind": "surplus_taproot", "script_type": "P2TR", "family": "Taproot",
     "label": "Surplus internal keys (taproot)", "outcome": "refuse",
     "screen": _PROBLEM_SCREEN, "expected": _MALFORMED,
     "blurb": ("It is a valid taproot change output, but it claims two internal keys "
               "where there can be only one.")},
    {"kind": "mixed_types", "script_type": "P2WPKH", "family": "Native SegWit",
     "label": "Mixed derivation path types", "outcome": "refuse",
     "screen": _PROBLEM_SCREEN, "expected": _MALFORMED,
     "blurb": ("It is a valid change output, but its scope lists derivation paths in "
               "both the ecdsa and taproot maps, which no script type can use.")},

    # --- aborts to the generic error screen ----------------------------------
    {"kind": "unsupported_script_type", "script_type": "P2WPKH", "family": "bare p2pk",
     "label": "Unsupported script type", "outcome": "error",
     "screen": _ERROR_SCREEN, "expected": _ERROR,
     "blurb": ("The inputs and change use bare pay-to-pubkey, which the device does not "
               "support. It aborts rather than guess. No dedicated screen for this yet.")},

    # --- accepted, output correctly shown as a spend -------------------------
    {"kind": "multisig_external_spend", "script_type": "P2WSH", "family": "Multisig (2-of-3)",
     "label": "Payment to another multisig", "outcome": "spend",
     "screen": _SPEND_RESULT, "expected": _SPEND,
     "blurb": ("An honest payment to a different multisig, fully annotated with that "
               "wallet's own keys. None are yours, so it is a plain external spend.")},
    {"kind": "multisig_change_no_paths", "script_type": "P2WSH", "family": "Multisig (2-of-3)",
     "label": "Change with no derivation paths", "outcome": "spend",
     "screen": _SPEND_RESULT, "expected": _SPEND,
     "blurb": ("Your real multisig change, with the derivation entries omitted (BIP-174 "
               "allows it). With no path to derive, the device cannot see your key in "
               "the script, so it over-reports the output as leaving.")},
    {"kind": "multisig_change_no_script", "script_type": "P2WSH", "family": "Multisig (2-of-3)",
     "label": "Change with no script", "outcome": "spend",
     "screen": _SPEND_RESULT, "expected": _SPEND,
     "blurb": ("Your real multisig change, with the witness script omitted. With no "
               "script there is no m-of-n to match, so the output is shown as a spend.")},
    {"kind": "taproot_scripttree_internal", "script_type": "P2TR", "family": "Taproot",
     "label": "Taproot change with a script tree", "outcome": "spend",
     "screen": _SPEND_RESULT, "expected": _SPEND,
     "blurb": ("Taproot change you own through the key path, but the address commits to a "
               "script tree the device does not yet parse, so it cannot confirm the "
               "output and shows it as a spend.")},
    {"kind": "taproot_scripttree_leaf", "script_type": "P2TR", "family": "Taproot",
     "label": "Taproot script-path change", "outcome": "spend",
     "screen": _SPEND_RESULT, "expected": _SPEND,
     "blurb": ("A script-path-only taproot address whose leaf holds your key. Same "
               "limitation: the tree is unparsed, so the output is shown as a spend.")},
    {"kind": "diff_quorum_xpubs", "script_type": "P2WSH", "family": "Multisig (2-of-3)",
     "label": "Different quorum, global xpubs", "outcome": "spend",
     "screen": _SPEND_RESULT, "expected": _SPEND,
     "blurb": ("The output pays a 2-of-3 that holds your key but swaps one cosigner for "
               "an outsider. With the wallet's global xpubs present, the mismatch is "
               "caught and the output is shown as a spend.")},
    {"kind": "diff_quorum_outsider_xpub", "script_type": "P2WSH", "family": "Multisig (2-of-3)",
     "label": "Different quorum, outsider xpub supplied", "outcome": "spend",
     "screen": _SPEND_RESULT, "expected": _SPEND,
     "blurb": ("The same different-quorum output, with the outsider's xpub also in the "
               "global xpubs. Every key resolves, but the cosigner set still differs, so "
               "it is shown as a spend.")},

    # --- accepted, shown as change (documented limitation) -------------------
    {"kind": "diff_quorum_no_xpubs", "script_type": "P2WSH", "family": "Multisig (2-of-3)",
     "label": "Different quorum, no global xpubs", "outcome": "change",
     "screen": _CHANGE_RESULT, "expected": _CHANGE,
     "blurb": ("The same different-quorum output, but with no global xpubs. Without them "
               "the device cannot compare cosigners, so the matching shape lets it be "
               "shown as your change though it pays a different wallet. Load the "
               "descriptor to catch it.")},
]


# PR #1044: the PR's own test matrix, a decoy entry (a key this seed owns that is
# not in the output's script) in each placement, plus the stranger-padding case
# that still lands on the surplus count. Decoy-first and stranger-padding are
# unchanged from #1032 and reuse its builders; the blurbs lead with what a #1032
# build does so a tester can tell the two apart.
_PR1044_DEFS = [
    {"kind": "contradiction_multisig_decoy_first", "script_type": "P2WSH", "family": "Multisig (2-of-3)",
     "label": "Decoy key listed first", "outcome": "refuse",
     "screen": _ATTACK_SCREEN, "expected": _REFUSE,
     "blurb": ("A genuine multisig change output, plus a decoy entry (a key you own that "
               "is not in the script) listed ahead of your real one. Already refused by "
               "#1032; unchanged here.")},
    {"kind": "decoy_last", "script_type": "P2WSH", "family": "Multisig (2-of-3)",
     "label": "Decoy key listed last", "outcome": "refuse",
     "screen": _ATTACK_SCREEN, "expected": _REFUSE,
     "blurb": ("The same decoy listed after your real entry. A #1032 build stops at the "
               "first verified entry and only the surplus count objects, a plain "
               "\"Transaction Problem\". Now every claim is held to the script and the "
               "decoy is refused as an attack.")},
    {"kind": "decoy_substituted", "script_type": "P2WSH", "family": "Multisig (2-of-3)",
     "label": "Decoy key in a cosigner's place", "outcome": "refuse",
     "screen": _ATTACK_SCREEN, "expected": _REFUSE,
     "blurb": ("The decoy replaces another cosigner's entry, so the output lists exactly "
               "three entries for three keys and the surplus count has nothing to say. A "
               "#1032 build shows this as change with no warning at all.")},
    {"kind": "surplus_multisig", "script_type": "P2WSH", "family": "Multisig (2-of-3)",
     "label": "Padded with a stranger's entry", "outcome": "refuse",
     "screen": _PROBLEM_SCREEN, "expected": _MALFORMED,
     "blurb": ("A genuine change output plus one extra entry claiming a stranger's "
               "fingerprint. Nothing of yours is misdescribed, so this still lands on "
               "the surplus count, unchanged from #1032.")},
]

# PR #1040: the two fingerprint records for one key must agree. The check needs
# the global xpubs to have anything to compare, so these builders add the
# wallet's; one leaves them out on purpose to show the limitation.
_PR1040_DEFS = [
    {"kind": "cosigner_mismatch", "script_type": "P2WSH", "family": "Multisig (2-of-3)",
     "label": "Cosigner fingerprint disagrees with its xpub", "outcome": "refuse",
     "screen": _PROBLEM_SCREEN, "expected": _MALFORMED,
     "blurb": ("Honest change, global xpubs present, but one cosigner's entry on the "
               "change output names a different fingerprint than that cosigner's xpub. "
               "The key and path are right, so only the consistency check objects. "
               "Earlier builds ignore the mislabel and show change.")},
    {"kind": "cosigner_mismatch_input", "script_type": "P2WSH", "family": "Multisig (2-of-3)",
     "label": "Cosigner fingerprint disagrees on an input", "outcome": "refuse",
     "screen": _PROBLEM_SCREEN, "expected": _MALFORMED,
     "blurb": ("The same mislabel on an input entry instead of the change output. The "
               "check walks inputs and outputs alike.")},
    {"kind": "singlesig_xpub_mismatch", "script_type": "P2WPKH", "family": "Native SegWit",
     "label": "Global xpub fingerprint disagrees with its keys", "outcome": "refuse",
     "screen": _PROBLEM_SCREEN, "expected": _MALFORMED,
     "blurb": ("Honest single-sig change with the wallet's global xpub added, then the "
               "xpub's fingerprint mislabeled. Every key entry is correct and claims "
               "your seed; only the xpub record disagrees.")},
    {"kind": "mismatch_beneath_contradiction", "script_type": "P2WSH", "family": "Multisig (2-of-3)",
     "label": "Mismatch beneath a fake change", "outcome": "refuse",
     "screen": _ATTACK_SCREEN, "expected": _REFUSE,
     "blurb": ("The #1032 fake change (the output pays an attacker's 2-of-3 while "
               "claiming your key) with a cosigner mislabel on an input as well. The "
               "fingerprint check runs last, so the device must report the attack, "
               "not the mismatch.")},
    {"kind": "cosigner_missing", "script_type": "P2WSH", "family": "Multisig (2-of-3)",
     "label": "Cosigner fingerprint is all zeros", "outcome": "change",
     "screen": _CHANGE_OK_RESULT, "expected": _CHANGE_OK,
     "blurb": ("The same cosigner entry with the all-zero fingerprint a coordinator "
               "writes for a key it cannot identify. A missing value is not a second "
               "answer, so it is skipped and the output is correctly counted as change.")},
    {"kind": "cosigner_mismatch_no_xpubs", "script_type": "P2WSH", "family": "Multisig (2-of-3)",
     "label": "Mismatch with no global xpubs", "outcome": "change",
     "screen": _CHANGE_RESULT, "expected": _CHANGE_NO_XPUBS,
     "blurb": ("The mislabeled cosigner entry, but the psbt carries no global xpubs. "
               "With no second record there is nothing to compare, so the mislabel "
               "goes unnoticed and the output is shown as change.")},
]

# PR #995: the fee a device that trusts the forged amount displays, and the fee
# the transaction really pays. The lie replaces one input's honest IN_VALUE with
# PR995_CLAIMED_INPUT_VALUE while the previous transaction it ships really pays
# PR995_REAL_INPUT_VALUE. Derived, never hardcoded, so the two cannot drift.
_PR995_OUTPUT_TOTAL = DEFAULT_NUM_INPUTS * IN_VALUE - FEE
_PR995_SHOWN_INPUT_TOTAL = PR995_CLAIMED_INPUT_VALUE + (DEFAULT_NUM_INPUTS - 1) * IN_VALUE
_PR995_REAL_INPUT_TOTAL = PR995_REAL_INPUT_VALUE + (DEFAULT_NUM_INPUTS - 1) * IN_VALUE
_PR995_SHOWN_FEE = _PR995_SHOWN_INPUT_TOTAL - _PR995_OUTPUT_TOTAL
_PR995_REAL_FEE = _PR995_REAL_INPUT_TOTAL - _PR995_OUTPUT_TOTAL

_PR995_FEE_LIE_BLURB = (
    f"The previous transaction is genuine and really pays {PR995_REAL_INPUT_VALUE:,} "
    f"sats for input 0, but a witness_utxo slipped in alongside it claims only "
    f"{PR995_CLAIMED_INPUT_VALUE:,}. A device that trusts the claim shows a "
    f"{_PR995_SHOWN_FEE:,}-sat fee while the transaction actually pays "
    f"{_PR995_REAL_FEE:,} sats to the miner. The cross-check refuses the disagreement.")

_PR995_NO_PREV_TX_BLURB = (
    "Every input carries a witness_utxo and no previous transaction at all, so the "
    "amounts are the coordinator's word and nothing more. A legacy sighash commits no "
    f"amount, so the signature is still valid and the difference burns as miner fee. "
    f"The device would show a plausible {FEE:,}-sat fee for it.")

_PR995_TAMPERED_BLURB = (
    "Input 0's previous transaction has its amount edited, so it no longer hashes to "
    "the txid the outpoint claims to spend. Before the check nothing hashed it at all, "
    "and the edited value was summed straight into the fee.")

# The site's "What's in this transaction?" table reads the psbt's own fields, so
# for these vectors it shows the claim, not the proven value. Spell out where
# the claim and the truth part ways.
_PR995_FEE_LIE_NOTE = (
    "This table repeats the psbt's own claim, exactly what a trusting device would "
    f"display: input 0 counts as {PR995_CLAIMED_INPUT_VALUE:,} sats. The previous "
    f"transaction it ships really pays {PR995_REAL_INPUT_VALUE:,}, so the transaction "
    f"actually pays {_PR995_REAL_FEE:,} sats to the miner.")

_PR995_NO_PREV_TX_NOTE = (
    "This table repeats the psbt's own claim. There is no previous transaction in the "
    "psbt to prove any input amount, so what the inputs are really worth is not knowable "
    "from the file.")

_PR995_TAMPERED_NOTE = (
    "This table repeats the psbt's own claim: input 0 counts the edited previous "
    "transaction's amount. The edit changed its txid, so the previous transaction no "
    "longer matches the outpoint it claims to spend, and neither its amount nor the "
    "displayed fee can be trusted.")

_PR995_DEFS = [
    {"kind": "legacy_fee_lie", "script_type": "P2PKH", "family": "Legacy",
     "label": "Forged input amount (single-sig)", "outcome": "refuse",
     "screen": _ATTACK_SCREEN, "expected": _UNVERIFIED,
     "blurb": _PR995_FEE_LIE_BLURB, "summary_note": _PR995_FEE_LIE_NOTE},
    {"kind": "legacy_fee_lie_multisig", "script_type": "P2SH", "family": "Legacy multisig (2-of-3)",
     "label": "Forged input amount (multisig)", "outcome": "refuse",
     "screen": _ATTACK_SCREEN, "expected": _UNVERIFIED,
     "blurb": _PR995_FEE_LIE_BLURB, "summary_note": _PR995_FEE_LIE_NOTE},
    {"kind": "legacy_no_prev_tx", "script_type": "P2PKH", "family": "Legacy",
     "label": "No previous transaction (single-sig)", "outcome": "refuse",
     "screen": _ATTACK_SCREEN, "expected": _UNVERIFIED,
     "blurb": _PR995_NO_PREV_TX_BLURB, "summary_note": _PR995_NO_PREV_TX_NOTE},
    {"kind": "legacy_no_prev_tx_multisig", "script_type": "P2SH", "family": "Legacy multisig (2-of-3)",
     "label": "No previous transaction (multisig)", "outcome": "refuse",
     "screen": _ATTACK_SCREEN, "expected": _UNVERIFIED,
     "blurb": _PR995_NO_PREV_TX_BLURB, "summary_note": _PR995_NO_PREV_TX_NOTE},
    {"kind": "legacy_prev_tx_tampered", "script_type": "P2PKH", "family": "Legacy",
     "label": "Previous transaction doesn't match (single-sig)", "outcome": "refuse",
     "screen": _ATTACK_SCREEN, "expected": _UNVERIFIED,
     "blurb": _PR995_TAMPERED_BLURB, "summary_note": _PR995_TAMPERED_NOTE},
]


def _make_pr_test(pr, d):
    info = script_types.get(d["script_type"])
    base_wallet = WALLET_FOR_SCRIPT_TYPE[d["script_type"]]
    slug = d["kind"].replace("_", "-")
    return Scenario(
        id=f"test-{pr}-{slug}", wallet=base_wallet, script_type=d["script_type"],
        num_inputs=DEFAULT_NUM_INPUTS, output_shape="change", network="main",
        title=f"{_ICON[d['outcome']]} {d['label']} ({d['family']})",
        blurb=d["blurb"], is_default=False,
        tags=["test", d["label"], info.label],
        pr=pr, attack=d["kind"], load_seed=TEST_VICTIM_SEED,
        expected=d["expected"], expected_screen=d["screen"], outcome=d["outcome"],
        summary_note=d.get("summary_note"),
    )


def test_scenarios() -> list:
    """Adversarial / malformed transactions for exercising the hardening PRs on device."""
    out = []
    # PR #1013: both forgeries across the three families, plus one wrong-seed case
    # (not script-type-sensitive, so native segwit stands in for it).
    for attack in ("fake_change", "bad_input"):
        for script_type, family in TEST_SCRIPT_FAMILIES:
            out.append(_make_test(attack, script_type, family))
    out.append(_make_test("wrong_seed", "P2WPKH", "Native SegWit"))
    # PR #1032: output-ownership contradictions and malformed derivation data.
    out.extend(_make_pr_test("1032", d) for d in _PR1032_DEFS)
    # PR #1044: a decoy claim of ours in every placement on a multisig output.
    out.extend(_make_pr_test("1044", d) for d in _PR1044_DEFS)
    # PR #1040: the two fingerprint records for a key must agree.
    out.extend(_make_pr_test("1040", d) for d in _PR1040_DEFS)
    # PR #995: prove each input's amount before any of them is summed.
    out.extend(_make_pr_test("995", d) for d in _PR995_DEFS)
    return out
