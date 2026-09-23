"""Adversarial and malformed PSBTs that exercise SeedSigner's ownership scan.

These reproduce the three conditions SeedSigner PR #1013 ("scan seed ownership")
was written to catch. Each one is a structurally valid PSBT, a coordinator or an
attacker really could hand it to a signer, whose *derivation metadata lies*. The
device only finds out by re-deriving keys from the loaded seed and comparing the
actual key material, which is exactly what the PR added.

    fake_change  A change output carries a derivation entry naming THIS seed's
                 fingerprint on a key the seed cannot derive. Single-sig and
                 taproot also repoint the scriptPubKey at the attacker, so the
                 funds leave; multisig keeps the wallet's real change script, so
                 the funds return and only the ownership claim is false. Either
                 way -> PSBTOutputOwnershipClaimError -> "Likely an Attack!"

    bad_input    An input does the same false claim. It gains an attacker nothing
                 (embit refuses to sign it either), so it reads as malformed data
                 rather than an attack. -> PSBTInputOwnershipClaimError ->
                 "Transaction Problem".

    wrong_seed   A perfectly valid PSBT that the loaded seed simply has no key in.
                 The PSBT itself is honest, the mismatch is the operator loading
                 the wrong seed. -> PSBTSeedCannotSignError -> "Seed Can't Sign".
                 There is nothing to forge here: the generator ships an ordinary
                 PSBT and the *scenario* pairs it with a decoy seed (see
                 common/scenarios.py). This module only covers the two forgeries.

The forgery is always the same shape: find the derivation entry that claims the
victim seed's fingerprint and swap its key for one the seed does not own, leaving
the fingerprint and the derivation path untouched. That is the entire trick the
ownership scan defeats, the fingerprint is metadata the file's author chose, so
it can say anything, and only re-derivation settles ownership.

Throwaway keys only; none of this is signable into a broadcastable transaction.
"""
import hashlib

from embit import bip32, script
from embit.networks import NETWORKS
from embit.psbt import DerivationPath
from embit.transaction import TransactionOutput

from common import script_types
from common.psbt import (build_psbt, _path_ints, CHANGE_BRANCH, RECEIVE_BRANCH)

# A key nobody in the fixtures owns. Deterministic so builds are reproducible;
# domain-separated so it can never collide with a real fixture seed.
_ATTACKER_ENTROPY = hashlib.sha256(b"btc-datagen-attacker-not-your-key").digest()


def _attacker_pubkey(network: str, branch: int, index: int):
    """An embit PublicKey the fixture seeds provably do not derive."""
    root = bip32.HDKey.from_seed(_ATTACKER_ENTROPY, version=NETWORKS[network]["xprv"])
    return root.derive([branch, index]).to_public().key


def _forged_path(victim, branch: int, index: int) -> list:
    """The derivation path the lie claims: the victim's own account path plus
    branch/index, so it looks exactly like a key this wallet would own."""
    return _path_ints(victim.derivation) + [branch, index]


def _forge_scope_claim(scope, forged_fp: bytes, forged_path: list,
                       attacker_key, is_taproot: bool):
    """Replace whatever entry in `scope` claims `forged_fp` with a lie: the same
    fingerprint and path, but the attacker's key. Single-sig scopes carry exactly
    one entry; a multisig scope carries one per cosigner, and only the victim's is
    rewritten so the others still verify."""
    if is_taproot:
        for pk, (_leaves, dp) in list(scope.taproot_bip32_derivations.items()):
            if dp.fingerprint == forged_fp:
                del scope.taproot_bip32_derivations[pk]
        scope.taproot_bip32_derivations[attacker_key] = (
            [], DerivationPath(forged_fp, forged_path))
        scope.taproot_internal_key = attacker_key
    else:
        for pk, dp in list(scope.bip32_derivations.items()):
            if dp.fingerprint == forged_fp:
                del scope.bip32_derivations[pk]
        scope.bip32_derivations[attacker_key] = DerivationPath(forged_fp, forged_path)


def _change_output_index(psbt) -> int:
    for i, out in enumerate(psbt.outputs):
        if out.bip32_derivations:
            _, dp = next(iter(out.bip32_derivations.items()))
            if dp.derivation[-2] == CHANGE_BRANCH:
                return i
        if out.taproot_bip32_derivations:
            _, (_, dp) = next(iter(out.taproot_bip32_derivations.items()))
            if dp.derivation[-2] == CHANGE_BRANCH:
                return i
    raise ValueError("no change output to forge; build with output_shape='change'")


def forge_fake_change(signers: list, script_type: str, network: str = "main",
                      num_inputs: int = 3, threshold: int = None):
    """Fake-change attack: dress an attacker's output as this wallet's change.

    Single-sig: the whole change output is replaced, its scriptPubKey pays the
    attacker and its lone derivation entry carries the victim's fingerprint, so a
    naive signer shows the amount as change while it is really leaving. Multisig:
    the p2wsh change script is left intact (so the summary still reads as a change
    address) and only the victim cosigner's derivation entry is swapped, which is
    all the ownership scan needs to reject it.
    """
    info = script_types.get(script_type)
    psbt = build_psbt(signers, script_type, num_inputs, "change", threshold=threshold)
    victim = signers[0]
    forged_fp = bytes.fromhex(victim.fingerprint)
    forged_path = _forged_path(victim, CHANGE_BRANCH, 0)

    idx = _change_output_index(psbt)
    out = psbt.outputs[idx]
    attacker_key = _attacker_pubkey(network, CHANGE_BRANCH, 0)

    # The committed scriptPubKey lives on the output scope; embit's psbt.tx is a
    # property that reassembles the tx from the scopes, so a psbt.tx.vout edit is
    # discarded. The ownership scan keys on the derivation entry either way, but
    # repointing the real scriptPubKey is what makes the funds actually leave.
    if info.is_multisig:
        # Deliberately NOT symmetric with the single-key branches below: keep the
        # wallet's real p2wsh change script and poison only our derivation entry.
        # The funds still come home to the real 2-of-3; what is false is the claim
        # about which key in that script is ours. Isolating the false claim from
        # any fund movement is the whole point of this vector, and it is the case
        # 0.8.7 misses entirely (its descriptor.owns() check tests the script, not
        # the claimed derivation path). Do not "fix" this to repoint the script.
        _forge_scope_claim(out, forged_fp, forged_path, attacker_key, is_taproot=False)
    elif script_type == "P2TR":
        _forge_scope_claim(out, forged_fp, forged_path, attacker_key, is_taproot=True)
        out.script_pubkey = script.p2tr(attacker_key)
    else:
        # P2WPKH / P2SH-P2WPKH / P2PKH: attacker gets a plain p2wpkh output.
        _forge_scope_claim(out, forged_fp, forged_path, attacker_key, is_taproot=False)
        out.script_pubkey = script.p2wpkh(attacker_key)

    return psbt


def forge_bad_input(signers: list, script_type: str, network: str = "main",
                    num_inputs: int = 3, threshold: int = None):
    """Malformed input ownership: the first input claims the victim's fingerprint
    on a key the seed does not derive. The scriptPubKey (in witness_utxo) is left
    as the wallet's real input so nothing upstream chokes; only the derivation
    lies. Outputs are honest, so the scan clears them and rejects on the input."""
    info = script_types.get(script_type)
    psbt = build_psbt(signers, script_type, num_inputs, "change", threshold=threshold)
    victim = signers[0]
    forged_fp = bytes.fromhex(victim.fingerprint)
    forged_path = _forged_path(victim, RECEIVE_BRANCH, 0)

    inp = psbt.inputs[0]
    attacker_key = _attacker_pubkey(network, RECEIVE_BRANCH, 0)
    _forge_scope_claim(inp, forged_fp, forged_path, attacker_key,
                       is_taproot=(script_type == "P2TR"))
    return psbt


def build_attack_psbt(kind: str, signers: list, script_type: str,
                      network: str = "main", num_inputs: int = 3,
                      threshold: int = None):
    if kind == "fake_change":
        return forge_fake_change(signers, script_type, network, num_inputs, threshold)
    if kind == "bad_input":
        return forge_bad_input(signers, script_type, network, num_inputs, threshold)
    raise ValueError(f"unknown attack kind: {kind!r}")


# --- D5 / PR #1032: "verify that change outputs actually pay this seed" -------
#
# Stage C (#1013, above) re-derives every derivation entry that claims our
# fingerprint and rejects a key that does not derive from the seed. It does not
# check that the output's committed scriptPubKey actually pays that key, nor that
# the derivation-path bookkeeping is well formed. D5 closes both gaps: an output
# counts as change only when the script rebuilt from the seed matches the
# scriptPubKey the output commits to, and a psbt whose claims contradict that (or
# whose derivation entries are malformed) is refused. The three refusals map to
# three device screens:
#
#   PSBTOutputOwnershipContradictionError -> PSBTOutputOwnershipContradictionView
#       The psbt's account of who an output pays contradicts the key(s) the output
#       actually commits to. Either it claims our seed on an output that pays
#       someone else, or it pays our seed while claiming someone else (or nobody).
#
#   PSBTSurplusDerivationPathsError -> PSBTSurplusDerivationPathsView
#       An output lists more derivation entries than its script can use: two paths
#       on a single-key output, two internal-key claims on a taproot output, or
#       more paths than a multisig script has keys.
#
#   PSBTMixedDerivationPathTypesError -> PSBTMixedDerivationPathTypesView
#       One scope declares entries in both the ecdsa and the taproot derivation
#       maps; no script type can use both.
#
# These build on a genuine change output from common.psbt and then edit only the
# change output, so the inputs stay honestly this seed's (the signability gate
# passes) and the refusal comes from the output alone. Throwaway keys only.


def _victim_key(victim, branch: int, index: int):
    """The victim seed's own public key at branch/index (a key it really owns)."""
    return victim.account.derive([branch, index]).key


def _attacker_root(network: str):
    return bip32.HDKey.from_seed(_ATTACKER_ENTROPY, version=NETWORKS[network]["xprv"])


def _attacker_fingerprint(network: str) -> bytes:
    """A master fingerprint that is real (a genuine key's) but not any fixture's."""
    return _attacker_root(network).my_fingerprint


def _attacker_multisig_keys(network: str, n: int) -> list:
    """n sorted public keys the fixture seeds do not own."""
    keys = [_attacker_pubkey(network, CHANGE_BRANCH, 100 + i) for i in range(n)]
    keys.sort(key=lambda k: k.sec())
    return keys


def _attacker_multisig_script(network: str, m: int, n: int):
    """An m-of-n sortedmulti script whose keys the fixture seeds do not own."""
    return script.multisig(m, _attacker_multisig_keys(network, n))


def _d5_contradiction_singlesig(signers, network, num_inputs):
    """Claims this seed truthfully, then pays someone else (single-sig).

    The change output keeps its honest derivation entry (our key, our fingerprint,
    our change path), so C's ownership scan is satisfied. Only the scriptPubKey is
    repointed at an attacker key, so the script rebuilt from the seed no longer
    matches what the output commits to -> contradiction.
    """
    psbt = build_psbt(signers, "P2WPKH", num_inputs, "change")
    idx = _change_output_index(psbt)
    attacker_key = _attacker_pubkey(network, CHANGE_BRANCH, 0)
    # The committed scriptPubKey lives on the output scope; embit's psbt.tx is a
    # property that reassembles the tx from these, so a psbt.tx.vout edit is lost.
    psbt.outputs[idx].script_pubkey = script.p2wpkh(attacker_key)
    return psbt


def _d5_contradiction_multisig(signers, network, num_inputs, threshold):
    """Claims this seed, but the committed multisig holds no key of ours.

    The output commits to an attacker's m-of-n (hashed correctly, same shape as
    the wallet), while a single derivation entry annotates it with our fingerprint
    at a path we really own. C passes (the claimed key derives from us); D5 finds
    our key is not in the committed script -> contradiction. This is the headline
    multisig fake-change the PR closes.
    """
    m, n = threshold, len(signers)
    psbt = build_psbt(signers, "P2WSH", num_inputs, "change", threshold=threshold)
    victim = signers[0]
    idx = _change_output_index(psbt)
    out = psbt.outputs[idx]

    attacker_script = _attacker_multisig_script(network, m, n)
    # scriptPubKey lives on the output scope (embit's psbt.tx is a rebuilt copy).
    out.script_pubkey = script.p2wsh(attacker_script)
    out.witness_script = attacker_script
    out.redeem_script = None
    out.bip32_derivations.clear()
    out.bip32_derivations[_victim_key(victim, CHANGE_BRANCH, 0)] = DerivationPath(
        bytes.fromhex(victim.fingerprint), _forged_path(victim, CHANGE_BRANCH, 0))
    return psbt


def _d5_contradiction_multisig_unclaimed(signers, network, num_inputs, threshold):
    """Pays a multisig this seed is in, but hides it behind foreign fingerprints.

    The committed script is the wallet's real change script (our key is in it), but
    every derivation entry is relabelled with a foreign fingerprint, so nothing
    claims our seed. Before D5 that one-field edit dropped the output out of every
    check; D5 derives at each supplied path, finds our key in the committed script,
    and refuses the concealment -> contradiction.
    """
    psbt = build_psbt(signers, "P2WSH", num_inputs, "change", threshold=threshold)
    idx = _change_output_index(psbt)
    out = psbt.outputs[idx]
    forged_fp = _attacker_fingerprint(network)
    for pk in list(out.bip32_derivations):
        dp = out.bip32_derivations[pk]
        out.bip32_derivations[pk] = DerivationPath(forged_fp, dp.derivation)
    return psbt


def _d5_surplus_singlesig(signers, network, num_inputs):
    """A single-key output that lists two derivation paths.

    Both entries are honest keys of ours (so C passes), which is enough to trip the
    single-key surplus check: one script, one key, cannot own two paths.
    """
    psbt = build_psbt(signers, "P2WPKH", num_inputs, "change")
    victim = signers[0]
    idx = _change_output_index(psbt)
    out = psbt.outputs[idx]
    out.bip32_derivations[_victim_key(victim, RECEIVE_BRANCH, 0)] = DerivationPath(
        bytes.fromhex(victim.fingerprint), _forged_path(victim, RECEIVE_BRANCH, 0))
    return psbt


def _d5_surplus_multisig(signers, network, num_inputs, threshold):
    """A multisig change output that lists more paths than its script has keys.

    The real change output is confirmed ours, then one extra derivation entry (a
    foreign fingerprint, so C skips it and the real entry stays the verified one)
    pushes the entry count past n -> surplus.
    """
    psbt = build_psbt(signers, "P2WSH", num_inputs, "change", threshold=threshold)
    victim = signers[0]
    idx = _change_output_index(psbt)
    out = psbt.outputs[idx]
    out.bip32_derivations[_attacker_pubkey(network, RECEIVE_BRANCH, 7)] = DerivationPath(
        _attacker_fingerprint(network), _forged_path(victim, RECEIVE_BRANCH, 7))
    return psbt


def _d5_surplus_taproot(signers, network, num_inputs):
    """A taproot output claiming two internal keys.

    A taproot output has exactly one internal key. A second internal-key entry
    (empty leaf hashes), again an honest key of ours so C passes, trips the taproot
    surplus check.
    """
    psbt = build_psbt(signers, "P2TR", num_inputs, "change")
    victim = signers[0]
    idx = _change_output_index(psbt)
    out = psbt.outputs[idx]
    out.taproot_bip32_derivations[_victim_key(victim, RECEIVE_BRANCH, 0)] = (
        [], DerivationPath(bytes.fromhex(victim.fingerprint),
                           _forged_path(victim, RECEIVE_BRANCH, 0)))
    return psbt


def _d5_mixed_types(signers, network, num_inputs):
    """One output scope declaring both an ecdsa and a taproot derivation entry.

    The p2wpkh change keeps its ecdsa entry; a taproot entry (foreign fingerprint,
    so the scan skips ownership and reaches the structural refusal) is added
    alongside it. No script type can use both maps -> mixed-types refusal.
    """
    psbt = build_psbt(signers, "P2WPKH", num_inputs, "change")
    idx = _change_output_index(psbt)
    out = psbt.outputs[idx]
    out.taproot_bip32_derivations[_attacker_pubkey(network, RECEIVE_BRANCH, 3)] = (
        [], DerivationPath(_attacker_fingerprint(network),
                           _forged_path(signers[0], RECEIVE_BRANCH, 3)))
    return psbt


# --- PR #1032 full parity: the rest of the parser's output scenarios ---------
#
# The builders above cover the core deceptions. These cover every remaining parse
# scenario the PR's test suite exercises: the other contradiction shapes, the
# structural refusals, and the cases the parser accepts but classifies as a spend
# (or, for one documented limitation, as change). The "spend"/"change" ones raise
# no error; a tester judges them by whether the review screen shows the output as
# change or as a payment out. Multisig cases use native segwit (p2wsh) as the
# single representative, matching the site's curated set.

from binascii import unhexlify

from embit.ec import PublicKey
from embit.hashes import tagged_hash

from common.keys import make_cosigner

# BIP-341's provably unspendable internal key (the "NUMS" point), for a taproot
# address that can only be spent through its script tree.
_NUMS_INTERNAL_KEY = PublicKey.from_xonly(unhexlify(
    "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"))

# A fixture seed that is NOT a cosigner of the multisig test wallet, for the
# different-quorum cases.
_OUTSIDER_SEED = "dave"


def _p2pk(public_key) -> "script.Script":
    """A bare pay-to-pubkey script. embit reports its type as None (unsupported)."""
    return script.Script(b"\x21" + public_key.sec() + b"\xac")


def _tapleaf_hash(public_key) -> bytes:
    """BIP-341 leaf hash of a lone-key checksig tapscript (embit's own form)."""
    leaf_script = script.Script(b"\x20" + public_key.xonly() + b"\xac")
    return tagged_hash("TapLeaf", bytes([0xC0]) + leaf_script.serialize())


def _p2tr_with_script_tree(internal_key, merkle_root: bytes):
    """The scriptPubKey of a taproot output whose internal key is tweaked by a
    script tree's merkle root. embit's script.p2tr cannot build this form."""
    return script.Script(b"\x51\x20" + internal_key.taproot_tweak(merkle_root).xonly())


def _outsider_cosigner(network: str, derivation: str):
    """Cosigner built from a fixture seed that is not in the multisig test wallet,
    at the wallet's own account path, for the different-quorum scenarios."""
    from common.fixtures import load_seeds
    mnemonic = load_seeds()[_OUTSIDER_SEED]["mnemonic"]
    return make_cosigner(_OUTSIDER_SEED, mnemonic, derivation, network)


def _add_wallet_xpubs(psbt, cosigners):
    """Add each cosigner's account xpub to the psbt's global xpubs, the way a
    coordinator that writes PSBT_GLOBAL_XPUB does."""
    for c in cosigners:
        psbt.xpubs[c.account] = DerivationPath(
            bytes.fromhex(c.fingerprint), _path_ints(c.derivation))


def _repoint_at_different_quorum(psbt, signers, network):
    """Rebuild the change output so one cosigner is swapped for an outsider. The
    output pays a 2-of-3 that still holds this seed's key but is a different wallet
    from the inputs, honestly annotated. Returns the outsider Cosigner."""
    idx = _change_output_index(psbt)
    out = psbt.outputs[idx]
    victim = signers[0]
    victim_fp = bytes.fromhex(victim.fingerprint)
    outsider = _outsider_cosigner(network, victim.derivation)

    # Displace the first cosigner that isn't this seed.
    displaced = next(c for c in signers if c.fingerprint != victim.fingerprint)
    displaced_key = displaced.account.derive([CHANGE_BRANCH, 0]).key
    outsider_key = outsider.account.derive([CHANGE_BRANCH, 0]).key

    m, n, pubkeys = _parse_multisig_keys(out.witness_script)
    new_keys = [outsider_key if pk.sec() == displaced_key.sec() else pk for pk in pubkeys]
    rebuilt = script.multisig(m, new_keys)
    out.witness_script = rebuilt
    out.script_pubkey = script.p2wsh(rebuilt)

    # Describe the rebuilt script truthfully: swap the displaced entry for the
    # outsider's, leave this seed's and the remaining cosigner's entries alone.
    for pk, dp in list(out.bip32_derivations.items()):
        if pk.sec() == displaced_key.sec():
            del out.bip32_derivations[pk]
    out.bip32_derivations[outsider_key] = DerivationPath(
        bytes.fromhex(outsider.fingerprint),
        _path_ints(outsider.derivation) + [CHANGE_BRANCH, 0])
    return outsider


def _parse_multisig_keys(multisig_script):
    """(m, n, pubkeys) from a sortedmulti script, matching the device parser."""
    from io import BytesIO
    from embit import ec
    data = multisig_script.data
    m = data[0] - 0x50
    n = data[-2] - 0x50
    s = BytesIO(data)
    s.read(1)
    pubkeys = []
    for _ in range(n):
        s.read(1)
        pubkeys.append(ec.PublicKey.parse(s.read(33)))
    return m, n, pubkeys


# --- additional contradiction refusals ---------------------------------------

def _d5_contradiction_pays_us_claims_other(signers, network, num_inputs):
    """Pays this seed, but the entry claims a stranger's fingerprint (single-sig).

    The scriptPubKey and derivation path are the real change; only the fingerprint
    is swapped for a foreign one. The rebuild matches, but nothing claims our
    fingerprint, so the parser refuses the contradiction.
    """
    psbt = build_psbt(signers, "P2WPKH", num_inputs, "change")
    idx = _change_output_index(psbt)
    out = psbt.outputs[idx]
    forged_fp = _attacker_fingerprint(network)
    for pk, dp in list(out.bip32_derivations.items()):
        out.bip32_derivations[pk] = DerivationPath(forged_fp, dp.derivation)
    return psbt


def _d5_contradiction_taproot_claims_other(signers, network, num_inputs):
    """The taproot mirror of the above: real change, foreign fingerprint."""
    psbt = build_psbt(signers, "P2TR", num_inputs, "change")
    idx = _change_output_index(psbt)
    out = psbt.outputs[idx]
    forged_fp = _attacker_fingerprint(network)
    for pk, (leaves, dp) in list(out.taproot_bip32_derivations.items()):
        out.taproot_bip32_derivations[pk] = (leaves, DerivationPath(forged_fp, dp.derivation))
    return psbt


def _d5_contradiction_multisig_decoy_first(signers, network, num_inputs, threshold):
    """A genuine multisig change output plus a decoy entry, listed FIRST.

    The decoy is another key this seed owns but which is not in the output's
    script. Because it is listed first, the scan records it as the verified path,
    and the participation check then finds that key is not in the committed script:
    a contradiction. (Listed last instead, it trips the surplus check; that variant
    is surplus_multisig.)
    """
    psbt = build_psbt(signers, "P2WSH", num_inputs, "change", threshold=threshold)
    victim = signers[0]
    idx = _change_output_index(psbt)
    out = psbt.outputs[idx]
    decoy_key = _victim_key(victim, RECEIVE_BRANCH, 0)
    decoy = DerivationPath(bytes.fromhex(victim.fingerprint),
                           _forged_path(victim, RECEIVE_BRANCH, 0))
    # Rebuild the dict with the decoy first, then the genuine entries.
    genuine = list(out.bip32_derivations.items())
    out.bip32_derivations.clear()
    out.bip32_derivations[decoy_key] = decoy
    for pk, dp in genuine:
        out.bip32_derivations[pk] = dp
    return psbt


def _d5_contradiction_multisig_bad_script(signers, network, num_inputs, threshold):
    """The supplied witness_script is not the one the output commits to.

    Only the scriptPubKey is repointed at a stranger's 2-of-3; the wallet's real
    witness_script and every derivation entry are kept. Every check passes until
    the supplied script is hashed and fails to match the committed scriptPubKey.
    """
    m, n = threshold, len(signers)
    psbt = build_psbt(signers, "P2WSH", num_inputs, "change", threshold=threshold)
    idx = _change_output_index(psbt)
    out = psbt.outputs[idx]
    out.script_pubkey = script.p2wsh(_attacker_multisig_script(network, m, n))
    return psbt


def _d5_unsupported_script_type(signers, network, num_inputs):
    """Inputs and change output both use bare p2pk, which embit types as None.

    The output's None policy shape matches the inputs', so it reaches the parser's
    catch-all for unhandled script types, which aborts with a RuntimeError.
    """
    psbt = build_psbt(signers, "P2WPKH", num_inputs, "change")
    victim = signers[0]
    idx = _change_output_index(psbt)
    # Repoint every input's committed script and the change output at p2pk.
    for i, inp in enumerate(psbt.inputs):
        inp.witness_utxo.script_pubkey = _p2pk(_victim_key(victim, RECEIVE_BRANCH, i))
    psbt.outputs[idx].script_pubkey = _p2pk(_victim_key(victim, CHANGE_BRANCH, 0))
    return psbt


# --- accepted, classified as a spend (or, for one, as change) ----------------

def _d5_multisig_external_spend(signers, network, num_inputs, threshold):
    """An honest payment to a different multisig, fully annotated with that
    wallet's own keys. No entry claims this seed, so it is a plain external spend
    (a check that annotated foreign outputs are not mistaken for change)."""
    m, n = threshold, len(signers)
    psbt = build_psbt(signers, "P2WSH", num_inputs, "change", threshold=threshold)
    idx = _change_output_index(psbt)
    out = psbt.outputs[idx]
    keys = _attacker_multisig_keys(network, n)
    out.witness_script = script.multisig(m, keys)
    out.script_pubkey = script.p2wsh(out.witness_script)
    out.redeem_script = None
    out.bip32_derivations.clear()
    forged_fp = _attacker_fingerprint(network)
    for i, pk in enumerate(keys):
        out.bip32_derivations[pk] = DerivationPath(
            forged_fp, _forged_path(signers[0], CHANGE_BRANCH, 100 + i))
    return psbt


def _d5_multisig_change_no_paths(signers, network, num_inputs, threshold):
    """Our real multisig change, with the derivation entries omitted (BIP-174
    allows it). With no path to derive from, the parser cannot see our key in the
    script, so it over-reports the output as a spend."""
    psbt = build_psbt(signers, "P2WSH", num_inputs, "change", threshold=threshold)
    out = psbt.outputs[_change_output_index(psbt)]
    out.bip32_derivations.clear()
    return psbt


def _d5_multisig_change_no_script(signers, network, num_inputs, threshold):
    """Our real multisig change, with the witness_script omitted. With no script
    there is no m-of-n to match the inputs, so the output never becomes a change
    candidate and is counted as a spend."""
    psbt = build_psbt(signers, "P2WSH", num_inputs, "change", threshold=threshold)
    psbt.outputs[_change_output_index(psbt)].witness_script = None
    return psbt


def _d5_taproot_scripttree_internal(signers, network, num_inputs):
    """Taproot change we own through the key path, but the address commits to our
    internal key tweaked by a script tree. embit does not parse the tree, so the
    key-path rebuild cannot match and the output is reported as a spend (taproot is
    exempt from the contradiction check for exactly this reason)."""
    psbt = build_psbt(signers, "P2TR", num_inputs, "change")
    victim = signers[0]
    idx = _change_output_index(psbt)
    out = psbt.outputs[idx]
    internal_key = _victim_key(victim, CHANGE_BRANCH, 0)
    leaf_key = _victim_key(victim, RECEIVE_BRANCH, 7)
    merkle_root = _tapleaf_hash(leaf_key)
    out.script_pubkey = _p2tr_with_script_tree(internal_key, merkle_root)
    # Add the leaf key's entry alongside the existing internal-key entry.
    out.taproot_bip32_derivations[leaf_key] = (
        [merkle_root], DerivationPath(bytes.fromhex(victim.fingerprint),
                                      _forged_path(victim, RECEIVE_BRANCH, 7)))
    return psbt


def _d5_taproot_scripttree_leaf(signers, network, num_inputs):
    """A script-path-only taproot address (NUMS internal key) whose one leaf holds
    a key this seed owns. Same limitation: the tree is unparsed, so the output is
    reported as a spend."""
    psbt = build_psbt(signers, "P2TR", num_inputs, "change")
    victim = signers[0]
    idx = _change_output_index(psbt)
    out = psbt.outputs[idx]
    leaf_key = _victim_key(victim, RECEIVE_BRANCH, 7)
    merkle_root = _tapleaf_hash(leaf_key)
    out.script_pubkey = _p2tr_with_script_tree(_NUMS_INTERNAL_KEY, merkle_root)
    out.taproot_bip32_derivations.clear()
    out.taproot_internal_key = None
    out.taproot_bip32_derivations[leaf_key] = (
        [merkle_root], DerivationPath(bytes.fromhex(victim.fingerprint),
                                      _forged_path(victim, RECEIVE_BRANCH, 7)))
    return psbt


def _d5_diff_quorum_xpubs(signers, network, num_inputs, threshold):
    """Output pays a 2-of-3 that holds our key but swaps one cosigner for an
    outsider. With the inputs' global xpubs present, the outsider's key fails to
    resolve, so the output's cosigners differ from the inputs' and it is a spend."""
    psbt = build_psbt(signers, "P2WSH", num_inputs, "change", threshold=threshold)
    _repoint_at_different_quorum(psbt, signers, network)
    _add_wallet_xpubs(psbt, signers)
    return psbt


def _d5_diff_quorum_outsider_xpub(signers, network, num_inputs, threshold):
    """Same different-quorum output, but the outsider's account xpub is also in the
    global xpubs. Now every key resolves, but the output's cosigner set differs
    from the inputs', so it is still a spend."""
    psbt = build_psbt(signers, "P2WSH", num_inputs, "change", threshold=threshold)
    outsider = _repoint_at_different_quorum(psbt, signers, network)
    _add_wallet_xpubs(psbt, signers)
    _add_wallet_xpubs(psbt, [outsider])
    return psbt


def _d5_diff_quorum_no_xpubs(signers, network, num_inputs, threshold):
    """The documented limitation: same different-quorum output, but no global
    xpubs. Without them the cosigner lists cannot be compared, so the output's
    matching shape lets it be presumed change though it is a different wallet."""
    psbt = build_psbt(signers, "P2WSH", num_inputs, "change", threshold=threshold)
    _repoint_at_different_quorum(psbt, signers, network)
    psbt.xpubs.clear()
    return psbt


# --- PR #1044: hold every claim of ours on a multisig output to its script -----
#
# #1032 verified only the FIRST entry claiming our seed on a multisig output.
# A decoy (a key our seed really derives, but which the committed script has no
# use for) listed after our genuine entry was caught only by the surplus count,
# and one substituted for another cosigner's entry (keeping the count at n) was
# not caught at all. #1044 keeps every verified entry and holds each one to the
# script, so a decoy in any position is PSBTOutputOwnershipContradictionError.
# The decoy-first and stranger-padding cases are unchanged from #1032 and reuse
# its builders; only the two builders below are new.


def _decoy_entry(victim):
    """A key this seed owns (its first receive key) that is not in the change
    script, annotated truthfully: our fingerprint, a path we really derive."""
    return (_victim_key(victim, RECEIVE_BRANCH, 0),
            DerivationPath(bytes.fromhex(victim.fingerprint),
                           _forged_path(victim, RECEIVE_BRANCH, 0)))


def _pr1044_decoy_last(signers, network, num_inputs, threshold):
    """A genuine multisig change output plus a decoy entry, listed LAST.

    Our real entry is verified first and its key is in the script; the decoy
    behind it is also ours but not in the script. #1032 stopped at the first
    verified entry and only the surplus count (four entries, three keys) objected,
    a plain "Transaction Problem". #1044 holds the decoy to the script too, and
    refuses it as a contradiction.
    """
    psbt = build_psbt(signers, "P2WSH", num_inputs, "change", threshold=threshold)
    out = psbt.outputs[_change_output_index(psbt)]
    decoy_key, decoy = _decoy_entry(signers[0])
    out.bip32_derivations[decoy_key] = decoy
    return psbt


def _pr1044_decoy_substituted(signers, network, num_inputs, threshold):
    """A genuine multisig change output with a decoy entry in place of another
    cosigner's, so the output still lists exactly n entries.

    Our real entry verifies and is in the script; the entry count matches the
    script's key count, so the surplus check has nothing to say. Only holding
    every verified entry to the script exposes the decoy. On a #1032 build this
    output parses silently as change; on #1044 it is a contradiction.
    """
    psbt = build_psbt(signers, "P2WSH", num_inputs, "change", threshold=threshold)
    out = psbt.outputs[_change_output_index(psbt)]
    victim_fp = bytes.fromhex(signers[0].fingerprint)
    for pk, dp in list(out.bip32_derivations.items()):
        if dp.fingerprint != victim_fp:
            del out.bip32_derivations[pk]
            break
    decoy_key, decoy = _decoy_entry(signers[0])
    out.bip32_derivations[decoy_key] = decoy
    return psbt


# --- PR #995: prove each input's amount before displaying the fee ------------
#
# fee = inputs - outputs, so a coordinator that lies about an input's amount can
# make the device display any fee it likes. Legacy inputs are the worst case:
# their signatures commit to no amount at all, so the lie survives signing and
# the difference is handed to the miner in a single session. #995's
# _verify_input_amounts() closes three deceptions:
#
#   PSBTInputAmountVerificationError -> PSBTInputAmountVerificationFailedView
#       A non_witness_utxo is the whole previous transaction, so it is hashed
#       against the outpoint it claims to spend; a legacy (or unrecognized)
#       input must supply one, because its sighash commits no amount; and a
#       witness_utxo sitting alongside a proven non_witness_utxo must agree
#       with it, because embit's InputScope.utxo and PSBT.fee() prefer the
#       witness_utxo and would otherwise display the unproven value.
#
# The fixtures' legacy inputs carry non_witness_utxo only (common/psbt.py), so
# each forgery adds or edits exactly the field a coordinator controls. Throwaway
# keys only; nothing here is broadcastable.

# The lie's two amounts: the previous transaction really pays the first, while
# the witness_utxo claims the second. The gap is what burns as miner fee.
PR995_REAL_INPUT_VALUE = 5_000_000
PR995_CLAIMED_INPUT_VALUE = 100_000


def _pr995_relink_prevout(psbt, idx: int, real_value: int):
    """Revalue input idx's funding transaction and point the outpoint at the
    result, so a genuine (hash-valid) previous transaction really pays
    `real_value` while the input still claims the builder's 100,000."""
    inp = psbt.inputs[idx]
    prev = inp.non_witness_utxo
    prev.vout[0].value = real_value
    inp.txid = prev.txid()


def _pr995_fee_lie(signers, script_type: str, num_inputs: int, threshold=None):
    psbt = build_psbt(signers, script_type, num_inputs, "change", threshold=threshold)
    _pr995_relink_prevout(psbt, 0, PR995_REAL_INPUT_VALUE)
    spk = psbt.inputs[0].non_witness_utxo.vout[0].script_pubkey
    psbt.inputs[0].witness_utxo = TransactionOutput(PR995_CLAIMED_INPUT_VALUE, spk)
    return psbt


def _pr995_fee_lie_p2pkh(signers, network, num_inputs):
    """A genuine previous transaction paired with a lying witness_utxo.

    The non_witness_utxo really is the transaction the outpoint spends, so
    embit's verify() passes; but embit's PSBT.fee() prefers the witness_utxo,
    so the device would display the claim. Here the previous transaction pays
    5,000,000 sats while the witness_utxo claims 100,000: a device that trusts
    the claim shows a 10,000-sat fee on a transaction that really pays 4,910,000
    sats to the miner. The cross-check refuses the disagreement.
    """
    return _pr995_fee_lie(signers, "P2PKH", num_inputs)


def _pr995_fee_lie_p2sh(signers, network, num_inputs, threshold):
    """The 2-of-3 legacy multisig version of the lying witness_utxo."""
    return _pr995_fee_lie(signers, "P2SH", num_inputs, threshold)


def _pr995_no_prev_tx(signers, script_type: str, num_inputs: int, threshold=None):
    """Every input carries a witness_utxo and no non_witness_utxo at all: the
    amounts rest on the coordinator's word alone, yet the legacy sighash still
    yields a valid signature over them, so the difference burns as miner fee."""
    psbt = build_psbt(signers, script_type, num_inputs, "change", threshold=threshold)
    for inp in psbt.inputs:
        prevout = inp.non_witness_utxo.vout[0]
        inp.witness_utxo = TransactionOutput(prevout.value, prevout.script_pubkey)
        inp.non_witness_utxo = None
    return psbt


def _pr995_no_prev_tx_p2pkh(signers, network, num_inputs):
    return _pr995_no_prev_tx(signers, "P2PKH", num_inputs)


def _pr995_no_prev_tx_p2sh(signers, network, num_inputs, threshold):
    return _pr995_no_prev_tx(signers, "P2SH", num_inputs, threshold)


def _pr995_prev_tx_tampered(signers, network, num_inputs):
    """The previous transaction's amount is edited, so it no longer hashes to
    the txid the outpoint claims to spend. Before #995 nothing hashed it at all
    and the edited value was summed straight into the fee."""
    psbt = build_psbt(signers, "P2PKH", num_inputs, "change")
    psbt.inputs[0].non_witness_utxo.vout[0].value += 100_000
    return psbt


# --- PR #1040: reject a psbt whose fingerprint records disagree --------------
#
# A psbt makes two claims about where a key comes from: the fingerprint on the
# key's own derivation entry, and the fingerprint on the global xpub that derives
# that key. Both are the coordinator's claims about the same master key, so they
# should agree. #1040 walks every input and output entry, finds the global xpub
# that derives its key, and raises PSBTInconsistentFingerprintError when the two
# fingerprints differ. All-zero fingerprints on either side are skipped (that is
# how a coordinator writes a fingerprint it does not know), and the check runs
# LAST so a more serious finding about our own keys is still the one reported.
#
# build_psbt writes no global xpubs, so every builder here adds the wallet's
# (the check has nothing to compare without them; one builder leaves them out
# on purpose to show exactly that).

_MISSING_FINGERPRINT = b"\x00\x00\x00\x00"


def _relabel_first_cosigner(scope, victim_fp: bytes, fingerprint: bytes):
    """Rewrite the fingerprint on the first entry in `scope` that is not this
    seed's, leaving its key and derivation path alone."""
    for pk, dp in scope.bip32_derivations.items():
        if dp.fingerprint != victim_fp:
            scope.bip32_derivations[pk] = DerivationPath(fingerprint, dp.derivation)
            return
    raise ValueError("scope has no cosigner entry besides this seed's")


def _pr1040_cosigner_mismatch(signers, network, num_inputs, threshold):
    """Honest multisig change, global xpubs present, but one cosigner's entry on
    the change output carries a fingerprint that disagrees with that cosigner's
    xpub. The key and path are right, so every ownership check passes, and only
    the consistency check has anything to report."""
    psbt = build_psbt(signers, "P2WSH", num_inputs, "change", threshold=threshold)
    _add_wallet_xpubs(psbt, signers)
    out = psbt.outputs[_change_output_index(psbt)]
    _relabel_first_cosigner(out, bytes.fromhex(signers[0].fingerprint),
                            _attacker_fingerprint(network))
    return psbt


def _pr1040_cosigner_mismatch_input(signers, network, num_inputs, threshold):
    """The same mislabel on an input entry instead of the change output; the
    check walks both."""
    psbt = build_psbt(signers, "P2WSH", num_inputs, "change", threshold=threshold)
    _add_wallet_xpubs(psbt, signers)
    _relabel_first_cosigner(psbt.inputs[0], bytes.fromhex(signers[0].fingerprint),
                            _attacker_fingerprint(network))
    return psbt


def _pr1040_cosigner_missing(signers, network, num_inputs, threshold):
    """The same cosigner entry, but with the all-zero fingerprint a coordinator
    writes for a key it cannot identify. That is a missing value, not a second
    answer, so the check skips it and the output is still counted as change."""
    psbt = build_psbt(signers, "P2WSH", num_inputs, "change", threshold=threshold)
    _add_wallet_xpubs(psbt, signers)
    out = psbt.outputs[_change_output_index(psbt)]
    _relabel_first_cosigner(out, bytes.fromhex(signers[0].fingerprint),
                            _MISSING_FINGERPRINT)
    return psbt


def _pr1040_cosigner_mismatch_no_xpubs(signers, network, num_inputs, threshold):
    """The mislabeled cosigner entry with NO global xpubs. There is no second
    record to compare against, so the check cannot run and the output is counted
    as change: the limitation, not a bug."""
    psbt = build_psbt(signers, "P2WSH", num_inputs, "change", threshold=threshold)
    out = psbt.outputs[_change_output_index(psbt)]
    _relabel_first_cosigner(out, bytes.fromhex(signers[0].fingerprint),
                            _attacker_fingerprint(network))
    return psbt


def _pr1040_singlesig_xpub_mismatch(signers, network, num_inputs):
    """Honest single-sig change with the wallet's one global xpub added, then the
    xpub's fingerprint mislabeled. Every key entry is correct (they claim our
    seed and derive from it), so only the xpub record disagrees."""
    psbt = build_psbt(signers, "P2WPKH", num_inputs, "change")
    _add_wallet_xpubs(psbt, signers)
    xpub, dp = next(iter(psbt.xpubs.items()))
    psbt.xpubs[xpub] = DerivationPath(_attacker_fingerprint(network), dp.derivation)
    return psbt


def _pr1040_mismatch_beneath_contradiction(signers, network, num_inputs, threshold):
    """The #1032 multisig fake change (the change output pays an attacker's 2-of-3
    while claiming our key) with a cosigner mislabel on an input as well. The
    fingerprint check runs last, so the device must report the contradiction,
    not the mismatch."""
    psbt = _d5_contradiction_multisig(signers, network, num_inputs, threshold)
    _add_wallet_xpubs(psbt, signers)
    _relabel_first_cosigner(psbt.inputs[0], bytes.fromhex(signers[0].fingerprint),
                            _attacker_fingerprint(network))
    return psbt


_TEST_BUILDERS = {
    "contradiction_singlesig": _d5_contradiction_singlesig,
    "contradiction_pays_us_claims_other": _d5_contradiction_pays_us_claims_other,
    "contradiction_taproot_claims_other": _d5_contradiction_taproot_claims_other,
    "contradiction_multisig": _d5_contradiction_multisig,
    "contradiction_multisig_unclaimed": _d5_contradiction_multisig_unclaimed,
    "contradiction_multisig_decoy_first": _d5_contradiction_multisig_decoy_first,
    "contradiction_multisig_bad_script": _d5_contradiction_multisig_bad_script,
    "surplus_singlesig": _d5_surplus_singlesig,
    "surplus_multisig": _d5_surplus_multisig,
    "surplus_taproot": _d5_surplus_taproot,
    "mixed_types": _d5_mixed_types,
    "unsupported_script_type": _d5_unsupported_script_type,
    "multisig_external_spend": _d5_multisig_external_spend,
    "multisig_change_no_paths": _d5_multisig_change_no_paths,
    "multisig_change_no_script": _d5_multisig_change_no_script,
    "taproot_scripttree_internal": _d5_taproot_scripttree_internal,
    "taproot_scripttree_leaf": _d5_taproot_scripttree_leaf,
    "diff_quorum_xpubs": _d5_diff_quorum_xpubs,
    "diff_quorum_outsider_xpub": _d5_diff_quorum_outsider_xpub,
    "diff_quorum_no_xpubs": _d5_diff_quorum_no_xpubs,
    "decoy_last": _pr1044_decoy_last,
    "decoy_substituted": _pr1044_decoy_substituted,
    "cosigner_mismatch": _pr1040_cosigner_mismatch,
    "cosigner_mismatch_input": _pr1040_cosigner_mismatch_input,
    "cosigner_missing": _pr1040_cosigner_missing,
    "cosigner_mismatch_no_xpubs": _pr1040_cosigner_mismatch_no_xpubs,
    "singlesig_xpub_mismatch": _pr1040_singlesig_xpub_mismatch,
    "mismatch_beneath_contradiction": _pr1040_mismatch_beneath_contradiction,
    "legacy_fee_lie": _pr995_fee_lie_p2pkh,
    "legacy_fee_lie_multisig": _pr995_fee_lie_p2sh,
    "legacy_no_prev_tx": _pr995_no_prev_tx_p2pkh,
    "legacy_no_prev_tx_multisig": _pr995_no_prev_tx_p2sh,
    "legacy_prev_tx_tampered": _pr995_prev_tx_tampered,
}

# Kinds that need the wallet threshold passed through (multisig builders).
_MULTISIG_KINDS = {"contradiction_multisig", "contradiction_multisig_unclaimed",
                   "contradiction_multisig_decoy_first", "contradiction_multisig_bad_script",
                   "surplus_multisig", "multisig_external_spend",
                   "multisig_change_no_paths", "multisig_change_no_script",
                   "diff_quorum_xpubs", "diff_quorum_outsider_xpub",
                   "diff_quorum_no_xpubs",
                   "decoy_last", "decoy_substituted",
                   "cosigner_mismatch", "cosigner_mismatch_input", "cosigner_missing",
                   "cosigner_mismatch_no_xpubs", "mismatch_beneath_contradiction",
                   "legacy_fee_lie_multisig", "legacy_no_prev_tx_multisig"}


def build_test_psbt(kind: str, signers: list, script_type: str,
                    network: str = "main", num_inputs: int = 3, threshold: int = None):
    """The PSBT for one test scenario, by its `attack` kind. Covers every PR:
    #1013's two forgeries and its honest wrong-seed psbt, then the per-output
    builders for #1032, #1044, and #1040, and #995's legacy input-amount lies."""
    if kind in ("fake_change", "bad_input"):
        return build_attack_psbt(kind, signers, script_type, network, num_inputs, threshold)
    if kind == "wrong_seed":
        return build_psbt(signers, script_type, num_inputs, "change", threshold=threshold)
    builder = _TEST_BUILDERS.get(kind)
    if builder is None:
        raise ValueError(f"unknown test kind: {kind!r}")
    if kind in _MULTISIG_KINDS:
        return builder(signers, network, num_inputs, threshold)
    return builder(signers, network, num_inputs)
