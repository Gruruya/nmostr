[
: Copyright © 2023 Gruruya <gruruya.chi4c@slmails.com>
: SPDX-License-Identifier: CC-BY-SA-4.0
]:#

# 0.1.2 - Unreleased

# 0.1.1 - September 28, 2023

#### Breaking
* Remove custom `toStackString`, nim-stack-strings [added their own function](https://github.com/termermc/nim-stack-strings/commit/2dfaa69bab56dd3fd6517461cfffd536e0423baf) with the same purpose.

#### Fix
* Fix `fromBytes(T: typedesc[NNote])` accidently accepting a `seq[byte]` address instead of `openArray[byte]`.
* Correct using `rangeCheck` for bounds checks, use `assert` instead.

#### Maintenance
* Bump dependencies' versions.
* Split single tests file into multiple files.

# 0.1.0 - September 13, 2023

#### Objects refactor

* Replace the [nim-secp256k1/secp256k1](https://github.com/status-im/nim-secp256k1/blob/master/secp256k1.nim) wrapper with our own.  
  Previously, nmostr wrapped the keys from that module in container types to hide the `{.requiresInit.}` pragma, working around initialization [in jsony](https://github.com/treeform/jsony/blob/1de1f0815e4ed6bfc36be4c96a59041e4620ebe2/src/jsony.nim#L388) when parsing objects as JSON.
* Refactor public keys, event IDs, and schnorr signatures to store their hex in their objects as [stack strings](https://github.com/termermc/nim-stack-strings).

#### Add
* [REUSE](https://reuse.software/) compliance and a workflow to track it.

# 0.0.15 - September 11, 2023

#### Adapt for [changes to NIP-01](https://github.com/nostr-protocol/nips/commit/72bb8a128b2d7d3c2c654644cd68d0d0fe58a3b1)
* Remove `recommendedServer`.
* `filter.matches` only checks for exact public key/event ID matches instead of matching prefixes.

#### Breaking
* Raise a `ValueError` when parsing an invalid hex, such as from an uninitialized event serialized to JSON.
* Re-order `init(T: Event)` to be consistent with `note` and other similar procs.

#### Fix
* Fix `hrpExpand` bug when encoding bech32 caused by incorrect use of `newSeqOfCap`.
* Fix Event.init's default `created_at` containing nanoseconds.
* Rewrite `filters.matches`.

#### Add
* Add `getParameterizedID` function to get the first `d` value of an event.

#### Maintenance
* Bump [union](https://github.com/alaviss/union) dependency version.
