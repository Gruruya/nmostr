# nmostr --- Nim library for working with the Nostr protocol.
# Copyright © 2023 Gruruya <gruruya.chi4c@slmails.com>
#
# This file is part of nmostr.
#
# nmostr is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, version 3 of the License.
#
# nmostr is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with nmostr.  If not, see <http://www.gnu.org/licenses/>.

## Types from `secp256k1` without {.requiresInit.} so that they can be null without using `stew/results`

import pkg/secp256k1, pkg/secp256k1/abi
from pkg/stew/byteutils import toHex
export secp256k1 except default

{.push raises: [], inline.}

type
  SecretKey* = SkSecretKey

  PublicKey* = object
    ## Representation of public key that only reveals the x-coordinate.
    ## Modified from `secp256k1` to not have `{.requiresInit.}`
    data: secp256k1_xonly_pubkey

  SchnorrSignature* = object
    ## Representation of a Schnorr signature.
    ## Modified from `secp256k1` to not have `{.requiresInit.}`
    data: array[SkRawSchnorrSignatureSize, byte]

# Equivalent to `secp256k1` types minus {.requireInit.}, so allow casting for interop
converter toPublicKey*(pubkey: SkXOnlyPublicKey): PublicKey = cast[PublicKey](pubkey)
converter toSkXOnlyPublicKey*(pubkey: PublicKey): SkXOnlyPublicKey = cast[SkXOnlyPublicKey](pubkey)
converter toSchnorrSignature*(sig: SkSchnorrSignature): SchnorrSignature = cast[SchnorrSignature](sig)
converter toSkSchnorrSignature*(sig: SchnorrSignature): SkSchnorrSignature = cast[SkSchnorrSignature](sig)

func fromRaw*(T: type PublicKey, data: openArray[byte]): SkResult[T] =
  ## Additionally accepts 33 byte compressed public keys, should upstream this
  if likely data.len == 32: cast[SkResult[PublicKey]](SkXOnlyPublicKey.fromRaw(data))
  elif data.len == 33: cast[SkResult[PublicKey]](SkXOnlyPublicKey.fromRaw(data[1..^1]))
  else: err(static("secp: x-only public key must be 32 or 33 bytes"))

func fromHex*(T: type PublicKey, data: string): SkResult[T] =
  T.fromRaw(? seq[byte].fromHex(data))

func fromRaw*(T: type SchnorrSignature, data: openArray[byte]): SkResult[T] =
  cast[SkResult[SchnorrSignature]](SkSchnorrSignature.fromRaw(data))

func fromHex*(T: type SchnorrSignature, data: string): SkResult[T] =
  T.fromRaw(? seq[byte].fromHex(data))

func toRaw*(pubkey: PublicKey): array[SkRawXOnlyPublicKeySize, byte] =
  ## Wrapper that checks if `pubkey` is uninitialized
  if pubkey == default(PublicKey): return
  secp256k1.toRaw(pubkey)

func toHex*(pubkey: PublicKey): string =
  toHex(toRaw(pubkey))

func verify*(sig: SchnorrSignature, msg: SkMessage, pubkey: PublicKey): bool =
  ## Wrapper that checks if `pubkey` is uninitialized
  if pubkey == default(typeof pubkey): return false
  secp256k1.verify(sig, msg, pubkey)

func verify*(sig: SchnorrSignature, msg: openArray[byte], pubkey: PublicKey): bool =
  ## Wrapper that checks if `pubkey` is uninitialized
  if pubkey == default(typeof pubkey): return false
  secp256k1.verify(sig, msg, pubkey)
