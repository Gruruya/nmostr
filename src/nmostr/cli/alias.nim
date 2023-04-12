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
#
# This file incorporates work covered by the following copyright and permission notices:
#
#    MIT License
#
#    Copyright © 2020 Status Research & Development GmbH
#
#    Permission is hereby granted, free of charge, to any person obtaining a copy
#    of this software and associated documentation files (the "Software"), to deal
#    in the Software without restriction, including without limitation the rights
#    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#    copies of the Software, and to permit persons to whom the Software is
#    furnished to do so, subject to the following conditions:
#
#    The above copyright notice and this permission notice shall be included in all
#    copies or substantial portions of the Software.
#
#    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
#    SOFTWARE.

## Generate a deterministic friendly name for a public key
## Modified from `nim-status/status/private/alias.nim`

import
  std/bitops,
  pkg/[secp256k1, stew/endians2],
  ./wordpool

# For details: https://en.wikipedia.org/wiki/Linear-feedback_shift_register
type
  AliasError* = enum
    FormatAliasError        = "alias: error formatting alias given " &
                                "adjectives and animal"
    ValidatePublicKeyError  = "alias: error validating public key"

  AliasResult*[T] = Result[T, AliasError]

  Lsfr = ref object
    poly*: uint64
    data*: uint64

proc next(self: Lsfr): uint64 {.raises: [].} =
  var bit: uint64 = 0
  for i in 0..64:
    if bitand(self.poly, 1.uint64 shl i) != 0:
      bit = bitxor(bit, self.data shr i)
  bit = bitand(bit, 1.uint64)
  self.data = bitor(self.data shl 1, bit)
  result = self.data

func truncPubKey(pubkey: SkPublicKey | SkXOnlyPublicKey): uint64 =
  let rawKey = pubkey.toRaw
  fromBytesBE(uint64, rawKey[25..32])

func truncPubKey(pubkey: SkXOnlyPublicKey): uint64 =
  let rawKey = pubkey.toRaw
  fromBytesBE(uint64, rawKey[24..31])

func generateAlias*(pubkey: SkPublicKey | SkXOnlyPublicKey): string =
  ## generateAlias returns a 3-words generated name given a public key.
  ## We ignore any error, empty string result is considered an error.
  let seed = truncPubkey(pubkey)
  const poly: uint64 = 0xB8
  let
    generator = Lsfr(poly: poly, data: seed)
    adjective1 = adjectives[generator.next mod adjectives.len]
    adjective2 = adjectives[generator.next mod adjectives.len]
    animal = animals[generator.next mod animals.len]
  adjective1 & adjective2 & animal
