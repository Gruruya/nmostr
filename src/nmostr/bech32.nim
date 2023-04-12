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
#    Copyright © 2017, 2020 Pieter Wuille
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

## Modified from Pieter Wuille's reference Python implementation `sipa/bech32/python/segwit_addr.py`
## Nostr-style Bech32 addresses use no witness version or m-encoding.

{.push raises: [].}

import std/[sequtils, strutils], pkg/secp256k1
from sugar import `=>`
from tables import toTable, `[]`

type InvalidBech32Error = object of ValueError

template error(why: string) =
  raise newException(InvalidBech32Error, why)
  
const CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
const CHARSET_MAP = CHARSET.map(c => (c, CHARSET.find(c))).toTable()

# proc bech32VerifyChecksum(hrp: string, data: openArray[int]): bool =
#   bech32Polymod(bech32HrpExpand(hrp) & @data) == 1
  
proc bech32Decode(bech: sink string): tuple[hrp: string, data: seq[int]] {.raises: [InvalidBech32Error].} =
  bech = bech.toLower()
  let pos = bech.rfind('1')
  if pos < 1 or pos + 7 > bech.len: # or len(bech) > 90:
    bech32.error("'1' not found in " & bech)
  result.hrp = bech[0..<pos]
  try:
    result.data = bech[pos + 1..^1].mapIt(CHARSET_MAP[it])
  except KeyError: error("Invalid character in bech32 hash " & bech)
  # if not bech32VerifyChecksum(result.hrp, result.data):
  #   bech32.error(bech & " has an invalid checksum")
  result.data.setLen(result.data.len - 6)

proc convertBits*(data: openArray[int], fromBits, toBits: static[int], pad = true): seq[int] {.raises: [InvalidBech32Error].} =
  var acc, bits = 0
  const maxV = (1 shl toBits) - 1
  # const maxAcc = (1 shl (fromBits + toBits - 1)) - 1
  result = newSeqOfCap[int](data.len)
  for value in data:
    # if acc < 0 or (acc shr fromBits) != 0:
    #   bech32.error("Bits must be positive " & $fromBits & " bit integers.")
    # acc = ((acc shl fromBits) or acc) and maxAcc
    acc = (acc shl fromBits) or value
    bits += fromBits
    while bits >= toBits:
      bits -= toBits
      result.add (acc shr bits) and maxV
  if pad and bits > 0:
    result.add (acc shl (toBits - bits)) and maxV
  else:
    if bits >= fromBits: bech32.error "Excess padding"
    if ((acc shl (toBits - bits)) and maxV) != 0: bech32.error "Non-zero padding"

template toWords*(bytes: openArray[int]): seq[int] =
  convertBits(bytes, 8, 5, true)

template fromWords*(words: openArray[int]): seq[int] =
  convertBits(words, 5, 8, false)

{.push inline.}
  
proc encode*(hrp: string, witprog: openArray[int]): string {.raises: [InvalidBech32Error].} =
  ## Encode into a bech32 address
  proc bech32Polymod(values: openArray[int]): int =
    const generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    result = 1
    for value in values:
      let top = result shr 25
      result = (result and 0x1ffffff) shl 5 xor value
      for i in 0 ..< 5:
        result = result xor (if (top shr i and 1) == 1: generator[i] else: 0)
  
  proc hrpExpand(hrp: string): seq[int] =
    result = newSeq[int](hrp.len * 2 + 1)
    for i, c in hrp:
      result[i] = ord(c) shr 5
      result[i + hrp.len + 1] = ord(c) and 31
  
  proc checksum(hrp: string, data: openArray[int]): seq[int] =
    let values = hrpExpand(hrp) & @data
    let polymod = bech32Polymod(values & @[0, 0, 0, 0, 0, 0]) xor 1
    result = newSeqOfCap[int](5)
    for i in 0 .. 5:
      result.add (polymod shr (5 * (5 - i))) and 31
  
  let data = toWords(witprog)
  let combined = data & checksum(hrp, data)
  result = hrp & '1' & combined.mapIt(CHARSET[it]).join("")

  # discard decode(hrp, result) # Verify

template encode*(hrp, witprog: string): string =
  encode(hrp, witprog.mapIt(ord(it)))
  
proc decode*(address: string): tuple[hrp: string, data: seq[int]] {.raises: [InvalidBech32Error].} =
  let (hrp, data) = bech32Decode(address)
  result = (hrp, fromWords(data))

proc decode*(hrp, address: string): seq[int] {.raises: [InvalidBech32Error].} =
  let (hrpGot, data) = bech32Decode(address)
  if hrpGot != hrp:
    bech32.error("Incorrect hrp " & hrpGot & " in bech32 address, expected " & hrp)
  result = fromWords(data)

proc bech32ToString*(bech32: seq[int]): string =
  bech32.mapIt(char(it)).join("")
  
template toString*(bech32: tuple[hrp: string, data: seq[int]]): string =
  bech32ToString bech32.data

proc toBech32*(pubkey: SkXOnlyPublicKey): string {.raises: [InvalidBech32Error].} =
  encode("npub", pubkey.toRaw.mapIt(ord(it)))

proc toBech32*(seckey: SkSecretKey): string {.raises: [InvalidBech32Error].} =
  encode("nsec", seckey.toRaw.mapIt(ord(it)))

proc fromBech32*(T: type SkXOnlyPublicKey, address: string): T {.raises: [InvalidBech32Error].} =
  let raw = decode("npub", address)
  let pubkey =
    if raw.len == 33:
      T.fromRaw(raw[0..^2].mapIt(byte(it)))
    elif raw.len == 32:
      T.fromRaw(raw.mapIt(byte(it)))
    else:
      bech32.error("bech32 encoded public key must be 33 or 32 bytes")
  if pubkey.isOk: pubkey.unsafeGet
  else: bech32.error($pubkey.error)
  
proc fromBech32*(T: type SkSecretKey, address: string): T {.raises: [InvalidBech32Error].} =
  let seckey = T.fromRaw(decode("nsec", address).mapIt(byte(it)))
  if seckey.isOk: seckey.unsafeGet
  else: bech32.error($seckey.error)

# Tests
# let hex = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d"
# let bech = "npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6"
# let pk = SkXOnlyPublicKey.fromHex(hex)[]
# echo pk.toBech32
# echo SkXOnlyPublicKey.fromBech32 pk.toBech32
# let sk = SkSecretKey.fromBech32 "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5"
# echo sk.toBech32
# assert encode("npub", pk.toRaw.mapIt(ord(it))) == bech
# assert SkXOnlyPublicKey.fromRaw(decode("npub", bech).mapIt(byte(it))[0..^2])[] == pk
# echo decode(encode("npub", "Hello".mapIt(ord(it)))).mapIt(char(it)).join()
#echo (SkXOnlyPublicKey.fromBech32 "npub1sn0wdenkukak0d9dfczzeacvhkrgz92ak56egt7vdgzn8pv2wfqqhrjdv9").toBech32
#echo decode("note", encode("note", "fntxtkcy9pjwucqwa9mddn7v03wwwsu9j330jj350nvhpky2tuaspk6nqc"))
# echo encode("note", decode("note", "note1fntxtkcy9pjwucqwa9mddn7v03wwwsu9j330jj350nvhpky2tuaspk6nqc"))
#                                   note1fntxtkcy9pjwucqwa9mddn7v03wwwsu9j330jj350nvhpky2tuasqtv84yn
# FIXME: Doesn't work (long bech32 hash) echo decode("nprofile", "nprofile1qqsrhuxx8l9ex335q7he0f09aej04zpazpl0ne2cgukyawd24mayt8gpp4mhxue69uhhytnc9e3k7mgpz4mhxue69uhkg6nzv9ejuumpv34kytnrdaksjlyr9p").mapIt(char(it)).join("")
# let p = decode("nprofile", "nprofile1qqsrhuxx8l9ex335q7he0f09aej04zpazpl0ne2cgukyawd24mayt8gpp4mhxue69uhhytnc9e3k7mgpz4mhxue69uhkg6nzv9ejuumpv34kytnrdaksjlyr9p").mapIt(char(it)).join("")
## should decode into a profile with the following TLV items:
## pubkey: 3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d
## relay: wss://r.x.com
## relay: wss://djbas.sadkb.com

proc nprofile*(address: seq[int]): string {.raises: [InvalidBech32Error].} =
  var i = 0
  while true:
    if i + 1 > address.len: break
    let (kind, length) = (address[i], address[i + 1])
    i += 2
    if i + length - 1 > address.len: error("End of value " & $(i + length - 1) & " exceeds bech32 address length " & $address.len & ".")
    let data = address[i..<i + length]
    i += length
    if kind == 0:
      let sk = SkXOnlyPublicKey.fromRaw(data.mapIt(byte(it)))
      echo sk
    elif kind == 1:
      let relay = data.mapIt(char(it)).join()
      echo relay
  # var i = 0
  # for x in address:
    
  #   if x == 0:
  #     # public key
  #     let a = SkPublicKey.fromRaw(address[i + 1..i + 33].mapIt(byte(it)))
  #     echo a
  #     i += 32
  #   inc(i)

# echo p[0..48]
# echo p[49..50]
# echo p[51..71]

# import std/unicode

# echo decode("npub1jk9h2jsa8hjmtm9qlcca942473gnyhuynz5rmgve0dlu6hpeazxqc3lqz7").data.mapIt(it.toHex(2))
# echo decode("nprofile1qqsrhuxx8l9ex335q7he0f09aej04zpazpl0ne2cgukyawd24mayt8gpp4mhxue69uhhytnc9e3k7mgpz4mhxue69uhkg6nzv9ejuumpv34kytnrdaksjlyr9p").toString
# echo "npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjptg".decode.data.len
# echo SkXOnlyPublicKey.fromBech32 "npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjptg"
# echo SkSecretKey.fromBech32 "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5"
# echo decode("nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5")
echo decode("nprofile1qqsrhuxx8l9ex335q7he0f09aej04zpazpl0ne2cgukyawd24mayt8gpp4mhxue69uhhytnc9e3k7mgpz4mhxue69uhkg6nzv9ejuumpv34kytnrdaksjlyr9p").data
echo nprofile(decode("nprofile1qqsrhuxx8l9ex335q7he0f09aej04zpazpl0ne2cgukyawd24mayt8gpp4mhxue69uhhytnc9e3k7mgpz4mhxue69uhkg6nzv9ejuumpv34kytnrdaksjlyr9p").data)

# echo "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459dwss://r.x.comwss://djbas.sadkb.com".len
