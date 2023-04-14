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

## Modified from Pieter Wuille's reference Python implementation `sipa/bech32/python/segwit_addr.py`
## Nostr-style Bech32 addresses use no witness version or m-encoding.

import std/[sequtils, strutils]
import pkg/[secp256k1, union], pkg/stew/byteutils
from sugar import `=>`, `->`
from tables import toTable, `[]`
import ./events

type InvalidBech32Error = object of ValueError

template error(why: string) =
  raise newException(InvalidBech32Error, why)
  
const CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
const CHARSET_MAP = CHARSET.map(c => (c, CHARSET.find(c))).toTable()

# proc bech32VerifyChecksum(hrp: string, data: openArray[int]): bool =
#   bech32Polymod(bech32HrpExpand(hrp) & @data) == 1

func to*[T](list: openArray[T], conv: type): seq[conv] {.inline.} =
  list.mapIt(conv(it))

{.push raises: [InvalidBech32Error].}

func bech32Decode(bech: sink string): tuple[hrp: string, data: seq[int]] =
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

func convertBits*(data: openArray[int], fromBits, toBits: static[int], pad = true): seq[int] =
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

func encode*(hrp: string, witprog: openArray[int]): string =
  ## Encode into a bech32 address
  func bech32Polymod(values: openArray[int]): int {.raises: [].} =
    const generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    result = 1
    for value in values:
      let top = result shr 25
      result = (result and 0x1ffffff) shl 5 xor value
      for i in 0 ..< 5:
        result = result xor (if (top shr i and 1) == 1: generator[i] else: 0)
  
  func hrpExpand(hrp: string): seq[int] {.raises: [].} =
    result = newSeq[int](hrp.len * 2 + 1)
    for i, c in hrp:
      result[i] = ord(c) shr 5
      result[i + hrp.len + 1] = ord(c) and 31
  
  func checksum(hrp: string, data: openArray[int]): seq[int] {.raises: [].} =
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
  encode(hrp, witprog.to(ord))
  
func decode*(address: string): tuple[hrp: string, data: seq[int]] {.inline.} =
  let (hrp, data) = bech32Decode(address)
  result = (hrp, fromWords(data))

func decode*(hrp, address: string): seq[int] {.inline, raises: [InvalidBech32Error].} =
  let (hrpGot, data) = bech32Decode(address)
  if hrpGot != hrp:
    bech32.error("Incorrect hrp " & hrpGot & " in bech32 address, expected " & hrp)
  result = fromWords(data)

func charsToString*[T](chars: seq[T]): string {.inline, raises: [].} =
  chars.to(char).join("")
  
template toString*(bech32: tuple[hrp: string, data: seq[int]]): string =
  charsToString bech32.data

## Nostr specific. NIP-19

type
  NProfile* = object
    key*: SkXOnlyPublicKey
    relays*: seq[string]

  NEvent* = object
    id*: EventID
    relays*: seq[string]
    author*: SkXOnlyPublicKey
    kind*: uint32

  NAddr* = object
    id*: string
    relays*: seq[string]
    author*: SkXOnlyPublicKey
    kind*: int

  NRelay* = object
    url*: string

  NNote* = object
    id*: EventID

  Bech32EncodedEntity* = (NProfile | NEvent | NAddr | NRelay | NNote | SkSecretKey | SkXOnlyPublicKey)

  UnknownTLVError* = object of ValueError

func getPubkey(raw: openArray[int]): SkResult[SkXOnlyPublicKey] {.raises: [].} =
  if raw.len == 33: SkXOnlyPublicKey.fromRaw(raw[0..^2].to(byte))
  elif raw.len == 32: SkXOnlyPublicKey.fromRaw(raw.to(byte))
  else: err("bech32: x-only public key must be 32 or 33 bytes")

func fromBech32*(T: type SkXOnlyPublicKey, address: string): T =
  let raw = decode("npub", address)
  let pubkey = getPubkey(raw)
  if pubkey.isOk: pubkey.unsafeGet
  else: bech32.error($pubkey.error)
  
func fromBech32*(T: type SkSecretKey, address: string): T =
  let seckey = T.fromRaw(decode("nsec", address).to(byte))
  if seckey.isOk: seckey.unsafeGet
  else: bech32.error($seckey.error)

template parseData(address: seq[int], i: var int): tuple[kind: int, data: seq[int]] =
  if i + 1 > address.len: break
  let (kind, length) = (address[i], address[i + 1])
  i += 2
  if i + length - 1 > address.len: error("End of value " & $(i + length - 1) & " exceeds bech32 address length " & $address.len & ".")
  let data = address[i..<i + length]
  i += length
  (kind, data)

func parseNProfile*(address: seq[int]): NProfile =
  var i = 0
  while true:
    let (kind, data) = parseData(address, i)
    case kind:
    of 0:
      let sk = SkXOnlyPublicKey.fromRaw(data.to(byte))
      if sk.isOk: result.key = sk.unsafeGet
      else: bech32.error("Invalid public key in nprofile bech32 address")
    of 1:
      result.relays.add charsToString(data)
    else:
      discard

func toArray[T](N: static int, data: openArray[T]): array[N, T] {.raises: [].} =
  # Taken from `stew/objects.nim`
  doAssert data.len == N
  copyMem(addr result[0], unsafeAddr data[0], N)

func parseNEvent*(address: seq[int]): NEvent =
  var i = 0
  while true:
    let (kind, data) = parseData(address, i)
    case kind:
    of 0:
      if data.len == 32:
        result.id = EventID(bytes: toArray(32, data.to(byte)))
      else: bech32.error("Invalid event id in nevent bech32 address")
    of 1:
      result.relays.add charsToString(data)
    of 2:
      let pubkey = getPubkey(data)
      if pubkey.isOk: result.author = pubkey.unsafeGet
    of 3:
      if data.len == 4:
        for i in 0..<4: result.kind = result.kind or (uint32(data[3 - i]) shl (i * 8))
    else:
      discard

func fromUInt32(data: seq[int]): uint32 {.inline, raises: [].} =
  for i in 0..<4: result = result or (uint32(data[3 - i]) shl (i * 8))

func parseNAddr*(address: seq[int]): NAddr =
  var i = 0
  while true:
    let (kind, data) = parseData(address, i)
    case kind:
    of 0:
      result.id = charsToString(data)
    of 1:
      result.relays.add charsToString(data)
    of 2:
      let pubkey = getPubkey(data)
      if pubkey.isOk: result.author = pubkey.unsafeGet
    of 3:
      if data.len == 4:
        result.kind = int(fromUInt32(data))
    else:
      discard

func parseNRelay*(address: seq[int]): NRelay {.raises: [InvalidBech32Error].} =
  var i = 0
  while true:
    let (kind, data) = parseData(address, i)
    if kind == 0:
      return NRelay(url: charsToString(data))

proc fromNostrBech32*(address: string): union(Bech32EncodedEntity) {.raises: [InvalidBech32Error, UnknownTLVError].} =
  let (kind, data) = decode(address)
  case kind:
  of "npub":
    SkXOnlyPublicKey.fromBech32(address) as union(Bech32EncodedEntity)
  of "nsec":
    SkSecretKey.fromBech32(address) as union(Bech32EncodedEntity)
  of "note":
    NNote(id: EventID(bytes: toArray(32, data.to(byte)))) as union(Bech32EncodedEntity)
  of "nprofile":
    parseNProfile(data) as union(Bech32EncodedEntity)
  of "nevent":
    parseNEvent(data) as union(Bech32EncodedEntity)
  of "naddr":
    parseNAddr(data) as union(Bech32EncodedEntity)
  of "nrelay":
    parseNRelay(data) as union(Bech32EncodedEntity)
  else:
    raise newException(UnknownTLVError, "Unknown TLV starting with " & kind)
