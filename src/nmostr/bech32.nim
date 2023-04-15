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

import pkg/[secp256k1, union, stew/byteutils]
from std/tables import toTable, `[]`
from std/sequtils import mapIt
from std/strutils import toLower, rfind, join
import ./events

type InvalidBech32Error* = object of ValueError

template error(reason: string) =
  raise newException(InvalidBech32Error, reason)
  
const CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
const CHARSET_MAP = CHARSET.mapIt((it, CHARSET.find(it))).toTable()

# proc bech32VerifyChecksum(hrp: string, data: openArray[int]): bool =
#   bech32Polymod(bech32HrpExpand(hrp) & @data) == 1

{.push raises: [InvalidBech32Error].}

func bech32Decode(bech: sink string): tuple[hrp: string, data: seq[int]] =
  bech = bech.toLower()
  let pos = bech.rfind('1')
  if pos < 1 or pos + 7 > bech.len: # or len(bech) > 90:
    error("'1' not found in " & bech)
  result.hrp = bech[0..<pos]
  try:
    result.data = bech[pos + 1..^1].mapIt(CHARSET_MAP[it])
  except KeyError: error("Invalid character in bech32 hash " & bech)
  # if not bech32VerifyChecksum(result.hrp, result.data):
  #   error(bech & " has an invalid checksum")
  result.data.setLen(result.data.len - 6)

func convertBits*(data: openArray[int], fromBits, toBits: static[int], pad = true): seq[int] =
  var acc, bits = 0
  const maxV = (1 shl toBits) - 1
  # const maxAcc = (1 shl (fromBits + toBits - 1)) - 1
  result = newSeqOfCap[int](data.len)
  for value in data:
    # if acc < 0 or (acc shr fromBits) != 0:
    #   error("Bits must be positive " & $fromBits & " bit integers.")
    # acc = ((acc shl fromBits) or acc) and maxAcc
    acc = (acc shl fromBits) or value
    bits += fromBits
    while bits >= toBits:
      bits -= toBits
      result.add (acc shr bits) and maxV
  if pad and bits > 0:
    result.add (acc shl (toBits - bits)) and maxV
  else:
    if bits >= fromBits: error "Excess padding"
    if ((acc shl (toBits - bits)) and maxV) != 0: error "Non-zero padding"

template toWords*(bytes: openArray[int]): seq[int] =
  convertBits(bytes, 8, 5, true)

template fromWords*(words: openArray[int]): seq[byte] =
  convertBits(words, 5, 8, false).mapIt(byte(it))

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
  encode(hrp, witprog.toBytes)
  
func decode*(address: string): tuple[hrp: string, data: seq[byte]] {.inline.} =
  let (hrp, data) = bech32Decode(address)
  result = (hrp, fromWords(data))

func decode*(hrp, address: string): seq[byte] {.inline, raises: [InvalidBech32Error].} =
  let (hrpGot, data) = bech32Decode(address)
  if hrpGot != hrp:
    error("Incorrect hrp " & hrpGot & " in bech32 address, expected " & hrp)
  result = fromWords(data)
  
template toString*(bech32: tuple[hrp: string, data: seq[byte]]): string =
  string.fromBytes bech32.data

## Nostr specific. NIP-19

type
  NProfile* = object
    pubkey*: SkXOnlyPublicKey
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

template parseData(address: seq[byte], i: var int): tuple[kind: int8, data: seq[byte]] =
  if i + 1 > address.len: break
  let (kind, length) = (cast[int8](address[i]), cast[int8](address[i + 1]))
  i += 2
  if i + length - 1 > address.len: error("End of value " & $(i + length - 1) & " exceeds bech32 address length " & $address.len & ".")
  let data = address[i..<i + length]
  i += length
  (kind, data)

func toArray[T](N: static int, data: openArray[T]): array[N, T] {.raises: [].} =
  # Taken from `stew/objects.nim`
  doAssert data.len == N
  copyMem(addr result[0], unsafeAddr data[0], N)

func fromUInt32(data: seq[byte]): uint32 {.inline, raises: [].} =
  for i in 0..<4: result = result or (uint32(data[3 - i]) shl (i * 8))

##### Parsing Bech32 #####

func fromRaw*(T: type SkXOnlyPublicKey, data: openArray[byte]): SkResult[SkXOnlyPublicKey] {.inline, raises: [].} =
  if data.len == 33: secp256k1.fromRaw(SkXOnlyPublicKey, data[0..^2])
  elif data.len == 32: secp256k1.fromRaw(SkXOnlyPublicKey, data)
  else: err("bech32: x-only public key must be 32 or 33 bytes")

func fromRaw*(T: type NProfile, address: seq[byte]): T =
  var i = 0
  while true:
    let (kind, data) = parseData(address, i)
    case kind:
    of 0:
      let pk = SkXOnlyPublicKey.fromRaw(data)
      if pk.isOk: result.pubkey = pk.unsafeGet
      else: error($pk.error)
    of 1:
      result.relays.add string.fromBytes(data)
    else:
      discard

func fromRaw*(T: type NEvent, address: seq[byte]): T =
  var i = 0
  while true:
    let (kind, data) = parseData(address, i)
    case kind:
    of 0:
      if data.len == 32:
        result.id = EventID(bytes: toArray(32, data))
      else: error("Invalid event id in nevent bech32 address")
    of 1:
      result.relays.add string.fromBytes(data)
    of 2:
      let pubkey = SkXOnlyPublicKey.fromRaw(data)
      if pubkey.isOk: result.author = pubkey.unsafeGet
    of 3:
      if data.len == 4:
        for i in 0..<4: result.kind = result.kind or (uint32(data[3 - i]) shl (i * 8))
    else:
      discard

func fromRaw*(T: type NAddr, address: seq[byte]): T =
  var i = 0
  while true:
    let (kind, data) = parseData(address, i)
    case kind:
    of 0:
      result.id = string.fromBytes(data)
    of 1:
      result.relays.add string.fromBytes(data)
    of 2:
      let pubkey = SkXOnlyPublicKey.fromRaw(data)
      if pubkey.isOk: result.author = pubkey.unsafeGet
    of 3:
      if data.len == 4:
        result.kind = int(fromUInt32(data))
    else:
      discard

func fromRaw*(T: type NRelay, address: seq[byte]): T =
  var i = 0
  while true:
    let (kind, data) = parseData(address, i)
    if kind == 0:
      return NRelay(url: string.fromBytes(data))

proc fromNostrBech32*(address: string): union(Bech32EncodedEntity) {.raises: [InvalidBech32Error, UnknownTLVError].} =
  let (kind, data) = decode(address)
  case kind:
  of "npub":
    let pk = SkXOnlyPublicKey.fromRaw(data)
    if pk.isOk: unsafeGet(pk) as union(Bech32EncodedEntity)
    else: error($pk.error)
  of "nsec":
    let sk = SkSecretKey.fromRaw(data)
    if sk.isOk: unsafeGet(sk) as union(Bech32EncodedEntity)
    else: error($sk.error)
  of "note":
    NNote(id: EventID(bytes: toArray(32, data))) as union(Bech32EncodedEntity)
  of "nprofile":
    NProfile.fromRaw(data) as union(Bech32EncodedEntity)
  of "nevent":
    NEvent.fromRaw(data) as union(Bech32EncodedEntity)
  of "naddr":
    NAddr.fromRaw(data) as union(Bech32EncodedEntity)
  of "nrelay":
    NRelay.fromRaw(data) as union(Bech32EncodedEntity)
  else:
    raise newException(UnknownTLVError, "Unknown TLV starting with " & kind)
