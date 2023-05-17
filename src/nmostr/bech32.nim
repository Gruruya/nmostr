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

import pkg/[union, stew/byteutils]
from std/tables import toTable, `[]`
from std/sequtils import mapIt
from std/strutils import toLower, rfind, join
import ./events

{.push raises: [].}

type uint5* = range[0.uint32..31.uint32]

type InvalidBech32Error* = object of ValueError

template error(reason: string) =
  raise newException(InvalidBech32Error, reason)

func fromRaw(T: type PublicKey, data: openArray[byte]): SkResult[T] {.inline, raises: [InvalidBech32Error].} =
  ## Same as `./keys/fromRaw` but with `InvalidBech32Error`
  if likely data.len == 32: cast[SkResult[PublicKey]](SkXOnlyPublicKey.fromRaw(data))
  elif data.len == 33: cast[SkResult[PublicKey]](SkXOnlyPublicKey.fromRaw(data))
  else: raise newException(InvalidBech32Error, "Raw x-only public key must be 32 or 33 bytes")

const CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
const CHARSET_MAP = CHARSET.mapIt((it, CHARSET.find(it).uint5)).toTable()

func toWords*(data: openArray[byte]): seq[uint5] =
  ## uint8 → uint5 conversion
  var acc, bits = 0
  const maxV = (1 shl 5) - 1
  let outputLen = (data.len * 8 + 4) div 5
  result = newSeq[uint5](outputLen)
  var idx = 0
  for value in data:
    acc = (acc shl 8) or ord(value)
    bits += 8
    while bits >= 5:
      bits -= 5
      result[idx] = uint5((acc shr bits) and maxV)
      inc(idx)
  if likely bits > 0:
    result[idx] = uint5((acc shl (5 - bits)) and maxV)

func fromWords*(data: openArray[uint5]): seq[byte] =
  ## uint5 → uint8 conversion
  var acc = 0.uint5
  var bits = 0.uint8
  const maxV = (1 shl 8) - 1
  let outputLen = (data.len * 5) div 8
  result = newSeq[byte](outputLen)
  var idx = 0
  for value in data:
    acc = (acc shl 5.uint5) or value
    bits += 5
    while bits >= 8:
      bits -= 8
      result[idx] = ((acc shr bits) and maxV).byte
      inc(idx)

func polymod(values: openArray[uint5]): uint32 =
  const generator = [uint32 0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
  result = 1
  for value in values:
    let top = result shr 25
    result = (result and 0x1ffffff) shl 5 xor value.uint32
    for i in 0 ..< 5:
      result = result xor (if (top shr i and 1) == 1: generator[i] else: 0)

func hrpExpand(hrp: string): seq[uint5] =
  result = newSeq[uint5](hrp.len * 2 + 1)
  for i, c in hrp:
    result[i] = uint5(ord(c) shr 5)
    result[i + hrp.len + 1] = uint5(ord(c) and 31)

func encode*(hrp: string, witprog: openArray[byte]): string =
  ## Encode into a bech32 address
  func checksum(hrp: string, data: seq[uint5]): seq[uint5] {.inline.} =
    let values = hrpExpand(hrp) & data
    let polymod = polymod(values & @[uint5 0, 0, 0, 0, 0, 0]) xor 1
    result = newSeqOfCap[uint5](5)
    for i in 0 ..< 6:
      result.add uint5((polymod shr (5 * (5 - i))) and 31)

  let data = toWords(witprog)
  let combined = data & checksum(hrp, data)
  result = hrp & '1' & combined.mapIt(CHARSET[it]).join("")

  # discard decode(hrp, result) # Verify

func encode*(hrp, witprog: string): string {.inline.} =
  encode(hrp, witprog.toBytes)
  
proc verifyChecksum*(hrp: string, data: seq[uint5]): bool {.inline.} =
  polymod(hrpExpand(hrp) & data) == 1

func decodeImpl(bech32: string): tuple[hrp: string, data: seq[uint5]] {.raises: [InvalidBech32Error].} =
  let bech32 = bech32.toLower()
  let pos = bech32.rfind('1')
  if unlikely pos < 1 or unlikely pos + 7 > bech32.len: # or len(bech32) > 90:
    error "'1' not found in " & bech32
  var hrp = bech32[0 ..< pos]
  var data =
    try: bech32[pos + 1..^1].mapIt(CHARSET_MAP[it])
    except KeyError: error "Invalid character in bech32 address " & bech32
  # if not verifyChecksum(hrp, data):
  #   error bech32 & " has an invalid checksum"
  (hrp, data[0..^7]) # [0..^7] cuts off checksum

func decode*(address: sink string): tuple[hrp: string, data: seq[byte]] {.inline, raises: [InvalidBech32Error].} =
  let (hrp, data) = decodeImpl(address)
  result = (hrp, fromWords(data))

func decode*(hrp: string, address: sink string): seq[byte] {.inline, raises: [InvalidBech32Error].} =
  let (hrpFound, data) = decodeImpl(address)
  if unlikely hrpFound != hrp:
    error "Incorrect hrp " & hrpFound & " in bech32 address, expected " & hrp
  result = fromWords(data)

#[___ Nostr specific. NIP-19 _________________________________________________________________]#

type
  NProfile* = object
    pubkey*: PublicKey
    relays*: seq[string]

  NEvent* = object
    id*: EventID
    relays*: seq[string]
    author*: PublicKey
    kind*: uint32

  NAddr* = object
    id*: string
    relays*: seq[string]
    author*: PublicKey
    kind*: uint32

  NRelay* = object
    url*: string

  NNote* = object
    id*: EventID

  Bech32EncodedEntity* = NProfile | NEvent | NAddr | NRelay | NNote | SecretKey | PublicKey

  UnknownTLVError* = object of ValueError

#[___ Parsing _________________________________________________________________]#

func toArray[T](N: static int, data: seq[T]): array[N, T] {.inline.} =
  # Taken from `stew/objects.nim`
  doAssert data.len == N
  copyMem(addr result[0], unsafeAddr data[0], N)

func toUInt32(data: openArray[byte]): uint32 {.inline.} =
  for i in 0 ..< 4: result = result or (uint32(data[3 - i]) shl (i * 8))

func fromUInt32(data: uint32): array[4, byte] {.inline.} =
  for i in 0 ..< 4:
    result[3 - i] = byte((data shr (i * 8)) and 0xFF)

template parseData(address: openArray[byte], i: var uint32): tuple[kind: uint8, data: seq[byte]] =
  if i + 1 >= address.len.uint32: break
  let (kind, length) = (cast[uint8](address[i]), cast[uint8](address[i + 1]))
  i += 2
  if unlikely i + length - 1 > address.len.uint32: error "End of value " & $(i + length - 1) & " exceeds bech32 address length " & $address.len
  let data = address[i..<i + length]
  i += length
  (kind, data)

func fromRaw*(T: type NProfile, address: openArray[byte]): T {.raises: [InvalidBech32Error].} =
  var i = 0.uint32
  while true:
    let (kind, data) = parseData(address, i)
    case kind:
    of 0:
      let pk = PublicKey.fromRaw(data)
      if likely pk.isOk: result.pubkey = pk.unsafeGet
      else: error $pk.error
    of 1:
      result.relays.add string.fromBytes(data)
    else:
      discard

func fromRaw*(T: type NEvent, address: openArray[byte]): T {.raises: [InvalidBech32Error].} =
  var i = 0.uint32
  while true:
    let (kind, data) = parseData(address, i)
    case kind:
    of 0:
      if likely data.len == 32:
        result.id = EventID(bytes: toArray(32, data))
      else: error "Invalid event id in nevent bech32 address"
    of 1:
      result.relays.add string.fromBytes(data)
    of 2:
      let pubkey = PublicKey.fromRaw(data)
      if likely pubkey.isOk: result.author = pubkey.unsafeGet
    of 3:
      if likely data.len == 4:
        result.kind = toUInt32(data)
    else:
      discard

func fromRaw*(T: type NAddr, address: openArray[byte]): T {.raises: [InvalidBech32Error].} =
  var i = 0.uint32
  while true:
    let (kind, data) = parseData(address, i)
    case kind:
    of 0:
      result.id = string.fromBytes(data)
    of 1:
      result.relays.add string.fromBytes(data)
    of 2:
      let pubkey = PublicKey.fromRaw(data)
      if likely pubkey.isOk: result.author = pubkey.unsafeGet
    of 3:
      if likely data.len == 4:
        result.kind = toUInt32(data)
    else:
      discard

func fromRaw*(T: type NRelay, address: openArray[byte]): T {.raises: [InvalidBech32Error].} =
  var i = 0.uint32
  while true:
    let (kind, data) = parseData(address, i)
    if likely kind == 0:
      return NRelay(url: string.fromBytes(data))

func fromRaw*(T: type NNote, address: seq[byte]): T {.raises: [InvalidBech32Error].} =
  if likely address.len == 32:
    NNote(id: EventID(bytes: toArray(32, address)))
  elif unlikely address.len > 32:
    NNote(id: EventID(bytes: toArray(32, address[0..31]))) #WARNING: Maybe? Silent failure.
  else:
    error "Event ID in bech32 encoded note should be 32 bytes, but was " & $address.len & " bytes instead"

func fromNostrBech32*(address: string): union(Bech32EncodedEntity) {.raises: [InvalidBech32Error, UnknownTLVError].} =
  let (kind, data) = decode(address)
  case kind:
  of "npub":
    let pk = PublicKey.fromRaw(data)
    if likely pk.isOk: unsafeGet(pk) as union(Bech32EncodedEntity)
    else: error $pk.error
  of "nsec":
    let sk = SecretKey.fromRaw(data)
    if likely sk.isOk: unsafeGet(sk) as union(Bech32EncodedEntity)
    else: error $sk.error
  of "note":
    NNote.fromRaw(data) as union(Bech32EncodedEntity)
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

func fromBech32*(T: type SecretKey, address: string): T {.raises: [InvalidBech32Error].} =
  let sk = SecretKey.fromRaw(decode("nsec", address))
  if likely sk.isOk: unsafeGet(sk)
  else: bech32.error $sk.error

func fromBech32*(T: type PublicKey, address: string): T {.raises: [InvalidBech32Error].} =
  let pk = bech32.fromRaw(PublicKey, (decode("npub", address)))
  if likely pk.isOk: unsafeGet(pk)
  else: bech32.error $pk.error

func fromBech32*(T: type NNote, address: string): T {.inline, raises: [InvalidBech32Error].} =
  NNote.fromRaw(decode("note", address))

func fromBech32*(T: type NProfile, address: string): T {.inline, raises: [InvalidBech32Error].} =
  NProfile.fromRaw(decode("nprofile", address))

func fromBech32*(T: type NEvent, address: string): T {.inline, raises: [InvalidBech32Error].} =
  NEvent.fromRaw(decode("nevent", address))

func fromBech32*(T: type NAddr, address: string): T {.inline, raises: [InvalidBech32Error].} =
  NAddr.fromRaw(decode("naddr", address))

func fromBech32*(T: type NRelay, address: string): T {.inline, raises: [InvalidBech32Error].} =
  NRelay.fromRaw(decode("nrelay", address))

#[___ Encoding _________________________________________________________________]#

func toBech32*(pubkey: PublicKey): string {.inline.} =
  encode("npub", pubkey.toRaw)
 
func toBech32*(seckey: SecretKey): string {.inline.} =
  encode("nsec", seckey.toRaw)

func toBech32*(nprofile: NProfile): string =
  var encoded = @[byte 0, 32] & @(nprofile.pubkey.toRaw)
  for relay in nprofile.relays:
    encoded &= @[byte 1, byte relay.len] & relay.toBytes
  encode("nprofile", encoded)

func toBech32*(nevent: NEvent): string  =
  var encoded = @[byte 0, 32] & @(nevent.id.bytes)
  for relay in nevent.relays:
    encoded &= @[byte 1, byte relay.len] & relay.toBytes
  if nevent.author != default(NEvent).author:
    encoded &= @[byte 2, 32] & @(nevent.author.toRaw)
  if nevent.kind != default(NEvent).kind:
    encoded &= @[byte 3, 4] & @(fromUInt32(nevent.kind))
  encode("nevent", encoded)  

func toBech32*(naddr: NAddr): string =
  var encoded = @[byte 0, byte naddr.id.len] & naddr.id.toBytes
  for relay in naddr.relays:
    encoded &= @[byte 1, byte relay.len] & relay.toBytes
  if naddr.author != default(NAddr).author:
    encoded &= @[byte 2, 32] & @(naddr.author.toRaw)
  if naddr.kind != default(NAddr).kind:
    encoded &= @[byte 3, 4] & @(fromUInt32(naddr.kind))
  encode("naddr", encoded)

func toBech32*(nrelay: NRelay): string {.inline.} =
  encode("nrelay", @[byte 0, byte nrelay.url.len] & nrelay.url.toBytes)

func toBech32*(note: NNote): string {.inline.} =
  encode("note", note.id.bytes)

#[___ Convenience _________________________________________________________________]#

func toFilter*(pubkey: PublicKey): Filter {.inline.} =
  Filter(authors: @[pubkey.toHex])

func toFilter*(seckey: SecretKey): Filter {.inline.} =
  Filter(authors: @[seckey.toPublicKey.toXOnly.toHex])

func toFilter*(nprofile: NProfile): Filter {.inline.}  =
  Filter(authors: @[nprofile.pubkey.toHex])

func toFilter*(nevent: NEvent): Filter =
  result.ids = @[nevent.id.toHex]
  if nevent.author != default(NEvent.author):
    result.authors = @[nevent.author.toHex]
  if nevent.kind != default(NEvent.kind):
    result.kinds = @[int nevent.kind]

func toFilter*(naddr: NAddr): Filter {.inline.} =
  Filter(tags: @[@["#d", naddr.id]],
         authors: @[naddr.author.toHex],
         kinds: @[int naddr.kind])

func toFilter*(nnote: NNote): Filter {.inline.} =
  Filter(ids: @[nnote.id.toHex])

func toFilter*(union: union(Bech32EncodedEntity)): Filter =
  unpack union, entity:
    when (compiles entity.toFilter): entity.toFilter
    else: Filter()
