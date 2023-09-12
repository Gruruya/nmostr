## Nostr Bech32 processing - for nmostr.
# Copyright © 2023 Gruruya <gruruya.chi4c@slmails.com>
# SPDX-License-Identifier: AGPL-3.0-only

### Description
## Used Pieter Wuille's `Python implementation <https://github.com/sipa/bech32/blob/master/ref/python/segwit_addr.py>`_ as a reference.  
## Nostr-style Bech32 addresses use no witness version or m-encoding.

import pkg/[union, stew/byteutils]
from std/tables import toTable, `[]`
from std/sequtils import mapIt
from std/strutils import toLower, rfind, join
from std/setutils import toSet
import ./events, ./filters


type
  uint5* =
    range[0'u8..31'u8]

  Bech32Entity* = object
    hrp: string
    data: seq[byte]

const Charset* = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
const CharsetMap = Charset.mapIt((it, Charset.find(it).uint5)).toTable()
const CharsetSet* = Charset.toSet

func toWords*(data: openArray[byte]): seq[uint5] =
  ## uint8 → uint5 conversion
  result = newSeqUninitialized[uint5]((data.len * 8 + 4) div 5)
  var
    acc = 0'u32
    bits = 0'u32
    i = 0
  for value in data:
    acc = (acc shl 8) or (value).uint8
    bits += 8
    while bits >= 5:
      bits -= 5
      result[i] = ((acc shr bits) and uint5.high).uint5
      inc(i)
  if likely bits > 0:
    result[i] = ((acc shl (5 - bits)) and uint5.high).uint5

func fromWords*(data: openArray[uint5]): seq[byte] =
  ## uint5 → uint8 conversion
  result = newSeqUninitialized[byte]((data.len * 5) div 8)
  var
    acc = 0'u32
    bits = 0'u32
    i = 0
  for value in data:
    acc = (acc shl 5) or value
    bits += 5
    while bits >= 8:
      bits -= 8
      result[i] = ((acc shr bits) and uint8.high).byte
      inc(i)

func polymod(values: openArray[uint5]): uint32 =
  const generator = [uint32 0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
  result = 1
  for value in values:
    let top = result shr 25
    result = (result and 0x1ffffff) shl 5 xor value.uint32
    for i in 0 ..< 5:
      result = result xor (if (top shr i and 1) == 1: generator[i] else: 0)

func hrpExpand(hrp: string): seq[uint5] =
  # ex: "nsec" → @[3, 3, 3, 3, 0, 14, 19, 5, 3]
  result = newSeqUninitialized[uint5](hrp.len * 2 + 1)
  result[hrp.len] = 0
  for i, c in hrp:
    result[i] = uint5(ord(c) shr 5)
    result[i + hrp.len + 1] = uint5(ord(c) and 31)

proc verifyChecksum*(hrp: string, data: seq[uint5]): bool {.inline.} =
  polymod(hrpExpand(hrp) & data) == 1


func decodeImpl(bech32: sink string, verify: bool): tuple[hrp: string, data: seq[uint5]] =
  bech32 = bech32.toLower()
  let pos = bech32.rfind('1')
  if unlikely pos < 1 or unlikely pos + 7 > bech32.len: # or len(bech32) > 90:
    raise newException(ValueError, "'1' not found in " & bech32)
  var hrp = bech32[0 ..< pos]
  var data =
    try: bech32[pos + 1..^1].mapIt(CharsetMap[it])
    except KeyError: raise newException(ValueError, "Invalid character in bech32 address " & bech32)
  if verify and not verifyChecksum(hrp, data):
    raise newException(ValueError, bech32 & " has an invalid checksum")
  (hrp, data[0..^7]) # [0..^7] cuts off checksum

func decode*(address: string, verify = true): Bech32Entity {.inline.} =
  let (hrp, data) = decodeImpl(address, verify)
  Bech32Entity(hrp: hrp, data: fromWords(data))

func decode*(hrp: string, address: string, verify = true): seq[byte] {.inline.} =
  let (hrpFound, data) = decodeImpl(address, verify)
  if unlikely hrpFound != hrp:
    raise newException(ValueError, "Incorrect hrp " & hrpFound & " in bech32 address, expected " & hrp)
  result = fromWords(data)


func encode*(hrp: string, witprog: openArray[byte]): string =
  ## Encode into a bech32 address
  func checksum(hrp: string, data: seq[uint5]): seq[uint5] {.inline.} =
    let values = hrpExpand(hrp) & data
    let polymod = polymod(values & @[uint5 0, 0, 0, 0, 0, 0]) xor 1
    result = newSeqUninitialized[uint5](6)
    for i in 0 .. 5:
      result[i] = uint5((polymod shr (5 * (5 - i))) and 31)

  let data = toWords(witprog)
  let combined = data & checksum(hrp, data)
  result = hrp & '1' & combined.mapIt(Charset[it]).join("")

func encode*(hrp, witprog: string): string {.inline.} =
  encode(hrp, witprog.toBytes)

func toString*(entity: Bech32Entity): string {.inline.} =
  # Not `$` as it's not always correct
  string.fromBytes(entity.data)


# Nostr specific. NIP-19
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

  NostrTLV* = NProfile | NEvent | NAddr | NRelay | NNote | SecretKey | PublicKey

# Parsing
func toUInt32(data: openArray[byte]): uint32 {.inline.} =
  for i in 0 ..< 4:
    result = result or (uint32(data[3 - i]) shl (i * 8))

func fromUInt32(data: uint32): array[4, byte] {.inline.} =
  for i in 0 ..< 4:
    result[3 - i] = byte((data shr (i * 8)) and 0xFF)

template parseData(address: openArray[byte], i: var uint32): tuple[kind: uint8, data: seq[byte]] =
  if i + 1 >= address.len.uint32: break
  let (kind, length) = (cast[uint8](address[i]), cast[uint8](address[i + 1]))
  i += 2
  if unlikely i + length - 1 > address.len.uint32: raise newException(ValueError, "End of value " & $(i + length - 1) & " exceeds bech32 address length " & $address.len)
  let data = address[i ..< i + length]
  i += length
  (kind, data)

func fromBytes*(T: type NProfile, address: openArray[byte]): T =
  var i = 0'u32
  while true:
    let (kind, data) = parseData(address, i)
    case kind
    of 0:
      result.pubkey = PublicKey.fromBytes(data)
    of 1:
      result.relays.add string.fromBytes(data)
    else:
      discard

func fromBytes*(T: type NEvent, address: openArray[byte]): T =
  var i = 0'u32
  while true:
    let (kind, data) = parseData(address, i)
    case kind
    of 0:
      if likely data.len == 32:
        result.id = EventID.fromBytes(data)
      else: raise newException(ValueError, "Invalid event id in nevent bech32 address")
    of 1:
      result.relays.add string.fromBytes(data)
    of 2:
      result.author = PublicKey.fromBytes(data)
    of 3:
      if likely data.len == 4:
        result.kind = toUInt32(data)
    else:
      discard

func fromBytes*(T: type NAddr, address: openArray[byte]): T =
  var i = 0'u32
  while true:
    let (kind, data) = parseData(address, i)
    case kind
    of 0:
      result.id = string.fromBytes(data)
    of 1:
      result.relays.add string.fromBytes(data)
    of 2:
      result.author = PublicKey.fromBytes(data)
    of 3:
      if likely data.len == 4:
        result.kind = toUInt32(data)
    else:
      discard

func fromBytes*(T: type NRelay, address: openArray[byte]): T =
  var i = 0'u32
  while true:
    let (kind, data) = parseData(address, i)
    if likely kind == 0:
      return NRelay(url: string.fromBytes(data))

func fromBytes*(T: type NNote, address: seq[byte]): T =
  rangeCheck address.len >= 32
  NNote(id: EventID.fromBytes(address))

func fromNostrBech32*(address: string): union(NostrTLV) =
  let decoded = decode(address)
  case decoded.hrp
  of "npub":
    PublicKey.fromBytes(decoded.data) as union(NostrTLV)
  of "nsec":
    SecretKey.fromBytes(decoded.data) as union(NostrTLV)
  of "note":
    NNote.fromBytes(decoded.data) as union(NostrTLV)
  of "nprofile":
    NProfile.fromBytes(decoded.data) as union(NostrTLV)
  of "nevent":
    NEvent.fromBytes(decoded.data) as union(NostrTLV)
  of "naddr":
    NAddr.fromBytes(decoded.data) as union(NostrTLV)
  of "nrelay":
    NRelay.fromBytes(decoded.data) as union(NostrTLV)
  else:
    raise newException(ValueError, "Unknown TLV starting with " & decoded.hrp)

func fromBech32*(T: type SecretKey, address: string): T =
  SecretKey.fromBytes(decode("nsec", address))

func fromBech32*(T: type PublicKey, address: string): T =
  PublicKey.fromBytes(decode("npub", address))

func fromBech32*(T: type NNote, address: string): T {.inline.} =
  NNote.fromBytes(decode("note", address))

func fromBech32*(T: type NProfile, address: string): T {.inline.} =
  NProfile.fromBytes(decode("nprofile", address))

func fromBech32*(T: type NEvent, address: string): T {.inline.} =
  NEvent.fromBytes(decode("nevent", address))

func fromBech32*(T: type NAddr, address: string): T {.inline.} =
  NAddr.fromBytes(decode("naddr", address))

func fromBech32*(T: type NRelay, address: string): T {.inline.} =
  NRelay.fromBytes(decode("nrelay", address))

# Encoding
func toBech32*(pubkey: PublicKey): string {.inline.} =
  encode("npub", pubkey.toBytes)
 
func toBech32*(seckey: SecretKey): string {.inline.} =
  encode("nsec", seckey.toBytes)

func toBech32*(nprofile: NProfile): string =
  var encoded = @[byte 0, 32] & @(nprofile.pubkey.toBytes)
  for relay in nprofile.relays:
    encoded &= @[byte 1, byte relay.len] & relay.toBytes
  encode("nprofile", encoded)

func toBech32*(nevent: NEvent): string  =
  var encoded = @[byte 0, 32] & @(nevent.id.toBytes)
  for relay in nevent.relays:
    encoded &= @[byte 1, byte relay.len] & relay.toBytes
  if nevent.author != default(NEvent).author:
    encoded &= @[byte 2, 32] & @(nevent.author.toBytes)
  if nevent.kind != default(NEvent).kind:
    encoded &= @[byte 3, 4] & @(fromUInt32(nevent.kind))
  encode("nevent", encoded)

func toBech32*(event: Event, relays = newSeq[string]()): string =
  # Encode an event as an `nevent` TLV
  var encoded = @[byte 0, 32] & @(event.id.toBytes)
  for relay in relays:
    encoded &= @[byte 1, byte relay.len] & relay.toBytes
  encoded &= @[byte 2, 32] & @(event.pubkey.toBytes)
  encoded &= @[byte 3, 4] & @(fromUInt32(event.kind.uint32))
  encode("nevent", encoded)

func toBech32*(naddr: NAddr): string =
  var encoded = @[byte 0, byte naddr.id.len] & naddr.id.toBytes
  for relay in naddr.relays:
    encoded &= @[byte 1, byte relay.len] & relay.toBytes
  if naddr.author != default(NAddr).author:
    encoded &= @[byte 2, 32] & @(naddr.author.toBytes)
  if naddr.kind != default(NAddr).kind:
    encoded &= @[byte 3, 4] & @(fromUInt32(naddr.kind))
  encode("naddr", encoded)

func toBech32*(nrelay: NRelay): string {.inline.} =
  encode("nrelay", @[byte 0, byte nrelay.url.len] & nrelay.url.toBytes)

func toBech32*(note: NNote): string {.inline.} =
  encode("note", note.id.toBytes)

func toBech32*(eventID: EventID): string {.inline.} =
  # Encode an event ID as a `note` TLV
  encode("note", eventID.toBytes)


# Convenience wrappers
func toFilter*(pubkey: PublicKey): Filter {.inline.} =
  Filter(authors: @[pubkey.toHex])

func toFilter*(seckey: SecretKey): Filter {.inline.} =
  Filter(authors: @[seckey.toPublicKey.toHex])

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

func toFilter*(union: union(NostrTLV)): Filter =
  unpack union, entity:
    when (compiles entity.toFilter): entity.toFilter
    else: Filter()
