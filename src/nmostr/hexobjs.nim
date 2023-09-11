## Objects with hex values - for nmostr.
# Copyright © 2023 Gruruya <gruruya.chi4c@slmails.com>
# SPDX-License-Identifier: AGPL-3.0-only
#
# This file incorporates work covered by the following copyright:
#   Copyright © 2020-2023 Andre von Houck
#   SPDX-License-Identifier: MIT

### Description
## Public and Private keys, Signatures, and Event IDs implemented as objects with data/hex pairs.
##
## See also:
## * `keys <keys.html>`_
## * `termermc/nim-stack-strings <https://github.com/termermc/nim-stack-strings>`_

import pkg/[stack_strings, secp256k1/abi]
from   pkg/jsony {.all.} import eatSpace, eatChar, parseUnicodeEscape, JsonError
from   std/unicode import Rune, toUTF8

export stack_strings
{.push inline, raises: [].}


### § Hex utils
## Primitives for working with hexadecimal strings.
## Implemented using `StackString`s as our hexes each have a constant length.

func toHex*(bytes: openArray[byte]): string =
  ## Convert a byte-sequence to its hex representation
  const hexChars = "0123456789abcdef"
  result = newStringUninit(2 * bytes.len)
  for i in 0..bytes.high:
    result[i * 2] = hexChars[int(bytes[i] shr 4 and 0x0f'u8)]
    result[i * 2 + 1] = hexChars[int(bytes[i] and 0x0f'u8)]

func toHex*[N](bytes: array[N, byte]): auto =
  ## Convert a byte-array to its hex representation
  const hexChars = "0123456789abcdef"
  const hexLen = 2*(1 + N.high - N.low)
  result = stackStringOfCap(hexLen)
  for b in bytes:
    result.add hexChars[int(b shr 4 and 0x0f'u8)]
    result.add hexChars[int(b and 0x0f'u8)]

func readHexChar*(c: char): byte {.raises: [ValueError].} =
  ## Converts a hex char to a byte
  case c
  of '0'..'9': byte(ord(c) - ord('0'))
  of 'a'..'f': byte(ord(c) - ord('a') + 10)
  of 'A'..'F': byte(ord(c) - ord('A') + 10)
  else: raise newException(ValueError, $c & " is not a hexadecimal character")

template skip0xPrefix(hexStr: typed): range[0..2] =
  ## Returns the index of the first meaningful char in `hexStr` by skipping "0x" prefix
  if hexStr.len > 1 and hexStr[0] == '0' and hexStr[1] in {'x', 'X'}: 2
  else: 0

template fromHexImpl(bytes: var openArray[byte]; start, last: Natural) =
  var sIdx = skip0xPrefix(hex).Natural
  sIdx += start * 2
  for bIdx in start..last:
    bytes[bIdx] = readHexChar(hex[sIdx]) shl 4 or readHexChar(hex[sIdx + 1])
    inc(sIdx, 2)

func fromHex*(T: typedesc[seq[byte]]; hex: auto): T =
  fromHexImpl(result, N.low, N.high)

func fromHex*[N](T: typedesc[array[N, byte]]; hex: openArray[char]): T {.raises: [ValueError].} =
  rangeCheck hex.len >= 2*(1 + N.high - N.low)
  fromHexImpl(result, N.low, N.high)

func fromHex*[N,N2](T: typedesc[array[N, byte]]; hex: array[N2, char]): T {.raises: [ValueError].} =
  const validLen = 2*(1 + N.high - N.low)
  const actualCap = hex.len
  when actualCap < validLen: {.error: "hex is too short, (" & $actualCap & " chars) it should be " & $validLen & " chars".}
  fromHexImpl(result, N.low, N.high)

func fromHex*[N](T: typedesc[array[N, byte]]; hex: StackString): T {.raises: [ValueError].} =
  const validLen = 2*(1 + N.high - N.low)
  const actualCap = hex.Size
  when actualCap < validLen: {.error: "hex is too short, (" & $actualCap & " chars) it should be " & $validLen & " chars".}
  rangeCheck hex.len >= validLen
  fromHexImpl(result, N.low, N.high)


proc dumpStrSlow(s: var string, v: StackString) =
  # Taken from `jsony <https://github.com/treeform/jsony/blob/master/src/jsony.nim>`_
  s.add '"'
  for c in v:
    case c:
    of '\\': s.add r"\\"
    of '\b': s.add r"\b"
    of '\f': s.add r"\f"
    of '\n': s.add r"\n"
    of '\r': s.add r"\r"
    of '\t': s.add r"\t"
    of '"': s.add "\\\""
    else: s.add c
  s.add '"'

proc dumpStrFast(s: var string, v: StackString) =
  # Taken from `jsony <https://github.com/treeform/jsony/blob/master/src/jsony.nim>`_
  # Its faster to grow the string only once.
  # Then fill the string with pointers.
  # Then cap it off to right length.
  var at = s.len
  s.setLen(s.len + v.len*2+2)

  var ss = cast[ptr UncheckedArray[char]](s[0].addr)
  template add(ss: ptr UncheckedArray[char], c: char) =
    ss[at] = c
    inc at
  template add(ss: ptr UncheckedArray[char], c1, c2: char) =
    ss[at] = c1
    inc at
    ss[at] = c2
    inc at

  ss.add '"'
  for c in v:
    case c:
    of '\\': ss.add '\\', '\\'
    of '\b': ss.add '\\', 'b'
    of '\f': ss.add '\\', 'f'
    of '\n': ss.add '\\', 'n'
    of '\r': ss.add '\\', 'r'
    of '\t': ss.add '\\', 't'
    of '"': ss.add '\\', '"'
    else:
      ss.add c
  ss.add '"'
  s.setLen(at)

proc dumpHook*(s: var string, v: StackString) =
  # Taken from `jsony <https://github.com/treeform/jsony/blob/master/src/jsony.nim>`_
  when nimvm:
    s.dumpStrSlow(v)
  else:
    when defined(js):
      s.dumpStrSlow(v)
    else:
      s.dumpStrFast(v)

func parseHook*(s: string, i: var int, v: var StackString) {.raises: [ValueError].} =
  # Taken from `jsony <https://github.com/treeform/jsony/blob/master/src/jsony.nim>`_
  eatSpace(s, i)
  if i + 3 < s.len and
      s[i+0] == 'n' and
      s[i+1] == 'u' and
      s[i+2] == 'l' and
      s[i+3] == 'l':
    i += 4
    return
  eatChar(s, i, '"')

  template add(v: var StackString; c: char) =
    discard v.addTruncate c

  while i < s.len:
    case s[i]
    of '"':
      break
    of '\\':
      inc i
      case s[i]
      of '"', '\\', '/': v.add(s[i])
      of 'b': v.add '\b'
      of 'f': v.add '\f'
      of 'n': v.add '\n'
      of 'r': v.add '\r'
      of 't': v.add '\t'
      of 'u':
        v.add(Rune(parseUnicodeEscape(s, i)).toUTF8())
      else:
        v.add(s[i])
    else:
      v.add(s[i])
    inc i
  eatChar(s, i, '"')

when isMainModule:
  from std/sugar import dump
  {.hint[DuplicateModuleImport]: off.}
  import pkg/jsony
  {.hint[DuplicateModuleImport]: on.}
  var hello = stackStringOfCap(32)
  hello.add "Hello, world!"
  doAssert hello.toJson == "\"Hello, world!\""
  dump hello.toJson
  dump fromJson(hello.toJson, StackString[32])


### § Objects
## The objects themselves, access the raw data and hex using obj.toHex and obj.toBytes.
## Use Object.fromHex or Object.fromRaw for initialization.

type
  PublicKey* = object
    ## x-only public key for Nostr
    raw*: array[64, byte] # note the raw field may contain a full public key (64 bytes) instead of x-only (32 bytes)
    hex*: StackString[32 * 2]

  EventID* = object
    raw*: array[32, byte]
    hex*: StackString[32 * 2]

  SchnorrSig* = object
    raw*: array[64, byte]
    hex*: StackString[64 * 2]

template bytesLen*(T: typedesc[EventID | SchnorrSig]): Positive = T.raw.len
template bytesLen*(T: typedesc[PublicKey]): Positive = 32

template toBytes*(v: EventID | SchnorrSig): auto =
  v.raw

func toBytes*(v: PublicKey): array[32, byte] =
  ## Returns the first 32 bytes in reverse
  for i in 0..31:
    result[i] = v.raw[31 - i]

template toHex*(v: PublicKey | EventID | SchnorrSig): auto =
  v.hex

func `$`*(v: PublicKey | EventID | SchnorrSig): string =
  # StackStrings have the option to warn on `$`,
  # see: https://github.com/termermc/nim-stack-strings/blob/master/stack_strings.nim#L107-L114
  $v.hex

func toString*(v: PublicKey | EventID | SchnorrSig): string =
  toString(v.hex)


# For populating fields of objects created without either raw data or hex:
func hexToRaw*(v: EventID | SchnorrSig): auto {.raises: [ValueError].} =
  ## Parse raw data from hex
  typeof(v.raw).fromHex(v.hex)

func hexToRaw*(v: PublicKey): array[64, byte] {.raises: [ValueError].}

func populateRaw*(v: var (PublicKey | EventID | SchnorrSig)) {.raises: [ValueError].} =
  ## Update the raw data based on the hex
  v.raw = v.hexToRaw

func populateHex*(v: var (PublicKey | EventID | SchnorrSig)) =
  ## Update the hex based on the raw data
  v.hex = v.toBytes.toHex

func populate*(v: var (PublicKey | EventID | SchnorrSig)) {.raises: [ValueError].} =
  ## Makes sure both the hex and raw fields are populated
  let needsRaw = unlikely v.raw == default(typeof v.raw)
  let needsHex = unlikely v.hex.len != typeof(v).hex.Size
  if needsRaw and needsHex:
    raise newException(ValueError, "object has no raw data nor hex data")
  elif needsRaw:
    populateRaw(v)
  elif needsHex:
    populateHex(v)


func toArray*[T](N: static int, data: openArray[T]): array[N, T] =
  rangeCheck data.len >= N
  copyMem(addr result[0], addr data[0], N)

func toStackString*(N: static int, data: openArray[char]): StackString[N] =
  rangeCheck data.len >= N
  copyMem(addr result.data[0], addr data[0], N)
  result.unsafeSetLen(N)

func fromRawOnly(T: typedesc[PublicKey], data: openArray[byte]): T {.raises: [ValueError].} =
  rangeCheck data.len >= 32
  let ret =
    secp256k1_xonly_pubkey_parse(secp256k1_context_no_precomp, cast[ptr secp256k1_xonly_pubkey](addr result), addr data[0])
  if unlikely ret != 1:
    raise newException(ValueError, "could not parse x-only public key")

func hexToRaw*(v: PublicKey): array[64, byte] {.raises: [ValueError].} =
  ## Parse raw data from hex
  PublicKey.fromRawOnly(array[32, byte].fromHex(v.hex)).raw

func fromRawOnly(T: typedesc[EventID], data: openArray[byte]): EventID =
  EventID(raw: toArray(32, data))

func fromRawOnly(T: typedesc[EventID], data: array[32, byte]): EventID =
  EventID(raw: data)

func fromRawOnly(T: typedesc[SchnorrSig], data: openArray[byte]): T =
  SchnorrSig(raw: toArray(64, data))

func fromRawOnly(T: typedesc[SchnorrSig], data: array[64, byte]): T =
  SchnorrSig(raw: data)

{.pop.}
func fromRaw*(T: typedesc[PublicKey | EventID | SchnorrSig], data: openArray[byte]): T {.inline.} =
  result = T.fromRawOnly(data)
  result.hex = result.toBytes.toHex
{.push inline, raises: [].}

func fromHex*(T: typedesc[PublicKey | EventID | SchnorrSig], hex: auto): T {.raises: [ValueError].} =
  const fromLen = T.bytesLen
  const toLen = fromLen*2
  result = T.fromRawOnly(array[fromLen, byte].fromHex(hex))
  when hex is StackString:
    when hex.Size == toLen:
      result.hex = hex
    else:
      result.hex.unsafeAdd(hex.data.toOpenArray(0, toLen - 1))
  else:
    result.hex.unsafeAdd(hex.toOpenArray(0, toLen - 1))


func parseHook*(s: string, i: var int, v: var (PublicKey | EventID | SchnorrSig)) {.raises: [ValueError].} =
  ## Parse id, pubkey, and sig as a hexadecimal encoding (of a sha256 hash).
  var j: string
  parseHook(s, i, j)
  v = fromHex(typeof(v), j)

func dumpHook*(s: var string, v: PublicKey | EventID | SchnorrSig) =
  ## Serialize id, pubkey, and sig into hexadecimal.
  dumpHook(s, v.toHex)


when isMainModule:
  dump PublicKey.fromHex("7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e").toJson
  dump EventID.fromHex("4cd665db042864ee600ee976d6cfcc7c5ce743859462f94a347cd970d88a5f3b").toJson
  dump SchnorrSig.fromHex("f771ac928eb78037c0f4ddacd483471f3d71797e7ae524f328613338affd31d7ffcc346d88d0cba8f9278778c013c3591c81df3b06556024c80549b9a3962db5").toJson
