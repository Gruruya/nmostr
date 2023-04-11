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

## Utilities for working with Nostr events.

import std/[times, strutils, sequtils, macros, sysrand]
import pkg/[jsony, adix/lptabz, secp256k1, stew/byteutils, crunchy]

export jsony, times, lptabz, secp256k1

# Types

type EventID* = object
  bytes*: array[32, byte]

func `$`*(id: EventID): string {.inline.} = toHex(id.bytes)
template toHex*(id: EventID): string = $id

const TagTableHashcodeBits* = 8 ## A higher number such as 8 means more memory usage and faster lookups
type TagTable* = LPTabz[string, seq[string], int8, TagTableHashcodeBits] ## A Table containing tags, translated to use the first element as the index.
## A tag could be any of the following:
##
## NIP-01:
## * ["#e", <32-bytes hex of the id of another event>, <recommended relay URL>]
## * ["#p", <32-bytes hex of a pubkey>, <recommended relay URL>]
# NIP-12: Generic tag
## * [<`#` followed by a single letter>, <array of strings>]

template initTagTable*(initialSize=lpInitialSize, numer=lpNumer, denom=lpDenom, minFree=lpMinFree, growPow2=lpGrowPow2, rehash=lpRehash, robinhood=lpRobinHood): TagTable =
  initLPTabz[string, seq[string], int8, TagTableHashcodeBits](initialSize, numer, denom, minFree, growPow2, rehash, robinhood)

template toTagTable*(pairs: openArray[(string, seq[string])], dups = false): untyped {.dirty.} =
  toLPTabz[string, seq[string], int8, TagTableHashcodeBits](pairs, dups)

type Event* = object
  id*: EventID      ## 32-bytes lowercase hex-encoded sha256 of the serialized event data
  pubkey*: SkXOnlyPublicKey ## 32-bytes lowercase hex-encoded public key of the event creator
  kind*: int64      ## The type of event this is.
  content*: string  ## Arbitrary string, what it is should be gleamed from this event's `kind`
  created_at*: Time ## Received and transmitted as a Unix timestamp in seconds
  tags*: TagTable   ## A table of tags. See `TagTable` for what a tag could be.
  sig*: SkSchnorrSignature ## 64-bytes hex of the signature of the sha256 hash of the serialized event data, which is the same as the "id" field

type Filter* = object
  ids*: seq[string]      ## List of event ids or prefixes.
  authors*: seq[string]  ## List of pubkeys or prefixes, the pubkey of an event must be one of these.
  kinds*: seq[int64]     ## A list of event kinds.
  tags*: TagTable        ## A table of tags. The tag's value must match exactly. See `TagTable` for what a tag could be.
  since*: Time           ## Events must be newer than this to pass.
  until*: Time = initTime(high(int64), 0)  ## Events must be older than this to pass.
  limit*: int            ## Maximum number of events to be returned in the initial query.

type Metadata* = object ## Content of kind 0 (metadata) event
  name: string    ## username
  about: string   ## description
  picture: string ## url

type Keypair* = object
  ## Representation of private/public keys pair.
  privkey*: SkSecretKey
  pubkey*: SkXOnlyPublicKey

# JSON interop

{.push inline.}

func parseHook*(s: string, i: var int, v: var EventID) =
  ## Parse `id` as a hexadecimal encoding [of a sha256 hash.]
  var j: string
  parseHook(s, i, j)
  v.bytes = array[32, byte].fromHex(j)

func parseHook*(s: string, i: var int, v: var SkXOnlyPublicKey) =
  ## Parse `id` as a hexadecimal encoding [of a sha256 hash].
  var j: string
  parseHook(s, i, j)
  # WARNING: Silently failing, replacing incorrect with nulled pubkeys
  v = (SkXOnlyPublicKey.fromHex j).valueOr: default(typeof v)

func parseHook*(s: string, i: var int, v: var SkSchnorrSignature) =
  ## Parse `id` as a hexadecimal encoding [of a sha256 hash.]
  var j: string
  parseHook(s, i, j)
  # FIXME: Silently failing, replacing incorrect with nulled pubkeys
  v = (SkSchnorrSignature.fromHex j).valueOr: default(typeof v)

func dumpHook*(s: var string, v: EventID | SkXOnlyPublicKey | SkSchnorrSignature) =
  ## Serialize `id`, `pubkey`, and `sig` into hexadecimal.
  dumpHook(s, v.toHex)

func parseHook*(s: string, i: var int, v: var Time) =
  ## Parse `created_at` as a `Time`.
  var j: int64
  parseHook(s, i, j)
  v = fromUnix(j)

func dumpHook*(s: var string, v: Time) =
  ## Serialize `created_at` into a Unix timestamp.
  dumpHook(s, v.toUnix)

proc parseHook*(s: string, i: var int, v: var TagTable) =
  ## Parse tags as a table.
  var j: seq[seq[string]]
  parseHook(s, i, j)
  v = initTagTable(j.len)
  for tag in j:
    v.add(tag[0], tag[1..^1])

func dumpHook*(s: var string, v: TagTable) =
  ## Serialize tags into a JSON array of arrays.
  var j = newSeqOfCap[seq[string]](v.len)
  for key, value in v.pairs:
    j.add (key & value)
  dumpHook(s, j)

{.pop inline.}

template isGenericTag*(s: string): bool =
  s.startsWith('#') and s.len == 2

proc parseHook*(s: string, i: var int, v: var Filter) =
  ## Parse filters exactly the same as a normal object, but add each field starting with # as an entry in `tags`.

  eatSpace(s, i)
  if i + 3 < s.len and
      s[i+0] == 'n' and
      s[i+1] == 'u' and
      s[i+2] == 'l' and
      s[i+3] == 'l':
    i += 4
    return
  eatChar(s, i, '{')
  when compiles(newHook(v)):
    newHook(v)
  # Set `until`'s default, `jsony` should implement a generic version of this, such as v = default(typeof v)
  v.until = default(Filter).until
  while i < s.len:
    eatSpace(s, i)
    if i < s.len and s[i] == '}':
      break
    var key: string
    parseHook(s, i, key)
    eatChar(s, i, ':')
    when compiles(renameHook(v, key)):
      renameHook(v, key)
    # NIP-12: Generic tag
    if key.startsWith('#'):
      # Parses each field that starts with a # as an entry in `tags`
      var j: seq[string]
      parseHook(s, i, j)
      v.tags.add key, j
    else:
      block all:
        for k, v in v.fieldPairs:
          if k == key:
            var v2: type(v)
            parseHook(s, i, v2)
            v = v2
            break all
        skipValue(s, i)
    eatSpace(s, i)
    if i < s.len and s[i] == ',':
      inc i
    else:
      break
  when compiles(postHook(v)):
    postHook(v)
  eatChar(s, i, '}')

macro fieldAccess(o: object, s: string): untyped =
  newDotExpr(o, newIdentNode(s.strVal))

proc dumpHook*(s: var string, v: Filter) =
  ## Dump filters exactly the same as a normal object, but empty fields are left out and its `tags` are split into seperate fields.

  template dumpKey(s: var string, v: string) =
    ## Taken from `jsony.nim`
    const v2 = v.toJson() & ":"
    s.add v2

  var i = 1
  s.add '{'
  for k, e in v.fieldPairs:
    if e != default(Filter).fieldAccess(k) and (when k == "until": e.toUnix != high(int64) else: true):
      when k == "tags":
        # Dumps each tag as a field whose name is specified by its key in the table
        for tag in e.pairs:
          if i > 1: s.add ','
          s.add tag[0].toJson & ":"
          s.dumpHook(tag[1])
      else:
        if i > 1: s.add ','
        s.dumpKey(k)
        s.dumpHook(e)
      inc(i)
    else:
      skipValue(s, i)
  s.add '}'


proc sysRng*(data: var openArray[byte]): bool =
  ## Fill `data` with random bytes generated by your operating system.
  try:
    let randData = urandom(data.len)
    for i in 0..<data.len:
      data[i] = randData[i]
  except OSError: return false
  return true

# Optimization
{.push inline.}

converter toKeypair*(keypair: SkKeyPair): Keypair =
  Keypair(privkey: keypair.seckey, pubkey: keypair.pubkey.toXOnly)

converter toKeypair*(privkey: SkSecretKey): Keypair =
  Keypair(privkey: privkey, pubkey: privkey.toPublicKey.toXOnly)

proc newKeypair*(rng: Rng = sysRng): Keypair =
  toKeypair SkKeyPair.random(rng).tryGet

func serialize*(e: Event): string =
  ## Serialize `event` into JSON so that it can be hashed in accordance with NIP-01.
  "[0," & e.pubkey.toJson & "," & e.created_at.toJson & "," & e.kind.toJson & "," & e.tags.toJson & "," & e.content.toJson & "]"

proc sign*(event: var Event, sk: SkSecretKey, rng: Rng = sysRng) =
  event.sig = signSchnorr(sk, event.serialize.sha256, rng).tryGet

template sign*(event: var Event, sk: Keypair, rng: Rng = sysRng) =
  sign(event, sk.privkey, rng)

proc updateID*(event: var Event) =
  event.id = EventID(bytes: sha256 event.serialize)

proc init*(T: type Event, kind: int64, content: string, keypair: Keypair, created_at = getTime(), tags = TagTable()): Event =
  result = Event(
    kind: kind,
    content: content,
    pubkey: keypair.pubkey,
    created_at: created_at,
    tags: tags)
  result.updateID
  result.sign(keypair)

proc metadata*(name, about, picture: string, keypair: Keypair, created_at = getTime(), tags = TagTable()): Event =
  ## Describes the user who created the event.
  ## A relay may delete past metadata events once it gets a new one for the same pubkey.
  Event.init(0, Metadata(name: name, about: about, picture: picture).toJson, keypair, created_at, tags)
proc note*(content: string, keypair: Keypair, created_at = getTime(), tags = TagTable()): Event  =
  ## Plaintext note (anything the user wants to say). Markdown links ([]() stuff) are not plaintext.
  Event.init(1, content, keypair, created_at, tags)
proc recommendServer*(content: string, keypair: Keypair, created_at = getTime(), tags = TagTable()): Event =
  ## URL (e.g., wss://somerelay.com) of a relay the event creator wants to recommend to its followers.
  Event.init(2, content, keypair, created_at, tags)

template verify*(event: Event): bool =
  verify(event.sig, sha256(serialize event), event.pubkey)

proc stamp*(event: var Event, keypair: Keypair, rng: Rng = sysRng) =
  ## Change the author of an event
  event.pubkey = keypair.pubkey
  event.updateID
  event.sign(keypair.privkey, rng)

# Working with events

template anyIt(s, iter, pred: untyped): bool =
  ## Like `sequtil's` `anyIt`, except it accepts an `iter` argument to use for iterating over `s` rather than only using `items` .
  var result = false
  for it {.inject.} in iter(s):
    if pred:
      result = true
      break
  result

func matches*(event: Event, filter: Filter): bool =
  ## Determine if `event` matches `filter`.
  filter.since < event.created_at and event.created_at < filter.until and
  (filter.kinds == @[] or anyIt(filter.kinds, event.kind == it)) and
  (filter.ids == @[] or anyIt(filter.ids, event.id.`$`.startsWith it)) and
  (filter.authors == @[] or anyIt(filter.authors, event.pubkey.toHex.startsWith it)) and
  (filter.tags == default(TagTable) or anyIt(filter.tags, pairs, try: event.tags[(if likely it[0].len > 1 and it[0].startsWith('#'): it[0][1..^1] else: it[0])] == it[1] except KeyError: false))
