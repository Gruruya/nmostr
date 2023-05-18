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

runnableExamples:
  echo note(newKeypair(), "hello world!").toJson

import
  std/[times, strutils, sequtils, macros, sugar],
  pkg/[jsony, crunchy, stew/byteutils],
  ./keys

export jsony, times, keys

{.push raises: [].}

# Types

type EventID* = object
  bytes*: array[32, byte]

func `$`*(id: EventID): string {.inline.} = toHex(id.bytes)
func toHex*(id: EventID): string {.inline.} = $id
func fromHex*(T: type EventID, hex: string): EventID {.inline, raises: [ValueError].} =
  EventID(bytes: array[32, byte].fromHex(hex))

type Event* = object
  pubkey*: PublicKey        ## 32-bytes lowercase hex-encoded public key of the event creator
  id*: EventID              ## 32-bytes lowercase hex-encoded sha256 of the serialized event data
  kind*: int                ## The type of event this is.
  content*: string          ## Arbitrary string, what it is should be gleamed from this event's `kind`
  created_at*: Time         ## Received and transmitted as a Unix timestamp in seconds
  tags*: seq[seq[string]]   ## A sequence of tags. This first item is the key and the rest is the content.
  sig*: SchnorrSignature    ## 64-bytes hex of the signature of the sha256 hash of the serialized event data, which is the same as the "id" field

type Filter* = object
  ids*: seq[string]       ## List of event ids or prefixes.
  authors*: seq[string]   ## List of pubkeys or prefixes, the pubkey of an event must be one of these.
  kinds*: seq[int]        ## A list of event kinds.
  tags*: seq[seq[string]] ## A sequence of tags. This first item is the key and the rest is the content.
  since*: Time            ## Events must be newer than this to pass.
  until*: Time = initTime(high(int64), 0)  ## Events must be older than this to pass.
  limit*: int             ## Maximum number of events to be returned in the initial query.

type Metadata* = object ## Content of kind 0 (metadata) event
  name*: string    ## username
  about*: string   ## description
  picture*: string ## url

# JSON interop

func parseHook*(s: string, i: var int, v: var EventID) {.inline, raises: [JsonError, ValueError].} =
  ## Parse `id` as a hexadecimal encoding [of a sha256 hash.]
  var j: string
  parseHook(s, i, j)
  v = EventID.fromHex j

func parseHook*(s: string, i: var int, v: var PublicKey) {.inline, raises: [JsonError, ValueError].} =
  ## Parse `id` as a hexadecimal encoding [of a sha256 hash].
  var j: string
  parseHook(s, i, j)
  # WARNING: Silently failing, replacing incorrect with nulled pubkeys
  v = (PublicKey.fromHex j).valueOr: default(typeof v)

func parseHook*(s: string, i: var int, v: var SchnorrSignature) {.inline, raises: [JsonError, ValueError].} =
  ## Parse `id` as a hexadecimal encoding [of a sha256 hash.]
  var j: string
  parseHook(s, i, j)
  # WARNING: Silently failing, replacing incorrect with nulled signature
  v = (SchnorrSignature.fromHex j).valueOr: default(typeof v)

func dumpHook*(s: var string, v: EventID | PublicKey | SchnorrSignature) {.inline.} =
  ## Serialize `id`, `pubkey`, and `sig` into hexadecimal.
  dumpHook(s, v.toHex)

func parseHook*(s: string, i: var int, v: var Time) {.inline, raises: [JsonError, ValueError].} =
  ## Parse `created_at` as a `Time`.
  var j: int64
  parseHook(s, i, j)
  v = fromUnix(j)

func dumpHook*(s: var string, v: Time) {.inline.} =
  ## Serialize `created_at` into a Unix timestamp.
  dumpHook(s, v.toUnix)

macro fieldAccess(o: object, s: string): untyped =
  newDotExpr(o, newIdentNode(s.strVal))

proc parseHook*(s: string, i: var int, v: var Filter) {.raises: [JsonError, ValueError].} =
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
  v.until = Filter().until
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
      v.tags.add key & j
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

proc dumpHook*(s: var string, v: Filter) {.raises: [JsonError, ValueError].} =
  ## Dump filters exactly the same as a normal object, but empty fields are left out and its `tags` are split into seperate fields.
  template dumpKey(s: var string, v: string) =
    ## Taken from `jsony.nim`
    const v2 = v.toJson() & ":"
    s.add v2

  var i = 1
  s.add '{'
  for k, e in v.fieldPairs:
    if e != default(Filter).fieldAccess(k) and (when k == "until": e.toUnix != high(int64) else: true): # Complex way of checking if the field is empty
      if i > 1: s.add ','
      s.dumpKey(k)
      s.dumpHook(e)
      inc i
    else:
      skipValue(s, i)
  s.add '}'

# End of JSON interop

func serialize*(e: Event): string =
  ## Serialize `event` into JSON so that it can be hashed in accordance with NIP-01.
  "[0," & e.pubkey.toJson & "," & e.created_at.toJson & "," & e.kind.toJson & "," & e.tags.toJson & "," & e.content.toJson & "]"

proc sign*(event: var Event, sk: SecretKey, rng: Rng = sysRng) {.raises: [ValueError].} =
  let sig = signSchnorr(sk, event.serialize.sha256, rng)
  if likely sig.isOk: event.sig = sig.unsafeGet
  else: raise newException(ValueError, $sig.error())

proc sign*(event: var Event, sk: Keypair, rng: Rng = sysRng) {.inline, raises: [ValueError].} =
  sign(event, sk.seckey, rng)

proc updateID*(event: var Event) =
  event.id = EventID(bytes: sha256 event.serialize)

proc init*(T: type Event, kind: int, content: string, keypair: Keypair, created_at = getTime(), tags = default(seq[seq[string]])): Event {.raises: [ValueError].} =
  result = Event(
    kind: kind,
    content: content,
    pubkey: keypair.pubkey,
    created_at: created_at,
    tags: tags)
  result.updateID
  result.sign(keypair)

proc metadata*(keypair: Keypair, name, about, picture: string, created_at = getTime(), tags = default(Event.tags)): Event {.inline, raises: [ValueError].} =
  ## Describes the user who created the event.
  ## A relay may delete past metadata events once it gets a new one for the same pubkey.
  Event.init(0, Metadata(name: name, about: about, picture: picture).toJson, keypair, created_at, tags)

proc note*(keypair: Keypair, content: string, created_at = getTime(), tags = default(Event.tags)): Event {.inline, raises: [ValueError].} =
  ## Plaintext note (anything the user wants to say). Markdown links ([]() stuff) are not plaintext.
  Event.init(1, content, keypair, created_at, tags)

proc recommendServer*(keypair: Keypair, url: string, created_at = getTime(), tags = default(Event.tags)): Event {.inline, raises: [ValueError].} =
  ## URL (e.g., wss://somerelay.com) of a relay the event creator wants to recommend to its followers.
  Event.init(2, url, keypair, created_at, tags)

proc verify*(event: Event): bool {.inline.} =
  verify(event.sig, sha256(serialize event), event.pubkey)

proc stamp*(event: var Event, keypair: Keypair, rng: Rng = sysRng) {.raises: [ValueError].} =
  ## Change the author of an event
  event.pubkey = keypair.pubkey
  event.updateID
  event.sign(keypair.seckey, rng)

# Working with events

func stripGeneric(tag: string): string {.inline.} =
  if likely tag.len > 1 and likely tag[0] == '#': tag[1..^1]
  else: tag

func matches*(event: Event, filter: Filter): bool =
  ## Determine if `event` matches `filter`.
  filter.since < event.created_at and event.created_at < filter.until and
  (filter.kinds == @[] or anyIt(filter.kinds, event.kind == it)) and
  (filter.ids == @[] or anyIt(filter.ids, event.id.`$`.startsWith it)) and
  (filter.authors == @[] or anyIt(filter.authors, event.pubkey.toHex.startsWith it)) and
  (filter.tags == @[] or any(filter.tags, ftags => likely ftags.len > 1 and any(event.tags, etags => likely etags.len > 1 and etags[0] == ftags[0].stripGeneric and etags[1] == ftags[1])))
