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

import
  times, strutils, macros,
  pkg/[jsony, crunchy, stew/byteutils],
  ./keys

export times, keys, jsony

{.push raises: [].}

# Types

type EventID* = object
  bytes*: array[32, byte]

func `$`*(id: EventID): string {.inline.} = toHex(id.bytes)
func toHex*(id: EventID): string {.inline.} = $id
func fromHex*(T: type EventID, hex: string): EventID {.inline, raises: [ValueError].} = EventID(bytes: array[32, byte].fromHex(hex))

type Event* = object
  pubkey*: PublicKey      ## 32-bytes lowercase hex-encoded public key of the event creator
  id*: EventID            ## 32-bytes lowercase hex-encoded sha256 of the serialized event data
  kind*: int              ## The type of event this is.
  content*: string        ## Arbitrary string, what it is should be gleamed from this event's `kind`
  created_at*: Time       ## Received and transmitted as a Unix timestamp in seconds
  tags*: seq[seq[string]] ## A sequence of tags. This first item is the key and the rest is the content.
  sig*: SchnorrSignature  ## 64-bytes hex of the signature of the sha256 hash of the serialized event data, which is the same as the "id" field

func parseHook*(s: string, i: var int, v: var EventID) {.inline, raises: [JsonError, ValueError].} =
  ## Parse `id` as a hexadecimal encoding [of a sha256 hash.]
  var j: string
  parseHook(s, i, j)
  v = EventID.fromHex j

func dumpHook*(s: var string, v: EventID) {.inline.} =
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

func serialize*(e: Event): string =
  ## Serialize `event` into JSON so that it can be hashed in accordance with NIP-01.
  "[0," & e.pubkey.toJson & "," & e.created_at.toJson & "," & e.kind.toJson & "," & e.tags.toJson & "," & e.content.toJson & "]"

proc sign*(event: var Event, sk: SecretKey, rng: Rng = sysRng) {.raises: [ValueError].} =
  let sig = signSchnorr(sk, sha256(serialize event), rng)
  if likely sig.isOk: event.sig = sig.unsafeGet
  else: raise newException(ValueError, $sig.error())

proc sign*(event: var Event, sk: Keypair, rng: Rng = sysRng) {.inline, raises: [ValueError].} =
  sign(event, sk.seckey, rng)

proc updateID*(event: var Event) =
  event.id = EventID(bytes: sha256(serialize event))

proc verify*(event: Event): bool {.inline.} =
  verify(event.sig, sha256(serialize event), event.pubkey)

proc stamp*(event: var Event, keypair: Keypair, rng: Rng = sysRng) {.raises: [ValueError].} =
  ## Change the author of an event
  event.pubkey = keypair.pubkey
  event.updateID
  event.sign(keypair.seckey, rng)

proc init*(T: type Event, kind: int, content: string, keypair: Keypair, created_at = getTime(), tags = default(seq[seq[string]])): Event {.raises: [ValueError].} =
  result = Event(kind: kind, content: content, pubkey: keypair.pubkey, created_at: created_at, tags: tags)
  result.updateID
  result.sign(keypair)

type Metadata* = object ## Content of kind 0 (metadata) event
  name*: string         ## username
  about*: string        ## description
  picture*: string      ## url

proc metadata*(keypair: Keypair, name, about, picture: string, tags = default(Event.tags), created_at = getTime()): Event {.inline, raises: [ValueError].} =
  ## Describes the user who created the event.
  ## A relay may delete past metadata events once it gets a new one for the same pubkey.
  Event.init(0, Metadata(name: name, about: about, picture: picture).toJson, keypair, created_at, tags)

proc note*(keypair: Keypair, content: string, tags = default(Event.tags), created_at = getTime()): Event {.inline, raises: [ValueError].} =
  ## Plaintext note (anything the user wants to say). Markdown links ([]() stuff) are not plaintext.
  Event.init(1, content, keypair, created_at, tags)

proc recommendServer*(keypair: Keypair, url: string, tags = default(Event.tags), created_at = getTime()): Event {.inline, raises: [ValueError].} =
  ## URL (e.g., wss://somerelay.com) of a relay the event creator wants to recommend to its followers.
  Event.init(2, url, keypair, created_at, tags)

proc article*(keypair: Keypair, content, d: string, tags: sink seq[seq[string]] = default(Event.tags), created_at = getTime()): Event {.inline, raises: [ValueError].} =
  ## Long-form text formatted in markdown.
  tags.add @["d", d]
  Event.init(30023, content, keypair, created_at, tags)
