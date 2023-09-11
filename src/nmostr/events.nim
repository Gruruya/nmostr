## Nostr event interface - for nmostr.
# Copyright © 2023 Gruruya <gruruya.chi4c@slmails.com>
# SPDX-License-Identifier: AGPL-3.0-only

import ./[hexobjs, keys],
       pkg/jsony,
       std/[times, strutils, options, macros]
import pkg/crunchy except toHex

export times, keys, jsony, hexobjs, options
{.push inline.}


type Event* = object
  id*: EventID            ## 32-bytes lowercase hex-encoded sha256 of the serialized event data
  pubkey*: PublicKey      ## 32-bytes lowercase hex-encoded public key of the event creator
  kind*: int              ## The type of event this is.
  content*: string        ## Arbitrary string, what it is should be gleamed from this event's `kind`
  tags*: seq[seq[string]] ## A sequence of tags. This first item is the key and the rest is the content.
  created_at*: Time       ## Received and transmitted as a Unix timestamp in seconds
  sig*: SchnorrSig  ## 64-bytes hex of the signature of the sha256 hash of the serialized event data, which is the same as the "id" field


func parseHook*(s: string, i: var int, v: var EventID) =
  ## Parse `id` as a hexadecimal encoding [of a sha256 hash.]
  var j: string = ""
  parseHook(s, i, j)
  v = EventID.fromHex(j)

func dumpHook*(s: var string, v: EventID) =
  ## Serialize `id`, `pubkey`, and `sig` into hexadecimal.
  dumpHook(s, v.toHex)

func parseHook*(s: string, i: var int, v: var Time) =
  ## Parse `created_at` as a `Time`.
  var j: int64 = 0
  parseHook(s, i, j)
  v = fromUnix(j)

func dumpHook*(s: var string, v: Time) =
  ## Serialize `created_at` into a Unix timestamp.
  dumpHook(s, v.toUnix)


func serialize*(e: Event): string =
  ## Serialize `event` into JSON so that it can be hashed in accordance with NIP-01.
  "[0," & e.pubkey.toJson & ',' & e.created_at.toJson & ',' & e.kind.toJson & ',' & e.tags.toJson & ',' & e.content.toJson & ']'

proc updateID*(event: var Event) =
  event.id = EventID.fromBytes(sha256(serialize event))

proc sign*(event: var Event, key: SecretKey, rng: Rng = sysRng) =
  event.sig = signSchnorr(key, sha256(serialize event), rng)

template sign*(event: var Event, keypair: Keypair, rng: Rng = sysRng) =
  sign(event, keypair.seckey, rng)

proc stamp*(event: var Event, keypair: Keypair, rng: Rng = sysRng) =
  ## Change the author of an event
  event.pubkey = keypair.pubkey
  event.updateID
  event.sign(keypair.seckey, rng)

proc verify*(event: Event): bool =
  verify(event.sig, sha256(serialize event), event.pubkey)

template getUnixTime(): Time =
  initTime(getTime().toUnix, 0)

proc init*(T: typedesc[Event]; kind: int; keypair: Keypair; content: string; tags = default(seq[seq[string]]); created_at = getUnixTime()): Event =
  result = Event(kind: kind, content: content, pubkey: keypair.pubkey, tags: tags, created_at: created_at)
  result.updateID
  result.sign(keypair)

# Convenience wrappers around Event.init
type Metadata* = object ## Content of kind 0 (metadata) event
  name*: string         ## username
  about*: string        ## description
  picture*: string      ## url

proc metadata*(keypair: Keypair, name, about, picture: string, tags = default(Event.tags), created_at = getUnixTime()): Event =
  ## Describes the user who created the event.
  ## A relay may delete past metadata events once it gets a new one for the same pubkey.
  Event.init(0, keypair, Metadata(name: name, about: about, picture: picture).toJson, tags, created_at)

proc note*(keypair: Keypair, content: string, tags = default(Event.tags), created_at = getUnixTime()): Event =
  ## Plaintext note (anything the user wants to say). Markdown links ([]() stuff) are not plaintext.
  Event.init(1, keypair, content, tags, created_at)

proc article*(keypair: Keypair, content, d: string, tags: sink seq[seq[string]] = default(Event.tags), created_at = getUnixTime()): Event =
  ## Long-form text formatted in markdown. Parameterized replaceable event.
  tags.add @["d", d]
  Event.init(30023, keypair, content, tags, created_at)


func getParameterizedID*(tags: openArray[seq[string]]): Option[string] =
  ## Get the first value of any "d" tag from a sequence of tags.
  for tag in tags:
    if tag.len >= 1 and tag[0] == "d":
      if unlikely tag.len == 1: return some ""
      else: return some tag[1]
  result = none string

template getParameterizedID*(event: Event): Option[string] =
  ## Get the first value of any "d" tag from an event's tags.
  getParameterizedID(event.tags)
