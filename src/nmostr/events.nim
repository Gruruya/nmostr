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

import std/[times, strutils, sequtils]
import pkg/[jsony, adix/lptabz]

export jsony, times, lptabz

template anyIt(s, iter, pred: untyped): bool =
  ## Like `sequtil's` `anyIt`, except it accepts an `iter` argument to use for iterating over `s` rather than only using `items` .
  var result = false
  for it {.inject.} in iter(s):
    if pred:
      result = true
      break
  result

# Types

const TagTableHashcodeBits* = 8 ## A higher number such as 8 means more memory usage and faster lookups
type TagTable* = LPTabz[string, seq[string], int8, TagTableHashcodeBits] ## A Table containing tags, translated to use the first element as the index.
## A tag could be any of the following:
##
## NIP-01:
## * \["e", <32-bytes hex of the id of another event>, <recommended relay URL>]
## * \["p", <32-bytes hex of a pubkey>, <recommended relay URL>]

template initTagTable*(initialSize=lpInitialSize, numer=lpNumer, denom=lpDenom, minFree=lpMinFree, growPow2=lpGrowPow2, rehash=lpRehash, robinhood=lpRobinHood): TagTable =
  initLPTabz[string, seq[string], int8, TagTableHashcodeBits](initialSize, numer, denom, minFree, growPow2, rehash, robinhood)

template toTagTable*(pairs: openArray[(string, seq[string])], dups = false): untyped {.dirty.} =
  toLPTabz[string, seq[string], int8, TagTableHashcodeBits](pairs, dups)

type EventKind* = enum
  metadata,       ## Indicates the content is set to a stringified JSON object {name: <username>, about: <string>, picture: <url, string>} describing the user who created the event.
                  ## A relay may delete past metadata events once it gets a new one for the same pubkey.
  shortTextNote,  ## Indicates the content is set to the plaintext content of a note (anything the user wants to say). Markdown links ([]() stuff) are not plaintext.
  recommendServer ## Indicates the content is set to the URL (e.g., wss://somerelay.com) of a relay the event creator wants to recommend to its followers.

type Event* = object
  id*: string       ## 32-bytes lowercase hex-encoded sha256 of the serialized event data
  pubkey*: string   ## 32-bytes lowercase hex-encoded public key of the event creator
  kind*: EventKind  ## The type of event this is. See `EventKind` for what an event can be.
  tags*: TagTable   ## A table of tags. See `TagTable` for what a tag could be.
  created_at*: Time ## Received and transmitted as a Unix timestamp in seconds
  content*: string  ## Arbitrary string, what it is should be gleamed from this event's `kind`
  sig*: string      ## 64-bytes hex of the signature of the sha256 hash of the serialized event data, which is the same as the "id" field

type Filter* = object
  ids*: seq[string]      ## List of event ids or prefixes.
  authors*: seq[string]  ## List of pubkeys or prefixes, the pubkey of an event must be one of these.
  kinds*: seq[EventKind] ## A list of event kinds. See `EventKind` for what an event can be.
  tags*: TagTable        ## A table of tags. The tag's value must match exactly. See `TagTable` for what a tag could be.
  since*: Time           ## Events must be newer than this to pass.
  until*: Time = initTime(high(int64), 0)  ## Events must be older than this to pass.
  limit*: int            ## Maximum number of events to be returned in the initial query.

# JSON interop

# Optimization
{.push inline.}

func dumpHook*(s: var string, v: EventKind) =
  ## Parse `kind` as its corresponding number.
  dumpHook(s, ord(v))

func parseHook*(s: string, i: var int, v: var Time) =
  ## Parse `created_at` as a `Time`.
  var j: int64
  parseHook(s, i, j)
  v = fromUnix(j)

func dumpHook*(s: var string, v: Time) =
  ## Send `created_at` as a Unix timestamp.
  dumpHook(s, v.toUnix)

proc parseHook*(s: string, i: var int, v: var TagTable) =
  ## Parse tags as a table.
  var j: seq[seq[string]]
  parseHook(s, i, j)
  v = initTagTable(j.len)
  for tag in j:
    v.add(tag[0], tag[1..^1])

func dumpHook*(s: var string, v: TagTable) =
  ## Send tags as an JSON array of arrays.
  var j = newSeqOfCap[seq[string]](v.len)
  for key, value in v.pairs:
    j.add (key & value)
  dumpHook(s, j)

{.pop inline.}

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
    if key[0] == '#':
      # Parses each field that starts with a # as an entry in a `TagTable`
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

import std/macros

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

# Working with events

func matches*(event: Event, filter: Filter): bool =
  ## Determine if `event` matches `filter`.
  filter.since < event.created_at and event.created_at < filter.until and
  (filter.kinds == @[] or anyIt(filter.kinds, event.kind == it)) and
  (filter.ids == @[] or anyIt(filter.ids, event.id.startsWith it)) and
  (filter.authors == @[] or anyIt(filter.authors, event.pubkey.startsWith it)) and
  (filter.tags == default(TagTable) or anyIt(filter.tags, pairs, try: event.tags[it[0]] == it[1] except KeyError: false))

#func serialize*(
