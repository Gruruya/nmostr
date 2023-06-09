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

## Nostr filters and utilities for using them.

import std/[times, strutils, sequtils, sugar, macros]
import std/json except JsonError
import pkg/jsony
import ./events
export events

{.push raises: [].}

type Filter* = object
  ids*: seq[string]       ## List of event ids or prefixes.
  authors*: seq[string]   ## List of pubkeys or prefixes, the pubkey of an event must be one of these.
  kinds*: seq[int]        ## A list of event kinds.
  since*: Time            ## Events must be newer than this to pass.
  until*: Time = initTime(high(int64), 0)  ## Events must be older than this to pass.
  limit*: int             ## Maximum number of events to be returned in the initial query.
  search*: string         ## A query in a human-readable form (NIP-50)
  tags*: seq[seq[string]] ## NIP-12 tags (like #e or #p), each sequence's first item is the key and the others its values "0": ["1", "2"]
  other*: seq[(string, JsonNode)] ## Catch-all for unknown fields

func stripGeneric(tag: string): string {.inline.} =
  if likely tag.len > 1 and likely tag[0] == '#': tag[1..^1]
  else: tag

func matches*(event: Event, filter: Filter): bool =
  ## Determine if `event` matches `filter`.
  filter.since < event.created_at and
  filter.until > event.created_at and
  (filter.kinds == @[] or anyIt(filter.kinds, event.kind == it)) and
  (filter.ids == @[] or anyIt(filter.ids, event.id.`$`.startsWith it)) and
  (filter.authors == @[] or anyIt(filter.authors, event.pubkey.toHex.startsWith it)) and
  (filter.tags == @[] or any(filter.tags, ftags => likely ftags.len > 1 and any(event.tags, etags => likely etags.len > 1 and etags[0] == ftags[0].stripGeneric and etags[1] == ftags[1])))

# JSON interop
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
    var parsed = false
    for k, v in v.fieldPairs:
      if k == key:
        var v2: type(v)
        parseHook(s, i, v2)
        v = v2
        parsed = true
        break
    if not parsed:
      eatSpace(s, i)
      if likely i < s.len:
        if s[i] == '[' and key.len == 2 and key[0] == '#':
          var j: seq[string]
          parseHook(s, i, j)
          v.tags.add key & j
        else:
          var j: JsonNode
          parseHook(s, i, j)
          v.other.add (key, j)
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
  for k, e in fieldPairs(v):
    when k == "tags":
      for tag in e:
        if tag.len >= 1:
          if i > 1: s.add ','
          s.add tag[0].toJson & ':'
          if tag.len >= 2:
            s.dumpHook(tag[1..^1])
          else:
            s.add "[]"
            i += 2
          inc i
        else:
          skipValue(s, i)
    elif k == "other":
      for kv in e:
        if likely kv[0].len > 0:
          if i > 1: s.add ','
          s.add kv[0].toJson & ':'
          try: s.dumpHook(kv[1])
          except Exception: assert false, "cannot happen"
          inc i
        else:
          skipValue(s, i)
    else:
      if e != default(Filter).fieldAccess(k) and (when k == "until": e.toUnix != high(int64) else: true): # Complex way of checking if the field is empty
        if i > 1: s.add ','
        s.dumpKey(k)
        s.dumpHook(e)
        inc i
  s.add '}'
