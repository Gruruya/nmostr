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

import std/[strutils, sequtils, sugar, macros]
import ./events
export events

{.push raises: [].}

type Filter* = object
  ids*: seq[string]       ## List of event ids or prefixes.
  authors*: seq[string]   ## List of pubkeys or prefixes, the pubkey of an event must be one of these.
  kinds*: seq[int]        ## A list of event kinds.
  tags*: seq[seq[string]] ## A sequence of tags. This first item is the key and the rest is the content.
  since*: Time            ## Events must be newer than this to pass.
  until*: Time = initTime(high(int64), 0)  ## Events must be older than this to pass.
  limit*: int             ## Maximum number of events to be returned in the initial query.

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
