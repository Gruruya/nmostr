## Nostr filter handling - for nmostr.
# Copyright © 2023 Gruruya <gruruya.chi4c@slmails.com>
# SPDX-License-Identifier: AGPL-3.0-only
#
# This file incorporates work covered by the following copyright:
#   Copyright © 2020-2023 Andre von Houck
#   SPDX-License-Identifier: MIT

import ./events, pkg/jsony, std/[times, strutils, sequtils, macros]
import std/json except JsonError

export events


type Filter* = object
  ids*: seq[StackString[64]]     ## List of event ids or prefixes.
  authors*: seq[StackString[64]] ## List of pubkeys or prefixes, the pubkey of an event must be one of these.
  kinds*: seq[int]        ## A list of event kinds.
  since*: Time            ## Events must be newer than this to pass.
  until*: Time = initTime(high(int64), 0)  ## Events must be older than this to pass.
  limit*: int             ## Maximum number of events to be returned in the initial query.
  tags*: seq[seq[string]] ## NIP-12 tags (like #e or #p), each sequence's first item is the key and the others its values "0": ["1", "2"]
  search*: string         ## A query in a human-readable form (NIP-50)
  other*: seq[(string, JsonNode)] ## Catch-all for unknown fields


func isGenericTag(key: string): bool {.inline.} =
  ## Checks if a filter's key is a generic tag query according to NIP-12
  key.len == 2 and key[0] == '#' and likely key[1] in Letters

func tagsMatch(filterTags, eventTags: seq[seq[string]]): bool =
  func genericTagsMatch(ftag, etag: seq[string]): bool =
    result = false
    if etag[0].len == 1 and ftag[0][1] == etag[0][0]:
      if ftag.len == 1 or ftag.len == 2 and ftag[1] == "": return true
      if etag.len == 1: return false
      for value in ftag[1..^1]:
        if etag[1] == value: return true

  result = false
  for tag in filterTags:
    if tag[0].isGenericTag:
      if anyIt(eventTags, genericTagsMatch(tag, it)): return true

func matches*(event: Event, filter: Filter): bool =
  ## Determine if `event` matches `filter`.
  filter.since <= event.created_at and
  filter.until >= event.created_at and
  (filter.kinds.len == 0 or anyIt(filter.kinds, event.kind == it)) and
  (filter.ids.len == 0 or contains(filter.ids, event.id.toHex)) and
  (filter.authors.len == 0 or contains(filter.authors, event.pubkey.toHex)) and
  (filter.tags.len == 0 or tagsMatch(filter.tags, event.tags))


# JSON interop
proc parseHook*(s: string, i: var int, v: var Filter) =
  ## Parse filters exactly the same as a normal object, but add each field starting with # as an entry in `tags`.
  # Taken from `jsony <https://github.com/treeform/jsony/blob/master/src/jsony.nim>`_
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
  v.until = static: default(Filter).until
  while i < s.len:
    eatSpace(s, i)
    if i < s.len and s[i] == '}':
      break
    var key: string = ""
    parseHook(s, i, key)
    eatChar(s, i, ':')
    when compiles(renameHook(v, key)):
      renameHook(v, key)
    var parsed = false
    for k, v in v.fieldPairs:
      if k == key:
        parseHook(s, i, v)
        parsed = true
        break
    if not parsed:
      eatSpace(s, i)
      if likely i < s.len:
        if s[i] == '[' and key.isGenericTag:
          var j: seq[string] = @[]
          parseHook(s, i, j)
          v.tags.add key & j
        else:
          var j: JsonNode = nil
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

proc dumpHook*(s: var string, v: Filter) =
  ## Dump filters exactly the same as a normal object, but empty fields are left out and its `tags` are split into seperate fields.
  # Taken from `jsony <https://github.com/treeform/jsony/blob/master/src/jsony.nim>`_
  template dumpKey(s: var string, v: string) =
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
          except Exception: raiseAssert "cannot happen"
          inc i
        else:
          skipValue(s, i)
    else:
      # Complex way of checking if the field shouldn't be output/is "empty"
      macro fieldAccess(o: object, s: string): untyped {.used.} =
        newDotExpr(o, newIdentNode(s.strVal))
      if (when k == "until": e.toUnix != high(int64) else: e != default(Filter).fieldAccess(k)):
        if i > 1: s.add ','
        s.dumpKey(k)
        s.dumpHook(e)
        inc i
  s.add '}'


when isMainModule:
  let e = note(Keypair.random(), "test", tags = @[@["e", "not empty"]])
  var f = Filter(ids: @[e.id.toHex], authors: @[e.pubkey.toHex], kinds: @[1], tags: @[@["#e", "not in event", "not empty"]], search: "", other: @[])
  doAssert e.matches(f)

