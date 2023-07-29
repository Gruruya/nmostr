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

## Utilities for creating and parsing Nostr messages.
## Implements NIP-01, NIP-20, NIP-42, NIP-45

import std/sysrand, pkg/[jsony, union, stew/byteutils]
import ./events, ./filters

export events, union

type
  # Use a variant object once they support duplicate fields
  CMEvent* = object   ## ["EVENT", <event JSON>]
    event*: Event
  CMRequest* = object ## ["REQ", <subscription_id>, <filters JSON>...]
    id*: string
    filter*: Filter
  CMClose* = object   ## ["CLOSE", <subscription_id>]
    id*: string
  CMAuth* = object    ## ["AUTH", <event kind 2242 JSON>]
    event*: Event
  CMCount* = object   ## ["COUNT", <subscription_id>, <filters JSON>]
    id*: string
    filter*: Filter

  SMEvent* = object   ## ["EVENT", <subscription_id>, <event JSON>]
    id*: string
    event*: Event
  SMNotice* = object  ## ["NOTICE", <message>]
    message*: string
  SMEose* = object    ## ["EOSE", <subscription_id>]
    id*: string
  SMOk* = object      ## ["OK", <event_id>, <true|false>, <message>]
    id*: string
    saved*: bool
    message*: string
  SMAuth* = object    ## ["AUTH", <challenge-string>]
    challenge*: string
  SMCount* = object   ## ["COUNT", <integer>]
    count*: int64

  ClientMessage* = CMEvent | CMRequest | CMClose | CMAuth | CMCount
  ServerMessage* = SMEvent | SMEose | SMNotice | SMOk | SMAuth | SMCount
  Message* = ClientMessage | ServerMessage

type UnknownMessageError* = object of ValueError

proc randomID*(): string {.raises: [OSError].} =
  ## Get a random ID to identify your messages
  toHex(urandom(32))
  
# JSON interop
# Modified `jsony.nim` procs to deserialize message arrays as object and serialize them back to arrays.

func parseArrayAsObject*[T](s: string, i: var int, v: var T) =
  ## Parse message array as its corresponding `Message` object.
  eatChar(s, i, '[')
  skipValue(s, i)
  for field in v.fields: # Every type is required to match in valid JSON or an error is raised, consider make this more forgiving
    eatChar(s, i, ',')
    parseHook(s, i, field)
  eatSpace(s, i)
  if likely s[i] == ']':
    inc(i)
  else:
    # Skip unused/invalid values
    var bracketCounter = 1
    while bracketCounter > 0 and i < s.len:
      eatSpace(s, i)
      case s[i]
      of ']':
        inc(i)
        bracketCounter -= 1
      of '[':
        inc(i)
        bracketCounter += 1
      of '\\':
        inc(i)
        if likely i < s.len: inc(i)
      of '"':
        inc(i)
        while true:
          if unlikely i >= s.len: break
          if s[i] == '"': inc(i); break
          if s[i] == '\\':
            inc(i)
            if likely i < s.len: inc(i)
          else: inc(i)
      else:
        inc(i)

func dumpObjectAsArray*[T](s: var string, v: T, flag: string) =
  ## Serialize message as an array with `flag` as the first element.
  s = "[\"" & flag & "\","
  var first = true
  for field in v.fields:
    if first: first = false
    else: s &= ","
    s &= field.toJson
  s &= ']'

{.push inline.}

func parseHook*(s: string, i: var int, v: var CMEvent) =
  parseArrayAsObject(s, i, v)
func parseHook*(s: string, i: var int, v: var CMRequest) =
  parseArrayAsObject(s, i, v)
func parseHook*(s: string, i: var int, v: var CMClose) =
  parseArrayAsObject(s, i, v)
func parseHook*(s: string, i: var int, v: var CMAuth) =
  parseArrayAsObject(s, i, v)
func parseHook*(s: string, i: var int, v: var CMCount) =
  parseArrayAsObject(s, i, v)
func parseHook*(s: string, i: var int, v: var SMEvent) =
  parseArrayAsObject(s, i, v)
func parseHook*(s: string, i: var int, v: var SMNotice) =
  parseArrayAsObject(s, i, v)
func parseHook*(s: string, i: var int, v: var SMEose) =
  parseArrayAsObject(s, i, v)
func parseHook*(s: string, i: var int, v: var SMOk) =
  parseArrayAsObject(s, i, v)
func parseHook*(s: string, i: var int, v: var SMAuth) =
  parseArrayAsObject(s, i, v)
func parseHook*(s: string, i: var int, v: var SMCount) =
  parseArrayAsObject(s, i, v)

func dumpHook*(s: var string, v: CMEvent) =
  dumpObjectAsArray(s, v, "EVENT")
func dumpHook*(s: var string, v: CMRequest) =
  dumpObjectAsArray(s, v, "REQ")
func dumpHook*(s: var string, v: CMClose) =
  dumpObjectAsArray(s, v, "CLOSE")
func dumpHook*(s: var string, v: CMAuth) =
  dumpObjectAsArray(s, v, "AUTH")
func dumpHook*(s: var string, v: CMCount) =
  dumpObjectAsArray(s, v, "COUNT")
func dumpHook*(s: var string, v: SMEvent) =
  dumpObjectAsArray(s, v, "EVENT")
func dumpHook*(s: var string, v: SMNotice) =
  dumpObjectAsArray(s, v, "NOTICE")
func dumpHook*(s: var string, v: SMEose) =
  dumpObjectAsArray(s, v, "EOSE")
func dumpHook*(s: var string, v: SMOk) =
  dumpObjectAsArray(s, v, "OK")
func dumpHook*(s: var string, v: SMAuth) =
  dumpObjectAsArray(s, v, "AUTH")
func dumpHook*(s: var string, v: SMCount) =
  dumpObjectAsArray(s, v, "COUNT")

{.pop inline.}

func parseHook*(s: string, i: var int, v: var union(Message)) =
  ## Parses a message of unknown type into the `Message` object inferred by the array's first element and shape.
  template parseAs(T: typedesc): union(Message) =
    i = start
    var j: T
    s.parseHook(i, j)
    j as union(Message)

  let start = i
  eatChar(s, i, '[')
  var kind: string
  parseHook(s, i, kind)
  case kind
  of "EVENT":
    eatChar(s, i, ',')
    eatSpace(s, i)
    # Check if the second element in the array is an object or a string.
    if s[i] == '{':
      v = parseAs(CMEvent)
    elif s[i] == '"':
      v = parseAs(SMEvent)
    else: raise newException(jsony.JsonError, "Expected { or \" after \"EVENT\", but got " & s[i] & " instead. At offset: " & $i)
  of "REQ":
    v = parseAs(CMRequest)
  of "CLOSE":
    v = parseAs(CMClose)
  of "EOSE":
    v = parseAs(SMEose)
  of "NOTICE":
    v = parseAs(SMNotice)
  of "OK":
    v = parseAs(SMOk)
  of "AUTH":
    eatChar(s, i, ',')
    eatSpace(s, i)
    if s[i] == '{':
      v = parseAs(CMAuth)
    elif s[i] == '"':
      v = parseAs(SMAuth)
    else: raise newException(jsony.JsonError, "Expected { or \" after \"AUTH\", but got " & s[i] & " instead. At offset: " & $i)
  of "COUNT":
    eatChar(s, i, ',')
    eatSpace(s, i)
    if s[i] == '"':
      v = parseAs(CMCount)
    else: # It should be a number, `in {0..9}`
      v = parseAs(SMCount)
  else:
    raise newException(UnknownMessageError, "Unknown message starting with \"" & kind & "\"")

func fromMessage*(s: string): union(Message) {.inline.} =
  ## Alias for s.fromJson(union(Message))
  s.fromJson(union(Message))

func dumpHook*(s: var string, v: union(Message)) {.inline.} =
  ## Serialize message union as its contained message.
  unpack v, msg:
    dumpHook(s, msg)
