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

import pkg/[jsony, union]
import ./events

export events, union

# Types

type
  Message* = object of RootObj
  # Use a variant object once they support duplicate fields
  ClientMessage* = object of Message
  ServerMessage* = object of Message

  CMEvent* = object of ClientMessage   ## ["EVENT", <event JSON>]
    event*: Event
  CMRequest* = object of ClientMessage ## ["REQ", <subscription_id>, <filters JSON>...]
    id*: string                        ## TODO: Find out wtf `...` means
    filter*: Filter
  CMClose* = object of ClientMessage   ## ["CLOSE", <subscription_id>]
    id*: string
  CMAuth* = object of ServerMessage    ## ["AUTH", <event kind 2242 JSON>]
    event*: Event
  CMCount* = object of ClientMessage   ## ["COUNT", <subscription_id>, <filters JSON>]
    id*: string
    filter*: Filter

  SMEvent* = object of ServerMessage   ## ["EVENT", <subscription_id>, <event JSON>]
    id*: string
    event*: Event
  SMNotice* = object of ServerMessage  ## ["NOTICE", <message>]
    message*: string
  SMEose* = object of ServerMessage    ## ["EOSE", <subscription_id>]
    id*: string
  SMOk* = object of ServerMessage      ## ["OK", <event_id>, <true|false>, <message>]
    id*: string
    saved*: bool
    message*: string
  SMAuth* = object of ServerMessage    ## ["AUTH", <challenge-string>]
    challenge*: string
  SMCount* = object of ServerMessage   ## ["COUNT", <integer>]
    count*: int64

  ClientMessageClass = (CMEvent | CMRequest | CMClose | CMAuth | CMCount)
  ServerMessageClass = (SMEvent | SMEose | SMNotice | SMOk | SMAuth | SMCount)
  MessageClass = (ClientMessageClass | ServerMessageClass)

type UnknownMessageError* = object of ValueError

# JSON interop

template parseArrayAsObject(T: typedesc) =
  ## Parse JSON array as object `T`.
  proc parseHook*(s: string, i: var int, v: var T) =
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

template dumpObjectAsArray(T: typedesc, flag: string) =
  func dumpHook*(s: var string, v: T) {.inline.} =
    ## Send message as an array with `flag` as the first element.
    s = "[\"" & flag & "\","
    for field in v.fields:
      s &= field.toJson
      s &= ","
    s.setLen(s.len - 1)
    s &= "]"

template setupArrayObjectParsing(T: typedesc, flag: string) =
  parseArrayAsObject(T)
  dumpObjectAsArray(T, flag)

setupArrayObjectParsing(CMEvent, "EVENT")
setupArrayObjectParsing(CMRequest, "REQ")
setupArrayObjectParsing(CMClose, "CLOSE")
setupArrayObjectParsing(CMAuth, "AUTH")
setupArrayObjectParsing(CMCount, "COUNT")
setupArrayObjectParsing(SMEvent, "EVENT")
setupArrayObjectParsing(SMEose, "EOSE")
setupArrayObjectParsing(SMNotice, "NOTICE")
setupArrayObjectParsing(SMOk, "OK")
setupArrayObjectParsing(SMAuth, "AUTH")
setupArrayObjectParsing(SMCount, "COUNT")

proc parseHook*(s: string, i: var int, v: var union(MessageClass)) =
  ## Parses a message of unknown type into the `Message` object inferred by the array's first element and shape.
  template parseAs(T: typedesc): union(MessageClass) =
    i = start
    var j: T
    s.parseHook(i, j)
    j as union(MessageClass)

  let start = i
  eatChar(s, i, '[')
  var kind: string
  parseHook(s, i, kind)
  case kind:
  of "EVENT":
    # TODO: Fix this to deal with arbitrary spaces
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
    else: # It should be a number, `in {0..9}`?
      v = parseAs(SMCount)
  else:
    raise newException(UnknownMessageError, "Unknown message starting with \"" & kind & "\"")

template fromMessage*(s: string): untyped =
  ## Alias for s.fromJson(union(MessageClass))
  s.fromJson(union(MessageClass))

func dumpHook*(s: var string, v: union(MessageClass)) {.inline.} =
  ## Send message union as its contained message.
  unpack v, msg:
    dumpHook(s, msg)
