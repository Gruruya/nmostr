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

import std/strutils
import pkg/[jsony, union]
import ./events

export events, union

# Types

type
  Message* = object of RootObj
  ClientMessage* = object of Message
  ServerMessage* = object of Message

  CMEvent* = object of ClientMessage   ## ["EVENT", <event JSON>]
    event*: Event
  CMRequest* = object of ClientMessage ## ["REQ", <subscription_id>, <filters JSON>...]
    id*: string
    filter*: Filter
  CMClose* = object of ClientMessage   ## ["CLOSE", <subscription_id>]
    id*: string
  SMEvent* = object of ServerMessage   ## ["EVENT", <subscription_id>, <event JSON>]
    id*: string
    event*: Event
  SMNotice* = object of ServerMessage  ## ["NOTICE", <message>]
    message*: string
  SMEose* = object of ServerMessage    ## ["EOSE", <subscription_id>]
    id*: string

  ClientMessageClass = (CMEvent | CMRequest | CMClose)
  ServerMessageClass = (SMEvent | SMEose | SMNotice)
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
      echo s[0..i]
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
setupArrayObjectParsing(SMEvent, "EVENT")
setupArrayObjectParsing(SMEose, "EOSE")
setupArrayObjectParsing(SMNotice, "NOTICE")

proc parseHook*(s: string, i: var int, v: var union(MessageClass)) =
  ## Parses a message of unknown type into the `Message` object inferred by the array's first element and shape.
  template parseAs(T: typedesc): union(MessageClass) =
    var j: T
    s.parseHook(i, j)
    j as union(MessageClass)

  let start = i
  eatChar(s, i, '[')
  var kind: string
  parseHook(s, i, kind)
  i = start
  case kind:
  of "EVENT":
    if likely s.len > 10:
      # Check if the second element in the array is an object or a string.
      if s[9] == '{':
        v = parseAs(CMEvent)
      elif s[9] == '"':
        v = parseAs(SMEvent)
      else: raise newException(jsony.JsonError, "Expected { or \" for the first char of the element following \"EVENT\" in the message array but got " & s[9] & " instead. At offset: 9\n" & (if s.len > 19: s[0..18] & "..." else: s[0..s.len - 1]) & "\n" & repeat(' ', 9) & "^")
    else: raise newException(jsony.JsonError, "Expected an element to follow \"EVENT\" in the message array but end reached. At offset: " & $s.len)
  of "REQ":
    v = parseAs(CMRequest)
  of "CLOSE":
    v = parseAs(CMClose)
  of "EOSE":
    v = parseAs(SMEose)
  of "NOTICE":
    v = parseAs(SMNotice)
  else:
    raise newException(UnknownMessageError, "Unknown message starting with \"" & kind & "\"")

template fromMessage*(s: string): untyped =
  ## Alias for s.fromJson(union(MessageClass))
  s.fromJson(union(MessageClass))

func dumpHook*(s: var string, v: union(MessageClass)) {.inline.} =
  ## Send message union as its contained message.
  unpack v, msg:
    dumpHook(s, msg)
