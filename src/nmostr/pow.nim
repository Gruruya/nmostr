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

## Proof of work as described by NIP-13.

import std/options, pkg/crunchy, ./events
from strutils import rfind, parseInt
{.warnings: off.} # weave/cross_thread_com/scoped_barriers.nim(66, 12) Warning: Moving a shared resource (an atomic type). [User]
import pkg/weave
{.warnings: on.}
export events, options

{.push raises: [].}

const powParallelChunkSize {.intdefine.} = 4096 ## How many nonces to check per (parallel) loop in `powParallel`
const powParallelCutoff {.intdefine.} = 13 ## Minimum difficulty before `pow` proc points to `powParallel`

template powImpl(findNonce: untyped) {.dirty.} =
  let
    numZeroBytes = difficulty shr 3
    numZeroBits = difficulty and 7
    mask = high(uint8) shl (8 - numZeroBits)
    serialized = serialize(event)
    tagIndex = serialized[0..^3].rfind(",\"") - 1
    prefix =
      if serialized[tagIndex - 1] == '[':
            serialized[0 ..< tagIndex] & "[\"nonce\",\""
      else: serialized[0 ..< tagIndex] & ",[\"nonce\",\""
    suffix = "\",\"" & $difficulty & "\"]" & serialized[tagIndex..^1]
  var
    iteration = 1
    found = 0

  findNonce

  event.tags.add @["nonce", $found, $difficulty]
  event.updateID

template hasValidNonce(hash: array[32, uint8]): bool =
  var valid = false
  block check:
    for i in 0 ..< numZeroBytes:
      if hash[i] != 0: break check
    valid = (hash[numZeroBytes] and mask) == 0
  valid

proc powSequential*(event: var Event, difficulty: range[0..256]) {.raises: [].} =
  ## Increment the second feild of a nonce tag in the event until the event ID has `difficulty` leading 0 bits (NIP-13 POW), single threaded
  powImpl:
    while true:
      let hash = sha256(prefix & $iteration & suffix)
      if unlikely hash.hasValidNonce:
        found = iteration
        break
      inc iteration

{.pop.} # Weave uses templates internally, so `push raises: []` will error
proc powParallel*(event: var Event, difficulty: range[0..256]) {.raises: [ValueError, ResourceExhaustedError, Exception].} =
  ## Increment the second field of a nonce tag in the event until the event ID has `difficulty` leading 0 bits (NIP-13 POW), multithreaded
  powImpl:
    init(Weave)

    while true:
      var waitableFound: Flowvar[int]
      let next = iteration + powParallelChunkSize
      parallelFor i in iteration ..< next:
        captures: {numZeroBytes, mask, prefix, suffix}
        reduce(waitableFound):
          prologue:
            var localFound = 0
          fold:
            let hash = sha256(prefix & $i & suffix)
            if unlikely hash.hasValidNonce:
              localFound = i
          merge(remoteFound):
            let rf = sync(remoteFound)
            if unlikely rf != 0:
              localFound = rf
          return localFound

      let itFound = sync(waitableFound)
      if unlikely itFound != 0:
        found = itFound
        break
      iteration = next

    exit(Weave)
{.push raises: [].}

proc pow*(event: var Event, difficulty: range[0..256]) {.inline, raises: [ValueError, ResourceExhaustedError, Exception].} =
  ## Increment the second field of a nonce tag in the event until the event ID has `difficulty` leading 0 bits (NIP-13 POW)
  if difficulty >= powParallelCutoff:
        event.powParallel(difficulty)
  else: event.powSequential(difficulty)

proc verifyPow*(id: array[32, byte], difficulty: range[0..256]): bool =
  ## Verify an array of bytes (event id) starts with `difficulty` leading 0 bits
  let
    numZeroBytes = difficulty shr 3
    numZeroBits = difficulty and 7
    mask = high(uint8) shl (8 - numZeroBits)

  hasValidNonce(id)

proc verifyPow*(id: EventID, difficulty: range[0..256]): bool {.inline.} = verifyPow(id.bytes, difficulty)
  ## Verify an event id starts with `difficulty` leading 0 bits
proc verifyPow*(event: Event, difficulty: range[0..256]): bool {.inline.} = verifyPow(event.id.bytes, difficulty)
  ## Verify an event's id starts with `difficulty` leading 0 bits

proc getDifficulty*(event: Event): Option[range[0..256]] =
  ## Get the specified target difficulty from an event's tags
  result = none range[0..256]
  for tag in event.tags:
    if tag.len >= 3 and tag[0] == "nonce":
      try:
        let thisTarget = parseInt(tag[2])
        if thisTarget in 0..256 and (result.isNone or thisTarget > result.unsafeGet):
          result = some[range[0..256]](thisTarget)
      except ValueError: discard

proc verifyPow*(event: Event): bool =
  ## Verify the POW of an event
  let target = event.getDifficulty()
  if target.isNone: false
  else: verifyPow(event, target.unsafeGet)

iterator bits(x: uint8): range[0'u8..1'u8] =
  for i in countdown(7, 0):
    yield (x shr i) and 1'u8

proc countZeroBits(byte: uint8): range[0'u8..8'u8] =
  result = 0
  for bit in byte.bits:
    if bit != 0: break
    inc result

proc countPow*(id: array[32, byte]): range[0..256] =
  ## Count the number of leading zero bits in an array of bytes (event id)
  for i in 0'u8 ..< 32:
    if id[i] != 0:
      return i * 8 + countZeroBits(id[i])
  result = 256

proc countPow*(id: EventID): range[0..256] {.inline.} = countPow(id.bytes)
  ## Count the number of leading zero bits in an event id
proc countPow*(event: Event): range[0..256] {.inline.} = countPow(event.id.bytes)
  ## Count the number of leading zero bits in an event's id
