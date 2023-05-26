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

import pkg/[weave, crunchy], ./events
from strutils import rfind
export events

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

proc powParallel*(event: var Event, difficulty: range[0..256]) {.raises: [ValueError, ResourceExhaustedError, Exception].} =
  ## Increment the second field of a nonce tag in the event until the event ID has `difficulty` leading 0 bits (NIP-13 POW), multithreaded
  powImpl:
    var waitableFound: Flowvar[int]
    init(Weave)

    while true:
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
