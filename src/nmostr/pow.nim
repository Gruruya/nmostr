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

const powChunkSize {.intdefine.} = 4096 ## How many nonces to iterate over at once in `powMulti`
const powMultiCutoff {.intdefine.} = 13 ## Minimum difficulty before `pow` proc points to `powMulti`

template powImpl(findNonce: untyped) {.dirty.} =
  let
    numZeroBytes = difficulty shr 3
    numZeroBits = difficulty and 0x7
    mask = 0xFF'u8 shl (8 - numZeroBits)
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

template hasLeadingZeroes(hash: array[32, uint8], difficulty: int): bool = # difficulty param is for show
  var result = false
  block check:
    for i in 0 ..< numZeroBytes:
      if hash[i] != 0: break check
    result = (hash[numZeroBytes] and mask) == 0
  result

proc powSingle*(event: var Event, difficulty: range[0..256]) {.raises: [].} =
  ## Increment the second filed of a nonce tag in the event until its ID has `difficulty` leading 0 bits (NIP-13 POW), single threaded
  powImpl:
    while true:
      let hash = sha256(prefix & $iteration & suffix)
      if unlikely hash.hasLeadingZeroes(difficulty):
        found = iteration
        break
      inc iteration

proc powMulti*(event: var Event, difficulty: range[0..256]) {.raises: [ValueError, ResourceExhaustedError, Exception].} =
  ## Increment the second filed of a nonce tag in the event until its ID has `difficulty` leading 0 bits (NIP-13 POW), multithreaded
  powImpl:
    let foundPtr = addr found
    init(Weave)

    while true:
      let next = iteration + powChunkSize
      syncScope():
        parallelForStaged i in iteration ..< next:
          captures: {numZeroBytes, mask, prefix, suffix, foundPtr}
          prologue:
            var localFound = 0
          loop:
            let hash = sha256(prefix & $i & suffix)
            if unlikely hash.hasLeadingZeroes(difficulty):
              localFound = i
              break
          epilogue:
            if unlikely localFound != 0:
              foundPtr[] = localFound

      if unlikely found != 0: break
      iteration = next

    exit(Weave)

proc pow*(event: var Event, difficulty: range[0..256]) {.inline, raises: [ValueError, ResourceExhaustedError, Exception].} =
  ## Increment the second filed of a nonce tag in the event until its ID has `difficulty` leading 0 bits (NIP-13 POW)
  if difficulty >= powMultiCutoff:
        event.powMulti(difficulty)
  else: event.powSingle(difficulty)

proc verifyPow*(id: array[32, byte], difficulty: range[0..256]): bool =
  let
    numZeroBytes = difficulty shr 3
    numZeroBits = difficulty and 0x7
    mask = 0xFF'u8 shl (8 - numZeroBits)

  id.hasLeadingZeroes(difficulty)

proc verifyPow*(id: EventID, difficulty: range[0..256]): bool {.inline.} = verifyPow(id.bytes, difficulty)
proc verifyPow*(event: Event, difficulty: range[0..256]): bool {.inline.} = verifyPow(event.id.bytes, difficulty)
