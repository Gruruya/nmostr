import locks, pkg/[weave, crunchy], ./events
from strutils import rfind
from sequtils import repeat
export events

const powChunkSize {.intdefine.} = 4096
const powMultiCutoff {.intdefine.} = 13

template powSetup() {.dirty.} =
  let
    numZeroBytes = difficulty div 8
    numZeroBits = difficulty - (numZeroBytes * 8)
    target = repeat(0.byte, numZeroBytes)
    serialized = serialize(event)
    tagIndex = serialized[0..^3].rfind(",\"") - 1
    sStart =
      if serialized[tagIndex - 1] == '[':
            serialized[0..<tagIndex] & "[\"nonce\",\""
      else: serialized[0..<tagIndex] & ",[\"nonce\",\""
    sEnd = "\",\"" & $difficulty & "\"]" & serialized[tagIndex..^1]

  var
    iteration = 1
    found = 0

proc powMulti*(event: var Event, difficulty: range[0..256]) {.raises: [ValueError, ResourceExhaustedError, Exception].} =
  ## Increment the second filed of a nonce tag in the event until its ID has `difficulty` leading 0 bits (NIP-13 POW)
  powSetup()
  var
    foundLock: Lock
  let
    foundPtr = addr found
    foundLockPtr = addr foundLock

  init(Weave)
  while true:
    let next = iteration + powChunkSize
    syncScope():
      parallelForStaged i in iteration ..< next:
        captures: {numZeroBytes, numZeroBits, target, sStart, sEnd, foundPtr, foundLockPtr}
        prologue:
          var localFound = 0
        loop:
          let hash = sha256(sStart & $i & sEnd)
          if unlikely hash[0 ..< numZeroBytes] == target and (numZeroBits == 0 or unlikely (hash[numZeroBytes] and (0xFF'u8 shl (8 - numZeroBits))) == 0):
            localFound = i
        epilogue:
          if unlikely localFound != 0:
            acquire foundLockPtr[]
            foundPtr[] = localFound
            release foundLockPtr[]
            return

    if unlikely found != 0: break
    iteration = next

  exit(Weave)
  event.tags.add @["nonce", $found, $difficulty]
  event.updateID

proc powSingle*(event: var Event, difficulty: range[0..256]) {.raises: [].} =
  ## Increment the second filed of a nonce tag in the event until its ID has `difficulty` leading 0 bits (NIP-13 POW)
  powSetup()

  while true:
    let hash = sha256(sStart & $iteration & sEnd)
    if unlikely hash[0 ..< numZeroBytes] == target and (numZeroBits == 0 or unlikely (hash[numZeroBytes] and (0xFF'u8 shl (8 - numZeroBits))) == 0):
      found = iteration
      break
    inc iteration

  event.tags.add @["nonce", $found, $difficulty]
  event.updateID

proc pow*(event: var Event, difficulty: range[0..256]) {.inline, raises: [ValueError, ResourceExhaustedError, Exception].} =
  if difficulty >= powMultiCutoff:
        event.powMulti(difficulty)
  else: event.powSingle(difficulty)
