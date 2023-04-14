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
#
# This file incorporates work covered by the following copyright and permission notices:
#
#    MIT License
#
#    Copyright © 2018-2023 Status Research & Development GmbH
#
#    Permission is hereby granted, free of charge, to any person obtaining a copy
#    of this software and associated documentation files (the "Software"), to deal
#    in the Software without restriction, including without limitation the rights
#    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#    copies of the Software, and to permit persons to whom the Software is
#    furnished to do so, subject to the following conditions:
#
#    The above copyright notice and this permission notice shall be included in all
#    copies or substantial portions of the Software.
#
#    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
#    SOFTWARE.

## Contains `stew/byteutils`

import
  std/[algorithm, typetraits]

{.push raises: [].}

func readHexChar*(c: char): byte
                 {.raises: [ValueError], inline.} =
  ## Converts an hex char to a byte
  case c
  of '0'..'9': result = byte(ord(c) - ord('0'))
  of 'a'..'f': result = byte(ord(c) - ord('a') + 10)
  of 'A'..'F': result = byte(ord(c) - ord('A') + 10)
  else:
    raise newException(ValueError, $c & " is not a hexademical character")

template skip0xPrefix(hexStr: string): int =
  ## Returns the index of the first meaningful char in `hexStr` by skipping
  ## "0x" prefix
  if hexStr.len > 1 and hexStr[0] == '0' and hexStr[1] in {'x', 'X'}: 2
  else: 0

func hexToByteArray*(hexStr: string, output: var openArray[byte], fromIdx, toIdx: int)
                    {.raises: [ValueError].} =
  ## Read a hex string and store it in a byte array `output`. No "endianness" reordering is done.
  ## Allows specifying the byte range to process into the array
  var sIdx = skip0xPrefix(hexStr)

  doAssert(fromIdx >= 0 and toIdx >= fromIdx and fromIdx < output.len and toIdx < output.len)
  let sz = toIdx - fromIdx + 1

  if hexStr.len - sIdx < 2*sz:
    raise (ref ValueError)(msg: "hex string too short")
  sIdx += fromIdx * 2
  for bIdx in fromIdx ..< sz + fromIdx:
    output[bIdx] = hexStr[sIdx].readHexChar shl 4 or hexStr[sIdx + 1].readHexChar
    inc(sIdx, 2)

func hexToByteArray*(hexStr: string, output: var openArray[byte])
                    {.raises: [ValueError], inline.} =
  ## Read a hex string and store it in a byte array `output`. No "endianness" reordering is done.
  hexToByteArray(hexStr, output, 0, output.high)

func fromHex*[N](A: type array[N, byte], hexStr: string): A
                {.raises: [ValueError], noinit, inline.}=
  ## Read an hex string and store it in a byte array. No "endianness" reordering is done.
  hexToByteArray(hexStr, result)

func toHex*(ba: openArray[byte], with0x: static bool = false): string =
  ## Convert a byte-array to its hex representation
  ## Output is in lowercase
  ## No "endianness" reordering is done.
  const hexChars = "0123456789abcdef"

  let extra = when with0x: 2 else: 0
  result = newStringOfCap(2 * ba.len + extra)
  when with0x:
    result.add("0x")

  for b in ba:
    result.add(hexChars[int(b shr 4 and 0x0f'u8)])
    result.add(hexChars[int(b and 0x0f'u8)])

func toBytes*(s: string): seq[byte] =
  ## Convert a string to the corresponding byte sequence - since strings in
  ## nim essentially are byte sequences without any particular encoding, this
  ## simply copies the bytes without a null terminator
  when nimvm:
    var r = newSeq[byte](s.len)
    for i, c in s:
      r[i] = cast[byte](c)
    r
  else:
    @(s.toOpenArrayByte(0, s.high))

func fromBytes*(T: type string, v: openArray[byte]): string =
  if v.len > 0:
    result = newString(v.len)
    when nimvm:
      for i, c in v:
        result[i] = cast[char](c)
    else:
      copyMem(addr result[0], unsafeAddr v[0], v.len)
