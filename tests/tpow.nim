## nmostr/pow.nim tests
# Copyright © 2023 Gruruya <gruruya.chi4c@slmails.com>
# SPDX-License-Identifier: AGPL-3.0-only

import pkg/balls
import ../src/nmostr/pow

suite "pow":
  var note = note(Keypair.random(), "Test note")

  block single_threaded:
    note.pow(2)
    check note.verifyPow()
    check note.getDifficulty.unsafeGet == 2
    check note.countPow >= 2

  block multi_threaded:
    when defined(useMalloc): skip() # weave seems to be busted under valgrind
    note.tags.reset
    note.powParallel(2)
    check note.verifyPow()
