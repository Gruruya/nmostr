## Metadata for nimble to build, package, and place nmostr.
# Copyright © 2023 Gruruya <gruruya.chi4c@slmails.com>
# SPDX-License-Identifier: AGPL-3.0-only

version     = "0.1.1"
author      = "Gruruya"
description = "Library for working with the Nostr protocol."
license     = "AGPL-3.0-only"

srcDir = "src"
skipDirs = @["tests"]

# Dependencies
requires "nim >= 2.0.0"
requires "jsony >= 1.1.5 & < 1.2.0"
requires "secp256k1 >= 0.6.0.3.2"
requires "crunchy >= 0.1.9 & < 0.2.0"
requires "stack_strings >= 1.1.4 & < 1.2.0"
requires "stew"
requires "https://github.com/alaviss/union >= 0.2.0 & < 0.3.0"
requires "weave >= 0.4.10 & < 0.5.0"

when not defined(windows) and not defined(macosx):
      taskRequires "test", "https://github.com/disruptek/balls >= 4.0.0"
else: taskRequires "test", "https://github.com/disruptek/balls >= 3.0.0 & < 4.0.0"

task test, "run tests":
  let balls =
    when defined(windows):
          "balls.cmd"
    else: "balls"
  exec balls & " --backend:c --mm:orc --mm:arc --define:debug --define:release --define:danger"
