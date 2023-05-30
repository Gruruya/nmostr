version     = "0.0.12.3"
author      = "Gruruya"
description = "Library for working with the Nostr protocol."
license     = "AGPL-3.0-only"

srcDir = "src"
skipDirs = @["tests"]

# Dependencies
requires "nim >= 1.9.1"
requires "jsony ^= 1.1"
requires "secp256k1 >= 0.6.0.3.1"
requires "stew"
requires "crunchy >= 0.1.8"
requires "weave >= 0.4.10"
requires "https://github.com/alaviss/union >= 0.1.4"

taskRequires "test", "https://github.com/disruptek/balls >= 3.0.0"

task test, "run tests":
  let balls =
    when defined(windows):
          "balls.cmd"
    else: "balls"
  exec balls & " --backend:c --mm:arc --define:danger"
