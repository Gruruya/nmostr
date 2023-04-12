version     = "0.0.1"
author      = "Gruruya"
description = "Library for working with the Nostr protocol."
license     = "AGPL-3.0-only"

namedBin["nmostr/cli"] = "nmostr"
srcDir = "src"
skipDirs = @["tests"]

# Dependencies
requires "nim >= 1.9.1"
requires "jsony ^= 1.1"
requires "crunchy >= 0.1.8"
requires "https://github.com/Gruruya/nim-secp256k1#less-safe"
requires "https://github.com/alaviss/union >= 0.1.3"
# For client
requires "cligen ^= 1.6.0"
requires "yaml ^= 1.1.0"
requires "whisky ^= 0.1.1"
requires "adix >= 0.5.2"

taskRequires "test", "https://github.com/disruptek/balls ^= 3.0.0" # Can't do 4.0 because of (incorrect) `union` deps, see https://github.com/alaviss/union/pull/33

task test, "run tests":
  let balls =
    when defined(windows):
          "balls.cmd"
    else: "balls"
  exec balls & " --backend:c --mm:orc --mm:arc --mm:refc --define:debug --define:release"
