version     = "0.0.1"
author      = "Gruruya"
description = "Library for working with the Nostr protocol."
license     = "AGPL-3.0-only"

srcDir = "src"
skipDirs = @["tests"]

# Dependencies
requires "nim >= 1.9.1"
requires "jsony ^= 1.1"
requires "adix >= 0.5.2"
requires "https://github.com/alaviss/union >= 0.1.3"
requires "secp256k1 >= 0.5.2"

when compiles(taskRequires):
  taskRequires "test", "https://github.com/disruptek/balls ^= 3.0.0"
else:
  requires "https://github.com/disruptek/balls >= 3.0.0 & < 4.0.0"
  before test: exec "nimble install -y"

task test, "run tests":
  let balls =
    when defined(windows):
          "balls.cmd"
    else: "balls"
  exec balls & " --backend:c --mm:orc --mm:arc --mm:refc --define:debug --define:release --define:danger"
