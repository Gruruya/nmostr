[
: Copyright © 2023 Gruruya <gruruya.chi4c@slmails.com>
: SPDX-License-Identifier: CC-BY-SA-4.0
]:#

# nmostr

Library for working with Nostr.

Contained modules:
* Events
* Messages
* Bech32
* Proof of work

Stability: Early days. Functional.

Usage
---

Compile with `-d:ssl` for `wss://` connections  
Example uses [guzba's whisky](https://github.com/guzba/whisky) i.e. `nimble install whisky`
```nim
import pkg/[nmostr, whisky]

let keypair = random Keypair
echo "New secret key: " & keypair.seckey.toBech32
echo "The public key: " & keypair.pubkey.toBech32

# Post a note
let socket = newWebSocket("wss://nostr.bongbong.com") # Remember to build with -d:ssl
socket.send CMEvent(event: note(keypair, "Hello world from nmostr!")).toJson
let response = socket.receiveMessage().get.data
echo response

# Read the note back
unpack fromMessage(response), msg:
  when msg is SMOk:
    socket.send CMRequest(id: randomID(), filter: Filter(ids: @[msg.id.hex])).toJson
    echo socket.receiveMessage().get.data
```

For more, see the reference client [niomo](https://github.com/Gruruya/niomo) and [tests](tests/tbasic.nim).

What is Nostr?
---
[Nostr](https://nostr.com) is a simple decentralized protocol. It defines a standard for sending and receiving messages between users identified by their public keys using generic servers or "relays" that handle storage and logic.

Its popularity grew with the goal of creating a decentralized alternative to Twitter and an alternative to the [Fediverse](https://www.fediverse.to) ([Mastodon](https://joinmastodon.org)/[Pleroma](https://pleroma.social)) that doesn't constrain users to one server that can be shut down or blocked.

---
[![GitHub CI](../../actions/workflows/build.yml/badge.svg?branch=master)](../../actions/workflows/build.yml)
[![Minimum supported Nim version](https://img.shields.io/badge/Nim-2.0.0+-informational?logo=Nim&labelColor=232733&color=F3D400)](https://nim-lang.org)
[![License](https://img.shields.io/github/license/Gruruya/nmostr?logo=GNU&logoColor=000000&labelColor=FFFFFF&color=663366)](LICENSE.md)
