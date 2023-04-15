# nmostr

Library for working with Nostr.

Contained modules:
* Events
* Messages
* Bech32 decoding

Stability: Early days. Functional.

Usage
---
Look at [niomo](https://github.com/Gruruya/niomo) for a reference client and [tests/test.nim](tests/test.nim).

What is Nostr?
---
[Nostr](https://nostr.com) is a standard for sending and receiving messages between users identified by their public keys using generic servers, or "relays", that handle the storage. There then can be multiple different "frontends" using these relays as "backends" that can interface with one another regardless of how they look.

It was made with the intent of being a decentralized alternative to Twitter and an alternative to the [Fediverse](https://www.fediverse.to) ([Mastodon](https://joinmastodon.org)/[Pleroma](https://pleroma.social)) that doesn't constrain users to one server that can be shut down or blocked.

---
[![GitHub CI](../../actions/workflows/build.yml/badge.svg?branch=master)](../../actions/workflows/build.yml)
[![Minimum supported Nim version](https://img.shields.io/badge/Nim-1.9.1+-informational?logo=Nim&labelColor=232733&color=F3D400)](https://nim-lang.org)
[![License](https://img.shields.io/github/license/Gruruya/nmostr?logo=GNU&logoColor=000000&labelColor=FFFFFF&color=663366)](LICENSE.md)
