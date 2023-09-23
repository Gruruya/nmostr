## nmostr/bech32.nim tests
# Copyright © 2023 Gruruya <gruruya.chi4c@slmails.com>
# SPDX-License-Identifier: AGPL-3.0-only

import pkg/balls
import ../src/nmostr/bech32

suite "(de)serializing":
  block secret_key:
    check SecretKey.fromBytes(decode("nsec", "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5")) == fromNostrBech32("nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5")
    check fromNostrBech32("nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5") == SecretKey.fromHex("67dea2ed018072d675f5415ecfaed7d2597555e202d85b3d65ea4e58d2d92ffa")
    check fromNostrBech32(SecretKey.fromHex("67dea2ed018072d675f5415ecfaed7d2597555e202d85b3d65ea4e58d2d92ffa").toBech32) == SecretKey.fromHex("67dea2ed018072d675f5415ecfaed7d2597555e202d85b3d65ea4e58d2d92ffa")

  block public_key:
    check fromNostrBech32("npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjptg") == PublicKey.fromHex("7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e")
    check fromNostrBech32(PublicKey.fromHex("7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e").toBech32) == PublicKey.fromHex("7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e")

  block nprofile:
    check fromNostrBech32("nprofile1qqsrhuxx8l9ex335q7he0f09aej04zpazpl0ne2cgukyawd24mayt8gpp4mhxue69uhhytnc9e3k7mgpz4mhxue69uhkg6nzv9ejuumpv34kytnrdaksjlyr9p") == NProfile(pubkey: PublicKey.fromHex("3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d"), relays: @["wss://r.x.com", "wss://djbas.sadkb.com"])
    check fromNostrBech32(NProfile(pubkey: PublicKey.fromHex("3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d"), relays: @["wss://r.x.com", "wss://djbas.sadkb.com"]).toBech32) == NProfile(pubkey: PublicKey.fromHex("3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d"), relays: @["wss://r.x.com", "wss://djbas.sadkb.com"])

  block nevent:
    check fromNostrBech32("nevent1qqstna2yrezu5wghjvswqqculvvwxsrcvu7uc0f78gan4xqhvz49d9spr3mhxue69uhkummnw3ez6un9d3shjtn4de6x2argwghx6egpr4mhxue69uhkummnw3ez6ur4vgh8wetvd3hhyer9wghxuet5nxnepm") == NEvent(id: EventID.fromHex("b9f5441e45ca39179320e0031cfb18e34078673dcc3d3e3a3b3a981760aa5696"), relays: @["wss://nostr-relay.untethr.me", "wss://nostr-pub.wellorder.net"])
    check fromNostrBech32(NEvent(id: EventID.fromHex("b9f5441e45ca39179320e0031cfb18e34078673dcc3d3e3a3b3a981760aa5696"), relays: @["wss://nostr-relay.untethr.me", "wss://nostr-pub.wellorder.net"], author: PublicKey.fromHex("3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d"), kind: 1).toBech32) == NEvent(id: EventID.fromHex("b9f5441e45ca39179320e0031cfb18e34078673dcc3d3e3a3b3a981760aa5696"), relays: @["wss://nostr-relay.untethr.me", "wss://nostr-pub.wellorder.net"], author: PublicKey.fromHex("3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d"), kind: 1)

  block naddr:
    check fromNostrBech32("naddr1qqxnzd3cxqmrzv3exgmr2wfeqy08wumn8ghj7mn0wd68yttsw43zuam9d3kx7unyv4ezumn9wshszyrhwden5te0dehhxarj9ekk7mf0qy88wumn8ghj7mn0wvhxcmmv9uq3zamnwvaz7tmwdaehgu3wwa5kuef0qy2hwumn8ghj7un9d3shjtnwdaehgu3wvfnj7q3qdergggklka99wwrs92yz8wdjs952h2ux2ha2ed598ngwu9w7a6fsxpqqqp65wy2vhhv") == NAddr(id: "1680612926599", relays: @["wss://nostr-pub.wellorder.net/", "wss://nostr.mom/", "wss://nos.lol/", "wss://nostr.wine/", "wss://relay.nostr.bg/"], author: PublicKey.fromHex("6e468422dfb74a5738702a8823b9b28168abab8655faacb6853cd0ee15deee93"), kind: 30023)
    check fromNostrBech32(NAddr(id: "ipsum", relays: @["wss://relay.nostr.org"], author: PublicKey.fromHex("a695f6b60119d9521934a691347d9f78e8770b56da16bb255ee286ddf9fda919"), kind: 30023).toBech32) == NAddr(id: "ipsum", relays: @["wss://relay.nostr.org"], author: PublicKey.fromHex("a695f6b60119d9521934a691347d9f78e8770b56da16bb255ee286ddf9fda919"), kind: 30023)

  block nrelay:
    # I cannot find a single example of an nostr:nrelay being used in the wild.
    check fromNostrBech32(NRelay(url: "wss://nostr.nostr").toBech32) == NRelay(url: "wss://nostr.nostr")

  block note:
    check fromNostrBech32("note1fntxtkcy9pjwucqwa9mddn7v03wwwsu9j330jj350nvhpky2tuaspk6nqc") == NNote(id: EventID.fromHex("4cd665db042864ee600ee976d6cfcc7c5ce743859462f94a347cd970d88a5f3b"))
    check fromNostrBech32(NNote(id: EventID.fromHex("4cd665db042864ee600ee976d6cfcc7c5ce743859462f94a347cd970d88a5f3b")).toBech32) == NNote(id: EventID.fromHex("4cd665db042864ee600ee976d6cfcc7c5ce743859462f94a347cd970d88a5f3b"))
