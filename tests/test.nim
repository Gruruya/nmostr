## Tests - for nmostr.
# Copyright © 2023 Gruruya <gruruya.chi4c@slmails.com>
# SPDX-License-Identifier: AGPL-3.0-only

import pkg/balls
import ../src/[nmostr, nmostr/pow]

suite "events":
  block hex:
    check SecretKey.fromHex("67dea2ed018072d675f5415ecfaed7d2597555e202d85b3d65ea4e58d2d92ffa") == SecretKey.fromHex(ss"67dea2ed018072d675f5415ecfaed7d2597555e202d85b3d65ea4e58d2d92ffa")
    check SecretKey.fromHex(@"67dea2ed018072d675f5415ecfaed7d2597555e202d85b3d65ea4e58d2d92ffa") == SecretKey.fromHex(['6', '7', 'd', 'e', 'a', '2', 'e', 'd', '0', '1', '8', '0', '7', '2', 'd', '6', '7', '5', 'f', '5', '4', '1', '5', 'e', 'c', 'f', 'a', 'e', 'd', '7', 'd', '2', '5', '9', '7', '5', '5', '5', 'e', '2', '0', '2', 'd', '8', '5', 'b', '3', 'd', '6', '5', 'e', 'a', '4', 'e', '5', '8', 'd', '2', 'd', '9', '2', 'f', 'f', 'a'])

  block filters:
    check Filter().toJson == "{}"
    let a = Filter(since: fromUnix(high(int64)), until: low(Time), kinds: @[0], ids: @[ss"661f805750735b1273df0f459bcf00fd3042c9f7e672cebe42ef60d1843cb05e"], authors: @[ss"ebec2d97d5928f535edf8ebb7cc1c5566ceb657b5a7c74e6e9e5c977c488eafc"], tags: @[@["#e", "48aa67648cad668033516cade8171c779b1b4649d842a5d4062ff769fcd925fa", "bad2aa2974281303e4632e3aeedee7fd6c829e2f63d343caa8fead8f9af95599"], @["#p", "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"]])
    let b = fromJson("""{"ids":["661f805750735b1273df0f459bcf00fd3042c9f7e672cebe42ef60d1843cb05e"],"authors":["ebec2d97d5928f535edf8ebb7cc1c5566ceb657b5a7c74e6e9e5c977c488eafc"],"kinds":[0],"#e":["48aa67648cad668033516cade8171c779b1b4649d842a5d4062ff769fcd925fa","bad2aa2974281303e4632e3aeedee7fd6c829e2f63d343caa8fead8f9af95599"],"#p":["79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"],"since":9223372036854775807,"until":0}""", Filter)
    check a == b
    check a.toJson == b.toJson

  block filtering_events:
    var f = Filter()
    let e = """
{
  "content": "hello world",
  "created_at": 1680870359,
  "id": "68e5d223ad9fa98c1c4b86d57a7f744f418664c3ce986d4dcf354cff2910081c",
  "kind": 1,
  "pubkey": "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
  "sig": "575f15910f1d4990ab07d959ce817de44b9b6bb93f4e3fe460ffbe5dd4d66a81cfe025da11be2bc9c153af9cfb70a4e14ae23ed4693292a1a0e03642a991bcc7",
  "tags": [
    ["d"],["d","not empty"]
  ]
}
""".fromJson(Event)

    check e.matches(f)

    f.since = high(Time)   # Add wrong value to filter
    check not e.matches(f) # Check filter doesn't match
    f.since = low(Time)    # Add right value to filter
    check e.matches(f)

    f.until = low(Time)
    check not e.matches(f)
    f.until = high(Time)
    check e.matches(f)

    f.tags.add @["#d", "not in event"]
    check not e.matches(f)
    f.tags.add @["#d", ""]
    check e.matches(f)

    f.kinds = @[0]
    check not e.matches(f)
    f.kinds = @[1]
    check e.matches(f)

    f.ids = @[ss"661f805750735b1273df0f459bcf00fd3042c9f7e672cebe42ef60d1843cb05e"]
    check not e.matches(f)
    f.ids = @[ss"68e5d223ad9fa98c1c4b86d57a7f744f418664c3ce986d4dcf354cff2910081c"]
    check e.matches(f)

    f.authors = @[ss"ebec2d97d5928f535edf8ebb7cc1c5566ceb657b5a7c74e6e9e5c977c488eafc"]
    check not e.matches(f)
    f.authors = @[ss"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"]
    check e.matches(f)

  block times_ignore_nanosecond:
    var a = Filter() # until: initTime(high(int64), 0)
    var b = Filter(until: high(Time))
    var c = Filter(until: low(Time))
    check a.toJson == b.toJson
    check a.toJson.fromJson(Filter) == b.toJson.fromJson(Filter) # stores only seconds, nanoseconds are discarded
    check a.toJson != c.toJson

  block example_event_is_valid:
    check """
{
  "id": "b9fead6eef87d8400cbc1a5621600b360438affb9760a6a043cc0bddea21dab6",
  "kind": 1,
  "pubkey": "82341f882b6eabcd2ba7f1ef90aad961cf074af15b9ef44a09f9d2a8fbfbe6a2",
  "created_at": 1676161639,
  "content": "this is going to work",
  "tags": [],
  "sig": "76d19889a803236165a290fa8f3cf5365af8977ee1e002afcfd37063d1355fc755d0293d27ba0ec1c2468acfaf95b7e950e57df275bb32d7a4a3136f8862d2b7"
}
""".fromJson(Event).verify

  block parameterized_id:
    var N = note(Keypair.init(), "test")
    check N.getParameterizedID == none string
    N.tags.add @["d"]
    check N.getParameterizedID == some ""
    N.tags[0].add "someval"
    check N.getParameterizedID == some "someval"

suite "messages":
  let exEvent = Event.init(1, Keypair.init(), "test")

  block serializing_and_parsing:
    check CMEvent(event: exEvent) == ("[\"EVENT\"," & exEvent.toJson & "]").fromMessage
    check CMEvent(event: exEvent).toJson == ("[\"EVENT\"," & exEvent.toJson & "]").fromMessage.toJson
    check CMRequest(id: "someid", filter: Filter()) == ("[\"REQ\",\"someid\"," & Filter().toJson & "]").fromJson(CMRequest)
    check CMRequest(id: "someid", filter: Filter()).toJson == ("[\"REQ\",\"someid\"," & Filter().toJson & "]").fromMessage.toJson
    check CMClose(id: "someid") == ("[\"CLOSE\",\"someid\"]").fromMessage
    check CMClose(id: "someid").toJson == ("[\"CLOSE\",\"someid\"]").fromMessage.toJson
    check CMAuth(event: exEvent) == ("[\"AUTH\"," & exEvent.toJson & "]").fromMessage
    check CMAuth(event: exEvent).toJson == ("[\"AUTH\"," & exEvent.toJson & "]").fromMessage.toJson
    check CMCount(id: "someid", filter: Filter()) == ("""["COUNT","someid",""" & Filter().toJson & "]").fromMessage
    check CMCount(id: "someid", filter: Filter()).toJson == ("""["COUNT","someid",""" & Filter().toJson & "]").fromMessage.toJson
    check SMEvent(id: "someid", event: exEvent) == ("[\"EVENT\",\"someid\"," & exEvent.toJson & "]").fromMessage
    check SMEvent(id: "someid", event: exEvent).toJson == ("[\"EVENT\",\"someid\"," & exEvent.toJson & "]").fromMessage.toJson
    check SMEose(id: "someid") == """["EOSE","someid"]""".fromMessage
    check SMEose(id: "someid").toJson == """["EOSE","someid"]""".fromMessage.toJson
    check SMNotice(message: "Important notice.") == """["NOTICE","Important notice."]""".fromMessage
    check SMNotice(message: "Important notice.").toJson == """["NOTICE","Important notice."]""".fromMessage.toJson
    check SMOk(id: exEvent.id, saved: true, message: "") == ("""["OK",""" & toJson(exEvent.id) & """,true,""]""").fromMessage
    check SMOk(id: exEvent.id, saved: true, message: "").toJson == ("""["OK",""" & toJson(exEvent.id) & """,true,""]""").fromMessage.toJson
    check SMAuth(challenge: "challengestringhere") == """["AUTH","challengestringhere"]""".fromMessage
    check SMAuth(challenge: "challengestringhere").toJson == """["AUTH","challengestringhere"]""".fromMessage.toJson
    check SMCount(count: 420) == """["COUNT",420]""".fromMessage
    check SMCount(count: 420).toJson == """["COUNT",420]""".fromMessage.toJson

  block ignore_invalid_message_fields:
    check """["NOTICE","Important \"notice.","other field"]""".fromMessage == """["NOTICE","Important \"notice."]""".fromMessage
    check """["NOTICE","Important \"notice."{}}{())([]][,\"\[\{""".fromMessage == """["NOTICE","Important \"notice."]""".fromMessage

  block unkown_message_error:
    expect UnknownMessageError:
      discard ("[\"EVE\"," & exEvent.toJson & "]").fromMessage

  block invalid_json_error:
    expect jsony.JsonError:
      discard "".fromMessage
    expect jsony.JsonError:
      discard ("[\"EVENT\"]").fromMessage
    expect jsony.JsonError:
      discard ("[\"EVENT\",L" & exEvent.toJson & "]").fromMessage

suite "signatures":
  block signing_and_verifying:
    var e = note(Keypair.init(), "hello world")
    check e.verify
    e.stamp(Keypair.init())
    check e.verify
    e.content = "goodbye world"
    check not e.verify

suite "bech32":
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
    check fromNostrBech32("nevent1qqstna2yrezu5wghjvswqqculvvwxsrcvu7uc0f78gan4xqhvz49d9spr3mhxue69uhkummnw3ez6un9d3shjtn4de6x2argwghx6egpr4mhxue69uhkummnw3ez6ur4vgh8wetvd3hhyer9wghxuet5nxnepm") == NEvent(id: EventID.fromHex "b9f5441e45ca39179320e0031cfb18e34078673dcc3d3e3a3b3a981760aa5696", relays: @["wss://nostr-relay.untethr.me", "wss://nostr-pub.wellorder.net"])
    check fromNostrBech32(NEvent(id: EventID.fromHex "b9f5441e45ca39179320e0031cfb18e34078673dcc3d3e3a3b3a981760aa5696", relays: @["wss://nostr-relay.untethr.me", "wss://nostr-pub.wellorder.net"], author: PublicKey.fromHex("3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d"), kind: 1).toBech32) == NEvent(id: EventID.fromHex "b9f5441e45ca39179320e0031cfb18e34078673dcc3d3e3a3b3a981760aa5696", relays: @["wss://nostr-relay.untethr.me", "wss://nostr-pub.wellorder.net"], author: PublicKey.fromHex("3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d"), kind: 1)

  block naddr:
    check fromNostrBech32("naddr1qqxnzd3cxqmrzv3exgmr2wfeqy08wumn8ghj7mn0wd68yttsw43zuam9d3kx7unyv4ezumn9wshszyrhwden5te0dehhxarj9ekk7mf0qy88wumn8ghj7mn0wvhxcmmv9uq3zamnwvaz7tmwdaehgu3wwa5kuef0qy2hwumn8ghj7un9d3shjtnwdaehgu3wvfnj7q3qdergggklka99wwrs92yz8wdjs952h2ux2ha2ed598ngwu9w7a6fsxpqqqp65wy2vhhv") == NAddr(id: "1680612926599", relays: @["wss://nostr-pub.wellorder.net/", "wss://nostr.mom/", "wss://nos.lol/", "wss://nostr.wine/", "wss://relay.nostr.bg/"], author: PublicKey.fromHex("6e468422dfb74a5738702a8823b9b28168abab8655faacb6853cd0ee15deee93"), kind: 30023)
    check fromNostrBech32(NAddr(id: "ipsum", relays: @["wss://relay.nostr.org"], author: PublicKey.fromHex("a695f6b60119d9521934a691347d9f78e8770b56da16bb255ee286ddf9fda919"), kind: 30023).toBech32) == NAddr(id: "ipsum", relays: @["wss://relay.nostr.org"], author: PublicKey.fromHex("a695f6b60119d9521934a691347d9f78e8770b56da16bb255ee286ddf9fda919"), kind: 30023)

  block nrelay:
    # I cannot find a single example of an nostr:nrelay being used in the wild.
    check fromNostrBech32(NRelay(url: "wss://nostr.nostr").toBech32) == NRelay(url: "wss://nostr.nostr")

  block note:
    check fromNostrBech32("note1fntxtkcy9pjwucqwa9mddn7v03wwwsu9j330jj350nvhpky2tuaspk6nqc") == NNote(id: EventID.fromHex "4cd665db042864ee600ee976d6cfcc7c5ce743859462f94a347cd970d88a5f3b")
    check fromNostrBech32(NNote(id: EventID.fromHex "4cd665db042864ee600ee976d6cfcc7c5ce743859462f94a347cd970d88a5f3b").toBech32) == NNote(id: EventID.fromHex "4cd665db042864ee600ee976d6cfcc7c5ce743859462f94a347cd970d88a5f3b")

suite "pow":
  var note = note(Keypair.init(), "Test note")

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
