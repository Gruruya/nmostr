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

import pkg/balls
import ./nmostr

suite "events":
  block filters:
    check Filter().toJson == "{}"
    let a = Filter(since: fromUnix(high(int64)), until: low(Time), kinds: @[0], ids: @["50"], authors: @["b97"], tags: @[@["#e", "48aa67648cad668033516cade8171c779b1b4649d842a5d4062ff769fcd925fa", "bad2aa2974281303e4632e3aeedee7fd6c829e2f63d343caa8fead8f9af95599"], @["#p", "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"]])
    let b = """{"ids":["50"],"authors":["b97"],"kinds":[0],"#e":["48aa67648cad668033516cade8171c779b1b4649d842a5d4062ff769fcd925fa","bad2aa2974281303e4632e3aeedee7fd6c829e2f63d343caa8fead8f9af95599"],"#p":["79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"],"since":9223372036854775807,"until":0}""".fromJson(Filter)
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
    ["d",""],["d","not empty"]
  ]
}
""".fromJson(Event)

    check e.matches(f)

    f.since = high(Time)   # Add wrong value to filter
    check not e.matches(f) # Check filter doesn't match
    f.since = low(Time)    # Add right value to filter

    f.until = low(Time)
    check not e.matches(f)
    f.until = high(Time)

    f.tags.add @["#d", "not in event"]
    check not e.matches(f)
    f.tags.add @["#d", ""]

    f.kinds = @[0]
    check not e.matches(f)
    f.kinds = @[1]

    f.ids = @["50"]
    check not e.matches(f)
    f.ids = @["68"]

    f.authors = @["b97"]
    check not e.matches(f)
    f.authors = @["79b"]

    check e.matches(f)

  block times_ignore_nanosecond:
    var a = Filter() # until: initTime(high(int64), 0)
    var b = Filter(until: high(Time))
    var c = Filter(until: low(Time))
    check a.toJson == b.toJson
    check a.toJson.fromJson(Filter) == b.toJson.fromJson(Filter) # stores only seconds, nanoseconds are discarded
    check a.toJson != c.toJson

suite "messages":
  block serializing_and_parsing:
    check CMEvent(event: Event()) == ("[\"EVENT\"," & Event().toJson & "]").fromMessage
    check CMEvent(event: Event()).toJson == ("[\"EVENT\"," & Event().toJson & "]").fromMessage.toJson
    check CMRequest(id: "someid", filter: Filter()) == ("[\"REQ\",\"someid\"," & Filter().toJson & "]").fromJson(CMRequest)
    check CMRequest(id: "someid", filter: Filter()).toJson == ("[\"REQ\",\"someid\"," & Filter().toJson & "]").fromMessage.toJson
    check CMClose(id: "someid") == ("[\"CLOSE\",\"someid\"]").fromMessage
    check CMClose(id: "someid").toJson == ("[\"CLOSE\",\"someid\"]").fromMessage.toJson
    check CMAuth(event: Event()) == ("[\"AUTH\"," & Event().toJson & "]").fromMessage
    check CMAuth(event: Event()).toJson == ("[\"AUTH\"," & Event().toJson & "]").fromMessage.toJson
    check CMCount(id: "someid", filter: Filter()) == ("""["COUNT","someid",""" & Filter().toJson & "]").fromMessage
    check CMCount(id: "someid", filter: Filter()).toJson == ("""["COUNT","someid",""" & Filter().toJson & "]").fromMessage.toJson
    check SMEvent(id: "someid", event: Event()) == ("[\"EVENT\",\"someid\"," & Event().toJson & "]").fromMessage
    check SMEvent(id: "someid", event: Event()).toJson == ("[\"EVENT\",\"someid\"," & Event().toJson & "]").fromMessage.toJson
    check SMEose(id: "someid") == """["EOSE","someid"]""".fromMessage
    check SMEose(id: "someid").toJson == """["EOSE","someid"]""".fromMessage.toJson
    check SMNotice(message: "Important notice.") == """["NOTICE","Important notice."]""".fromMessage
    check SMNotice(message: "Important notice.").toJson == """["NOTICE","Important notice."]""".fromMessage.toJson
    check SMOk(id: "someid", saved: true, message: "") == """["OK","someid",true,""]""".fromMessage
    check SMOk(id: "someid", saved: true, message: "").toJson == """["OK","someid",true,""]""".fromMessage.toJson
    check SMAuth(challenge: "challengestringhere") == """["AUTH","challengestringhere"]""".fromMessage
    check SMAuth(challenge: "challengestringhere").toJson == """["AUTH","challengestringhere"]""".fromMessage.toJson
    check SMCount(count: 420) == """["COUNT",420]""".fromMessage
    check SMCount(count: 420).toJson == """["COUNT",420]""".fromMessage.toJson

  block ignore_invalid_message_fields:
    check """["NOTICE","Important \"notice.","other field"]""".fromMessage == """["NOTICE","Important \"notice."]""".fromMessage
    check """["NOTICE","Important \"notice."{}}{())([]][,\"\[\{""".fromMessage == """["NOTICE","Important \"notice."]""".fromMessage

  block unkown_message_error:
    expect UnknownMessageError:
      discard ("[\"EVE\"," & Event().toJson & "]").fromMessage

  block invalid_json_error:
    expect jsony.JsonError:
      discard "".fromMessage
    expect jsony.JsonError:
      discard ("[\"EVENT\"]").fromMessage
    expect jsony.JsonError:
      discard ("[\"EVENT\",L" & Event().toJson & "]").fromMessage

suite "signatures":
  block signing_and_verifying:
    var e = note("hello world", newKeypair())
    check e.verify
    e.stamp(newKeypair())
    check e.verify
    e.content = "goodbye world"
    check not e.verify

suite "bech32":
  block parsing_nip19:
    check SkSecretKey.fromRaw(decode("nsec", "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5"))[] == fromNostrBech32("nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5")
    check fromNostrBech32("nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5") == SkSecretKey.fromHex("67dea2ed018072d675f5415ecfaed7d2597555e202d85b3d65ea4e58d2d92ffa")[]
    check fromNostrBech32("npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjptg") == SkXOnlyPublicKey.fromHex("7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e")[]
    check fromNostrBech32("nprofile1qqsrhuxx8l9ex335q7he0f09aej04zpazpl0ne2cgukyawd24mayt8gpp4mhxue69uhhytnc9e3k7mgpz4mhxue69uhkg6nzv9ejuumpv34kytnrdaksjlyr9p") == NProfile(pubkey: SkXOnlyPublicKey.fromHex("3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d")[], relays: @["wss://r.x.com", "wss://djbas.sadkb.com"])
    check fromNostrBech32("nevent1qqstna2yrezu5wghjvswqqculvvwxsrcvu7uc0f78gan4xqhvz49d9spr3mhxue69uhkummnw3ez6un9d3shjtn4de6x2argwghx6egpr4mhxue69uhkummnw3ez6ur4vgh8wetvd3hhyer9wghxuet5nxnepm") == NEvent(id: EventID.fromHex "b9f5441e45ca39179320e0031cfb18e34078673dcc3d3e3a3b3a981760aa5696", relays: @["wss://nostr-relay.untethr.me", "wss://nostr-pub.wellorder.net"])
    check fromNostrBech32("naddr1qqzkjurnw4ksz9thwden5te0wfjkccte9ehx7um5wghx7un8qgs2d90kkcq3nk2jry62dyf50k0h36rhpdtd594my40w9pkal876jxgrqsqqqa28pccpzu") == NAddr(id: "ipsum", relays: @["wss://relay.nostr.org"], author: SkXOnlyPublicKey.fromHex("a695f6b60119d9521934a691347d9f78e8770b56da16bb255ee286ddf9fda919")[], kind: 30023)
    # I cannot find a single example of an nostr:nrelay being used in the wild.
    echo fromNostrBech32("note1fntxtkcy9pjwucqwa9mddn7v03wwwsu9j330jj350nvhpky2tuaspk6nqc") == NNote(id: EventID.fromHex "4cd665db042864ee600ee976d6cfcc7c5ce743859462f94a347cd970d88a5f3b")
