## Basic tests - for nmostr.
# Copyright © 2023 Gruruya <gruruya.chi4c@slmails.com>
# SPDX-License-Identifier: AGPL-3.0-only

import pkg/balls
import ../src/nmostr

suite "basic":
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
    var N = note(Keypair.random(), "test")
    check N.getParameterizedID == none string
    N.tags.add @["d"]
    check N.getParameterizedID == some ""
    N.tags[0].add "someval"
    check N.getParameterizedID == some "someval"

  block signing_and_verifying:
    var e = note(Keypair.random(), "hello world")
    check e.verify
    e.stamp(Keypair.random())
    check e.verify
    e.content = "goodbye world"
    check not e.verify
