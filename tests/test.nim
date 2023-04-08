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
import nmostr
import std/importutils

suite "events":
  block filters:
    check Filter().toJson == "{}"
    let a = Filter(since: fromUnix(high(int64)), until: low(Time), kinds: @[metadata], ids: @["50"], authors: @["b97"], tags: {"#e": @["48aa67648cad668033516cade8171c779b1b4649d842a5d4062ff769fcd925fa", "bad2aa2974281303e4632e3aeedee7fd6c829e2f63d343caa8fead8f9af95599"], "#p": @["79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"]}.toTagTable)
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

    f.since = high(Time)
    check not e.matches(f)
    f.since = low(Time)

    f.until = low(Time)
    check not e.matches(f)
    f.until = high(Time)

    f.tags["d"] = @["not empty"]
    check not e.matches(f)
    f.tags["d"] = @[""]

    f.kinds = @[metadata]
    check not e.matches(f)
    f.kinds = @[note]

    f.ids = @["50"]
    check not e.matches(f)
    f.ids = @["68"]

    f.authors = @["b97"]
    check not e.matches(f)
    f.authors = @["79b"]

    check e.matches(f)

  block time:
    var a = Filter() # until: initTime(high(int64), 0)
    var b = Filter(until: high(Time))
    var c = Filter(until: low(Time))
    check a.toJson == b.toJson
    check a.toJson.fromJson(Filter) == b.toJson.fromJson(Filter)
    check a.toJson != c.toJson

suite "messages":
  block client_event:
    check CMEvent(event: Event()) == ("[\"EVENT\"," & Event().toJson & "]").fromMessage
    check CMEvent(event: Event()).toJson == ("[\"EVENT\"," & Event().toJson & "]").fromMessage.toJson

  block request:
    check CMRequest(id: "someid", filter: Filter()) == ("[\"REQ\",\"someid\"," & Filter().toJson & "]").fromJson(CMRequest)
    check CMRequest(id: "someid", filter: Filter()).toJson == ("[\"REQ\",\"someid\"," & Filter().toJson & "]").fromMessage.toJson

  block close:
    check CMClose(id: "someid") == ("[\"CLOSE\",\"someid\"]").fromMessage
    check CMClose(id: "someid").toJson == ("[\"CLOSE\",\"someid\"]").fromMessage.toJson

  block server_event:
    check SMEvent(id: "someid", event: Event()) == ("[\"EVENT\",\"someid\"," & Event().toJson & "]").fromMessage
    check SMEvent(id: "someid", event: Event()).toJson == ("[\"EVENT\",\"someid\"," & Event().toJson & "]").fromMessage.toJson

  block notice:
    check SMNotice(message: "Important notice.") == """["NOTICE","Important notice."]""".fromMessage
    check SMNotice(message: "Important notice.").toJson == """["NOTICE","Important notice."]""".fromMessage.toJson

  block ignore_invalid_message_fields:
    check """["NOTICE","Important \"notice.","other field"]""".fromMessage == """["NOTICE","Important \"notice."]""".fromMessage
    check """["NOTICE","Important \"notice."{}}{())([]][,\"\[\{""".fromMessage == """["NOTICE","Important \"notice."]""".fromMessage

  block unkown_message_error:
    expect KeyError:
      discard ("[\"EVE\"," & Event().toJson & "]").fromMessage

  block invalid_json_error:
    expect jsony.JsonError:
      discard "".fromMessage
    expect jsony.JsonError:
      discard ("[\"EVENT\"]").fromMessage
    expect jsony.JsonError:
      discard ("[\"EVENT\",L" & Event().toJson & "]").fromMessage

  block signatures:
    var e = note("hello world", newKeypair())
    check e.verify
    e.stamp(newKeypair())
    check e.verify
    e.content = "goodbye world"
    check not e.verify
    # Clear memory to prevent 208 byte leak caused by `SkContext`
    # discard SkContext.releaseThread()
