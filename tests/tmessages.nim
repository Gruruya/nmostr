## nmostr/messages.nim tests
# Copyright © 2023 Gruruya <gruruya.chi4c@slmails.com>
# SPDX-License-Identifier: AGPL-3.0-only

import pkg/balls
import ../src/nmostr/messages

suite "(de)serializing":
  let exEvent = Event.init(1, Keypair.random(), "test")

  block client_event:
    check CMEvent(event: exEvent) == ("[\"EVENT\"," & exEvent.toJson & "]").fromMessage
    check CMEvent(event: exEvent).toJson == ("[\"EVENT\"," & exEvent.toJson & "]").fromMessage.toJson

  block client_request:
    check CMRequest(id: "someid", filter: Filter()) == ("[\"REQ\",\"someid\"," & Filter().toJson & "]").fromJson(CMRequest)
    check CMRequest(id: "someid", filter: Filter()).toJson == ("[\"REQ\",\"someid\"," & Filter().toJson & "]").fromMessage.toJson

  block client_close:
    check CMClose(id: "someid") == ("[\"CLOSE\",\"someid\"]").fromMessage
    check CMClose(id: "someid").toJson == ("[\"CLOSE\",\"someid\"]").fromMessage.toJson

  block client_auth:
    check CMAuth(event: exEvent) == ("[\"AUTH\"," & exEvent.toJson & "]").fromMessage
    check CMAuth(event: exEvent).toJson == ("[\"AUTH\"," & exEvent.toJson & "]").fromMessage.toJson

  block client_count:
    check CMCount(id: "someid", filter: Filter()) == ("""["COUNT","someid",""" & Filter().toJson & "]").fromMessage
    check CMCount(id: "someid", filter: Filter()).toJson == ("""["COUNT","someid",""" & Filter().toJson & "]").fromMessage.toJson

  block server_event:
    check SMEvent(id: "someid", event: exEvent) == ("[\"EVENT\",\"someid\"," & exEvent.toJson & "]").fromMessage
    check SMEvent(id: "someid", event: exEvent).toJson == ("[\"EVENT\",\"someid\"," & exEvent.toJson & "]").fromMessage.toJson

  block server_end_of_stream:
    check SMEose(id: "someid") == """["EOSE","someid"]""".fromMessage
    check SMEose(id: "someid").toJson == """["EOSE","someid"]""".fromMessage.toJson

  block server_notice:
    check SMNotice(message: "Important notice.") == """["NOTICE","Important notice."]""".fromMessage
    check SMNotice(message: "Important notice.").toJson == """["NOTICE","Important notice."]""".fromMessage.toJson

  block server_ok:
    check SMOk(id: exEvent.id, saved: true, message: "") == ("""["OK",""" & toJson(exEvent.id) & """,true,""]""").fromMessage
    check SMOk(id: exEvent.id, saved: true, message: "").toJson == ("""["OK",""" & toJson(exEvent.id) & """,true,""]""").fromMessage.toJson

  block server_auth:
    check SMAuth(challenge: "challengestringhere") == """["AUTH","challengestringhere"]""".fromMessage
    check SMAuth(challenge: "challengestringhere").toJson == """["AUTH","challengestringhere"]""".fromMessage.toJson

  block server_count:
    check SMCount(count: 420) == """["COUNT",420]""".fromMessage
    check SMCount(count: 420).toJson == """["COUNT",420]""".fromMessage.toJson

  block ignore_invalid_message_fields:
    check """["NOTICE","Important \"notice.","other field"]""".fromMessage == """["NOTICE","Important \"notice."]""".fromMessage
    check """["NOTICE","Important \"notice."{}}{())([]][,\"\[\{""".fromMessage == """["NOTICE","Important \"notice."]""".fromMessage

suite "errors":
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

  block invalid_key_error:
    expect ValueError:
      discard Event().toJson.fromJson(Event)
