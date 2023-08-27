## Nim library for the Nostr protocol - nmostr.
# Copyright © 2023 Gruruya <gruruya.chi4c@slmails.com>
# SPDX-License-Identifier: AGPL-3.0-only

## Posting and retrieving an event
## ===============================
##
## Example uses [whisky](https://github.com/guzba/whisky)
##
## .. code-block:: Nim
##   import pkg/[nmostr, whisky]
##
##   let keypair = newKeypair()
##   echo "New secret key: " & keypair.seckey.toBech32
##   echo "The public key: " & keypair.pubkey.toBech32
##
##   # Post a note
##   let socket = newWebSocket("wss://nostr.oxtr.dev") # Remember to build with -d:ssl
##   socket.send CMEvent(event: note(keypair, "Hello world from nmostr!")).toJson
##   let response = socket.receiveMessage().get.data
##   echo response
##
##   # Read the note back
##   unpack fromMessage(response), msg:
##     when msg is SMOk:
##       socket.send CMRequest(id: randomID(), filter: Filter(ids: @[msg.id])).toJson
##       echo socket.receiveMessage().get.data

import nmostr/[events, filters, messages, bech32]
export events, filters, messages, bech32
