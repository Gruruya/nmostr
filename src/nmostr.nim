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

## Library for Nostr.
##
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
