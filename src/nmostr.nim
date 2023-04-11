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

import nmostr/[events, messages]
export events, messages

# echo "[\"EVENT\",\"\",{\"id\":\"32eccf41578b9d680ff1b4c19ad487bb26d148e6ad1afbd1d94d2fbeac061139\",\"pubkey\":\"d0bfc94bd4324f7df2a7601c4177209828047c4d3904d64009a3c67fb5d5e7ca\",\"created_at\":0,\"kind\":4,\"tags\":[[\"p\",\"c1aa0a2f0e1211dd3c46e285d64a411aca4f250bd372a0e85b98f7d6d03c9251\"]],\"content\":\"JmwJ1V+d5Rregry/lFyoFzTy9jGkA+5gUXGoMLBK9zY=?iv=EM86UPHMGfQRXQJ9ogOGoQ==\",\"sig\":\"bb9711fa67937a04f09393489a99480cad2b22311837912eac4a91ccac58c6996d8539792d0f782bb2ffa6061180288c9aaff921d387fee7a446335bf117a806\"}]".fromJson().toJson()
# echo SMEvent(event: Event()).toJson
echo "[\"EVENT\",\"\",{\"id\":\"32eccf41578b9d680ff1b4c19ad487bb26d148e6ad1afbd1d94d2fbeac061139\",\"pubkey\":\"d0bfc94bd4324f7df2a7601c4177209828047c4d3904d64009a3c67fb5d5e7ca\",\"created_at\":0,\"kind\":4,\"tags\":[[\"p\",\"c1aa0a2f0e1211dd3c46e285d64a411aca4f250bd372a0e85b98f7d6d03c9251\"]],\"content\":\"JmwJ1V+d5Rregry/lFyoFzTy9jGkA+5gUXGoMLBK9zY=?iv=EM86UPHMGfQRXQJ9ogOGoQ==\",\"sig\":\"bb9711fa67937a04f09393489a99480cad2b22311837912eac4a91ccac58c6996d8539792d0f782bb2ffa6061180288c9aaff921d387fee7a446335bf117a806\"}]".fromJson(SMEvent)
