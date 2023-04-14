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

## Command line client for Nostr.

import
  std/[os, strutils, sequtils, sugar, options, streams, random],
  pkg/[yaml, adix/lptabz, cligen, whisky],
  ../nmostr, ./bech32, ./cli/alias, ./cli/lptabz_yaml

from std/terminal import getch

template usage*(why: string): untyped =
  raise newException(HelpError, "No private keys given, nothing to import. ${HELP}")

proc promptYN(default: bool): bool =
  while true:
    case getch():
    of 'y', 'Y':
      return true
    of 'n', 'N':
      return false # RET
    of '\13':
      return default
    of '\3', '\4': # C-c, C-d
      return default
      # raise newException(CatchableError, "User requested exit")
    else:
      continue

type Config = object
  account = ""
  accounts: LPTabz[string, string, int8, 6]
  relays: LPSetz[string, int8, 6]
  relays_known: LPSetz[string, int8, 6] # collect relays from posts

template save(config: Config, path: string) =
  var s = newFileStream(path, fmWrite)
  dump(config, s)
  s.close()

template getConfig: Config =
  let configPath {.inject.} = os.getConfigDir() / "nmostr/config.yaml"
  var config = Config()
  if not fileExists(configPath):
    createDir(configPath.parentDir)
    config.save(configPath)
  else:
    # TODO: Check if it's empty
    var s = newFileStream(configPath)
    load(s, config)
    s.close()
  config

template display(keypair: Keypair): string =
  "Private key: " & $keypair.seckey & "\n" &
  "Public key: " & $keypair.pubkey & "\n"

template keypair(config: Config, name: string): Keypair =
  if name in config.accounts:
    toKeypair(SkSecretKey.fromHex(config.accounts[name]).get)
  else:
    echo name, " isn't an existing account. Creating it."
    let created = newKeypair()
    echo display(created)
    config.accounts[name] = $created.seckey
    config.save(configPath)
    created

template defaultKeypair: Keypair =
  if config.account == "": newKeypair()
  else: config.keypair(config.account)

template randomAccount: (string, Keypair) =
  var kp = newKeypair()
  var name = generateAlias(kp.pubkey)
  while name in config.accounts:
    kp = newKeypair()
    name = generateAlias(kp.seckey.toPublicKey)
  (name, kp)

template setAccount(config: Config, name: string, kp: Keypair, echo: bool): string =
  if not echo:
    config.accounts[name] = $kp.seckey
    config.save(configPath)
  name & ":\n" & display(kp)

proc accountCreate*(echo = false, overwrite = false, names: seq[string]): string =
  ## generate new accounts
  var config = getConfig()

  if names.len == 0:
    # Generate a new account with a random name based on its public key
    var (name, kp) = randomAccount()
    return config.setAccount(name, kp, echo)
  else:
    if names.len == 1:
      # Check if `name` is a number, if so, create that many accounts
      try:
        let num = parseInt(names[0])
        for _ in 1..num:
          var (name, kp) = randomAccount()
          result &= config.setAccount(name, kp, echo)
        return
      except ValueError: discard
    for name in names:
      if name notin config.accounts or overwrite:
        let kp = newKeypair()
        result &= config.setAccount(name, kp, echo)
      else:
        result &= name & " already exists, refusing to overwrite\n"

proc accountImport*(echo = false, private_keys: seq[string]): int =
  ## import private keys as accounts
  var config = getConfig()
  if privateKeys.len == 0:
    usage "No private keys given, nothing to import. ${HELP}"
  for key in privateKeys:
    let seckey =
      if key.len == 64:
        SkSecretKey.fromHex(key).tryGet
      elif key.len == 63 and key.startsWith("nsec1"):
        SkSecretKey.fromBech32 key
      else:
        usage "Unknown private key format. Supported: hex, bech32"
    let kp = seckey.toKeypair
    echo config.setAccount(generateAlias(seckey.toPublicKey), kp, echo)
      
proc accountRemove*(names: seq[string]): int =
  ## remove accounts
  if names.len == 0:
    usage "No account names given, nothing to remove"
  else:
    var config = getConfig()
    for name in names:
      if name in config.accounts:
        echo "About to remove record of ", name, "'s private key, are you sure? [Y/n]"
        if promptYN(true):
          #TODO prompt are you sure?
          echo "Removing account: ", name, "\nPrivate key: " & config.accounts[name]
          if config.account == name: config.account = ""
          config.accounts.del(name)
    config.save(configPath)

proc accountList*(prefixes: seq[string]): string =
  ## list accounts (optionally) only showing those whose names start with any of the given `prefixes`
  let config = getConfig()
  if config.account != "":
        echo "Default account: " & config.account
  else: echo "No default account set, a random key will be generated every time you post"
  for account, key in config.accounts.pairs:
    if prefixes.len == 0 or any(prefixes, prefix => account.startsWith(prefix)):
      let kp = SkSecretKey.fromHex(key).tryGet.toKeypair
      result &= account & ":\nPrivate key: " & $kp.seckey & "\nPublic key: " & $kp.pubkey & "\n"
  if result.len == 0:
    result = "No accounts found. Use `account create` to make one.\nYou could also use nmostr without an account and have a different random key for every post."

proc accountSet*(name: seq[string]): string =
  ## change what account to use by default, pass no arguments to be anonymous
  ##
  ## without an account set, a new key will be generated every time you post
  var config = getConfig()
  template setAcc(newAcc: string) =
    result = "Setting default account to \"" & newAcc & '"'
    config.account = newAcc
    config.save(configPath)

  if name.len > 1 or name.len == 0:
    result = "Unsetting default account. A new random key will be generated for every post."
    config.account = ""
    config.save(configPath)
    return
  if name[0] in config.accounts.keys.toSeq:
    setAcc name[0]
    return
  else:
    for existing in config.accounts.keys:
      if existing.startsWith(name[0]):
        setAcc existing
        return
  "No account found for " & name[0]

proc relayEnable*(relays: seq[string]): int =
  ## enable relays to broadcast your posts with
  var config = getConfig()
  for relay in relays:
    try:
      let index = parseInt(relay)
      if index < config.relays_known.len:
        echo "Enabling ", config.relays_known.nthKey(index)
        config.relays.incl config.relays_known.nthKey(index)
      else:
        echo $index & " is out of bounds, there are only " & $config.relays_known.len & " known relays."
    except ValueError:
      if relay in config.relays_known:
        echo "Enabling ", relay
      else:
        echo "Adding and enabling ", relay
        config.relays_known.incl relay
      config.relays.incl relay
  config.save(configPath)

proc relayDisable*(relays: seq[string]): int =
  ## stop sending posts to specified relays
  var config = getConfig()
  for relay in relays:
    if relay in config.relays_known:
      if relay in config.relays:
        echo "Disabling ", relay
        config.relays.excl relay
      else:
        echo relay, "is already disabled"
    else:
      try: # Disable by index
        let index = parseInt(relay)
        if index < config.relays_known.len:
          let relay = config.relays_known.nthKey(index)
          echo "Disabling ", relay
          config.relays.excl relay
      except ValueError: discard # Ignore request to disable non-existant relay
  config.save(configPath)

proc relayRemove*(relays: seq[string]): int =
  ## remove urls from known relays
  if relays.len == 0:
    usage "No relay urls or indexes given, nothing to remove"
  var config = getConfig()
  var toRemove: seq[string]
  for relay in relays:
    if relay in config.relays_known:
      echo "Removing ", relay, " from relay list"
      config.relays.excl relay
      config.relays_known.excl relay
    else:
      try: # Remove by index
        let index = parseInt(relay)
        if index < config.relays_known.len:
          toRemove.add config.relays_known.nthKey(index)
      except ValueError: discard # Ignore request to remove non-existant relay
  config.save(configPath)
  if toRemove.len > 0:
    return relayRemove(toRemove)

proc relayList*(prefixes: seq[string]): string =
  ## list relay urls and their indexes. enable/disable/remove can use the index instead of a url.
  ##
  ## optionally filters shown relays to only those with any of the given `prefixes`
  let config = getConfig()
  for i, relay in pairs[string, int8, 6](config.relays_known):
    if prefixes.len == 0 or any(prefixes, prefix => relay.startsWith(prefix)):
      echo $i, (if relay in config.relays: " * " else: " "), relay
  # could put enabled relays first

proc post(echo = false, account: Option[string] = none string, text: seq[string]): int =
  ## make a post
  var config = getConfig()
  let keypair =
    if account.isNone: defaultKeypair()
    elif account == some "": newKeypair()
    else: config.keypair(unsafeGet account)

  let post = CMEvent(event: note(text.join(" "), keypair)).toJson # Add enabled relays
  if echo:
    echo post
    return

  let ws = newWebSocket("wss://relay.snort.social")
  ws.send(post)
#  ws.send(CMEvent(event: note("test", newKeypair())).toJson)
  let response = ws.receiveMessage()
  echo response.toJson
#  let res = some((kind: TextMessage, data: "[\"OK\",\"977e6cdc7b33874d0b45ce71b462aeedb51be8c2930cee01ff32889d8e81ec8a\",true,\"\"]"))
  #(id: 0ee959e156cce11f590ce1ed8ddb642036be6a02935055bf920126338d90ba30, pubkey: eeb7632a3dae4a3e89219565a7b194975551a0559f592d406c9ffebbf114870f, kind: 1, content: "hello lovely", created_at: 2023-04-14T12:23:33-04:00, tags: @[], sig: 327e093aa6620233f729c23f32df062a5bf1775c0462751ebf8d8ce4ad455aabef5030bedceabb468d1add63bae6fd5370a6523e2c19551b486fa9129122082e)

  
proc show(echo = false, raw = false, kinds: seq[int] = @[1, 6, 30023], limit = 10, ids: seq[string]): int =
  ## show a post
  var messages = newSeqOfCap[CMRequest](ids.len)
  var ids = ids
  if ids.len == 0: ids = @[""] # Workaround cligen default opts
  for id in ids:
    var filter = Filter(limit: limit, kinds: kinds)
    try:
      # TODO: Get relays as well
      let bech32 = fromNostrBech32(id)
      unpack bech32, entity:
        when entity is NNote:
          filter.ids = @[entity.id.toHex]
        elif entity is NProfile:
          filter.authors = @[entity.pubkey.toHex]
        elif entity is NEvent:
          filter.ids = @[entity.id.toHex]
        elif entity is NAddr:
          filter.authors = @[entity.author.toHex]
          filter.tags = @[@["#d", entity.id]]
        elif entity is SkXOnlyPublicKey:
          filter.authors = @[entity.toHex]
    except: filter.ids = @[id]
    if filter.kinds == @[1, 6, 30023, -1]:
      filter.kinds = @[]
    messages.add CMRequest(id: randomID(), filter: filter)

  if echo:
    for request in messages:
      echo request.toJson()
    return

  var config = getConfig()
  var relays = config.relays
  if relays.len == 0:
    usage "No relays configured, add relays with `nmostr relay enable`"
  randomize()
  for request in messages:
    while relays.len > 0:
      let relay = relays.nthKey(rand(relays.len - 1))
      relays.del(relay)
      let ws = newWebSocket(relay)
      ws.send(request.toJson)
      while true:
        let optMsg = ws.receiveMessage(10000)
        if optMsg.isNone or optMsg.unsafeGet.data == "": break
        try:
          let msgUnion = optMsg.unsafeGet.data.fromMessage
          unpack msgUnion, msg:
            if raw:
              echo msg.toJson
            else:
              when msg is SMEvent:
                # echo "@" & $msg.event.pubkey & "\n" & $msg.event.id
                echo $msg.event.created_at & ":"
                if msg.event.kind == 6: # repost
                  if msg.event.content.startsWith("{"): # is a stringified post
                    echo msg.event.content.fromJson(events.Event).content
                  # else fetch from #e tag
                else:
                  echo msg.event.content
            when msg is SMEose: break
            else: echo ""
        except: discard
      # ws.send(Close(id: id)
      ws.close()
#        if msg 
#        some((kind: TextMessage, data: "[\"NOTICE\",\"ERROR: bad req: subscription id too short\"]"))

when isMainModule:
  import pkg/[cligen/argcvt]
  # taken from c-blake "https://github.com/c-blake/cligen/issues/212#issuecomment-1167777874"
  include cligen/mergeCfgEnvMulMul
  proc argParse[T](dst: var Option[T], dfl: Option[T],
                   a: var ArgcvtParams): bool =
      var uw: T           # An unwrapped value
      if argParse(uw, (if dfl.isSome: dfl.get else: uw), a):
        dst = option(uw); return true
  proc argHelp*[T](dfl: Option[T]; a: var ArgcvtParams): seq[string] =
    result = @[ a.argKeys, $T, (if dfl.isSome: $dfl.get else: "?")]
  dispatchMultiGen(
    ["accounts"],
    [accountCreate, cmdName = "create", help = {"echo": "generate and print accounts without saving", "overwrite": "overwrite existing accounts"}, dispatchName = "aCreate"],
    [accountImport, cmdName = "import", dispatchName = "aImport"],
    [accountSet, cmdName = "set", dispatchName = "aSet", usage = "$command $args\n${doc}"],
    [accountRemove, cmdName = "remove", dispatchName = "aRemove", usage = "$command $args\n${doc}"], # alias rm
    [accountList, cmdName = "list", dispatchName = "aList", usage = "$command $args\n${doc}"])
  dispatchMultiGen(
    ["relay"],
    [relayEnable, cmdName = "enable", dispatchName = "rEnable", usage = "$command $args\n${doc}"],
    [relayDisable, cmdName = "disable", dispatchName = "rDisable", usage = "$command $args\n${doc}"],
    [relayRemove, cmdName = "remove", dispatchName = "rRemove", usage = "$command $args\n${doc}"],
    [relayList, cmdName = "list", dispatchName = "rList", usage = "$command $args\n${doc}"])
  # dispatchMultiGen(
  #   ["fetch"],
  #   [fetchSearch, cmdName = "search", dispatchName = "fSearch", usage = "$command $args\n${doc}"])
  dispatchMulti(["multi", cmdName = "nmostr"],
    [accounts, doc = "manage your identities/keypairs", stopWords = @["create", "import", "remove", "list"]],
    [relay, doc = "configure what relays to send posts to", stopWords = @["enable", "disable", "remove", "list"]],
    # [fetch, doc = "fetch posts from relays", stopWords = @["search"]],
    # post, (send, messsage > use for DM?)
    [show, help = {"kinds": "kinds to filter for, pass -1 for any", "raw": "display all of the response rather than filtering to just the content"}, positional = "ids"],
    [post])
