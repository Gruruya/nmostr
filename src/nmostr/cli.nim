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
  pkg/yaml/[serialization, presenter, taglib, private/internal], pkg/adix/lptabz, cligen,
  ../nmostr, ./bech32, ./cli/alias

from std/strformat import fmt
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

# YAML serialization
{.push inline.}

# Taken from `NimYAML/yaml/serialization.nim`, `Table` and `set` replaced with `LPTabz` and `LPSetz`
proc constructionError(s: YamlStream, mark: Mark, msg: string): ref YamlConstructionError =
  return newYamlConstructionError(s, mark, msg)

proc safeTagUri(tag: Tag): string {.raises: [].} =
  try:
    var uri = $tag
    # '!' is not allowed inside a tag handle
    if uri.len > 0 and uri[0] == '!': uri = uri[1..^1]
    # ',' is not allowed after a tag handle in the suffix because it's a flow
    # indicator
    for i in countup(0, uri.len - 1):
      if uri[i] == ',': uri[i] = ';'
    return uri
  except KeyError:
    internalError("Unexpected KeyError for Tag " & $tag)

proc yamlTag*[K,V:not void,Z,z](T: typedesc[LPTabz[K, V, Z, z]]): Tag {.raises: [].} =
  return nimTag("tables:Table(" & safeTagUri(yamlTag(K)) & ';' & safeTagUri(yamlTag(V)) & ")")

proc constructObject*[K,V:not void,Z,z](s: var YamlStream, c: ConstructionContext,
                            result: var LPTabz[K, V, Z, z]) {.raises: [YamlConstructionError, YamlStreamError].} =
  let event = s.next()
  if event.kind != yamlStartMap:
    return # Skip empty `field:` Could be made more specific/correct possibly
  result = initLPTabz[K, V, Z, z]()
  while s.peek.kind != yamlEndMap:
    var
      key: K
      value: V
    constructChild(s, c, key)
    constructChild(s, c, value)
    if result.contains(key):
      raise s.constructionError(event.startPos, "Duplicate table key!")
    try: result[key] = value
    except IOError: raise s.constructionError(event.startPos, "IOError when attempting to include into LPTabz")
  discard s.next()

proc representObject*[K,V:not void,Z,z](value: LPTabz[K, V, Z, z], ts: TagStyle, c: SerializationContext, tag: Tag) =
  let childTagStyle = if ts == tsRootOnly: tsNone else: ts
  c.put(startMapEvent(tag = tag))
  if value.len != 0:
    for key, value in value.pairs:
      representChild(key, childTagStyle, c)
      representChild(value, childTagStyle, c)
  else:
    # should put {}
    discard
  c.put(endMapEvent())

proc yamlTag*[K,Z,z](T: typedesc[LPSetz[K, Z, z]]): Tag {.raises: [].} =
  return nimTag("system:set(" & safeTagUri(yamlTag(K)) & ')')

proc constructObject*[K,Z,z](s: var YamlStream, c: ConstructionContext, result: var LPSetz[K,Z,z])
    {.raises: [YamlConstructionError, YamlStreamError].} =
  let event = s.next()
  if event.kind != yamlStartSeq:
    raise s.constructionError(event.startPos, "Expected sequence start")
  result = initLPSetz[K,Z,z]()
  while s.peek().kind != yamlEndSeq:
    var item: K
    constructChild(s, c, item)
    try: result.incl(item)
    except IOError: raise s.constructionError(event.startPos, "IOError when attempting to include into LPSetz") # should use proper mark rather than the start (event.startPos)
  discard s.next()

proc representObject*[K,Z,z](value: LPSetz[K,Z,z], ts: TagStyle, c: SerializationContext, tag: Tag) =
  let childTagStyle = if ts == tsRootOnly: tsNone else: ts
  c.put(startSeqEvent(tag = tag))
  for item in value:
    representChild(item, childTagStyle, c)
  c.put(endSeqEvent())

{.pop inline.}
# End of YAML serialization

template setAccount(config: Config, name: string, kp: KeyPair, echo: bool): string =
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
        SkSecretkey.fromHex(key).tryGet
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

proc accountList*(bech32 = false, prefixes: seq[string]): string =
  ## list accounts (optionally) only showing those whose names start with any of the given `prefixes`
  let config = getConfig()
  if config.account != "":
    echo "Default account: " & config.account
  for account, key in config.accounts.pairs:
    if prefixes.len == 0 or any(prefixes, prefix => account.startsWith(prefix)):
      let kp = SkSecretKey.fromHex(key).tryGet.toKeypair
      if not bech32:
        result &= account & ":\nPrivate key: " & $kp.seckey & "\nPublic key: " & $kp.pubkey & "\n"
      else:
        result &= account & ":\nPrivate key: " & kp.seckey.toBech32 & "\nPublic key: " & kp.pubkey.toBech32 & "\n"
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

import pkg/whisky

proc fetchSearch(): string =
  let kp = newKeypair()
  # let ws = newWebSocket("wss://relay.snort.social")
  # ws.send(CMRequest(id: "npub1jk9h2jsa8hjmtm9qlcca942473gnyhuynz5rmgve0dlu6hpeazxqc3lqz7", filter: Filter()).toJson)
  # let msg = ws.receiveMessage(1000)
  let msg = (kind: TextMessage, data: "[\"EVENT\",\"npub1jk9h2jsa8hjmtm9qlcca942473gnyhuynz5rmgve0dlu6hpeazxqc3lqz7\",{\"id\":\"48f7ed0a9fe9e1ab29aa3250a8af0fcc0e90d5f63c15b2fa41a5375bf19f2e60\",\"pubkey\":\"0339f668b5ab95a3622b583c32569f7daa6b85d5facad9d7b9bb997222c61563\",\"created_at\":0,\"kind\":0,\"tags\":[],\"content\":\"{\\\"name\\\":\\\"jllam34265@minds.com\\\",\\\"about\\\":\\\"\\\",\\\"picture\\\":\\\"https://www.minds.com/icon/1409550373508616195/medium/1661438997/0/1660028401\\\"}\",\"sig\":\"bfc57ea0c34832da557f6ea0cd19b3c1527d356fd909704df8f525f3edb705b965c4e2f3f70fdb6f1cff3a4858cbe3dcf3f5023b798dacee06887141861cb8b4\"}]")
  unpack(msg.data.fromMessage, x):
    echo x.toJson
  #Message(kind: TextMessage, data: "[\"EVENT\",\"npub1jk9h2jsa8hjmtm9qlcca942473gnyhuynz5rmgve0dlu6hpeazxqc3lqz7\",{\"id\":\"48f7ed0a9fe9e1ab29aa3250a8af0fcc0e90d5f63c15b2fa41a5375bf19f2e60\",\"pubkey\":\"0339f668b5ab95a3622b583c32569f7daa6b85d5facad9d7b9bb997222c61563\",\"created_at\":0,\"kind\":0,\"tags\":[],\"content\":\"{\\\"name\\\":\\\"jllam34265@minds.com\\\",\\\"about\\\":\\\"\\\",\\\"picture\\\":\\\"https://www.minds.com/icon/1409550373508616195/medium/1661438997/0/1660028401\\\"}\",\"sig\":\"bfc57ea0c34832da557f6ea0cd19b3c1527d356fd909704df8f525f3edb705b965c4e2f3f70fdb6f1cff3a4858cbe3dcf3f5023b798dacee06887141861cb8b4\"}]")
  # subscribe, not just search. would continue showing feed until you exit
    
proc post(account: Option[string] = none string, echo = true, text: seq[string]): string =
  ## make a post
  var config = getConfig()
  let keypair =
    if account.isNone: defaultKeypair()
    elif account == some "": newKeypair()
    else: config.keypair(unsafeGet account)
  let msg = note(text.join(" "), keypair)
  if echo:
    echo msg
    return
#  let ws = newWebSocket("wss://relay.snort.social")
#  ws.send(CMEvent(event: note("test", newKeypair())).toJson)
#  let msg = ws.receiveMessage()
  let res = some((kind: TextMessage, data: "[\"OK\",\"977e6cdc7b33874d0b45ce71b462aeedb51be8c2930cee01ff32889d8e81ec8a\",true,\"\"]"))
  echo res
  
proc show(echo = false, limit = 10, ids: seq[string] = @[""]): int =
  ## show a post found by its id
  proc request(id: string): auto =
    CMRequest(id: id, filter: Filter(limit: limit)) # (decode(id).toString)) #(if id.startsWith("note1") or id.startsWith("npub1"): (decode(id).toString).runes.toSeq else: id.toRunes), filter: Filter(limit: limit))).toJson

  if echo:
    for id in ids:
      echo request id
    return
  var config = getConfig()
  var relays = config.relays
  if relays.len == 0:
    usage "No relays configured, add relays with `nmostr relay enable`"
  randomize()
  for id in ids:
    while relays.len > 0:
      let relay = relays.nthKey(rand(relays.len - 1))
      relays.del(relay)
      let ws = newWebSocket(relay)
      ws.send(CMRequest(id: id, filter: Filter(limit: 1)).toJson)
      while true:
        let optMsg = ws.receiveMessage(10000)
        if optMsg.isNone or optMsg.unsafeGet.data == "": break # if is SMEose
        let msgUnion = optMsg.unsafeGet.data.fromMessage
        unpack msgUnion, msg:
          echo msg
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
  dispatchMultiGen(
    ["fetch"],
    [fetchSearch, cmdName = "search", dispatchName = "fSearch", usage = "$command $args\n${doc}"])
  dispatchMulti(["multi", cmdName = "nmostr"],
    [accounts, doc = "manage your identities/keypairs", stopWords = @["create", "import", "remove", "list"]],
    [relay, doc = "configure what relays to send posts to", stopWords = @["enable", "disable", "remove", "list"]],
    [fetch, doc = "fetch posts from relays", stopWords = @["search"]],
    # post, (send, messsage > use for DM?) 
    [post], [show, positional = "ids"])
  # allow echoing instead of sending messages, for cli unix purposes
