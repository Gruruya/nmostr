import pkg/yaml/[serialization, presenter, taglib, private/internal], pkg/[adix/lptabz]

## YAML serialization for LPTabz types
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
