# How to update GDDumper for new unsupported engine versions

Versions are handled as profiles, the mathcing one is selected at initialization.

With each new minor version, a respective update/check is requried to retain features.
Until support is provided, a nearest fallback profile (nearest minor of the same major) is selected.

## 1. Register a runtime profile

Profiles are defined in `autorun/GDDumperModules/GDVersioning.lua`.

For a theoretically compatible Godot X.Y release:

```lua
resolver:register(
  {
    id = 'godotX_Y',
    extends = 'godotX_Y-1',
    priority = 40, -- more on it below, avoid overlapping profiles with equal priority
    match = { major = XXX, minor = YYY },
    supported = true, -- all required profiles/offsets/signatures/implementation validated
    capabilities =                    -- inheritance copies capabilities/layouts from the parent
    {
      objectMetadataLayout = 'gdTypeV9', -- override only the diff
    },
  }
)
```
Profile priority guide:

| Priority | Intended use |
| --- | --- |
| `0` | Unsupported base profile (like interface) |
| `20` | Major/family profile |
| `25` | Broad compatible interface range |
| `30` | Known minor version range |
| `40` | Exact minor specialization |
| `50+` | Exceptional build specialization |

## 2. Variant type profiles

In `autorun/GDDumperModules/GDTypes.lua`

```lua
["X.Y"] =
{
  base = "X.Y-1",
  patches = {}, -- no changes
},

["X.Y+1"] = {
  base = "X.Y",
  patches =
  {
    { -- describe the change 
      kind = "insertValueAfter", -- pr insertValueBefore/removeValue
      anchor = "PACKED_VECTOR4_ARRAY",
      value = "NEW_VARIANT_TYPE",
    },
  },
},
```
A new type means many handlers have to be added in the core script.

## 3. Update bytecode profiles
in `/GDDumperModules/GDFunctionStructDisassembler.lua`

```lua
["X.Y"] =
{
  base = "X.Y-1",
  patches = {}, -- identical to type adding
},
```
For a new added/removed opcode, opcode disassembly handler and enums have to be added:
- Opcode enum-to-handler mapping
- `FUNC_OPCODE_END` resolution
- opcode-to-struct handler
- Address decoding: stack, constants, globals, members (should be fine)

## 4. Add hardcoded offsets

In `autorun/GDDumperModules/GDHardOffsets.lua`

```lua
OffsetProfiles[X][Y] =
{
  default =
  {
    GET_TYPE_INDX = 10,
    CALLP_DELTA = 4, -- offset from get_type_index
    GDScriptRealoadIndex = 47,
  },

  ["*"] = -- base when no specification is needed
  {
    x64 =
    {
      -- concrete offsets
    },

    x86 =
    {
      fallback = true,
    },

    debug = {},
    tools = {},
    usesDouble = {},
  },
}
```

`set` offset:

```lua
debug =
{
  set =
  {
    GDScriptFunctionMap = 0x170,
  },
}
```

`add` to offset (a build neatly shifts an existing layout):

```lua
tools =
{
  add =
  {
    GDScriptFunctionMap = 0x8,
    GDScriptConstantMap = 0x8,
  },
}
```

## 5. Add/override an implementation family
`VersionImplementations` in the core script

For cases when ABI/data structs change

### Object metadata example

If the class `StringName` moves in a new `GDType` layout:

```lua
VersionImplementations.objects.gdTypeV9 = -- objectMetadataLayout in `GDVersioning.lua`
{
  getObjectName = function(objAddr)
    return readObjectNameAtMetadataOffset(objAddr, NEW_OFFSET) -- or whatever
  end,
}
```

### Container example

A container family must satisfy the complete container contract:

```lua
VersionImplementations.containers.modernHashV2 = -- selected as: containerFamily = 'modernHashV2',
{
  getNodeChildrenInfo = ...,
  getNextMapElement = ...,
  getDictElemPairNext = ...,
  getVariantNameFromMapElement = ...,
  getFunctionMapName = ...,
  createNextConstContainer = ...,
  createNextConstSymbol = ...,
  getDictionaryInfo = ...,
  createNextDictContainer = ...,
  createNextSymbol = ...,
  normalizeMapHead = ...,
}
```

When only a few methods change, use an explicit table copy/merge and override those methods

## 6. AOB signatures & engine interfaces

Validate/add signatures for:

### SceneTree

- AOB-signatures for `SceneTree` in `GDDumperModules/GDSignatures.lua`
  - Essential for out-of-the-box usage

### `GDScriptFunction::call()`

- AOB-signatures to get a pointer of `GDScriptFunction::call()` method in `GDDumperModules/GDSignatures.lua`
  - the AOB-signature has to find a caller of `GDScriptFunction::call()`
  - mark the signature as heavy when the first native argument is a return buffer rather than `this`

- Virtual table index for `Object::callp()` in `GDDumperModules/GDHardOffsets.lua`
  - Essential for the engine API

### `Object::callp()`

- Virtual table index in `GDDumperModules/GDHardOffsets.lua`
- Verify argument and return buffer layouts

### GDExtension

- AOB-signatures for `gdextension_get_proc_address(const char *p_name)` in `GDDumperModules/GDSignatures.lua` to enable 4.x+ GDExtended Interface
- If a new major changes this ABI, a new `engineInterface` capability has to be introduced for compatibility
- GDNative for 3.x is reliable

### Mono/.NET

- Only for 3.x .NET targets: find AOB-signatures for `mono_getobject()` in `GDDumperModules/GDSignatures.lua`

## 8. Supporting a new major version
New majors must start with an interface base

```lua
-- GDDumperModules\GDVersioning.lua
resolver:register(
  {
    id = 'godot9',
    extends = 'base',
    priority = 20,
    match = { major = 9 },
    supported = false,
    capabilities =
    {
      engineInterface = 'unknown',
      containerFamily = 'unknown',
      stringEncoding = 'unknown',
      bytecodeFamily = 'unknown',
      objectMetadataLayout = 'unknown',
    },
  }
)
```