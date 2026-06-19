# How to update GDDumper for new unsupported engine versions

Most initializations happen in the `initDumper(config)`. With every new minor version shipped the script needs a respective update to retain all its features.

As for new major releases - the script would likely require considerable changes to internal functions if godot internal types happen to change.

Each new minor version needs the following updates (or validation).

### Offsets for auto-resolution

- Struct offset [major.minor] versions in `getStoredOffsetsFromVersion()`
  - Essential `Object`'s offsets usually change between minor versions, thus they have to be defined
  - `DEBUG` and `TOOLS_ENABLED` releases introduce meaningful changes to object memory and vtable layouts
  - Due to `x32` apps being unpopular since the rise of Godot Engine, not all script pointer arithmetic heuristics might succeed. Feel free to reference 32bit apps, however.

- Virtual table index for `getClassName()`
  - Essential.

### SceneTree

- AOB-signatures for `SceneTree` in `GDDumperModules/GDSignatures.lua`
  - Essential for out-of-the-box usage

### Godot Engine Variant Types (essential)

- Variant [major.minor] profiles in `GDDumperModules/GDTypes.lua`

### GD Function Disassembler

- GDFunction [major.minor] profiles in `GDDumperModules/GDFunctionStructDisassembler.lua`
  - In case new opcodes are added, they have to be added to all respective enums and structure disassembler handlers have to be defined.
  - Essential for GDFunction disassembler to operate

### Interface

- AOB-signatures to get a pointer of `GDScriptFunction::call()` method in `GDDumperModules/GDSignatures.lua`
  - the AOB-signature has to find a hit in the `GDScriptFunction::call()` caller, it follows stdcall call conventions
  - The signature has to be marked as heavy if the calee's first argument isn't `this` but a buffer instead

- Virtual table index for `Object::callp()` in `GDDumperModules/GDHardOffsets.lua`
  - Essential for the engine API

- AOB-signatures for `GDExtensionInterfaceFunctionPtr gdextension_get_proc_address(const char *p_name)` in `GDDumperModules/GDSignatures.lua` to enable 4.x+ GDExtended Interface
  - The AOB must find the unique address of `gdextension_get_proc_address()` prologue

- AOB-signatures for `mono_getobject()` in `GDDumperModules/GDSignatures.lua`
  - Only for 3.x .NET targets, 4.x ScriptInstances reference CLR object pointers
