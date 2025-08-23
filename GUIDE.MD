# How to find a root viewport address, version and offsets

## Viewport
The easiest and most straightforward way to obtain the root viewport address to find any runtime var defined in nodes since any node keeps a root viewport reference.

Variant (var) structures are stored in Godot vectors where the first item of the vector is pointed in a `GDScriptInstance` object (`Node->GDScriptInstance->firstVectorItem`).
A Variant structure may vary in size depending on the largest type stored (`0x18` - `0x40` with `0x18` being the most usual one). Each variant's first member is its type enum, the value at `+0x8` or `+0x10` offset is the value. The largest enum type for 4.x/3.x is 39/27 respectively (e.g. float/double is always 3, int is 2, bool is 1, etc). If you subtract `0x4` (3.x-4.2) or `0x8` (4.2+) from the first Variant address, you get the vector size - knowing that you can deduce the first item address and easily find the pointer inside a `GDScriptInstance`. It has a vtable at 0x0 (as any other obj with virtual methods), so find the pointer inside a Node and then find the root viewport pointer inside a Node. The offset differs, but the root viewport has a StringName object which holds a String with 'root' (at 0x8 or 0x10 offset) - and since the root viewport is derived from Node in Godot, it has its own reference - should be enough to deduce it

## Game Version
Game version can be either deduced or found by scanning the app's executable (try searching for the string `godot`, case-insensitively and both ASCII and Unicode)

## Offsets
Offsets can be assumed by calling `defineGDOffsets` with no args, but that's not reliable.

- `CHILDREN`: `Viewport->CHILDREN`, earliest is `0x100`; it's an array of Nodes
- `OBJ_STRING_NAME`: `Viewport->OBJ_STRING_NAME`, earliest is `0x118`
- `GDSCRIPTINSTANCE`: `Node->GDSCRIPTINSTANCE`, earliest is `0x58`
*GDScript instance has a Node reference it's a member of and GDScript standing next (usually)*
- `GDSCRIPTNAME`: `Node->GDSCRIPTINSTANCE->GDScript->StringName` containing the resource name, earliest is `0x108`
- `FUNC_MAP`: `GDScript->Function(Hash)Map`, earliest is `0x1A8`
*function map is not important as no functionality for funciton injections has been implemented*
- `CONST_MAP`: `GDScript->Const(Hash)Map`, earliest is `0x190`
- `VAR_NAMEINDEX_MAP`: `GDScript->Variant(Hash)Map`, earliest is `0x1C0`
- `VAR_VECTOR`: `Node->GDSCRIPTINSTANCE->Vector`, earliest is `0x20`
- `VAR_NAMEINDEX_VARTYPE`: `GDScriptInstance->GDScript->HashMap<StringName, MemberInfo*>.head.varType` at `0x48` (but not always) or nil for 3.x
- `SIZE_VECTOR`: either `0x4` or `0x8`