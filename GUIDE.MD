# How to find a root viewport address, version and offsets

## Viewport
The easiest and most straightforward way to obtain the root viewport address to find any runtime Variant defined in Nodes since any node keeps a root viewport reference.

Variant (var) structures are stored in Godot Vectors where the 1st item of the vector is pointed at in a `GDScriptInstance` object (`Node->GDScriptInstance->firstVectorItem`).
A Variant structure may vary in size depending on the largest type stored (`0x18` - `0x40` with `0x18` being the most usual one). Each Variant's first member is its type enum, the value at its `+0x8` or `+0x10` offset is the value. The largest enum type for 4.x/3.x is 39/27 respectively (e.g. float/double is always 3, int is 2, bool is 1, etc). If you subtract `0x4` (3.x-4.2) or `0x8` (4.2-4.5) from the first Variant address, you get the vector size - knowing that you can deduce the first item address and easily find the pointer inside a `GDScriptInstance`. It has a vtable at 0x0 (as any other obj with virtual methods), so find the pointer inside a Node and then find the root viewport pointer inside a Node. The offset differs, but the root viewport has a StringName object which holds a String with 'root' (at 0x8 or 0x10 offset) - and since the root viewport is derived from Node in Godot, it has its own reference - should be enough to deduce it

## Game Version
Game version can be either deduced or found by scanning the app's executable (try searching for the string `Godot Engine` to find something like `Godot Engine v4.4.1.stable.official`, usually ASCII. You can also use a regex formula to search the string.

## Offsets
Offsets can be assumed by calling `defineGDOffsets` with no args, but that's not reliable.

offsetNodeChildren =        -- offset to Node->children, it's a classic array of Nodes: consecutive 8/4 byte ptrs on x64/x32 apps respectively

offsetNodeStringName =      -- offset to Node->name, it's a pointer to StringName object which usually has a string at either 0x8 or 0x10 (x64)

offsetGDScriptInstance =    -- for Node types that have a GDScript, Node->GDScriptInstance, it points to an object with a vTable where the next pointer is the owner Node reference and the next offset being the GDScript

offsetVariantVector =       -- Node->GDScriptInstance->

offsetVariantVectorSize =   -- is an int located before the 1st item in the Vector container, exact offset varies

offsetGDScriptName =        -- Node->GDScriptInstance->GDScript->name, it points to a raw string data that starts with res://

offsetFuncMap =             -- if you need funcs: GDScript->member_functions - in 4.x - (4 ptrs, capacity, size) use offset to the Head (second to the last ptr); in 3.x (ptr to the RBT root and sentinel after it) use roor offset.

offsetGDFunctionCode =      -- if you need funcs: GDScript->member_functions['abc']->code - it's an int array inside a function storing implemented GDFunction byetcode, very easy to spot

offsetGDFunctionConst =     -- if you need funcs: GDScript->member_functions['abc']->constants - it's a Vector<Variant> with script constants, relative to code

offsetGDFunctionGlobals =   -- if you need funcs: GDScript->member_functions['abc']->global_names - Vector of StringNames, relative to code and constants

offsetConstMap =            -- GDScript->constants - layout same as w/ offsetGDFunctionCode

offsetVariantMap =          -- GDScript->member_indices - layout same as w/ offsetGDFunctionCode

offsetVariantMapVarType =   -- essential for 4.x: MemberInfo inside GDScript->member_indices, we need pointer to the Variant type for crosschecking 

offsetVariantMapIndex =     -- essential for 3.x: MemberInfo inside GDScript->member_indices, we need pointer to the Variant index for correctly mapping Variants in Nodes
