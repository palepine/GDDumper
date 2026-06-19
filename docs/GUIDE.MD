# How to find a root viewport address, version and offsets
The following guide works with targets that have `GDScripts` & `GDScriptInstance`s.

## C# Targets
Godot targets with `C# Script`s have different object layouts and work via mono/.net interface. If the target exposes the respective endpoints, CE would identify it as dotnet with its collector reversing CLR objects via reflection - these objects contain a `Node` reference (internal Godot object).

If the libraries in question are static (pretty much all 3.x targets) - that would make it harder, but the aforementioned internal reference in the dotnet object would be a good path to find the respective Godot `Node` object - you just have to do it with more effort.

## Viewport
The easiest and most straightforward way to obtain the root viewport address to find any runtime `Variant` struct of a `Node`'s `Vector` since any `Node` keeps a root reference by a reverse path of `Node->GDScriptInstance->Vector<Variant>`

## Vector & Variant
The size of `Variant` struct may vary between `0x18` & `0x28` depending on whether double is used for `real_t` (which is rare).

`Variant` is a struct with a `Type` `enum` & `union` aligned by 8 bytes; hence the value is offset by `0x8`, object pointers are offset by `0x10` due to their `ObjectID` (which is `std::uint64_t`) stored at `0x8`.

Godot 4.x/3.x `Types` aren't numerous, `>=39` and `27` respectively, primitive types like `FLOAT`, `INT`, `BOOL` are enumerated as 3, 2, 1 respectively.

The `Variants` we are interested in are stored in a `Vector` as continuous elements (the layout is pretty similar to `std::vector`). A `Vector`'s 1st item is pointed at in a `GDScriptInstance` object.

So if you find the first element address of the `Vector` container - substract `0x4` (3.x-4.2) or `0x8` (4.2-4.5) or `0x10` (4.5+) from its address, you get the vector size. If the `Vector` size matches what you see, i.e. the elements stored in the `Vector`, you pretty much confirmed it's the 0-th element of the container.

Take the address of the 0th `Vector` element and search for it in the target (obviously it's a heap-allocated object). Most likely you'd end with a unique address, that would be the `Vector<Variant>` field of `GDScriptInstance`
> Don't forget about the sizeof(void*) which would be 4 byte in x32 and 8 byte long in x64 targets respectively.

Now that you are inside a `GDScriptInstance`, find the preceding `vtable` (read about vtables below). The `Vector` field isn't far from it, usually less than `0x60` on x64 (usually `0x28`).

Take the base of the `GDScriptInstance` object, i.e. the address that has the vtable pointer and search for it again, you should get the `GDScriptInstance script_instance` field of a `Node` which is around `0x50-0x70` in x64 targets, you'd deduce it by finding the `Node`'s vtable.

Now that you see a `Node`'s fields, you can find the root `Viewport/Window`. Nodes and the root have an object name field (it's a `StringName` containing a pointer to a `String`), in case of root it's 'root' (`0x8`/`0x10` inside `StringName` object). The root also has a self-reference - that should suffice to deduce it.

## Game Version
If the target has a .pck file, open it with a hex editor, it starts with `47 44 50 43` magic number in hex, after the magic there would be 3 32bit numbers: major, minor, patch. If the target doesn't have it, just search the executable with a hex editor for the very same magic number.
If the .pck is encrypted, there would be a different magic and as far as I remember, it won't feature the semantic verion.

Another way to indentify the version is by scanning the app's executable, but make sure to also search the read only sections as well. Search for `Godot Engine` in ASCII to find something like `Godot Engine v4.4.1.stable.official`. You can also use a regex formula to search the string with a hex editor featuring that.

## Offsets
> offsetNodeChildren - offset to Node->children, it's an array of `Node` pointers

> offsetNodeStringName - offset to Node->object_name, it's a pointer to a `StringName` object featuring a string at 0x8/0x10

> offsetGDScriptInstance - Node->GDScriptInstance, points to an object with a vtable where the next pointer is the owner `Node` reference with a following `GDScript` reference

> offsetVariantVector - Node->GDScriptInstance->Vector<Variant>

> offsetVariantVectorSize - size preceeding the 1st element in the Vector container, exact offset varies

> offsetGDScriptName - Node->GDScriptInstance->GDScript->name, a pointer to a raw UTF16/UTF32 string data that starts with res://

> offsetFuncMap - GDScript->member_functions, it's a `HashMap` in 4.x (4 ptrs, capacity, size) use offset to the Head (second to the last ptr); in 3.x (ptr to the RBT root and sentinel after it) use root offset.

> offsetGDFunctionCode - GDScript->member_functions['funcName']->code - Vector of 4byte integers, function bytecode

> offsetGDFunctionConst - GDScript->member_functions['funcName']->constants - a Vector<Variant> with script constants, relative to code (after it in 4.x, before globals it in 3.x)

> offsetGDFunctionGlobals - GDScript->member_functions['funcName']->global_names - Vector<StringName>, relative to code (after it and constants in 4.x, before code and after constants it in 3.x)

> offsetConstMap - GDScript->constants - layout same as w/ offsetGDFunctionCode `HashMap`/`Map`

> offsetVariantMap - GDScript->member_indices - layout same as w/ offsetGDFunctionCode `HashMap`/`Map`

## vtable
If you don't know the purpose of `vtable`s, just google/ask some LLM. In a nutshell, it's how dynamic polymorphism is achieved - hence only classes with virtual methods will feature a vtable.

The important stuff is identifying one. A vtable pointer is stored at the very start of objects. It's a c-array to readonly data section of an executable, i.e. a dense table of pointers that in turn point to some place inside the .text section (executable). .rdata and .text would be 'static' relative to the base address of the executable.

If you see a vtable, it's most likely the beginning of an object - unless you are looking at an object with multiple inheritances which is generally rare.