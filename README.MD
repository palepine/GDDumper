# Cheat Engine Runtime Godot Dumper

Cheat Engine Godot Dumper is a [Cheat Engine](https://github.com/cheat-engine/cheat-engine) script that extracts data from running Godot apps via Cheat Engine API. The script dumps node data of a root viewport, helping with reverse engineering or debugging.

THE SCRIPT IS PROVIDED FOR EDUCATIONAL AND RESEARCH PURPOSES. USE IT RESPONSIBLY.

## Features
- Works with Godot 3.x and 4.x.
- Dumps all active nodes or a single node of a root viewport to Cheat Engine's AddressList.
- Create Cheat Engine structures from a root viewport.
- Optionally monitors nodes and updates the Symbol List.
- Basic API functions

## Making it work
The script works only with GD applications where `GDScript` was used.
The script works only with `x64` as of now.

It's not an out of the box solution and might be quite complex for beginners. It also requires creating 1) a symbol for a root viewport, 2) defining an engine version and 3) offsets. You can learn how to find them in this [guide](GUIDE.MD)

## Usage
1. Install [Cheat Engine](https://github.com/cheat-engine/cheat-engine).
2. Place `GDumper.lua` inside `Cheat Engine\autorun`
3. Run Cheat Engine.
4. Hook any routine that handles the root viewport address or find a static pointer to it in the target process and store it inside a symbol called 'ptVP'
5. A `GDumper` menu item will appear, click `Create Script`
6. Run the `Dumper` letting it try to assume the offsets or define them on your own and call `initDumper` with values and offsets corresponding to the following arguments: `bOverrideAssumption, majorVersion, oChildren, oObjStringName, oGDScriptInstance, oGDScriptName, oFuncDict, oGDConst, oVariantNameHM, oVariantVector, oVariantNameHMVarType, oVarSize`
7. *(optional)* call `DumpAllNodesToAddr()` to dump all nodes of the root viewport to the address list or `DumpNodeToAddr(memrec, getDumpedNode( "Globals" ), false)` for a specific node (both can be called asynchronically).
8. Use `nodeMonitor()` to enable/disable automatic monitoring of nodes.
9. In the 'GDumper' menu, enable `GD Dissector` and click `VP Struct` to build a viewport children structure

## Support
If you find the script useful, [consider supporting me here](https://ko-fi.com/vesperpallens) or [here](https://www.patreon.com/c/palepine)

## Contributing
I'd appreciate any help/ideas with features I haven't implemented or that can be implemented more efficiently.

## License

This project is released under the MIT License. See [LICENSE](LICENSE) for details.
