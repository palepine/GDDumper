# Cheat Engine Runtime Godot Dumper

Cheat Engine Godot Dumper is a [Cheat Engine](https://github.com/cheat-engine/cheat-engine) script that extracts data from running Godot apps via Cheat Engine API. The script dumps node data of a root viewport, helping with reverse engineering or debugging.

THE SCRIPT IS PROVIDED FOR EDUCATIONAL AND RESEARCH PURPOSES. USE IT RESPONSIBLY.

## Features
- Godot 3.x and 4.x. support
- `x64` and `x32` support
- Dumping nodes to Cheat Engine's AddressList.
- Root node structure dissecting
- Updating node symbollist
- Basic API functions
- GDScriptFunction disassembler (structure-based)

## Making it work
The script works only with godot apps with `GDScript` used (C# applications aren't supported).
The script works only more consistent with `x64`, `x32` should work properly too.

Despite my efforts, it's not a complete out of the box solution. For it to work, the script needs 1) a CE symbol registered for a root viewport, 2) godot engine version definition and 3) internal godot structure offsets. You can learn how to find them in this [guide](GUIDE.MD)

By enabling this [CE regex plugin](https://github.com/palepine/CERegEx) along with the script, you can test your luck avoiding the steps above letting the script do that: tick `GDDumper->Use stored offsets`, do `Add tempalte`, activate the `Dumper script` and try using it.

## Usage
1. Install [Cheat Engine](https://github.com/cheat-engine/cheat-engine).
2. Place `GDumper.lua` inside `Cheat Engine\autorun`
3. Run Cheat Engine and attach to a godot app.
4. A `GDumper` menu item will appear, click `Add Template`
5. Hook any routine that handles the root viewport address / find a static pointer to it in the target process; assocoate it with a symbol called `ptVP`
6. Open `Dumper` script and configure the config object following the instructions or letting the script try it.

To build a CE address tree, call `DumpAllNodesToAddr()` (dumps all viewport nodes, might become heavy on GUI) or `DumpNodeToAddr(memrec, getDumpedNode( "NodeName" ), false)` for a specific node (both can be called asynchronically).
To use getDumpedNode, use `nodeMonitor()` to enable/disable automatic monitoring of nodes.
For struct building, enable `GD Dissector` inside `GDumper` menu, then click `VP Struct` to build a viewport children struct.

## Support
If you find the script useful, [consider supporting me here](https://ko-fi.com/vesperpallens)

## Contributing
I'd appreciate any help/ideas with features I haven't implemented or that can be implemented more efficiently.

## License
This project is released under the MIT License. See [LICENSE](LICENSE) for details.