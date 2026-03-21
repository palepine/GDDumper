# Cheat Engine Runtime Godot Dumper

Cheat Engine Godot Dumper is a [Cheat Engine](https://github.com/cheat-engine/cheat-engine) script that extracts data from running Godot apps via Cheat Engine API. The script dumps node data of a root viewport, helping with reverse engineering or debugging.

THE SCRIPT IS PROVIDED FOR EDUCATIONAL AND RESEARCH PURPOSES. USE IT RESPONSIBLY.

## Features
- Works with Godot 3.x and 4.x.
- Dumps all active nodes / a single node of a root viewport to Cheat Engine's AddressList.
- Builds Cheat Engine structure tree from a root viewport.
- Optionally monitors nodes and updates the Symbol List.
- Basic API functions
- GDScriptFunction disassembler (structure-based)

## Making it work
The script works only with godot apps with `GDScript` used (C# applications aren't supported).
The script works only more steadily with `x64`, `x32` apps should work properly too.

It's not an out of the box solution. For script to work, it needs 1) a CE symbol registered for a root viewport, 2) defining godot engine version and 3) internal godot structure offsets. You can learn how to find them in this [guide](GUIDE.MD)

## Usage
1. Install [Cheat Engine](https://github.com/cheat-engine/cheat-engine).
2. Place `GDumper.lua` inside `Cheat Engine\autorun`
3. Run Cheat Engine and attach to a godot app.
4. A `GDumper` menu item will appear, click `Add Template`
5. Hook any routine that handles the root viewport address / find a static pointer to it in the target process; store it inside a symbol called 'ptVP'
6. Open `Dumper` script and configure the config object following the instructions or letting the script try it.

To build a CE address tree, call `DumpAllNodesToAddr()` (dumps all viewport nodes, can become heavy on GUI) or `DumpNodeToAddr(memrec, getDumpedNode( "NodeName" ), false)` for a specific node (both can be called asynchronically).
To use getDumpedNode, use `nodeMonitor()` to enable/disable automatic monitoring of nodes.
For struct building, enable `GD Dissector` inside `GDumper` menu, then click `VP Struct` to build a viewport children struct.

## Support
If you find the script useful, [consider supporting me here](https://ko-fi.com/vesperpallens)

## Contributing
I'd appreciate any help/ideas with features I haven't implemented or that can be implemented more efficiently.

## License
This project is released under the MIT License. See [LICENSE](LICENSE) for details.


