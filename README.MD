# Cheat Engine Runtime Godot Dumper

Cheat Engine Godot Dumper is a [Cheat Engine](https://github.com/cheat-engine/cheat-engine) script that extracts data from running Godot apps via Cheat Engine API. The script dumps node data of a root viewport, helping with reverse engineering or debugging.

THE SCRIPT IS PROVIDED FOR EDUCATIONAL AND RESEARCH PURPOSES. USE IT RESPONSIBLY.

## Features
- Godot 3.x and 4.x. support
- Automatic offset resolution
- `x64` and `x32` support
- Dumping nodes to Cheat Engine's AddressList
- Root node structure dissecting
- Updating node symbollist
- Basic API functions
- GDScriptFunction disassembler (structure-based)
- Arbitrary GDFunction calling (experimental)
- Arbitrary GDScript reloading (experimental)

## Making it work
The script works only with godot apps with `GDScript` used (C# applications are supported to a limited extent).
The script is primarily developed for `x64`, `x32` should generally work if provided with offsets.

Despite my efforts, it's not an ultimate out-of-the-box solution, but it pretty much is for most cases. For it to work, the script needs 1) a CE symbol registered for a root viewport, 2) godot engine version definition and 3) internal godot structure offsets. You can learn how to find them in this [guide](/docs/GUIDE.MD)

You can test your luck avoiding the steps above letting the script do that: tick `GDDumper->Use stored offsets`, do `Add tempalte`, activate the `Dumper script` and try using it.

## Usage
1. Install [Cheat Engine](https://github.com/cheat-engine/cheat-engine).
2. Place `GDumper.lua` inside `Cheat Engine\autorun`
3. Run Cheat Engine and attach to a godot app.
4. A `GDumper` menu item will appear, click `Add Template`
5. Open `Dumper` script and configure the config object following the instructions or letting the script try it.
6. Upon initialization, the engine will try to find the root viewport/window address, if it can't - find and register the Viewport/Window address with a symbol called `ptVP`

Call `DumpAllNodesToAddr()`or `DumpNodeToAddr(memrec, getDumpedNode( "NodeName" ), false)` to dump to the address list.
For struct building, enable `GD Dissector` inside `GDumper` menu, then click `VP Struct` to build a viewport children struct.

## Support
If you find the script useful, [consider supporting me here](https://ko-fi.com/vesperpallens)

## Contributing
I'd appreciate any help/ideas with features I haven't implemented or that can be implemented more efficiently.

## License
This project is released under the MIT License. See [LICENSE](LICENSE) for details.
