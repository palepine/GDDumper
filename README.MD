<h1 align="center">
  <img src="docs/logo.svg" alt="Logo" width="60" valign="middle">
  Cheat Engine Runtime Godot Dumper
</h1>

Cheat Engine Godot Dumper is a [Cheat Engine](https://github.com/cheat-engine/cheat-engine) script that let's you inspect & extract runtime Godot apps via Cheat Engine API. The script features dumping SceneTree data, helping with reverse engineering, modding or debugging.

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
- Arbitrary GDScript and ScriptInstance hot-reloading (experimental)

## Making it work
The script works only with godot apps with `GDScript` used (C# applications are supported to a limited extent).
The script is primarily developed for `x64`, `x32` should generally work if provided with offsets.

Despite my efforts, it's not an ultimate out-of-the-box solution, but it pretty much is for most cases. For it to work, the script needs 1) a CE symbol registered for a root viewport, 2) godot engine version definition and 3) internal godot structure offsets. You can learn how to find them in this [guide](/docs/GUIDE.MD)

You can test your luck avoiding the steps above letting the script do that: tick `GDDumper->Use stored offsets`, do `Add tempalte`, activate the `Dumper script` and try using it.

## Usage
1. Install [Cheat Engine](https://github.com/cheat-engine/cheat-engine).
2. Place `GDumper.lua` inside `Cheat Engine\autorun`
3. Run Cheat Engine and attach to a godot app.
4. A `GDumper` menu item will appear
5. e.g. click `Add Template` and/or follow instructions in the [API doc](/docs/GDUMPER_API.MD).

## Support
If you find the script useful, [consider supporting me here](https://ko-fi.com/vesperpallens)

## Contributing
I'd appreciate any help/ideas with features I haven't implemented or that can be implemented more efficiently.

Feel free to open new issues if the script doesn't support some engine versions

## License
This project is released under the MIT License. See [LICENSE](LICENSE) for details.