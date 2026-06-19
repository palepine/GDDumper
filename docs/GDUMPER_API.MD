# GDDumper API

This doc covers the usage of exposed API functions.

For the moment being, the doc isn't complete and features only most useful functions.

## Dumper

- `gd_initDumped(config)`
> Initializes the dumper with the passed config. The script might guess the offsets if passed as `gd_initDumped( {useHardcoded = true} )`

  > Notes:
  > 1. Use `Debug Mode` to log errors/status
  > 2. When called, the script will try to find the SceneTree/root, in case of failure - find and register the root address with a symbol called `pRoot`

- `gd_dumpNodeToAddr( parentMemoryRecord, nodeAddr, doConstantsAsWell )`
> Builds the tree for the specified node into the CE Address List (recursively)
  ```lua
  gd_dumpNodeToAddr(memrec, gd_getDumpedNode( "NodeName" ), false)
  ```

- `gd_dumpAllNodesToAddr()`
> Builds the current root tree into the CE Address List including node members and constants (both recursively)

## Objects

- `gd_getDumpedNode(nodeScriptName)`
> If a node with this nodeScript name was discovered, returns its currently discovered address. The address might be any instance of the script that's attached to the root.

- `gd_registerNodeOffsets( nodeScriptName, namespace )`
> Registers Variant offsets of the respective nodeScript name as `nodescriptname.healthfield` symbol whose value is the respective offset in the `Vector<Variant> members`.

  > Notes:
  > 1. requires a runtime object with the respective script constructed and present in the root tree
  > 2. Use case: creating consistent address tables in case script members change across versions
  > 3. Specifying namespace doesn't do anything meaningful except for adding `somenamespace.nodescriptname.healthfield` to avoid symbol collisions.

  ```lua
  gd_registerNodeOffsets('Globals') -- then some pointer may feature Globals.isGrounded
  ```

- `gd_node_registerVariantsSelectively`
> Same as `gd_registerNodeOffsets`, but registers specific fields only to avoid a fat symbol table.

  ```lua
  local fields =
  {
    "timeout",
    "isDone",
  }
  gd_node_registerVariantsSelectively( 'Globals', fields )
  ```

- `gd_getObjectName(objectAddr)`
> returns Objects class name

  > Note: be cautious for it calls a virtual method whose index might shift in some versions - the target would just likely crash

- `gd_mono_getObjectFromNode(nodeAddr)`
>returns a mono object address for the respective node address. A script must be attached to the node. Do whatever DotNet Collector API allows you to with it.

## Script

- `gd_patchFunction( funcObjAddr, patchToBytes, startPos )`
> patches the function's bytecode to the bytes passed
  ```lua
  local toPatchBytes = { 0xDEADBEEF, 0xDEADBEEF, 0xDEADBEEF }
  local originalBytes = { 0xDEADBEEF, 0xDEADBEEF, 0xDEADBEEF }
  local funcAddr = gd_getFunctionFromNode( gd_getDumpedNode('Glogal'), '_process' )
  gd_patchFunction( funcAddr , toPatchBytes ) -- startPos would default to 0
  -- gd_patchFunction( funcAddr , originalBytes ) -- restore the bytes
  ```

- `gd_getFunctionFromNode( nodeAddr, funcName )`
> gets the func from the respective node via its name (example above)

- `gd_callFunctionFromNode( nodeAddr, funcName, argTable )`
>Invokes a user-defined script function for the respective node. Note: not every Variant type is implemented

  > arguments to be passed: e.g. { type = 'STRING' , value = 'Oh hi Mark', copy = nil }
  ```lua
  local args =
  {
    { type="FLOAT" , value=100.0 },
  }
  gd_callFunctionFromNode( gd_getDumpedNode('game') , 'checkAccuracy' , args )
  ```

- `gd_recompileScript(nodeAddr, fileName)`
>Hot-reloads the Script that's attached to the Node (will affect all nodes who are attached to the same script). The new script must be attached to Cheat Engine in `Table->Add File` menu, its name must be passed to the function

  > Notes: 
  >1) Changes might be reverted with `gd_revertScript`
  >2) Do NOT add NEW member variables (globals) to the script unless you hot-reload the respective ScriptInstance(s) subsequently for them to be constructed.
  ```lua
  gd_recompileScript( gd_getDumpedNode('silly_node') , 'new_silly_node.gd' ) -- hotreload the script from the attached file
  ```

- `gd_revertScript(nodeAddr)`
> tries to reverse the changes done to the script by `gd_recompileScript`

- `gd_reloadScriptInstance(nodeAddr)`
> hotreload the ScriptInstance for the respective node address. A script must be attached to it in the first place.

  >_Note: doesn't preserve the ScriptInstance state._
  ```lua
  local nodeAddr = gd_getDumpedNode('silly_node')
  gd_recompileScript( nodeAddr , 'new_silly_node.gd' ) -- hotreload the script from the attached file, new silly has a new member variable so I ...
  gd_reloadScriptInstance( nodeAddr ) -- hot-reload this node's ScriptInstance for members to be constructed
  ```

## Misc

- `gd_printDumped()`
>prints the currently discovered nodes with a Script attached to the Lua Engine output window

- `gd_buildGUI()`
>creates a GDumper menu button if the script doesn't do that automatically - i.e. the target wasn't identified as Godot

  >Note:
  > 1. this menu lets you explore the Scene Tree via CE's Structure Dissector
  > 2. enable `GD Dissector` inside `GDumper` menu, then click `VP Struct` to build a viewport children struct and dissect them automatically.