-- This script was created by palepine. Support me: https://ko-fi.com/vesperpallens
-- I'd like to thank cfemen for some basic insights about the godot engine which saved me from reading much of the Godot Engine source code initially.
-- Source code on github: https://github.com/palepine/GDDumper
-- ///---///--///---///--///---///--///--///---///--///---///--///---///--/// TODOS
  -- TODO addresslist should include node's children of children
  -- TODO tree view form with polling
  -- TODO more offsets for non-GDI objects
  -- TODO doxygen comments
  -- TODO: explore how timeconsuming would it be to pull off what gdsdecomp does with token streams for runtime decompilation and runtime re-compilation
  -- TODO: full object path as a separate symbol?

-- ///---///--///---///--///---///--///--///---///--///---///--///---///--///--///--/// FORWARD DECLARATIONS
  local GDAPI = {}

  local isNullOrNil
  local isNotNullOrNil
  
  local getExportTableName
  local getGodotVersionString
  
  local readUTFString
  local codePointToUTF8
  local getStringNameStr
  local UTF8Codepoints

  local getViewport
  
  local rootOffset
  local fieldOffset
  
  local processNodeForNodes
  local checkForGDScript
  local checkScriptType
  local checkIfObjectWithChildren
  local iterateNodeChildrenToStruct
  local iterateNodeChildrenForNodes
  local iterateMNodeToAddr
  local iterateNodeToStruct
  local getGDResName
  local checkObjectOffset
  
  local getGDFunctionName
  local getFuncObjectCodeAddr
  local getFuncObjectConstAddr
  local getNodeFuncMap
  local iterateNodeFuncMapToStruct
  local iterateFuncConstantsToStruct
  local iterateFuncGlobalsToStruct
  local disassembleGDFunctionCodeToStruct
  local formatDisassembledAddress
  local checkIfGDFunction
  local setupCallArgs

  local getNodeConstName
  local iterateNodeConstToAddr
  local iterateNodeConstToStruct

  local iterateDictionary
  local iterateDictionaryToAddr
  local iterateDictionaryToStruct
  local iterateDictionaryForNodes
  local iterateArray
  local iterateArrayToAddr
  local iterateArrayToStruct
  local iterateArrayForNodes
  local iteratePackedArrayToAddr
  local iteratePackedArrayToStruct
  local iterateVectorVariants
  local iterateVectorVariantsForFields
  local iterateVecVarToAddr
  local iterateVecVarToStruct
  local iterateVecVarForNodes
  local getNodeVariantVector
  local getNodeVariantMap
  local getVariantByIndex
  local VariantArena
  local GDVariant
  
  local getGDTypeName

  local getMainNodeTable

  local makeAddr
  local makeSymAddr


  local stdcall = 0
  local timeout = nil
-- ///---///--///---///--///---///--///--///---///--///---///--///---///--///--///--/// DUMPER CODE
  -- ///---///--///---///--///---///--///--///---///--///---///--///---///--/// CE & UTILS
    -- ///---///--///---///--///---/// POINTER HANDLERS

      --- checks if the value is a valid pointer
      ---@param addr number
      ---@return boolean
      local function isValidPointer(addr)
        local success, result = pcall(readPointer, addr)
        return success and result ~= nil
      end

      local function isInvalidPointer(addr)
        return isValidPointer(addr) == false
      end

      --- checks if the value is a valid pointer and not nullptr
      ---@param addr number
      ---@return boolean
      local function isPointerNotNull(addr)
        return isValidPointer(addr) and readPointer(addr) ~= 0
      end

      --- gets some section info (bounds)
      ---@param sectionName number
      ---@return table
      function GDAPI.getSectionBounds(sectionName)
        local base = getAddress(process)
        if base == 0 or base == nil then
          base = enumModules()[1].Address
        end -- for cases when getAddress fails
        if not base then
          return nil
        end -- if it's still failing, quit

        -- DOS header -> e_lfanew
        local peOffset = readInteger(base + 0x3C)
        if not peOffset then
          return nil
        end

        local PE = base + peOffset

        local signature = readInteger(PE)
        if signature ~= 0x00004550 then
          return nil
        end

        -- IMAGE_FILE_HEADER
        local numberOfSections = readSmallInteger(PE + 0x6)
        local sizeOfOptionalHdr = readSmallInteger(PE + 0x14)

        if not numberOfSections or not sizeOfOptionalHdr then
          return nil
        end

        -- Section table starts after:
        -- 4 bytes PE signature + 20 bytes IMAGE_FILE_HEADER + optional header
        local sectionTable = PE + 0x18 + sizeOfOptionalHdr

        for i = 0, numberOfSections - 1 do
          local sec = sectionTable + (i * 0x28) -- IMAGE_SECTION_HEADER = 40 bytes

          local name = readString(sec, 8) or ""
          name = name:gsub("%z.*", "") -- strip trailing nulls

          if name == sectionName then
            local virtualSize = readInteger(sec + 0x8)
            local virtualAddress = readInteger(sec + 0xC)

            if not virtualSize or not virtualAddress then
              return nil
            end

            return
            {
              name = name,
              base = base,
              virtualAddress = virtualAddress, -- RVA
              virtualSize = virtualSize,
              startAddress = base + virtualAddress,
              endAddress = base + virtualAddress + virtualSize - 1
            }
          end
        end

        return nil
      end

      local function isInsideSectionRange(addr, sectionInfo)
        if addr == nil or addr == 0 then
          return false
        end
        if addr > sectionInfo.startAddress and sectionInfo.endAddress > addr then
          return true
        end
      end

      -- check VTable validity for main module
      ---@param VTAddr number
      ---@return boolean
      local function isVtable(VTAddr)
        if VTAddr == 0 or VTAddr == nil then
          return false
        end
        if isNullOrNil(GDDEFS.MAIN_MODULE_INFO) then
          GDDEFS.MAIN_MODULE_INFO = getMainModuleInfo()
          GDDEFS.TEXT_SECTIONINFO = getSectionBounds(".text")
          if GDDEFS.TEXT_SECTIONINFO == nil then return false end
        end

        if GDDEFS.MAIN_MODULE_INFO.moduleStart < VTAddr and VTAddr < GDDEFS.MAIN_MODULE_INFO.moduleEnd then
          -- iterate a few pointers and confirm if they are executable
          local ptrsize = targetIs64Bit() and 0x8 or 0x4

          for i = 0, 5 do -- 5 pointers
            local pmethod = readPointer(VTAddr + ptrsize * i)
            if not isInsideSectionRange(pmethod, GDDEFS.TEXT_SECTIONINFO) then
              return false
            end
          end
        else -- outside the main module
          return false
        end

        return true
      end

      local function isInsideRDataStatic(strAddr)
        if strAddr == nil or strAddr == 0 then
          return false
        end
        -- in pck range
        local sectionInfo = getSectionBounds(".rdata")
        if sectionInfo == nil then
          return false
        end
        if isInsideSectionRange(strAddr, sectionInfo) then
          return true
        end
        return false
      end

    -- ///---///--///---///--///---/// MEMRECS
      --- adds a memrec to parent
      ---@param memRecName string
      ---@param gdPtr number
      ---@param CEType number
      ---@param parent userdata -- to append to
      ---@return userdata
      local function addMemRecTo(memRecName, gdPtr, CEType, parent, contextTable)
        local newMemRec = getAddressList().createMemoryRecord()
        local useSymbol = bGDUseSymbols and contextTable

        newMemRec.setType(CEType)
        newMemRec.setDescription(memRecName)

        if CEType == vtString then
          if GDDEFS.GD4_STRING_EXISTS then
            newMemRec.setType(vtCustom)
            newMemRec.CustomTypeName = "GD4 String"
          else
            newMemRec.String.Size = 100
            newMemRec.String.Unicode = true
          end

          if useSymbol then
            newMemRec.setAddress(contextTable.symbol or "")
          else
            newMemRec.setAddress(readPointer(gdPtr))
          end
        else
          if useSymbol then
            newMemRec.setAddress(contextTable.symbol or "")
          else
            newMemRec.setAddress(gdPtr)
          end
        end

        if CEType == vtQword then
          newMemRec.ShowAsHex = true
        end

        if CEType == vtDword then
          newMemRec.ShowAsSigned = true
        end -- color and int

        -- if bGDUseSymbols and contextTable then newMemRec.DropDownList.Text = contextTable.symbol end

        -- newMemRec.DontSave = true
        newMemRec.appendToEntry(parent)
        return newMemRec
      end



    -- ///---///--///---///--///---/// MISC UTILS

      --- turns off showOnPrint
      local function fuckoffPrint()
        GetLuaEngine().cbShowOnPrint.Checked = false
      end

      function isNullOrNil(toCheck)
        return toCheck == nil or toCheck == 0
      end

      function isNotNullOrNil(toCheck)
        return not isNullOrNil(toCheck)
      end

      function getMainModuleInfo()
        -- the vtables are stored in some readonly data section, text included too
        local moduleStart = getAddress(process) or 0
        local moduleEnd;
        local moduleSize = getModuleSize(process)

        -- for cases when getAddress fails
        if moduleStart == 0 or moduleStart == nil or moduleSize == nil or moduleSize == 0 then
          moduleStart = enumModules()[1].Address
          moduleEnd = moduleStart + enumModules()[1].Size
        else
          moduleEnd = moduleStart + moduleSize
        end

        return
        {
          moduleStart = moduleStart,
          moduleEnd = moduleEnd,
          moduleSize = moduleSize
        }
      end

      local function wrapBrackets(stringToWrap)
        return '['.. (stringToWrap or "") .. "]"
      end

      local function readU32LE(f)
        local b = f:read(4)

        if not b or #b < 4 then return nil end

        local b1, b2, b3, b4 = string.byte(b, 1, 4)

        return b1 | (b2 << 8) | (b3 << 16) | (b4 << 24)
      end

      local function streamFileToString(fileName)
        local tableFile = findTableFile(fileName)
        if tableFile == nil then return nil end -- error('attached file not found')
        local stringStream = createStringStream()
        stringStream.Position = 0
        stringStream.copyFrom(tableFile.Stream, tableFile.Stream.Size)
        local newScript = stringStream.DataString
        stringStream.destroy()

        return newScript
      end

      local function getVtable(addr)
        return readPointer(addr)
      end

      local function getVtableValidated(addr)
        -- if isInvalidPointer(addr) then return nil end
        local vtable = readPointer(addr)
        if not isVtable(vtable) then return nil end
        return vtable
      end

      local function getObjectVMethodByIndex(addr, index)
        index = index or 0
        local vtable = getVtableValidated(addr)
        if isNullOrNil(vtable) then return nil end
        local offsetToMethod = GDDEFS.PTRSIZE * index
        return readPointer(vtable + offsetToMethod)
      end

      GDTEAL_COLOR = 0x808040

    -- ///---///--///---///--///---/// DEBUG

      --- multiplies a string by a number for more neat debug
      ---@param str string
      ---@param times number
      ---@return string
      local function strMul(str, times)
        return string.rep(str, times)
      end

      function numtohexstr(num)
        return ("%X"):format(num or -1)
      end

      local function getStackDepth()
        local level = 1
        -- kind of expensive, but fair for debug mode
        while debug.getinfo(level, "f") do
          level = level + 1
        end
        return level - 1
      end

      local function getDebugPrefix()
        local depth = getStackDepth()
        return strMul('>', depth) .. ' '
      end

      local function sendDebugMessage(msg)
        if bGDDebug and isNotNullOrNil(msg) and inMainThread() then
          local info = debug.getinfo(2, "nl") -- previous function, name and currentline
          local name = info.name or " ??? "
          local currLine = info.currentline or -1
          print(getDebugPrefix() .. name .. ":" .. currLine .. " " .. tostring(msg))
        end
      end

      function GDAPI.getGDSemver()
        if GDDEFS and GDDEFS.FULL_GDVERSION_STRING then
          print(GDDEFS.FULL_GDVERSION_STRING)
          print(getExportTableName())
        else
          print((getExportTableName() or "exportnomatch") .. '\n' .. (getGodotVersionString() or "semver not hit"))
        end
      end

      function GDAPI.printGDConfig()
        print
        (
          ([[local config = {majorVersion = 0X%X,minorVersion = 0X%X,GDCustomver = %s,GDDebugVer = %s,isMonoTarget = %s,useHardcoded = %s,offsetNodeChildren = 0X%X,offsetNodeStringName = 0X%X,offsetGDScriptInstance = 0X%X,offsetVariantVector = 0X%X,offsetVariantVectorSize = 0X%X,offsetGDScriptName = 0X%X,offsetFuncMap = 0X%X,offsetGDFunctionCode = 0X%X,offsetGDFunctionConst = 0X%X,offsetGDFunctionGlobals = 0X%X,offsetConstMap = 0X%X,offsetVariantMap = 0X%X,offsetVariantMapVarType = 0X%X,offsetVariantMapIndex = 0X%X}]]):format(
          (GDDEFS.MAJOR_VER or 0x0),
          (GDDEFS.MINOR_VER or 0x0),
          (tostring(GDDEFS.CUSTOMVER)),
          (tostring(GDDEFS.DEBUGVER)),
          (tostring(GDDEFS.MONO)),
          (tostring(true)),
          (GDDEFS.CHILDREN or 0x0),
          (GDDEFS.OBJ_STRING_NAME or 0x0),
          (GDDEFS.GDSCRIPTINSTANCE or 0x0),
          (GDDEFS.VAR_VECTOR or 0x0),
          (GDDEFS.SIZE_VECTOR or 0x0),
          (GDDEFS.GDSCRIPTNAME or 0x0),
          (GDDEFS.FUNC_MAP or 0x0),
          (GDDEFS.FUNC_CODE or 0x0),
          (GDDEFS.FUNC_CONST or 0x0),
          (GDDEFS.FUNC_GLOBNAMEPTR or 0x0),
          (GDDEFS.CONST_MAP or 0x0),
          (GDDEFS.VAR_NAMEINDEX_MAP or 0x0),
          (GDDEFS.VAR_NAMEINDEX_VARTYPE or 0x0),
          (GDDEFS.VAR_NAMEINDEX_I or 0x0))
          )
      end

      function GDAPI.gd_monitorProfile()
        print( NodeMonitorServiceThread.name )
      end

    -- ///---///--///---///--///---/// STRUCTURES

      --- deletes ALL structures, constructs a children structure of the viewport
      local function createVPStructure()
        -- https://wiki.cheatengine.org/index.php?title=Help_File:Script_engine#structure

        -- remove all structures
        -- structure.miClear if you want a confirmation
        while getStructureCount() > 0 do -- getStructure(n).Name, getStructure(n).Destroy()
          getStructure(0).Destroy()
        end

        -- Structure class related functions:
        -- getStructureCount(): Returns the number of Global structures. (Global structures are the visible structures)
        -- getStructure(index): Returns the Structure object at the given index
        -- createStructure(name): Returns an empty structure object (Not yet added to the Global list. Call structure.addToGlobalStructureList manually)

        local struct = createStructure('GDNODES')
        local structElem, childElem;
        local mainNodeTable = getMainNodeTable()

        struct.beginUpdate()
        for i = 0, #mainNodeTable - 1 do
          structElem = struct.addElement()
          structElem.BackgroundColor = 0x6C3157
          structElem.Offset = i * GDDEFS.PTRSIZE -- GDDEFS.PTRSIZE
          structElem.VarType = vtPointer
          structElem.Name = getNodeName(mainNodeTable[i + 1])
        end
        struct.endUpdate()
        struct.addToGlobalStructureList() -- so we can use it

        return struct
      end

      --- when called, creates a CE structure form window for the viewport and selects a newly-created GNODES structure
      local function createVPStructForm()
        if not (gdOffsetsDefined) then
          print('define the offsets first, silly')
          return
        end
        -- let's ensure VP is found, it will throw an error otherwise
        getViewport()

        local symbolToChildren = '[[ptVP]+' .. numtohexstr(GDDEFS.CHILDREN) .. ']' -- '[[ptVP]+CHILDREN]'
        local viewportStructForm = createStructureForm(symbolToChildren, 'VP', 'Viewport')
        local childrenStruct = createVPStructure()

        -- I couldn't find a better way to select a structure inside a StructDissect form
        for i = 0, viewportStructForm.Structures1.Count - 1 do
          local menuItem = viewportStructForm.Structures1.Item[i]
          if menuItem.Caption == 'GDNODES' then
            menuItem.doClick()
          end
        end

      end

      --- creates an element in a parent structure
      local function addStructureElem(parentStructElement, elementName, offset, CEType)
        local element = parentStructElement.ChildStruct.addElement()
        element.Name = elementName
        element.Offset = offset
        element.Vartype = CEType

        if CEType == vtUnicodeString then
          if GDDEFS.GD4_STRING_EXISTS then
            element.Vartype = vtCustom;
            element.CustomTypeName = "GD4 String"
          else
            element.Bytesize = 100;
          end
        elseif CEType == vtDword then
          element.DisplayMethod = 'dtSignedInteger'
        end

        return element
      end

      --- for node layout creation
      local function addLayoutStructElem(parentStructElement, childName, backgroundColor, offset, CEType)
        parentStructElement.ChildStruct = parentStructElement.ChildStruct and parentStructElement.ChildStruct or createStructure(parentStructElement.parent.Name or 'ChStructure')
        local childStructElement = parentStructElement.ChildStruct.addElement()
        childStructElement.Name = childName
        if backgroundColor ~= nil then
          childStructElement.BackgroundColor = backgroundColor
        end
        childStructElement.Offset = offset or 0x0
        childStructElement.VarType = CEType
        return childStructElement
      end

      local function createChildStructElem(parent, label, offset, ceType, structName)
        local elem = addStructureElem(parent, label, offset, ceType)
        elem.ChildStruct = createStructure(structName)
        return elem
      end

      --- overriden structure dissector function
      ---@param struct userdata @the newly created struct
      ---@param baseaddr number  @the address form the parent pointer
      function GDStructureDissect(struct, baseaddr)
        if not (gdOffsetsDefined) then
          print('define the offsets first, silly')
          return
        end

        if isNullOrNil(baseaddr) then
          return false
        end
        struct = struct and struct or createStructure('') -- should not happen though?
        struct.beginUpdate()

        if checkForGDScript(baseaddr) and isVtable(readPointer(baseaddr)) then
          dumpedDissectorNodes = {} -- redundant?
          -- safe to assume, that's a starting point
          local nodeName = getNodeName(baseaddr)
          if nodeName == 'N??' then nodeName = getNodeNameFromGDScript(baseaddr) end
          nodeName = nodeName and nodeName or 'Anon Node'
          struct.Name = ' Node: ' .. nodeName
          local scriptInstStructElem = struct.addElement()
          scriptInstStructElem.Name = 'GDScriptInstance'
          scriptInstStructElem.BackgroundColor = 0x400040
          scriptInstStructElem.Offset = GDDEFS.GDSCRIPTINSTANCE
          scriptInstStructElem.VarType = vtPointer

          if checkIfObjectWithChildren(baseaddr) then
            local childrenStructElem = struct.addElement()
            childrenStructElem.Name = 'Children'
            childrenStructElem.BackgroundColor = 0xFF0080
            childrenStructElem.Offset = GDDEFS.CHILDREN
            childrenStructElem.VarType = vtPointer
            childrenStructElem.ChildStruct = createStructure('Children')
            iterateNodeChildrenToStruct(childrenStructElem, baseaddr)
          end

          iterateNodeToStruct(baseaddr, scriptInstStructElem)

        elseif bDisasmFunc and checkIfGDFunction(baseaddr) then
          disassembleGDFunctionCodeToStruct(baseaddr, struct)

        elseif checkIfObjectWithChildren(baseaddr) then -- experimental, creating structs for nonGDScript objects
          local childrenStructElem = struct.addElement()
          childrenStructElem.Name = 'Children'
          childrenStructElem.BackgroundColor = 0xFF0080
          childrenStructElem.Offset = GDDEFS.CHILDREN
          childrenStructElem.VarType = vtPointer
          childrenStructElem.ChildStruct = createStructure('Children')
          iterateNodeChildrenToStruct(childrenStructElem, baseaddr)
        else
          -- otherwise just let CE decide, btw the base address must be a fucking hex string?
          struct.autoGuess(numtohexstr(baseaddr), 0x0, 0x500 ) -- 0x500 for researching
        end

        struct.endUpdate()
        return true
      end

      --- structname lookup that uses the virtual table to guess the type
      ---@param addr integer @address to typeguess
      ---@return string @name; base address isn't returned
      local function GDStructNameLookup(addr)
        if isInvalidPointer(addr) or not isVtable(readPointer(addr)) then
          return nil
        end

        local result = getGDObjectName(addr)
        if result == nil or result == '??' then
          return nil
        end

        return result
      end

      --- address lookup, not implemented
      ---@param addr integer @address to typeguess
      ---@return string @name;
      local function GDAddressLookup(addr)
        return nil
        -- if isInvalidPointer(addr) or not isVtable( readPointer( addr ) ) then
        --     return nil
        -- end

        -- local result = getGDObjectName(addr)
        -- if result == nil or result == '??' then
        --     return nil
        -- end

        -- return result
      end

      function GDAPI.godotAA_GETNODESTRUCT(nodeName)
        --[[
          take type size into account
          struct NODENAME
          padding: resb 99 // decimal
          fieldName: resb 4
          end
        ]]
        -- local nodeAddr = getDumpedNode(nodeName)
        -- local fields = godot_node_enumVariants(nodeAddr)
        -- if fields == nil or next(fields) == nil then return nil end

      end

      function GDAPI.godot_node_enumVariants(nodeAddr)
        return iterateVectorVariantsForFields(nodeAddr)
      end


      --- register our own structure dissector callback
      local function enableGDDissect()
        -- override CE's callback
        if GDstructDissectID ~= nil then
          unregisterStructureDissectOverride(GDstructDissectID)
        end
        GDstructDissectID = registerStructureDissectOverride(GDStructureDissect)
      end

      --- unregister our structure dissector callback
      local function disableGDDissect()
        -- restore CE's callback
        if GDstructDissectID ~= nil then
          unregisterStructureDissectOverride(GDstructDissectID)
        end
        GDstructDissectID = nil;
      end

      local function enableGDStructNameLookup()
        -- override CE's lookup
        if GDStructNameLookupID ~= nil then
          unregisterStructureNameLookup(GDStructNameLookupID)
        end
        GDStructNameLookupID = registerStructureNameLookup(GDStructNameLookup)
      end

      local function disableGDStructNameLookup()
        -- restore CE's lookup
        if GDStructNameLookupID ~= nil then
          unregisterStructureNameLookup(GDStructNameLookupID)
        end
        GDStructNameLookupID = nil;
      end

      local function enableGDAddressLookup()
        -- override CE's lookup
        if GDAddressLookupID ~= nil then
          unregisterAddressLookupCallback(GDAddressLookupID)
        end
        GDAddressLookupID = registerAddressLookupCallback(GDStructNameLookup)
      end

      local function disableGDAddressLookup()
        -- restore CE's lookup
        if GDAddressLookupID ~= nil then
          unregisterAddressLookupCallback(GDAddressLookupID)
        end
        GDAddressLookupID = nil;
      end

    -- ///---///--///---///--///---/// GUI

      --- toggling dissector override
      local function GDDissectorSwitch(sender)
        -- if not (gdOffsetsDefined) then print('define the offsets first, silly') return end
        sender.Checked = not sender.Checked
        if sender.Checked then
          enableGDDissect()
        else
          disableGDDissect()
        end
      end

      local function GDStructNameLookupSwitch(sender)
        if not (gdOffsetsDefined) then
          print('define the offsets first, silly')
          return
        end
        sender.Checked = not sender.Checked
        if sender.Checked then
          enableGDStructNameLookup()
        else
          disableGDStructNameLookup()
        end
      end

      local function GDAddressLookupSwitch(sender)
        if not (gdOffsetsDefined) then
          print('define the offsets first, silly')
          return
        end
        sender.Checked = not sender.Checked
        if sender.Checked then
          enableGDAddressLookup()
        else
          disableGDAddressLookup()
        end
      end

      local function GDDebugSwitch(sender)
        sender.Checked = not sender.Checked
        if sender.Checked then
          bGDDebug = true
        else
          bGDDebug = false
        end
      end

      local function GDDisasmFuncSwitch(sender)
        sender.Checked = not sender.Checked
        if sender.Checked then
          bDisasmFunc = true
        else
          bDisasmFunc = false
        end
      end

      local function GDStoredOffsetsSwitch(sender)
        sender.Checked = not sender.Checked
        if sender.Checked then
          bHardOffsets = true
        else
          bHardOffsets = false
        end
      end

      local function addGDMemrecToTable(sender)
        local addrList = getAddressList()
        local mainMemrec = addrList.createMemoryRecord()
        mainMemrec.Description = "Dumper"
        mainMemrec.Type = vtAutoAssembler
        mainMemrec.Options = '[moHideChildren,moDeactivateChildrenAsWell]'
        mainMemrec.Script = "{$lua}\n[ENABLE]\nif syntaxcheck then return end\nlocal config = {\n---- e.g. Godot Engine v4.5.1.stable.custom_build ;;; godot.windows.template_debug.x86_64.exe\n---- If you specify all ENGINE VER values, set useHardcoded to true to let script use hardcoded offsets\n---- If you don't have the CERegEx plugin, the\n\n-- ENGINE VER START\nuseHardcoded =              true, -- set to true if you want the script to use hardcoded offsets to skip defining OFFSETS below, false if you do it yourself\nGDCustomver =               nil, -- (optional) if custom build ver, false otherwise;\nmajorVersion =              nil, -- (optional) major godot ver, e.g. 4\nminorVersion =              nil, -- (optional) minor godot ver, e.g. 5\nGDDebugVer =                nil, -- (optional) if it's template_debug ver, false otherwise\nisMonoTarget =              nil, -- (optional) set to true if it's using mono/C#, false otherwise\n-- ENGINE VER END\n\n-- replace nil with hex offsets according to the instruction\n-- OFFSETS START\noffsetNodeChildren =        nil, -- offset to Node->children, it's a classic array of Nodes: consecutive 8/4 byte ptrs on x64/x32 apps respectively\noffsetNodeStringName =      nil,  -- offset to Node->name, it's a pointer to StringName object which usually has a string at either 0x8 or 0x10 (x64)\noffsetGDScriptInstance =    nil, -- for Node types that have a GDScript, Node->GDScriptInstance, it points to an object with a vTable where the next pointer is the owner Node reference and the next offset being the GDScript\noffsetVariantVector =       nil, -- Node->GDScriptInstance->\noffsetVariantVectorSize =   nil, -- located 0x4 or 0x8 or 0x10 behind 1st elem of a vector\n\noffsetGDScriptName =        nil, -- Node->GDScriptInstance->GDScript->name, it points to a raw string data that starts with res://\noffsetFuncMap =             nil, -- if you need funcs: GDScript->member_functions - in 4.x - (4 consecutive pointers, capacity and size) use offset to the Head (second to the last ptr) || in 3.x (pointer to the RBT root and the sentinel after it) use offset to the root\noffsetGDFunctionCode =      nil, -- if you need funcs: GDScript->member_functions['abc']->code - it's an int array inside a function storing implemented GDFunction byetcode, very easy to spot\noffsetGDFunctionConst =     nil, -- if you need funcs: GDScript->member_functions['abc']->constants - it's a Vector<Variant> with script constants, relative to code\noffsetGDFunctionGlobals =   nil, -- if you need funcs: GDScript->member_functions['abc']->global_names - Vector of StringNames, relative to code and constants\noffsetConstMap =            nil, -- GDScript->constants - layout same as w/ offsetGDFunctionCode\noffsetVariantMap =          nil, -- GDScript->member_indices - layout same as w/ offsetGDFunctionCode\noffsetVariantMapVarType =   nil, -- essential for 4.x: MemberInfo inside GDScript->member_indices, we need pointer to the Variant type for crosschecking \noffsetVariantMapIndex =     nil, -- essential for 3.x: MemberInfo inside GDScript->member_indices, we need pointer to the Variant index for correctly mapping Variants in Nodes\n\n--vtGetClassNameIndex =       nil, -- 0-based vtable index to the virtual method that returns class name for _this_ object\n-- OFFSETS END\n}\ninitDumper(config)\n[DISABLE]\n--NodeMonitorServiceSwitch()\n"

        local dumpMemrec = addrList.createMemoryRecord()
        dumpMemrec.Description = 'TEMPLATE: DumpOneNodeSymbol'
        dumpMemrec.Type = vtAutoAssembler
        dumpMemrec.Async = true
        dumpMemrec.Options = '[moHideChildren,moDeactivateChildrenAsWell]'
        dumpMemrec.Script = '{$lua}\nif syntaxcheck then return end\n[ENABLE]\nDumpNodeToAddr(memrec, getDumpedNode( "Globals" ), false) -- change Globals to other node names\n[DISABLE]'
        dumpMemrec.appendToEntry(mainMemrec)

        local dumpMemrec = addrList.createMemoryRecord()
        dumpMemrec.Description = 'Dump All Nodes (main)'
        dumpMemrec.Type = vtAutoAssembler
        dumpMemrec.Options = '[moHideChildren,moDeactivateChildrenAsWell]'
        dumpMemrec.Async = true
        dumpMemrec.Script = '{$lua}\nif syntaxcheck then return end\n[ENABLE]\nDumpAllNodesToAddr()\n[DISABLE]'
        dumpMemrec.appendToEntry(mainMemrec)

        local supportPalique = addrList.createMemoryRecord()
        supportPalique.Description = 'Support the development & author: ko-fi.com/vesperpallens'
        supportPalique.Type = vtAutoAssembler
        supportPalique.Color = 0x8F379F
        supportPalique.Script = '{$lua}\n[ENABLE]\nshellExecute("https://ko-fi.com/vesperpallens")\n[DISABLE]'
      end

      -- attaches the script to the table
      local function appendDumperScript(sender)
        local cedir = getCheatEngineDir()
        local scriptPath = cedir .. [[autorun\GDumper.lua]]
        createTableFile("GDumper", scriptPath)
        sender.Enabled = false
      end

      -- appends the script as a memrec
      local function appendDumperScriptAsMemrec(sender)
        local cedir = getCheatEngineDir()
        local scriptPath = cedir .. [[autorun\GDumper.lua]]
        
        sender.Enabled = false
      end

      -- load from attached script
      local function loadDumperScript(sender)
        local tableFile = findTableFile("GDumper")
        if tableFile == nil then error('no script file found') end
        local fileStream = tableFile.getData()
        local scriptString = readStringLocal(fileStream.Memory, fileStream.Size)
        if scriptString ~= nil then
          local doScript = loadstring(scriptString)
          if type(doScript) == 'function' then
            doScript()
            if sender then sender.Checked = true end
          else
            error('script not parsed')
          end
        else
          error('script not loaded from file')
        end
      end

      local function loadDumperScriptFromFile(sender)
        local cedir = getCheatEngineDir()
        local scriptPath = cedir .. [[autorun\GDumper.lua]]
        local scriptFile, err = io.open(scriptPath, "r")
        if not scriptFile then
          error("Could not open file: " .. scriptPath .. "\n" .. tostring(err))
        end
        local scriptCode = scriptFile:read("*a")
        scriptFile:close()
        if scriptCode and scriptCode ~= "" then
          local doScript, loadErr = loadstring(scriptCode)
          if not doScript then
            error("Compile error in " .. scriptPath .. ":\n" .. tostring(loadErr))
          end
          local ok, runErr = pcall(doScript)
          if not ok then
            error("Runtime error in " .. scriptPath .. ":\n" .. tostring(runErr))
          end
        else
          error("File is empty: " .. scriptPath)
        end
      end

      local function loadGDDumperForm()
        local gdform = createFormFromFile(getCheatEngineDir()..[[autorun\gdform\GDForm.FRM]])
        gdform.setDoNotSaveInTable(true)
        -- TODO: setup
        local gdtreeview = gdform.ComponentByName["treeviewNodes"]

        -- https://wiki.cheatengine.org/index.php?title=Help_File:Script_engine#TreeNode
        -- https://wiki.cheatengine.org/index.php?title=Help_File:Script_engine#TreeNodes
        local rootNode = gdtreeview.getItems().add("root")
        rootNode.getItem().Text = "NodeChild"
      end

      --- creates a menu button in the main menu
      function GDAPI.buildGDGUI()
        if GDGUIInit then
          return
        end
        GDGUIInit = true

        -- creates and adds button to parent with callback on click
        local function addCustomMenuButtonTo(ownerParent, captionName, customCallback)
          local newMenuItem = createMenuItem(ownerParent)
          newMenuItem.Caption = captionName
          ownerParent.add(newMenuItem)
          newMenuItem.OnClick = customCallback
          return newMenuItem
        end

        local menuItemCaption = 'GDDumper'
        local mainMenu = getMainForm().Menu
        local gdMenuItem = nil

        for i = 0, mainMenu.Items.Count - 1 do
          if mainMenu.Items.Item[i].Caption == menuItemCaption then
            gdMenuItem = mainMenu.Items.Item[i]
            break
          end
        end

        if not gdMenuItem then
          gdMenuItem = createMenuItem(mainMenu)
          gdMenuItem.Caption = menuItemCaption
          mainMenu.Items.add(gdMenuItem)
          addCustomMenuButtonTo(gdMenuItem, 'VP Struct', createVPStructForm)
          addCustomMenuButtonTo(gdMenuItem, 'GD Dissector', GDDissectorSwitch)
          addCustomMenuButtonTo(gdMenuItem, 'Add Template', addGDMemrecToTable)
          addCustomMenuButtonTo(gdMenuItem, 'Use stored offsets', GDStoredOffsetsSwitch)
          -- addCustomMenuButtonTo(gdMenuItem, 'Disasm Funcs', GDDisasmFuncSwitch)
          addCustomMenuButtonTo(gdMenuItem, 'Debug Mode', GDDebugSwitch)
          addCustomMenuButtonTo(gdMenuItem, 'GD StuctName Lookup', GDStructNameLookupSwitch)
          -- addCustomMenuButtonTo( gdMenuItem, 'GD Addr Lookup', GDAddressLookupSwitch )
          local menuItem = addCustomMenuButtonTo(gdMenuItem, 'Append Script', appendDumperScript)
          -- menuItem.OnEnter = function(sender) if sender.Enabled==false and findTableFile("GDumper")==nil then sender.Enabled=true end end
          
          -- addCustomMenuButtonTo(gdMenuItem, 'Append as memrec', appendDumperScriptAsMemrec)
          addCustomMenuButtonTo(gdMenuItem, 'Load Script', loadDumperScript)
          addCustomMenuButtonTo(gdMenuItem, 'Support development', function() shellExecute("https://ko-fi.com/vesperpallens") end)
          -- addCustomMenuButtonTo( gdMenuItem, 'Reload from file', loadDumperScriptFromFile )
        end
      end



  -- ///---///--///---///--///---///--///--///---///--///---///--///---///--/// TYPES/SIZE

    --- @unreliable takes in a vector + its size. Returns an inferred variant size and successBool
    ---@param vectorPtr number
    ---@param vectorSize number
    local function redefineVariantSizeByVector(vectorPtr, vectorSize)
      if isNullOrNil(vectorPtr) or isNullOrNil(vectorSize) then return 0, false; end
      -- assert((type(vectorPtr) == 'number'), "vectorPtr has to be a number, instead got: " .. type(vectorPtr))
      -- assert((type(vectorSize) == 'number') and (vectorSize > 0), "VectorSize is empty or not a number, type: " .. type(vectorSize))

      if isNullOrNil(vectorSize) then
        -- sendDebugMessage('Bad vector size for '..numtohexstr(vectorPtr));
        return 0x18, true;
      end

      if GDDEFS.MAJOR_VER == 4 then
        if (vectorSize == 1) and (getGDTypeName( readInteger(vectorPtr) ) == "DICTIONARY") then -- TODO: BRITTLE, investigate how consistent dictionaries do that
          -- sendDebugMessage("1-sized Vector: Variant was resized to 0x30 (vector: "..('%x '):format(vectorPtr))
          return 0x30, true;
        elseif (vectorSize == 1) then
          -- sendDebugMessage("1-sized Vector: Variant was left 0x18 long (vector: "..('%x '):format(vectorPtr))
          return 0x18, true;
        end

        if (vectorSize == 2) and getGDTypeName(readInteger(vectorPtr)) and getGDTypeName(readInteger(vectorPtr + 0x18)) then -- is it a valid variant Type?
          return 0x18, true;
        elseif (vectorSize == 2) and getGDTypeName(readInteger(vectorPtr)) and getGDTypeName(readInteger(vectorPtr + 0x30)) then -- if it's 0x30
          -- sendDebugMessage("Variant was resized to 0x30 (vector: "..('%x'):format(vectorPtr)..")")
          return 0x30, true;
        elseif (vectorSize == 2) and getGDTypeName(readInteger(vectorPtr)) and getGDTypeName(readInteger(vectorPtr + 0x40)) then -- if it's 0x40
          -- sendDebugMessage("Variant was resized to 0x40 (vector: "..('%x'):format(vectorPtr)..")")
          return 0x40, true;
        end

        if getGDTypeName(readInteger(vectorPtr)) and getGDTypeName(readInteger(vectorPtr + 0x18)) and getGDTypeName(readInteger(vectorPtr + 0x18 * 2)) then -- is it a valid variant Type?
          return 0x18, true;
        elseif getGDTypeName(readInteger(vectorPtr)) and getGDTypeName(readInteger(vectorPtr + 0x30)) and getGDTypeName(readInteger(vectorPtr + 0x30 * 2)) then
          -- sendDebugMessage("Variant was resized to 0x30 (vector: "..('%x'):format(vectorPtr)..")")
          return 0x30, true;
        elseif getGDTypeName(readInteger(vectorPtr)) and getGDTypeName(readInteger(vectorPtr + 0x40)) and getGDTypeName(readInteger(vectorPtr + 0x40 * 2)) then
          -- sendDebugMessage("Variant was resized to 0x40 (vector: "..('%x'):format(vectorPtr)..")")
          return 0x40, true;
        end

      elseif GDDEFS.MAJOR_VER == 3 then
        if (vectorSize == 1) and (getGDTypeName(vectorPtr) == 'DICTIONARY') then -- for some reasons single-sized vectors with dict were 0x30
          -- sendDebugMessage("1-sized Vector: Variant was resized to 0x30 (vector: "..('%x '):format(vectorPtr))
          return 0x20, true;
        elseif (vectorSize == 1) then
          -- sendDebugMessage("1-sized Vector: Variant was left 0x18 long (vector: "..('%x '):format(vectorPtr))
          return 0x18, true; -- Usual size is 0x18 in 3.x
        end

        if (vectorSize == 2) and getGDTypeName(readInteger(vectorPtr)) and getGDTypeName(readInteger(vectorPtr + 0x18)) then -- is it a valid variant Type?
          return 0x18, true; -- Usual size is 0x18 in 3.x
        elseif (vectorSize == 2) and getGDTypeName(readInteger(vectorPtr)) and getGDTypeName(readInteger(vectorPtr + 0x20)) then
          -- sendDebugMessage("2s Variant was resized to 0x20 (vector: "..('%x'):format(vectorPtr)..")")
          return 0x20, true;
        elseif (vectorSize == 2) and getGDTypeName(readInteger(vectorPtr)) and getGDTypeName(readInteger(vectorPtr + 0x30)) then
          -- sendDebugMessage("2s Variant was resized to 0x30 (vector: "..('%x'):format(vectorPtr)..")")
          return 0x30, true; -- what's the longest for 3.x?
        end

        if getGDTypeName(readInteger(vectorPtr)) and getGDTypeName(readInteger(vectorPtr + 0x18)) and getGDTypeName(readInteger(vectorPtr + 0x18 * 2)) then -- is it a valid variant Type?
          return 0x18, true; -- Usual size is 0x18 in 3.x
        elseif getGDTypeName(readInteger(vectorPtr)) and getGDTypeName(readInteger(vectorPtr + 0x20)) and getGDTypeName(readInteger(vectorPtr + 0x20 * 2)) then
          -- sendDebugMessage("Variant was resized to 0x20 (vector: "..('%x'):format(vectorPtr)..")")
          return 0x20, true;
        elseif getGDTypeName(readInteger(vectorPtr)) and getGDTypeName(readInteger(vectorPtr + 0x30)) and getGDTypeName(readInteger(vectorPtr + 0x30 * 2)) then
          -- sendDebugMessage("Variant was resized to 0x30 (vector: "..('%x'):format(vectorPtr)..")")
          return 0x30, true; -- what's the longest for 3.x?
        end
      else
        -- TODO
      end

      -- sendDebugMessage("Variant resize failed past 4 cases (vector: "..numtohexstr(vectorPtr)..")")
      -- // Variant takes 24 bytes when real_t is float, and 40 bytes if double.
      -- // It only allocates extra memory for AABB/Transform2D (24, 48 if double),
      -- // Basis/Transform3D (48, 96 if double), Projection (64, 128 if double),
      -- // and PackedArray/Array/Dictionary (platform-dependent).
      return false;
    end

    --- returns an adjusted offset to a variant value
    ---@param gdType number
    local function getVariantValueOffset(gdType)
      if gdType == nil then
        return 0x8
        -- if inMainThread() then return 0x8 else getCurrentThreadObject().terminate() end
      end
      if (getGDTypeName(gdType) == 'OBJECT') then
        return 0x10
      end -- objects have 0x10 offset for value
      -- not sure about the rest
      return 0x8 -- the rest have this offset
    end

    local function defineVariantTypeProfile()
      if isNotNullOrNil(GDDEFS.VARIANT_TYPE_PROFILE) then
        return GDDEFS.VARIANT_TYPE_PROFILE
      end

      local function cloneArray(tabl)
        local result = {}
        for i, val in ipairs(tabl) do result[i] = val end
        return result
      end

      local function insertValueBefore(list, anchor, valueToInsert)
        for i, val in ipairs(list) do
          if val == anchor then
            table.insert(list, i, valueToInsert)
            return
          end
        end
        error("insertValueBefore: anchor not found: " .. tostring(anchor))
      end

      local function insertValueAfter(list, anchor, valueToInsert)
        for i, val in ipairs(list) do
          if val == anchor then
            table.insert(list, i + 1, valueToInsert)
            return
          end
        end
        error("insertValueAfter: anchor not found: " .. tostring(anchor))
      end

      local function removeValue(list, valueToRemove)
        for i, val in ipairs(list) do
          if val == valueToRemove then
            table.remove(list, i)
            return
          end
        end
        error("removeValue: value not found: " .. tostring(valueToRemove))
      end

      local function applyPatchOnList(list, patch)
        if patch.kind == "insertValueBefore" then
          insertValueBefore(list, patch.anchor, patch.value)
        elseif patch.kind == "insertValueAfter" then
          insertValueAfter(list, patch.anchor, patch.value)
        elseif patch.kind == "removeValue" then
          removeValue(list, patch.value)
        else
          error("Unknown patch kind: " .. tostring(patch.kind))
        end
      end

      local function prepareProfileSpec(version, specs, visited)
        local spec = specs[version]
        if not spec then
          error("Unknown Variant type version: " .. tostring(version))
        end

        visited = visited or {}
        if visited[version] then
          error("Circular Variant type profile inheritance for version: " .. tostring(version))
        end
        visited[version] = true

        local resolved = { version = version, orderedTypes = nil }

        if spec.base then
          local parent = prepareProfileSpec(spec.base, specs, visited)
          resolved.orderedTypes = cloneArray(parent.orderedTypes)

          if spec.patches then
            for _, patch in ipairs(spec.patches) do
              applyPatchOnList(resolved.orderedTypes, patch)
            end
          end
        else
          resolved.orderedTypes = cloneArray(spec.orderedTypes or {})
        end

        return resolved
      end

      local ceTypeByName =
        {
          NIL = vtPointer,
          BOOL = vtByte,
          INT = vtDword,
          FLOAT = vtDouble,
          STRING = vtString,

          VECTOR2 = vtSingle,
          VECTOR2I = vtSingle,
          RECT2 = vtSingle,
          RECT2I = vtSingle,
          VECTOR3 = vtSingle,
          VECTOR3I = vtSingle,
          TRANSFORM2D = vtSingle,
          VECTOR4 = vtSingle,
          VECTOR4I = vtSingle,
          COLOR = vtSingle,

          PLANE = vtPointer,
          QUATERNION = vtPointer,
          AABB = vtPointer,
          BASIS = vtPointer,
          TRANSFORM3D = vtPointer,
          PROJECTION = vtPointer,
          STRING_NAME = vtPointer,
          NODE_PATH = vtPointer,
          RID = vtPointer,
          OBJECT = vtPointer,
          CALLABLE = vtPointer,
          SIGNAL = vtPointer,
          DICTIONARY = vtPointer,
          ARRAY = vtPointer,
          PACKED_BYTE_ARRAY = vtPointer,
          PACKED_INT32_ARRAY = vtPointer,
          PACKED_INT64_ARRAY = vtPointer,
          PACKED_FLOAT32_ARRAY = vtPointer,
          PACKED_FLOAT64_ARRAY = vtPointer,
          PACKED_STRING_ARRAY = vtPointer,
          PACKED_VECTOR2_ARRAY = vtPointer,
          PACKED_VECTOR3_ARRAY = vtPointer,
          PACKED_COLOR_ARRAY = vtPointer,
          PACKED_VECTOR4_ARRAY = vtPointer,
          VARIANT_MAX = vtPointer
        }

      local specs =
        {
          -- no changes on major-minor
          ["3.0"] =
            {
              orderedTypes =
              {
                "NIL",
                "BOOL",
                "INT",
                "FLOAT", -- REAL
                "STRING",
                "VECTOR2",
                "RECT2",
                "VECTOR3",
                "TRANSFORM2D",
                "PLANE",
                "QUATERNION", -- QUAT
                "AABB",
                "BASIS",
                "TRANSFORM3D",
                "COLOR",
                "NODE_PATH",
                "RID", -- _RID
                "OBJECT",
                "DICTIONARY",
                "ARRAY",
                "PACKED_BYTE_ARRAY",
                "PACKED_INT64_ARRAY",
                "PACKED_FLOAT32_ARRAY", -- REAL
                "PACKED_STRING_ARRAY",
                "PACKED_VECTOR2_ARRAY",
                "PACKED_VECTOR3_ARRAY",
                "PACKED_COLOR_ARRAY",
                "VARIANT_MAX"
              }
            },
          ["3.1"] = { base = "3.0", patches = {} },
          ["3.2"] = { base = "3.1", patches = {} },
          ["3.3"] = { base = "3.2", patches = {} },
          ["3.4"] = { base = "3.3", patches = {} },
          ["3.5"] = { base = "3.4", patches = {} },
          ["3.6"] = { base = "3.5", patches = {} },

          ["4.0"] =
            {
              orderedTypes =
              {
                "NIL",
                "BOOL",
                "INT",
                "FLOAT",
                "STRING",
                "VECTOR2",
                "VECTOR2I",
                "RECT2",
                "RECT2I",
                "VECTOR3",
                "VECTOR3I",
                "TRANSFORM2D",
                "VECTOR4",
                "VECTOR4I",
                "PLANE",
                "QUATERNION",
                "AABB",
                "BASIS",
                "TRANSFORM3D",
                "PROJECTION",
                "COLOR",
                "STRING_NAME",
                "NODE_PATH",
                "RID",
                "OBJECT",
                "CALLABLE",
                "SIGNAL",
                "DICTIONARY",
                "ARRAY",
                "PACKED_BYTE_ARRAY",
                "PACKED_INT32_ARRAY",
                "PACKED_INT64_ARRAY",
                "PACKED_FLOAT32_ARRAY",
                "PACKED_FLOAT64_ARRAY",
                "PACKED_STRING_ARRAY",
                "PACKED_VECTOR2_ARRAY",
                "PACKED_VECTOR3_ARRAY",
                "PACKED_COLOR_ARRAY",
                "VARIANT_MAX"
              }
            },

          ["4.1"] = { base = "4.0", patches = {} },
          ["4.2"] = { base = "4.1", patches = {} },
          ["4.3"] = { base = "4.2", patches = {} },
          ["4.4"] = { base = "4.3", patches = { kind = "insertValueAfter", anchor = "PACKED_COLOR_ARRAY", value = "PACKED_VECTOR4_ARRAY" } },
          ["4.5"] = { base = "4.4", patches = {} },
          ["4.6"] = { base = "4.5", patches = {} },
          ["4.7"] = { base = "4.6", patches = {} },
          ["4.8"] = { base = "4.7", patches = {} },
        }

      local version = GDDEFS.VERSION_STRING
      local resolved = prepareProfileSpec(version, specs)

      local profile =
        {
          version = version,
          names = {},
          enums = {},
          ceTypes = {},
          maxType = #resolved.orderedTypes - 1
        }

      for i, typeName in ipairs(resolved.orderedTypes) do
        local enum = i - 1
        profile.names[enum] = typeName
        profile.enums[typeName] = enum
        profile.ceTypes[enum] = ceTypeByName[typeName] or vtPointer
      end

      GDDEFS.VARIANT_TYPE_PROFILE = profile
      GDDEFS.VARIANT_TYPE_NAMES = profile.names
      GDDEFS.VARIANT_TYPE_ENUMS = profile.enums
      GDDEFS.VARIANT_TYPES = profile.ceTypes
      GDDEFS.MAXTYPE = profile.maxType

      return profile
    end

    --- takes a godot type. Returns CEType
    ---@param gdType number
    local function getCETypeFromGD(gdType)
      if type(gdType) ~= "number" then return vtPointer end
      return GDDEFS.VARIANT_TYPE_PROFILE.ceTypes[gdType] or vtPointer
    end

    --- takes in a godot type, returns a godot type name
    ---@param typeInt number
    function getGDTypeName(typeInt)
      if type(typeInt) ~= "number" then return false; end
      return GDDEFS.VARIANT_TYPE_PROFILE.names[typeInt] or "BEYOND_VARIANT_MAX"
    end

    --- takes in a godot type, returns a godot type name
    ---@param typeInt number
    local function getGDTypeEnumFromName(typeName)
      if type(typeName) ~= "string" then error("invalid typename") end
      local enum = GDDEFS.VARIANT_TYPE_PROFILE.enums[typeName]
      if isNullOrNil(enum) then error("getGDTypeEnumFromName: invalid typename " .. typeName) end
      return enum
    end

    --- I'm gonna add a 4byte string type
    local function checkGDStringType()

      local function gd4string_bytestovalue(b1, address)
        local MAX_CHARS_TO_READ = 15000
        local charTable = {}
        local buff = 0;

        for i = 0, MAX_CHARS_TO_READ do
          buff = readInteger(address + i * 0x4) or 0x0
          if buff == 0 then
            break
          end
          charTable[#charTable + 1] = codePointToUTF8(buff)
        end

        return table.concat(charTable)
      end

      local function gd4string_valuetobytes(str, address)
        error('Writing not implemented until I figure out how to do it properly')
        local idx = 0
        for codePoint in UTF8Codepoints(str) do
          -- clamping invalid/surrogate range
          if codePoint < 0 or codePoint > 0x10FFFF or codePoint >= 0xD800 and codePoint <= 0xDFFF then
            codePoint = 0xFFFD
          end

          writeInteger(address + idx * 0x4, codePoint)
          idx = idx + 1
        end

        -- null terminator
        writeInteger(address + idx * 4, 0x0)

        return readByte(address) or 0x0
        -- return string.byte( str, 1 ) -- bullshit, from what I suggest, CE stores the last 8bytes (?) of the orig memory in advance and after the callback it writes
        -- those 8 bytes replacing the first byte with a 0x0 (if returned nothing here)
      end

      local cAAUTF32StringTypeScript = '{$c}\n\nchar TypeName[] = "GD4 String";\nint ByteSize = 800;\nchar usesFloat = 0;\nchar usesString = 1;\nchar CallMethod = 1;\nunsigned short MaxStringSize = 800;\n\n#include <stdint.h>\n#include <stddef.h>\n\nstatic int is_valid_codepoint(uint32_t cp)\n{\n  if (cp > 0x10FFFF)\n  {\n    return 0;\n  }\n\n  if (cp >= 0xD800 && cp <= 0xDFFF)\n  {\n    return 0;\n  }\n\n  return 1;\n}\n\nstatic size_t utf32le_to_utf8(const uint32_t *input, char *output, size_t max_output)\n{\n  if (input == 0 || output == 0 || max_output == 0)\n  {\n    return 0;\n  }\n\n  size_t o = 0;\n\n  for (size_t i = 0; input[i] != 0; i++)\n  {\n    uint32_t cp = input[i];\n\n    if (!is_valid_codepoint(cp))\n    {\n      cp = 0xFFFD;\n    }\n\n    if (cp <= 0x7F)\n    {\n      if (o + 1 >= max_output)\n      {\n        break;\n      }\n\n      output[o++] = (char)cp;\n    }\n    else if (cp <= 0x7FF)\n    {\n      if (o + 2 >= max_output)\n      {\n        break;\n      }\n\n      output[o++] = (char)(0xC0 | (cp >> 6));\n      output[o++] = (char)(0x80 | (cp & 0x3F));\n    }\n    else if (cp <= 0xFFFF)\n    {\n      if (o + 3 >= max_output)\n      {\n        break;\n      }\n\n      output[o++] = (char)(0xE0 | (cp >> 12));\n      output[o++] = (char)(0x80 | ((cp >> 6) & 0x3F));\n      output[o++] = (char)(0x80 | (cp & 0x3F));\n    }\n    else\n    {\n      if (o + 4 >= max_output)\n      {\n        break;\n      }\n\n      output[o++] = (char)(0xF0 | (cp >> 18));\n      output[o++] = (char)(0x80 | ((cp >> 12) & 0x3F));\n      output[o++] = (char)(0x80 | ((cp >> 6) & 0x3F));\n      output[o++] = (char)(0x80 | (cp & 0x3F));\n    }\n  }\n\n  output[o] = \'\\0\';\n  return o;\n}\n\nstatic size_t utf8_to_utf32le(const char *input, uint32_t *output, size_t max_output)\n{\n  if (input == 0 || output == 0 || max_output == 0)\n  {\n    return 0;\n  }\n\n  size_t i = 0;\n  const unsigned char *p = (const unsigned char *)input;\n\n  while (*p != 0 && i + 1 < max_output)\n  {\n    uint32_t cp = 0xFFFD;\n\n    if (*p < 0x80)\n    {\n      cp = *p;\n      p += 1;\n    }\n    else if (*p >= 0xC2 && *p < 0xE0)\n    {\n      unsigned char b1 = p[0];\n      unsigned char b2 = p[1];\n\n      if ((b2 & 0xC0) == 0x80)\n      {\n        cp = ((uint32_t)(b1 & 0x1F) << 6) | (uint32_t)(b2 & 0x3F);\n        p += 2;\n      }\n      else\n      {\n        p += 1;\n      }\n    }\n    else if (*p < 0xF0)\n    {\n      unsigned char b1 = p[0];\n      unsigned char b2 = p[1];\n      unsigned char b3 = p[2];\n\n      if ((b2 & 0xC0) == 0x80 && (b3 & 0xC0) == 0x80)\n      {\n        cp = ((uint32_t)(b1 & 0x0F) << 12) | ((uint32_t)(b2 & 0x3F) << 6) | (uint32_t)(b3 & 0x3F);\n\n        if (!is_valid_codepoint(cp))\n        {\n          cp = 0xFFFD;\n        }\n\n        p += 3;\n      }\n      else\n      {\n        p += 1;\n      }\n    }\n    else if (*p < 0xF5)\n    {\n      unsigned char b1 = p[0];\n      unsigned char b2 = p[1];\n      unsigned char b3 = p[2];\n      unsigned char b4 = p[3];\n\n      if ((b2 & 0xC0) == 0x80 && (b3 & 0xC0) == 0x80 && (b4 & 0xC0) == 0x80)\n      {\n        cp = ((uint32_t)(b1 & 0x07) << 18) | ((uint32_t)(b2 & 0x3F) << 12) | ((uint32_t)(b3 & 0x3F) << 6) | (uint32_t)(b4 & 0x3F);\n\n        if (!is_valid_codepoint(cp))\n        {\n          cp = 0xFFFD;\n        }\n\n        p += 4;\n      }\n      else\n      {\n        p += 1;\n      }\n    }\n    else\n    {\n      p += 1;\n    }\n\n    output[i++] = cp;\n  }\n\n  output[i] = 0;\n  return i;\n}\n\n__cdecl int ConvertRoutine(unsigned char *data, unsigned long long address, unsigned char *output)\n{\n  const uint32_t *gd_string = (const uint32_t *)data;\n\n  utf32le_to_utf8(gd_string, (char *)output, MaxStringSize);\n\n  return 1;\n}\n\n__cdecl void ConvertBackRoutine(unsigned char *input, unsigned long long address, unsigned char *output)\n{\n  const char *s = (const char *)input;\n\n  // theres an issue where a char like \'/\' would feak CE to wrap the str with brackets\n  if (s[0] == \'[\')\n  {\n    s++;\n  }\n\n  char cleaned[512];\n  size_t len = 0;\n\n  while (s[len] != 0 && s[len] != \']\' && len + 1 < sizeof(cleaned))\n  {\n    cleaned[len] = s[len];\n    len++;\n  }\n\n  // end bracket\n  cleaned[len] = 0;\n\n  uint32_t *gd_string = (uint32_t *)output;\n  size_t max_codepoints = ByteSize / 4;\n\n  utf8_to_utf32le(cleaned, gd_string, max_codepoints);\n}\n\n{$asm}'
      --[[
        {$c}

        char TypeName[] = "GD4 String";
        int ByteSize = 800;
        char usesFloat = 0;
        char usesString = 1;
        char CallMethod = 1;
        unsigned short MaxStringSize = 800;

        #include <stdint.h>
        #include <stddef.h>

        static int is_valid_codepoint(uint32_t cp)
        {
          if (cp > 0x10FFFF)
          {
            return 0;
          }

          if (cp >= 0xD800 && cp <= 0xDFFF)
          {
            return 0;
          }

          return 1;
        }

        static size_t utf32le_to_utf8(const uint32_t *input, char *output, size_t max_output)
        {
          if (input == 0 || output == 0 || max_output == 0)
          {
            return 0;
          }

          size_t o = 0;

          for (size_t i = 0; input[i] != 0; i++)
          {
            uint32_t cp = input[i];

            if (!is_valid_codepoint(cp))
            {
              cp = 0xFFFD;
            }

            if (cp <= 0x7F)
            {
              if (o + 1 >= max_output)
              {
                break;
              }

              output[o++] = (char)cp;
            }
            else if (cp <= 0x7FF)
            {
              if (o + 2 >= max_output)
              {
                break;
              }

              output[o++] = (char)(0xC0 | (cp >> 6));
              output[o++] = (char)(0x80 | (cp & 0x3F));
            }
            else if (cp <= 0xFFFF)
            {
              if (o + 3 >= max_output)
              {
                break;
              }

              output[o++] = (char)(0xE0 | (cp >> 12));
              output[o++] = (char)(0x80 | ((cp >> 6) & 0x3F));
              output[o++] = (char)(0x80 | (cp & 0x3F));
            }
            else
            {
              if (o + 4 >= max_output)
              {
                break;
              }

              output[o++] = (char)(0xF0 | (cp >> 18));
              output[o++] = (char)(0x80 | ((cp >> 12) & 0x3F));
              output[o++] = (char)(0x80 | ((cp >> 6) & 0x3F));
              output[o++] = (char)(0x80 | (cp & 0x3F));
            }
          }

          output[o] = '\0';
          return o;
        }

        static size_t utf8_to_utf32le(const char *input, uint32_t *output, size_t max_output)
        {
          if (input == 0 || output == 0 || max_output == 0)
          {
            return 0;
          }

          size_t i = 0;
          const unsigned char *p = (const unsigned char *)input;

          while (*p != 0 && i + 1 < max_output)
          {
            uint32_t cp = 0xFFFD;

            if (*p < 0x80)
            {
              cp = *p;
              p += 1;
            }
            else if (*p >= 0xC2 && *p < 0xE0)
            {
              unsigned char b1 = p[0];
              unsigned char b2 = p[1];

              if ((b2 & 0xC0) == 0x80)
              {
                cp = ((uint32_t)(b1 & 0x1F) << 6) | (uint32_t)(b2 & 0x3F);
                p += 2;
              }
              else
              {
                p += 1;
              }
            }
            else if (*p < 0xF0)
            {
              unsigned char b1 = p[0];
              unsigned char b2 = p[1];
              unsigned char b3 = p[2];

              if ((b2 & 0xC0) == 0x80 && (b3 & 0xC0) == 0x80)
              {
                cp = ((uint32_t)(b1 & 0x0F) << 12) | ((uint32_t)(b2 & 0x3F) << 6) | (uint32_t)(b3 & 0x3F);

                if (!is_valid_codepoint(cp))
                {
                  cp = 0xFFFD;
                }

                p += 3;
              }
              else
              {
                p += 1;
              }
            }
            else if (*p < 0xF5)
            {
              unsigned char b1 = p[0];
              unsigned char b2 = p[1];
              unsigned char b3 = p[2];
              unsigned char b4 = p[3];

              if ((b2 & 0xC0) == 0x80 && (b3 & 0xC0) == 0x80 && (b4 & 0xC0) == 0x80)
              {
                cp = ((uint32_t)(b1 & 0x07) << 18) | ((uint32_t)(b2 & 0x3F) << 12) | ((uint32_t)(b3 & 0x3F) << 6) | (uint32_t)(b4 & 0x3F);

                if (!is_valid_codepoint(cp))
                {
                  cp = 0xFFFD;
                }

                p += 4;
              }
              else
              {
                p += 1;
              }
            }
            else
            {
              p += 1;
            }

            output[i++] = cp;
          }

          output[i] = 0;
          return i;
        }

        __cdecl int ConvertRoutine(unsigned char *data, unsigned long long address, unsigned char *output)
        {
          const uint32_t *gd_string = (const uint32_t *)data;

          utf32le_to_utf8(gd_string, (char *)output, MaxStringSize);

          return 1;
        }

        __cdecl void ConvertBackRoutine(unsigned char *input, unsigned long long address, unsigned char *output)
        {
          const char *s = (const char *)input;

          // there's an issue where a char like '/' would feak CE to wrap the str with brackets
          if (s[0] == '[')
          {
            s++;
          }

          char cleaned[512];
          size_t len = 0;

          while (s[len] != 0 && s[len] != ']' && len + 1 < sizeof(cleaned))
          {
            cleaned[len] = s[len];
            len++;
          }

          // end bracket
          cleaned[len] = 0;

          uint32_t *gd_string = (uint32_t *)output;
          size_t max_codepoints = ByteSize / 4;

          utf8_to_utf32le(cleaned, gd_string, max_codepoints);
        }

        {$asm}
      ]]

      if GDDEFS.MAJOR_VER == 4 then
        if getCustomType("GD4 String") then
          GDDEFS.GD4_STRING_EXISTS = true
        else
          -- lua implementation lacking writing functionality
          registerCustomTypeLua('GD4 String', 1, gd4string_bytestovalue, gd4string_valuetobytes, false, true)

          -- c implementation
          -- https://github.com/cheat-engine/cheat-engine/issues/3345
          -- local procName = process
          -- registerCustomTypeAutoAssembler(cAAUTF32StringTypeScript)
          -- OpenProcess(procName)
          GDDEFS.GD4_STRING_EXISTS = true
        end
      else
        GDDEFS.GD4_STRING_EXISTS = false
      end
    end

    local function getObjectMeta(objAddr)
      local method = getObjectVMethodByIndex( objAddr, GDDEFS.GET_TYPE_INDX)
      if isNullOrNil(method) then return nil end
      return executeMethod(0, nil, method, objAddr)
    end

    function GDAPI.getGDObjectName(objAddr)
      -- up until 4.6, the method was StringName* Object::_get_class_namev()
      -- in 4.6 it's GDType& Object::_get_typev(); GDType being a struct whose 2nd member is StringName with the object class name
      local metaAddr = getObjectMeta(objAddr)
      local className = ''

      if isNullOrNil(metaAddr) then return '??' end

      if GDDEFS.MAJOR_VER == 3 or (GDDEFS.MAJOR_VER == 4 and GDDEFS.MINOR_VER < 6) then
        className = getStringNameStr(readPointer(metaAddr) or 0) or '??'

      else --[[if GDDEFS.MAJOR_VER == 4 and GDDEFS.MINOR_VER >= 6 then]]
        metaAddr = getObjectMeta(objAddr)
        local stringNameAddr = readPointer(metaAddr + GDDEFS.PTRSIZE)
        className = getStringNameStr(stringNameAddr or 0) or '??'
      end

      return className
    end

  -- ///---///--///---///--///---///--///--///---///--///---///--///---///--/// HELPERS

    -- TODO: make magic dereferences more obvious

    local function getNodeChildrenInfo(nodeAddr)
      if isNullOrNil(nodeAddr) then
        return nil, nil;
      end

      local childrenAddr = readPointer((nodeAddr or 0) + GDDEFS.CHILDREN) -- viewport has an array of all main ingame Nodes, those Nodes can contain further nodes
      if isNullOrNil(childrenAddr) then
        return nil, nil;
      end

      local childrenSize;
      if GDDEFS.MAJOR_VER == 4 then
        childrenSize = readInteger( (nodeAddr or 0) + GDDEFS.CHILDREN - GDDEFS.CHILDREN_SIZE) -- size is 8 bytes behind
      else
        childrenSize = readInteger(childrenAddr - GDDEFS.CHILDREN_SIZE)
      end

      return childrenAddr, childrenSize
    end

    local function getNextMapElement(mapElement)
      if GDDEFS.MAJOR_VER == 4 then
        return readPointer(mapElement)
      else
        return readPointer(mapElement + GDDEFS.MAP_NEXTELEM)
      end
    end

    local function getDictElemPairNext(mapElement)
      if GDDEFS.MAJOR_VER == 4 then
        return readPointer(mapElement)
      else
        return readPointer( (mapElement or 0) + GDDEFS.DICTELEM_PAIR_NEXT)
      end
    end

    local function getDictionarySizeFromVariantPtr(variantPtr)
      -- if GDDEFS.MAJOR_VER == 4 then
      --     return readInteger(readPointer(variantPtr) + GDDEFS.DICT_SIZE)
      -- else
      --     return readInteger(readPointer(readPointer(variantPtr) + GDDEFS.DICT_LIST) + GDDEFS.DICT_SIZE)
      -- end
      return readInteger( ( readPointer(variantPtr) or 0) + GDDEFS.DICT_SIZE)
    end

    local function isArrayEmptyFromVariantPtr(variantPtr)
      return readPointer( (readPointer(variantPtr) or 0) + GDDEFS.ARRAY_TOVECTOR) == 0
    end

    local function resolveScriptVariantType(mapElement, runtimeVariantType)


      if GDDEFS.MAJOR_VER < 4 then
        return runtimeVariantType
      end

      local scriptType = readInteger(mapElement + GDDEFS.VAR_NAMEINDEX_VARTYPE)

      if scriptType > GDDEFS.MAXTYPE then
        scriptType = readInteger(mapElement + GDDEFS.VAR_NAMEINDEX_VARTYPE - 0x8)
      end

      if scriptType == runtimeVariantType then
        return scriptType
      elseif (scriptType > runtimeVariantType) and (scriptType > 0 and scriptType <= GDDEFS.MAXTYPE) then
        -- sendDebugMessage('fallback1, cached type is used') -- if the source is incorrect
        return scriptType
      else
        -- sendDebugMessage('fallback2, cached type is used') -- let's have cached if everything is wrong
        return runtimeVariantType
      end
    end

    local function getVariantNameFromMapElement(mapElement)
      if GDDEFS.MAJOR_VER == 4 then
        return getStringNameStr(readPointer(mapElement + GDDEFS.CONSTELEM_KEYVAL))
      else
        return getStringNameStr(readPointer(mapElement + GDDEFS.MAP_KVALUE))
      end
    end

    local function prepareObjectParent(entry, emitter, parent, contextTable)

      local shifted
      local ptr = entry.variantPtr
      local offset = rootOffset(entry, emitter)
      local currentParent = parent
      local currentContext = contextTable

      ptr, shifted = checkObjectOffset(ptr)

      if shifted then
        offset = offset - GDDEFS.PTRSIZE

        if currentContext.symbol then
          local symbolOffset = entry.offsetToValue or 0
          if GDDEFS.MAJOR_VER == 3 then
            symbolOffset = symbolOffset - GDDEFS.PTRSIZE
          end
          currentContext.symbol = wrapBrackets( makeSymAddr( currentContext.symbol, symbolOffset ) )
          currentContext.symbol = wrapBrackets( makeSymAddr( currentContext.symbol, 0 ) )
        end

        currentContext =
        {
          nodeAddr = contextTable.nodeAddr,
          nodeName = contextTable.nodeName,
          baseAddress = ptr,
          symbol = currentContext.symbol and currentContext.symbol or ''
        }

        currentParent = emitter.branch(currentContext, parent, "Wrapper: " .. entry.name, offset, vtPointer, "Wrapper")
        offset = 0x0
      end

      sendDebugMessage(numtohexstr(ptr) .. " Object: " .. entry.name)
      return currentParent, ptr, offset, currentContext, shifted
    end

    local function getFunctionMapName(mapElement)
      if isNullOrNil(mapElement) then
        return nil
      end

      if GDDEFS.MAJOR_VER == 4 then
        return getGDFunctionName(mapElement)
      end
      return getStringNameStr(readPointer(mapElement + GDDEFS.MAP_KVALUE))
    end

    local function findMapEntryByName(mapHead, targetName, getNameFn, getResultCallback, goAdvanceCallback)
      if isNullOrNil(mapHead) then return nil end

      local mapElement = mapHead

      repeat
        local currentName = getNameFn(mapElement)
        if currentName == targetName then
          return getResultCallback(mapElement)
        end

        mapElement = goAdvanceCallback(mapElement)
      until (mapElement == 0)

      return nil
    end

    local function getConstMapLookupResult(mapElement)
      if GDDEFS.MAJOR_VER == 4 then
        local constType = readInteger(mapElement + GDDEFS.CONSTELEM_VALTYPE)
        local offsetToValue = getVariantValueOffset(constType)
        return getAddress(mapElement + GDDEFS.CONSTELEM_VALTYPE + offsetToValue), getCETypeFromGD(constType)
      else
        local constType = readInteger(mapElement + GDDEFS.CONSTELEM_VALTYPE)
        return getAddress(mapElement + GDDEFS.CONSTELEM_VALVAL), getCETypeFromGD(constType)
      end
    end

    local function getFunctionMapLookupResult(mapElement)
      return readPointer(mapElement + GDDEFS.FUNC_MAPVAL)
    end

    local function createNextConstContainer(currentContainer, index)
      if GDDEFS.MAJOR_VER == 4 then
        local nextElem = addStructureElem(currentContainer, 'Next[' .. index .. ']', 0x0, vtPointer)
        nextElem.ChildStruct = createStructure('ConstNext')
        return nextElem
      end

      local nextElem = addStructureElem(currentContainer, 'Next[' .. index .. ']', GDDEFS.MAP_NEXTELEM, vtPointer)
      nextElem.ChildStruct = createStructure('ConstNext')
      return nextElem
    end

    local function createNextConstSymbol(currentSymbol)
      local nextSymbol
      if GDDEFS.MAJOR_VER == 4 then
        nextSymbol = wrapBrackets( currentSymbol .. "+0" )
      else --if GDDEFS.MAJOR_VER == 3 then
        nextSymbol = wrapBrackets( currentSymbol .. "+MAP_NEXTELEM" )
      end
      return nextSymbol
    end

    local function formatArrayEntry(entry)
      local cloned = {}
      for k, v in pairs(entry) do
          cloned[k] = v
      end
      cloned.name = "array[" .. tostring(entry.index) .. "]"
      return cloned
    end

    local function getArrayVectorInfo(arrayAddr)

      if isInvalidPointer(arrayAddr) then
        sendDebugMessage('arrayAddr invalid')
        return nil
      end

      local arrVectorAddr = readPointer(arrayAddr + GDDEFS.ARRAY_TOVECTOR)
      if isNullOrNil(arrVectorAddr) then
        sendDebugMessage('arrVectorAddr uninitialized')
        return nil
      end

      local arrVectorSize = readInteger(arrVectorAddr - GDDEFS.SIZE_VECTOR)
      if isNullOrNil(arrVectorSize) then
        sendDebugMessage('vector size is invalid')
        return nil
      end

      local variantArrSize, ok = redefineVariantSizeByVector(arrVectorAddr, arrVectorSize)
      if not ok then
        return nil
      end
      return arrVectorAddr, arrVectorSize, variantArrSize
    end

    local function formatDictionaryEntry(entry)
      local cloned = {}
      for k, v in pairs(entry) do
        cloned[k] = v
      end
      cloned.name = "[ " .. tostring(entry.name) .. " ]"
      return cloned
    end

    local function decodeDictionaryKeyName(mapElement)
      local keyType, keyValueAddr

      if GDDEFS.MAJOR_VER == 3 then
        local keyPtr = readPointer(mapElement) -- key is a ptr
        keyType = readInteger(keyPtr + GDDEFS.DICTELEM_KEYTYPE)
        keyValueAddr = getAddress(keyPtr + GDDEFS.DICTELEM_KEYVAL)
      else
        keyType = readInteger(mapElement + GDDEFS.DICTELEM_KEYTYPE) -- those can be a key , NodePath, Callable, StringName, etc
        keyValueAddr = getAddress(mapElement + GDDEFS.DICTELEM_KEYVAL)
      end

      local keyTypeName = getGDTypeName(keyType)
      local keyName = "UNKNOWN"

      if keyTypeName == 'STRING' then
        -- immediate String
        keyName = readUTFString(readPointer(keyValueAddr)) or "_couldnt_read"
      elseif keyTypeName == 'STRING_NAME' then
        keyName = getStringNameStr(readPointer(keyValueAddr)) or "_couldnt_read"
      elseif keyTypeName == 'FLOAT' then
        keyName = tostring(readDouble(keyValueAddr) or "_couldnt_read") -- in godot 3.x real is 4 byte float or not?
      elseif keyTypeName == 'NODE_PATH' or keyTypeName == 'RID' or keyTypeName == 'CALLABLE' then
        keyName = tostring(readPointer(keyValueAddr) or "_couldnt_read")
      elseif keyTypeName == 'INT' then
        keyName = tostring(readInteger(keyValueAddr, true) or "_couldnt_read")
      else -- bool | might need separate for Vector2, Vector3, Color, etc
        keyName = tostring(readInteger(keyValueAddr) or "_couldnt_read")
      end

      return keyType, keyValueAddr, keyName
    end

    local function getDictionaryInfo(dictAddr)
      if isInvalidPointer(dictAddr) then
        sendDebugMessage('dictAddr isnt pointer')
        return nil
      end

      local dictRoot = dictAddr
      if GDDEFS.MAJOR_VER == 3 then
        dictRoot = readPointer(dictAddr + GDDEFS.DICT_LIST)
        if isNullOrNil(dictRoot) then
          sendDebugMessage('dictRoot isnt valid')
          return nil
        end
      end

      -- local dictSize = readInteger(dictRoot + GDDEFS.DICT_SIZE)
      local dictSize = readInteger(dictAddr + GDDEFS.DICT_SIZE)
      if isNullOrNil(dictSize) then
        sendDebugMessage('dictSize isnt valid')
        return nil
      end

      local dictHead = readPointer(dictRoot + GDDEFS.DICT_HEAD)
      if isNullOrNil(dictHead) then
        sendDebugMessage('dictHead isnt valid')
        return nil
      end

      local dictTail = readPointer(dictRoot + GDDEFS.DICT_TAIL)

      return dictRoot, dictSize, dictHead, dictTail
    end

    local function createNextDictContainer(currentContainer, index)
      if GDDEFS.MAJOR_VER == 4 then
        return createChildStructElem(currentContainer, 'Next', 0x0, vtPointer, 'DictNext')
      end

      return createChildStructElem(currentContainer, 'Next', GDDEFS.DICTELEM_PAIR_NEXT, vtPointer, 'DictNext')
    end

    local function createNextSymbol(currentSymbol)
      if GDDEFS.MAJOR_VER == 4 then
        return wrapBrackets( currentSymbol .. '+' .. numtohexstr(0x0) )
      else--if GDDEFS.MAJOR_VER == 3 then
        return wrapBrackets( currentSymbol .. '+' .. numtohexstr(GDDEFS.DICTELEM_PAIR_NEXT) )
      end
    end

    local function getPackedArrayInfo(packedArrayAddr)

      if isInvalidPointer(packedArrayAddr) then
        sendDebugMessage('packedArrayAddr isnt pointer')
        return nil
      end

      local packedDataArrAddr = readPointer(packedArrayAddr + GDDEFS.P_ARRAY_TOARR)
      if isNullOrNil(packedDataArrAddr) then
        sendDebugMessage('packedDataArrAddr isnt pointer')
        return nil
      end

      local packedVectorSize
      if GDDEFS.MAJOR_VER == 4 then
        packedVectorSize = readInteger(packedDataArrAddr - GDDEFS.SIZE_VECTOR)
        if isNullOrNil(packedVectorSize) or packedVectorSize > 150 then
          packedVectorSize = 150
        end
      else
        packedVectorSize = 150 -- no size to rely :(
      end
      if isNullOrNil(packedVectorSize) then
        sendDebugMessage('packedVectorSize isnt valid')
        return nil
      end

      return packedDataArrAddr, packedVectorSize
    end

    local function iteratePackedArrayCore(packedDataArrAddr, packedVectorSize, packedTypeName, parent, emitter, contextTable)

      sendDebugMessage("Packed Array: " .. packedTypeName .. (" address %x"):format(packedDataArrAddr or -1))
      local handler = GDHandlers.PackedArrayHandlers[packedTypeName] or GDHandlers.PackedArrayHandlers.DEFAULT
      handler(packedDataArrAddr, packedVectorSize, parent, emitter, contextTable)
    end

    local function getContainerFromEmitterAndContext(emitter, nodeContext)
      if emitter == GDEmitters.StructEmitter then
        return nodeContext.struct
      elseif emitter == GDEmitters.AddrEmitter then
        return nodeContext.memrec
      end
    end

    local function cloneContextWithSymbol(contextTable, newSymbol)
      return
      {
        nodeAddr = contextTable.nodeAddr,
        nodeName = contextTable.nodeName,
        baseAddress = contextTable.baseAddress,
        symbol = newSymbol
      }
    end

    --- will return the leftmost map element @3.x
    ---@param rootElement number
    ---@param endElement number
    ---@param mapSize number
    ---@param contextTable table
    local function getLeftmostMapElem(rootElement, endElement, mapSize, nodeContext, options)
      options = options or {}

      local mapElement = readPointer(rootElement + GDDEFS.MAP_LELEM)

      if isNullOrNil(mapElement) then
        sendDebugMessage('mapElement is likely non-existent: root : ' .. numtohexstr(rootElement) .. ' last ' .. numtohexstr(endElement) .. ' size ' .. numtohexstr(mapSize));
        return 0, endElement, mapSize -- return 0 as for failure
      end

      if not options.silentLeftWalk then
        if nodeContext.struct then
          nodeContext.struct = addStructureElem(nodeContext.struct, 'rootElem', GDDEFS.MAP_LELEM, vtPointer)
          nodeContext.struct.ChildStruct = createStructure('rootElem')
        end
        if nodeContext.symbol then
          nodeContext.symbol = wrapBrackets(nodeContext.symbol .. "+" .. numtohexstr(GDDEFS.MAP_LELEM))
        end
      end

      -- if mapElement == endElement then
      --   return mapElement, endElement, mapSize, nodeContext
      -- end

      while readPointer(mapElement + GDDEFS.MAP_LELEM) ~= endElement do
        mapElement = readPointer(mapElement + GDDEFS.MAP_LELEM)

        if not options.silentLeftWalk then
          if nodeContext.symbol then
            nodeContext.symbol = wrapBrackets( nodeContext.symbol .. '+MAP_LELEM' ) -- nextElement
          end

          if nodeContext.struct then
            nodeContext.struct = addStructureElem(nodeContext.struct, 'goLeft', GDDEFS.MAP_LELEM, vtPointer)
            nodeContext.struct.ChildStruct = createStructure('goLeft')
          end
        end

      end

      if isNullOrNil(mapElement) then
        sendDebugMessage('mapElement is likely non-existent: root : ' .. numtohexstr(rootElement) .. ' last ' .. numtohexstr(endElement) .. ' size ' .. numtohexstr(mapSize));
        return 0, endElement, mapSize -- return 0 as a head element
      end

      return mapElement, endElement, mapSize, nodeContext
    end

  -- ///---///--///---///--///---///--///--///---///--///---///--///---///--/// READERS

    local function readNodeVariantEntry(mapElement, variantVector, variantSize)
      -- the vector is stored inside a GDScirptInstance and memberIndices inside the GDScript (as a BP)
      local variantIndex = readInteger(mapElement + GDDEFS.VAR_NAMEINDEX_I);
      local variantPtr, runtimeType, offsetToValue = getVariantByIndex(variantVector, variantIndex, variantSize)

      local name = getVariantNameFromMapElement(mapElement);
      local finalType = resolveScriptVariantType(mapElement, runtimeType);

      local entry =
      {
        index = variantIndex,
        name = name or "UNKNOWN",
        runtimeType = runtimeType,
        typeId = finalType,
        typeName = getGDTypeName(finalType) or "UNKNOWNTYPE",
        variantPtr = variantPtr,
        offsetToValue = offsetToValue or 0,
        offset = offsetToValue or 0,
        ceType = getCETypeFromGD(finalType)
      }

      -- sendDebugMessage("name:\t" .. entry.name .. "\tIndex: " .. entry.index .. " type: " .. entry.typeName .. "\tPtr: " .. numtohexstr(entry.variantPtr) .. "\t Offset: " .. numtohexstr(entry.offsetToValue))

      return entry
    end

    local function readFunctionConstantEntry(funcConstantVect, variantIndex, variantSize)
      local variantPtr, runtimeType, offsetToValue = getVariantByIndex(funcConstantVect, variantIndex, variantSize, true)

      local finalType = runtimeType
      local typeName = getGDTypeName(finalType) or "UNKNOWNTYPE"

      local entry =
      {
        index = variantIndex,
        name = "Const[" .. tostring(variantIndex) .. "]",
        runtimeType = runtimeType,
        typeId = finalType,
        typeName = typeName,
        variantPtr = variantPtr,
        offsetToValue = offsetToValue,
        offset = offsetToValue,
        ceType = getCETypeFromGD(finalType)
      }

      -- sendDebugMessage("name:\t" .. entry.name .. "\tIndex: " .. entry.index .. "\ttype: " .. entry.typeName .. "\tPtr: " .. numtohexstr(entry.variantPtr) .. "\t Offset: " .. numtohexstr(entry.offsetToValue))

      return entry
    end

    local function readNodeConstEntry(mapElement)
      local constName = getNodeConstName(mapElement)
      local constType = readInteger(mapElement + GDDEFS.CONSTELEM_VALTYPE)
      local offsetToValue = GDDEFS.CONSTELEM_VALTYPE + getVariantValueOffset(constType)
      local constPtr = getAddress(mapElement + offsetToValue)

      local entry =
      {
        index = 0,
        name = constName or "UNKNOWN_CONST",
        runtimeType = constType,
        typeId = constType,
        typeName = getGDTypeName(constType) or "UNKNOWNTYPE",
        variantPtr = constPtr,
        offsetToValue = offsetToValue,
        offset = offsetToValue,
        ceType = getCETypeFromGD(constType)
      }

      -- sendDebugMessage("name:\t" .. entry.name .. "\tIndex: " .. entry.index .. "\ttype: " .. entry.typeName .. "\tPtr: " .. numtohexstr(entry.variantPtr) .. "\t Offset: " .. numtohexstr(entry.offsetToValue))

      return entry
    end

    -- for node search
    local function readVectorVariantEntry(variantVector, variantIndex, variantSize)
      local variantPtr, variantType = getVariantByIndex(variantVector, variantIndex, variantSize)

      return
      {
        index = variantIndex,
        typeId = variantType,
        typeName = getGDTypeName(variantType) or "UNKNOWNTYPE",
        variantPtr = variantPtr
      }
    end

    -- for node search
    local function readArrayValueEntry(arrVectorAddr, varIndex, variantArrSize)
      local variantPtr, variantType = getVariantByIndex(arrVectorAddr, varIndex, variantArrSize)

      return
      {
        index = varIndex,
        typeId = variantType,
        typeName = getGDTypeName(variantType) or "UNKNOWNTYPE",
        variantPtr = variantPtr
      }
    end

    local function readArrayContainerEntry(arrVectorAddr, varIndex, variantArrSize, bNeedStructOffset)
      local variantPtr, runtimeType, offsetToValue = getVariantByIndex(arrVectorAddr, varIndex, variantArrSize, bNeedStructOffset)

      local entry =
      {
        index = varIndex,
        name = "array[" .. tostring(varIndex) .. "]",
        runtimeType = runtimeType,
        typeId = runtimeType,
        typeName = getGDTypeName(runtimeType) or "UNKNOWNTYPE",
        variantPtr = variantPtr,
        offsetToValue = offsetToValue or 0,
        offset = offsetToValue,
        ceType = getCETypeFromGD(runtimeType)
      }

      -- sendDebugMessage("name:\t" .. entry.name .. "\tIndex: " .. entry.index .. "\ttype: " .. entry.typeName .. "\tPtr: " .. numtohexstr(entry.variantPtr) .. "\t Offset: " .. numtohexstr(entry.offsetToValue))

      return entry
    end

    local function readDictionaryContainerEntry(mapElement)

      local keyType, keyValueAddr, keyName = decodeDictionaryKeyName(mapElement)
      local valueType = readInteger(mapElement + GDDEFS.DICTELEM_VALTYPE)
      local offsetToValue = GDDEFS.DICTELEM_VALTYPE + getVariantValueOffset(valueType)
      local valueValuePtr = getAddress(mapElement + offsetToValue)

      local entry =
        {
          index = 0,
          name = keyName or ("key@" .. numtohexstr(mapElement)),
          runtimeType = valueType,
          typeId = valueType,
          typeName = getGDTypeName(valueType) or "UNKNOWNTYPE",
          variantPtr = valueValuePtr,
          offsetToValue = offsetToValue,
          offset = offsetToValue,
          ceType = getCETypeFromGD(valueType),
          keyType = keyType,
          keyValueAddr = keyValueAddr
        }

      -- sendDebugMessage("name:\t" .. entry.name .. "\tIndex: " .. entry.index .. "\ttype: " .. entry.typeName .. "\tPtr: " .. numtohexstr(entry.variantPtr) .. "\t Offset: " .. numtohexstr(entry.offsetToValue))

      return entry
    end

    -- for node search
    local function readDictionaryValueEntry(mapElement)
        local valueType = readInteger( (mapElement or 0) + GDDEFS.DICTELEM_VALTYPE)
        local offsetToValue = GDDEFS.DICTELEM_VALTYPE + getVariantValueOffset(valueType)
        return
        {
          typeId = valueType,
          typeName = getGDTypeName(valueType) or "UNKNOWNTYPE",
          variantPtr = getAddress( (mapElement or 0) + offsetToValue)
        }
    end

  -- ///---///--///---///--///---///--///--///---///--///---///--///---///--/// VISITORS

    local NodeVisitor = {}

      function NodeVisitor.recurseDictionary(dictPtr, dumpContext)
        iterateDictionaryForNodes(dictPtr, dumpContext)
      end

      function NodeVisitor.recurseArray(arrPtr, dumpContext)
        iterateArrayForNodes(arrPtr, dumpContext)
      end

      function NodeVisitor.visitObject(objPtr, dumpContext)
        local realPtr, bShifted = checkObjectOffset(objPtr)
        local nodeAddr = readPointer(realPtr)
        processNodeForNodes(nodeAddr, dumpContext)
      end

  -- ///---///--///---///--///---///--///--///---///--///---///--///---///--/// EMITTERS
      -- leaves just add entries
      -- layouts are basically leaves with colors (where it makes sense)
      -- branches are developing tree structures/recursion

      GDEmitters = {}
        ---------------------------------------------------------------------------------
        GDEmitters.StructEmitter = {}

          function rootOffset(entry, emitter)
            if emitter == GDEmitters.StructEmitter then
              return entry.offsetToValue
            end
            return 0x0
          end

          function fieldOffset(entry, emitter, rel)
            if emitter == GDEmitters.StructEmitter then
              return entry.offsetToValue + rel
            end
            return rel
          end

          function GDEmitters.StructEmitter.leaf(contextTable, parent, label, offset, ceType)
            return addStructureElem(parent, label, offset, ceType)
          end

          function GDEmitters.StructEmitter.layout(contextTable, parent, label, color, offset, ceType)
            return addLayoutStructElem(parent, label, color, offset, ceType)
          end

          function GDEmitters.StructEmitter.branch(contextTable, parent, label, offset, ceType, childStructName)
            local elem = addStructureElem(parent, label, offset, ceType)
            elem.ChildStruct = createStructure(childStructName)
            return elem
          end

          function GDEmitters.StructEmitter.recurseDictionary(contextTable, parent, dictPtr)
            iterateDictionaryToStruct(dictPtr, parent, contextTable)
          end

          function GDEmitters.StructEmitter.recurseArray(contextTable, parent, arrPtr)
            iterateArrayToStruct(arrPtr, parent, contextTable)
          end

          function GDEmitters.StructEmitter.recurseNode(contextTable, parent, nodePtr)
            -- DISABLED
          end

          function GDEmitters.StructEmitter.recursePackedArray(contextTable, parent, arrayAddr, typeName)
            iteratePackedArrayToStruct(arrayAddr, typeName, parent, contextTable)
          end

        ---------------------------------------------------------------------------------

        GDEmitters.AddrEmitter = {}

          function makeAddr(base, offset)
            return (base or 0) + (offset or 0)
          end

          function makeSymAddr(base, offset)
            return (tostring(base) or '') .. '+' .. (numtohexstr(offset) or '')
          end

          function GDEmitters.AddrEmitter.leaf(contextTable, parent, label, offset, ceType)
            local created
            synchronize(function(label, addr, ceType, parent, contextTable)
              created = addMemRecTo(label, addr, ceType, parent, contextTable)
            end, label, makeAddr(contextTable.baseAddress, offset), ceType, parent, contextTable)
            return created
          end

          function GDEmitters.AddrEmitter.layout(contextTable, parent, label, color, offset, ceType)
            local created
            synchronize(function(label, addr, ceType, parent, contextTable)
              created = addMemRecTo(label, addr, ceType, parent, contextTable)
            end, label, makeAddr(contextTable.baseAddress, offset), ceType, parent, contextTable)
            return created
          end

          function GDEmitters.AddrEmitter.branch(contextTable, parent, label, offset, ceType, childStructName)
            local created
            synchronize(function(label, addr, ceType, parent, contextTable)
              created = addMemRecTo(label, addr, ceType, parent, contextTable)
              created.Options = '[moHideChildren, moAllowManualCollapseAndExpand, moManualExpandCollapse]'
            end, label, makeAddr(contextTable.baseAddress, offset), ceType, parent, contextTable)
            return created
          end

          function GDEmitters.AddrEmitter.recurseDictionary(contextTable, parent, dictPtr)
            iterateDictionaryToAddr(dictPtr, parent, contextTable)
          end

          function GDEmitters.AddrEmitter.recurseArray(contextTable, parent, arrPtr)
            iterateArrayToAddr(arrPtr, parent, contextTable)
          end

          function GDEmitters.AddrEmitter.recurseNode(contextTable, parent, nodePtr)
            iterateMNodeToAddr(nodePtr, parent, contextTable)
          end

          function GDEmitters.AddrEmitter.recursePackedArray(contextTable, parent, arrayAddr, typeName)
            iteratePackedArrayToAddr(arrayAddr, typeName, parent, contextTable)
          end

        ---------------------------------------------------------------------------------

        local function emitStringNameStruct(parent, label, offset, stringFieldLabel, bUniShift)
          local outer = addStructureElem(parent, label, offset, vtPointer)
          outer.ChildStruct = createStructure("StringName")

          local innerOffset = bUniShift and GDDEFS.STRING or (GDDEFS.STRING - GDDEFS.PTRSIZE)
          local inner = addStructureElem(outer, label, innerOffset, vtPointer)
          inner.ChildStruct = createStructure("stringy")
          local stringElem = addStructureElem(outer.ChildStruct and inner or inner, label .. " string", 0x0,
            bUniShift and vtUnicodeString or vtString)

          if not bUniShift then
            stringElem.Bytesize = 100
          end

          return outer, inner, stringElem
        end

        local function emitFunctionCodeStruct(funcParent, funcName)
          return addStructureElem(funcParent, 'Code: ' .. funcName, GDDEFS.FUNC_CODE, vtPointer)
        end

        local function emitFunctionConstantsStruct(funcParent, funcName, funcValueAddr)
          local constantsElem = createChildStructElem(funcParent, "Constants: " .. funcName, GDDEFS.FUNC_CONST, vtPointer, "GDFConst")
          local funcConstAddr = readPointer(funcValueAddr + GDDEFS.FUNC_CONST)
          iterateFuncConstantsToStruct(funcConstAddr, constantsElem)
          return constantsElem
        end

        local function emitFunctionGlobalsStruct(funcParent, funcName, funcValueAddr)
          local globalsElem = createChildStructElem(funcParent, "Globals: " .. funcName, GDDEFS.FUNC_GLOBNAMEPTR, vtPointer, "GDFGlobals")
          local funcGlobalAddr = readPointer(funcValueAddr + GDDEFS.FUNC_GLOBNAMEPTR)
          iterateFuncGlobalsToStruct(funcGlobalAddr, globalsElem)
          return globalsElem
        end

        local function emitFunctionStructEntry(funcStructElement, mapElement, funcName)
          local funcRoot
          if not bDisasmFunc then -- let's 
            funcRoot = createChildStructElem(funcStructElement, "func: " .. funcName, GDDEFS.FUNC_MAPVAL, vtPointer, "GDFunction")
            local funcValueAddr = readPointer(mapElement + GDDEFS.FUNC_MAPVAL)
            emitFunctionCodeStruct(funcRoot, funcName)
            emitFunctionConstantsStruct(funcRoot, funcName, funcValueAddr)
            emitFunctionGlobalsStruct(funcRoot, funcName, funcValueAddr)
          else
            funcRoot = addStructureElem(funcStructElement, "func: " .. funcName, GDDEFS.FUNC_MAPVAL, vtPointer)
          end

          return funcRoot
        end

        local function advanceFunctionMapElement(mapElement)
          if GDDEFS.MAJOR_VER == 4 then
            return readPointer(mapElement)
          end
          return readPointer(mapElement + GDDEFS.MAP_NEXTELEM)
        end

        local function createNextFunctionContainer(currentContainer, index)
          if GDDEFS.MAJOR_VER == 4 then
            local nextElem = addStructureElem(currentContainer, "Next[" .. index .. "]", 0x0, vtPointer)
            nextElem.ChildStruct = createStructure("FuncNext")
            return nextElem
          end

          local nextElem = addStructureElem(currentContainer, "Next", GDDEFS.MAP_NEXTELEM, vtPointer)
          nextElem.ChildStruct = createStructure('FuncNext')
          return nextElem
        end

        ---------------------------------------------------------------------------------

        GDEmitters.PackedStructEmitter = {}

          function GDEmitters.PackedStructEmitter.emitPackedString(parent, elemIndex, offsetToValue, arrElement, contextTable)
            local stringPtrElement = addStructureElem(parent, ('strElem[%d]'):format(elemIndex), offsetToValue, vtPointer)
            stringPtrElement.ChildStruct = createStructure('StringItem')
            addStructureElem(stringPtrElement, 'String', 0x0, vtUnicodeString)
          end

          function GDEmitters.PackedStructEmitter.emitPackedScalar(parent, prefixStr, elemIndex, offsetToValue, arrElement, ceType, contextTable)
            addStructureElem(parent, prefixStr .. elemIndex .. ']', offsetToValue, ceType)
          end

          function GDEmitters.PackedStructEmitter.emitPackedVec2(parent, prefixStr, elemIndex, offsetToValue, arrElement, contextTable)
            addStructureElem(parent, prefixStr .. elemIndex .. ']: x', offsetToValue, vtSingle)
            addStructureElem(parent, prefixStr .. elemIndex .. ']: y', offsetToValue + 0x4, vtSingle)
          end

          function GDEmitters.PackedStructEmitter.emitPackedVec3(parent, prefixStr, elemIndex, offsetToValue, arrElement, contextTable)
            addStructureElem(parent, prefixStr .. elemIndex .. ']: x', offsetToValue, vtSingle)
            addStructureElem(parent, prefixStr .. elemIndex .. ']: y', offsetToValue + 0x4, vtSingle)
            addStructureElem(parent, prefixStr .. elemIndex .. ']: z', offsetToValue + 0x8, vtSingle)
          end

          function GDEmitters.PackedStructEmitter.emitPackedColor(parent, prefixStr, elemIndex, offsetToValue, arrElement, contextTable)
            addStructureElem(parent, prefixStr .. elemIndex .. ']: R', offsetToValue, vtSingle)
            addStructureElem(parent, prefixStr .. elemIndex .. ']: G', offsetToValue + 0x4, vtSingle)
            addStructureElem(parent, prefixStr .. elemIndex .. ']: B', offsetToValue + 0x8, vtSingle)
            addStructureElem(parent, prefixStr .. elemIndex .. ']: A', offsetToValue + 0xC, vtSingle)
          end

        GDEmitters.PackedAddrEmitter = {}

          function GDEmitters.PackedAddrEmitter.emitPackedString(parent, elemIndex, offsetToValue, arrElement, contextTable)
            synchronize(function(elemIndex, arrElement, parent, contextTable)
              addMemRecTo('pck_arr[' .. elemIndex .. ']', arrElement, vtString, parent, contextTable)
            end, elemIndex, arrElement, parent, contextTable)
          end

          function GDEmitters.PackedAddrEmitter.emitPackedScalar(parent, prefixStr, elemIndex, offsetToValue, arrElement, ceType, contextTable)
            synchronize(function(prefixStr, elemIndex, arrElement, ceType, parent, contextTable)
              addMemRecTo(prefixStr .. elemIndex .. ']', arrElement, ceType, parent, contextTable)
            end, prefixStr, elemIndex, arrElement, ceType, parent, contextTable)
          end

          function GDEmitters.PackedAddrEmitter.emitPackedVec2(parent, prefixStr, elemIndex, offsetToValue, arrElement, contextTable)
            synchronize(function(prefixStr, elemIndex, arrElement, parent, contextTable)
              addMemRecTo(prefixStr .. elemIndex .. ']: x', arrElement, vtSingle, parent, contextTable)
              contextTable.symbol = makeSymAddr(contextTable.symbol, 0x4)
              addMemRecTo(prefixStr .. elemIndex .. ']: y', arrElement + 0x4, vtSingle, parent, contextTable)
            end, prefixStr, elemIndex, arrElement, parent, contextTable)
          end

          function GDEmitters.PackedAddrEmitter.emitPackedVec3(parent, prefixStr, elemIndex, offsetToValue, arrElement, contextTable)
            synchronize(function(prefixStr, elemIndex, arrElement, parent, contextTable)
              addMemRecTo(prefixStr .. elemIndex .. ']: x', arrElement, vtSingle, parent, contextTable)
              contextTable.symbol = makeSymAddr(contextTable.symbol, 0x4)
              addMemRecTo(prefixStr .. elemIndex .. ']: y', arrElement + 0x4, vtSingle, parent, contextTable)
              contextTable.symbol = makeSymAddr(contextTable.symbol, 0x4)
              addMemRecTo(prefixStr .. elemIndex .. ']: z', arrElement + 0x8, vtSingle, parent, contextTable)
            end, prefixStr, elemIndex, arrElement, parent, contextTable)
          end

          function GDEmitters.PackedAddrEmitter.emitPackedColor(parent, prefixStr, elemIndex, offsetToValue, arrElement, contextTable)
            synchronize(function(prefixStr, elemIndex, arrElement, parent, contextTable)
              addMemRecTo(prefixStr .. elemIndex .. ']: R', arrElement, vtSingle, parent, contextTable)
              contextTable.symbol = makeSymAddr(contextTable.symbol, 0x4)
              addMemRecTo(prefixStr .. elemIndex .. ']: G', arrElement + 0x4, vtSingle, parent, contextTable)
              contextTable.symbol = makeSymAddr(contextTable.symbol, 0x4)
              addMemRecTo(prefixStr .. elemIndex .. ']: B', arrElement + 0x8, vtSingle, parent, contextTable)
              contextTable.symbol = makeSymAddr(contextTable.symbol, 0x4)
              addMemRecTo(prefixStr .. elemIndex .. ']: A', arrElement + 0xC, vtSingle, parent, contextTable)
            end, prefixStr, elemIndex, arrElement, parent, contextTable)
          end

  -- ///---///--///---///--///---///--///--///---///--///---///--///---///--/// TYPE HANDLERS

    GDHandlers = {}
    GDHandlers.VariantHandlers = {}

      GDHandlers.VariantHandlers.DICTIONARY = function(entry, emitter, parent, contextTable)
        sendDebugMessage("DICTIONARY case for name: " .. entry.name .. " address: " .. numtohexstr(entry.variantPtr) .. " offset: " .. numtohexstr(entry.offsetToValue))
        local dictSize = getDictionarySizeFromVariantPtr(entry.variantPtr)
        local offsetToValue = rootOffset(entry, emitter)
        if contextTable.symbol then contextTable.symbol = makeSymAddr(contextTable.symbol, entry.offset) end
        if isNullOrNil(dictSize) then
          emitter.leaf(contextTable, parent, "<Dict> (empty): " .. entry.name, offsetToValue, entry.ceType) -- entry.offsetToValue
          return;
        end

        local child = emitter.branch(contextTable, parent, "<Dict> " .. entry.name, offsetToValue, entry.ceType, "Dict")
        emitter.recurseDictionary(contextTable, child, readPointer(entry.variantPtr)) -- we pass the actual base addr
      end

      GDHandlers.VariantHandlers.ARRAY = function(entry, emitter, parent, contextTable)
        sendDebugMessage("ARRAY case for name: " .. entry.name)
        local offsetToValue = rootOffset(entry, emitter)
        if contextTable.symbol then contextTable.symbol = wrapBrackets( contextTable.symbol .. '+' .. numtohexstr(entry.offset) ) end
        if isArrayEmptyFromVariantPtr(entry.variantPtr) then
          emitter.leaf(contextTable, parent, "<Array> (empty): " .. entry.name, offsetToValue, entry.ceType);
          return;
        end

        local child = emitter.branch(contextTable, parent, "<Array>: " .. entry.name, offsetToValue, entry.ceType, "Array");
        emitter.recurseArray(contextTable, child, readPointer(entry.variantPtr))
      end

      GDHandlers.VariantHandlers.OBJECT = function(entry, emitter, parent, contextTable)
        local objectParent, realPtr, realOffset, objectContext = prepareObjectParent(entry, emitter, parent, contextTable)
        local objectTypeName = getGDObjectName(readPointer(realPtr))
        objectTypeName = '<' .. objectTypeName .. '>'

        sendDebugMessage("OBJECT case: name: " .. entry.name .. " type: " .. objectTypeName .. " addr: " .. numtohexstr(realPtr))

        if objectContext.symbol then -- AddrEmitter stores the real addr, so its symbol must advance by the variant field offset
          if emitter == GDEmitters.AddrEmitter then
            if objectContext == contextTable then
              objectContext = cloneContextWithSymbol( objectContext, wrapBrackets( makeSymAddr( objectContext.symbol, (entry.offsetToValue or entry.offset or 0) ) ) )
            end
          else
            objectContext.symbol = makeSymAddr(objectContext.symbol, realOffset)
          end
        end

        if checkForGDScript(readPointer(realPtr)) then
          if emitter == GDEmitters.StructEmitter then
            local nodeChild = emitter.leaf(objectContext, objectParent, objectTypeName .. ' ' .. entry.name, realOffset, vtPointer)
            nodeChild.BackgroundColor = 0x6C3157
          else
            local nodeChild = emitter.branch(objectContext, objectParent, objectTypeName .. ' ' .. entry.name, realOffset, vtPointer, "Node")
            nodeChild.BackgroundColor = 0x6C3157

            if emitter.recurseNode then
              emitter.recurseNode(objectContext, nodeChild, readPointer(realPtr))
            end
          end
        else
          emitter.leaf(objectContext, objectParent, objectTypeName .. " obj: " .. entry.name, realOffset, vtPointer)
        end
      end

      GDHandlers.VariantHandlers.STRING = function(entry, emitter, parent, contextTable)
        if contextTable.symbol then contextTable.symbol = wrapBrackets( makeSymAddr(contextTable.symbol, entry.offset) ) end

        if emitter == GDEmitters.StructEmitter then
          local outer = emitter.branch(contextTable, parent, "<STRING> " .. entry.name, rootOffset(entry, emitter), vtPointer, "String")
          local inner = emitter.branch(contextTable, outer, "StringData: " .. entry.name, 0x0, vtUnicodeString, "stringy")
        else
          emitter.leaf(contextTable, parent, "String: " .. entry.name, rootOffset(entry, emitter), vtString)
        end
      end

      GDHandlers.VariantHandlers.STRING_NAME = function(entry, emitter, parent, contextTable)
        if contextTable.symbol then
          contextTable.symbol = makeSymAddr(contextTable.symbol, entry.offset)
          contextTable.symbol =  wrapBrackets( wrapBrackets( contextTable.symbol ) .. '+STRING' )
        end

        if emitter == GDEmitters.StructEmitter then
          local outer = emitter.branch(contextTable, parent, "<STRINGNAME> " .. entry.name, rootOffset(entry, emitter), vtPointer, "StringName")
          local inner = emitter.branch(contextTable, outer, "StringName: " .. entry.name, GDDEFS.STRING, vtPointer, "stringy")
          emitter.leaf(contextTable, inner, "String: " .. entry.name, 0x0, vtUnicodeString)
        else
          local stringNameAddr = readPointer(entry.variantPtr)
          if isNullOrNil(stringNameAddr) then
            emitter.leaf(contextTable, parent, "<STRINGNAME> " .. entry.name, rootOffset(entry, emitter), vtPointer)
            return
          end

          local stringContext =
          {
            nodeAddr = contextTable.nodeAddr,
            nodeName = contextTable.nodeName,
            baseAddress = stringNameAddr + GDDEFS.STRING,
            symbol = contextTable.symbol and contextTable.symbol or ''
          }
          emitter.leaf(stringContext, parent, "<STRINGNAME> " .. entry.name, 0x0, vtString)
        end

      end

      GDHandlers.VariantHandlers.PACKED_STRING_ARRAY = function(entry, emitter, parent, contextTable)
        sendDebugMessage("PackedArray: " .. entry.typeName .. " case for name: " .. entry.name)
        if contextTable.symbol then contextTable.symbol = makeSymAddr(contextTable.symbol, entry.offset) end
        
        local arrayAddr = readPointer(entry.variantPtr)
        local offsetToValue = rootOffset(entry, emitter)
        if readPointer(arrayAddr + GDDEFS.P_ARRAY_TOARR) == 0 then
          emitter.leaf(contextTable, parent, "<" .. entry.typeName .. "> " .. ' (empty): ' .. entry.name, offsetToValue, entry.ceType)
        else
          local child = emitter.branch(contextTable, parent, "<" .. entry.typeName .. "> " .. ' ' .. entry.name, offsetToValue, entry.ceType, "P_Array")
          if contextTable.symbol then contextTable.symbol = wrapBrackets( contextTable.symbol ) end
          emitter.recursePackedArray(contextTable, child, arrayAddr, entry.typeName)
        end
      end

      GDHandlers.VariantHandlers.PACKED_BYTE_ARRAY = GDHandlers.VariantHandlers.PACKED_STRING_ARRAY
      GDHandlers.VariantHandlers.PACKED_INT32_ARRAY = GDHandlers.VariantHandlers.PACKED_STRING_ARRAY
      GDHandlers.VariantHandlers.PACKED_INT64_ARRAY = GDHandlers.VariantHandlers.PACKED_STRING_ARRAY
      GDHandlers.VariantHandlers.PACKED_FLOAT32_ARRAY = GDHandlers.VariantHandlers.PACKED_STRING_ARRAY
      GDHandlers.VariantHandlers.PACKED_FLOAT64_ARRAY = GDHandlers.VariantHandlers.PACKED_STRING_ARRAY
      GDHandlers.VariantHandlers.PACKED_VECTOR2_ARRAY = GDHandlers.VariantHandlers.PACKED_STRING_ARRAY
      GDHandlers.VariantHandlers.PACKED_VECTOR3_ARRAY = GDHandlers.VariantHandlers.PACKED_STRING_ARRAY
      GDHandlers.VariantHandlers.PACKED_COLOR_ARRAY = GDHandlers.VariantHandlers.PACKED_STRING_ARRAY
      GDHandlers.VariantHandlers.PACKED_VECTOR4_ARRAY = GDHandlers.VariantHandlers.PACKED_STRING_ARRAY

      GDHandlers.VariantHandlers.COLOR = function(entry, emitter, parent, contextTable)
        local typeName = "Color"
        if contextTable.symbol then contextTable.symbol = makeSymAddr(contextTable.symbol, entry.offset) end
        emitter.leaf(contextTable, parent, typeName .. entry.name .. ": R", fieldOffset(entry, emitter, 0x0), vtSingle)
        if contextTable.symbol then contextTable.symbol = makeSymAddr(contextTable.symbol, 0x4) end
        emitter.leaf(contextTable, parent, typeName .. entry.name .. ": G", fieldOffset(entry, emitter, 0x4), vtSingle)
        if contextTable.symbol then contextTable.symbol = makeSymAddr(contextTable.symbol, 0x4) end
        emitter.leaf(contextTable, parent, typeName .. entry.name .. ": B", fieldOffset(entry, emitter, 0x8), vtSingle)
        if contextTable.symbol then contextTable.symbol = makeSymAddr(contextTable.symbol, 0x4) end
        emitter.leaf(contextTable, parent, typeName .. entry.name .. ": A", fieldOffset(entry, emitter, 0xC), vtSingle)
      end

      GDHandlers.VariantHandlers.VECTOR2 = function(entry, emitter, parent, contextTable)
        local typeName = "Vec2"
        if contextTable.symbol then contextTable.symbol = makeSymAddr(contextTable.symbol, entry.offset) end
        emitter.leaf(contextTable, parent, "<" .. typeName .. "> " .. entry.name .. ': x', fieldOffset(entry, emitter, 0x0), vtSingle)
        if contextTable.symbol then contextTable.symbol = makeSymAddr(contextTable.symbol, 0x4) end
        emitter.leaf(contextTable, parent, "<" .. typeName .. "> " .. entry.name .. ': y', fieldOffset(entry, emitter, 0x4), vtSingle)
      end

      GDHandlers.VariantHandlers.VECTOR2I = function(entry, emitter, parent, contextTable)
        local typeName = "vec2I"
        emitter.leaf(contextTable, parent, "<" .. typeName .. "> " .. entry.name .. ': x', fieldOffset(entry, emitter, 0x0), vtDword)
        if contextTable.symbol then contextTable.symbol = makeSymAddr(contextTable.symbol, 0x4) end
        emitter.leaf(contextTable, parent, "<" .. typeName .. "> " .. entry.name .. ': y', fieldOffset(entry, emitter, 0x4), vtDword)
      end

      GDHandlers.VariantHandlers.RECT2 = function(entry, emitter, parent, contextTable)
        local typeName = "Rect2"
        if contextTable.symbol then contextTable.symbol = makeSymAddr(contextTable.symbol, entry.offset) end
        emitter.leaf(contextTable, parent, "<" .. typeName .. "> " .. entry.name .. ': x', fieldOffset(entry, emitter, 0x0), vtSingle)
        if contextTable.symbol then contextTable.symbol = makeSymAddr(contextTable.symbol, 0x4) end
        emitter.leaf(contextTable, parent, "<" .. typeName .. "> " .. entry.name .. ': y', fieldOffset(entry, emitter, 0x4), vtSingle)
        if contextTable.symbol then contextTable.symbol = makeSymAddr(contextTable.symbol, 0x4) end
        emitter.leaf(contextTable, parent, "<" .. typeName .. "> " .. entry.name .. ': w', fieldOffset(entry, emitter, 0x8), vtSingle)
        if contextTable.symbol then contextTable.symbol = makeSymAddr(contextTable.symbol, 0x4) end
        emitter.leaf(contextTable, parent, "<" .. typeName .. "> " .. entry.name .. ': h', fieldOffset(entry, emitter, 0xC), vtSingle)
      end

      GDHandlers.VariantHandlers.RECT2I = function(entry, emitter, parent, contextTable)
        local typeName = "Rect2I"
        if contextTable.symbol then contextTable.symbol = makeSymAddr(contextTable.symbol, entry.offset) end
        emitter.leaf(contextTable, parent, "<" .. typeName .. "> " .. entry.name .. ': x', fieldOffset(entry, emitter, 0x0), vtDword)
        if contextTable.symbol then contextTable.symbol = makeSymAddr(contextTable.symbol, 0x4) end
        emitter.leaf(contextTable, parent, "<" .. typeName .. "> " .. entry.name .. ': y', fieldOffset(entry, emitter, 0x4), vtDword)
        if contextTable.symbol then contextTable.symbol = makeSymAddr(contextTable.symbol, 0x4) end
        emitter.leaf(contextTable, parent, "<" .. typeName .. "> " .. entry.name .. ': w', fieldOffset(entry, emitter, 0x8), vtDword)
        if contextTable.symbol then contextTable.symbol = makeSymAddr(contextTable.symbol, 0x4) end
        emitter.leaf(contextTable, parent, "<" .. typeName .. "> " .. entry.name .. ': h', fieldOffset(entry, emitter, 0xC), vtDword)
      end

      GDHandlers.VariantHandlers.VECTOR3 = function(entry, emitter, parent, contextTable)
        local typeName = "Vec3"
        if contextTable.symbol then contextTable.symbol = makeSymAddr(contextTable.symbol, entry.offset) end
        emitter.leaf(contextTable, parent, "<" .. typeName .. "> " .. entry.name .. ': x', fieldOffset(entry, emitter, 0x0), vtSingle)
        if contextTable.symbol then contextTable.symbol = makeSymAddr(contextTable.symbol, 0x4) end
        emitter.leaf(contextTable, parent, "<" .. typeName .. "> " .. entry.name .. ': y', fieldOffset(entry, emitter, 0x4), vtSingle)
        if contextTable.symbol then contextTable.symbol = makeSymAddr(contextTable.symbol, 0x4) end
        emitter.leaf(contextTable, parent, "<" .. typeName .. "> " .. entry.name .. ': z', fieldOffset(entry, emitter, 0x8), vtSingle)
      end

      GDHandlers.VariantHandlers.VECTOR3I = function(entry, emitter, parent, contextTable)
        local typeName = "Vec3I"
        if contextTable.symbol then contextTable.symbol = makeSymAddr(contextTable.symbol, entry.offset) end
        emitter.leaf(contextTable, parent, "<" .. typeName .. "> " .. entry.name .. ': x', fieldOffset(entry, emitter, 0x0), vtDword)
        if contextTable.symbol then contextTable.symbol = makeSymAddr(contextTable.symbol, 0x4) end
        emitter.leaf(contextTable, parent, "<" .. typeName .. "> " .. entry.name .. ': y', fieldOffset(entry, emitter, 0x4), vtDword)
        if contextTable.symbol then contextTable.symbol = makeSymAddr(contextTable.symbol, 0x4) end
        emitter.leaf(contextTable, parent, "<" .. typeName .. "> " .. entry.name .. ': z', fieldOffset(entry, emitter, 0x8), vtDword)
      end

      GDHandlers.VariantHandlers.VECTOR4 = function(entry, emitter, parent, contextTable)
        local typeName = "Vec4"
        if contextTable.symbol then contextTable.symbol = makeSymAddr(contextTable.symbol, entry.offset) end
        emitter.leaf(contextTable, parent, "<" .. typeName .. "> " .. entry.name .. ': x', fieldOffset(entry, emitter, 0x0), vtSingle)
        if contextTable.symbol then contextTable.symbol = makeSymAddr(contextTable.symbol, 0x4) end
        emitter.leaf(contextTable, parent, "<" .. typeName .. "> " .. entry.name .. ': y', fieldOffset(entry, emitter, 0x4), vtSingle)
        if contextTable.symbol then contextTable.symbol = makeSymAddr(contextTable.symbol, 0x4) end
        emitter.leaf(contextTable, parent, "<" .. typeName .. "> " .. entry.name .. ': z', fieldOffset(entry, emitter, 0x8), vtSingle)
        if contextTable.symbol then contextTable.symbol = makeSymAddr(contextTable.symbol, 0x4) end
        emitter.leaf(contextTable, parent, "<" .. typeName .. "> " .. entry.name .. ': w', fieldOffset(entry, emitter, 0xC), vtSingle)
      end

      GDHandlers.VariantHandlers.VECTOR4I = function(entry, emitter, parent, contextTable)
        local typeName = "Vec4I"
        if contextTable.symbol then contextTable.symbol = makeSymAddr(contextTable.symbol, entry.offset) end
        emitter.leaf(contextTable, parent, "<" .. typeName .. "> " .. entry.name .. ': x', fieldOffset(entry, emitter, 0x0), vtDword)
        if contextTable.symbol then contextTable.symbol = makeSymAddr(contextTable.symbol, 0x4) end
        emitter.leaf(contextTable, parent, "<" .. typeName .. "> " .. entry.name .. ': y', fieldOffset(entry, emitter, 0x4), vtDword)
        if contextTable.symbol then contextTable.symbol = makeSymAddr(contextTable.symbol, 0x4) end
        emitter.leaf(contextTable, parent, "<" .. typeName .. "> " .. entry.name .. ': z', fieldOffset(entry, emitter, 0x8), vtDword)
        if contextTable.symbol then contextTable.symbol = makeSymAddr(contextTable.symbol, 0x4) end
        emitter.leaf(contextTable, parent, "<" .. typeName .. "> " .. entry.name .. ': w', fieldOffset(entry, emitter, 0xC), vtDword)
      end

      GDHandlers.VariantHandlers.DEFAULT = function(entry, emitter, parent, contextTable)
        if contextTable.symbol then contextTable.symbol = makeSymAddr(contextTable.symbol, entry.offset) end
        emitter.leaf(contextTable, parent, "<" .. entry.typeName .. ">" .. " " .. entry.name , rootOffset(entry, emitter), entry.ceType)
      end

    GDHandlers.NodeDiscoveryHandlers = {}

      GDHandlers.NodeDiscoveryHandlers.DICTIONARY = function(entry, visitor, dumpContext)
        if dumpContext:shouldStop() then return end
        local dictSize = getDictionarySizeFromVariantPtr(entry.variantPtr)
        if isNotNullOrNil(dictSize) then
          visitor.recurseDictionary(readPointer(entry.variantPtr), dumpContext)
        end
      end

      GDHandlers.NodeDiscoveryHandlers.ARRAY = function(entry, visitor, dumpContext)
        if dumpContext:shouldStop() then return end
        if not isArrayEmptyFromVariantPtr(entry.variantPtr) then
          visitor.recurseArray(readPointer(entry.variantPtr), dumpContext)
        end
      end

      GDHandlers.NodeDiscoveryHandlers.OBJECT = function(entry, visitor, dumpContext)
        if dumpContext:shouldStop() then return end
        visitor.visitObject(entry.variantPtr, dumpContext)
      end

      -- GDHandlers.NodeMetaHandlers = {}

      --   GDHandlers.NodeMetaHandlers.DICTIONARY = function(entry, visitor)
      --     local dictSize = getDictionarySizeFromVariantPtr(entry.variantPtr)
      --     if isNotNullOrNil(dictSize) then
      --       visitor.recurseDictionary(readPointer(entry.variantPtr))
      --     end
      --   end

      --   GDHandlers.NodeMetaHandlers.ARRAY = function(entry, visitor)
      --     if not isArrayEmptyFromVariantPtr(entry.variantPtr) then
      --       visitor.recurseArray(readPointer(entry.variantPtr))
      --     end
      --   end

      --   GDHandlers.NodeMetaHandlers.OBJECT = function(entry, visitor)
      --     visitor.visitObject(entry.variantPtr)
      --   end


    GDHandlers.PackedArrayHandlers = {}

      GDHandlers.PackedArrayHandlers.PACKED_STRING_ARRAY = function(packedDataArrAddr, packedVectorSize, parent, emitter, contextTable)
        local baseSymbol;
        if contextTable.symbol then baseSymbol = contextTable.symbol end

        for elemIndex = 0, packedVectorSize - 1 do
          local offsetToValue = elemIndex * GDDEFS.PTRSIZE
          local arrElement = getAddress(packedDataArrAddr + offsetToValue)
          if contextTable.symbol then contextTable.symbol = makeSymAddr( baseSymbol, offsetToValue ) end

          if readPointer(arrElement) ~= 0 then
            emitter.emitPackedString(parent, elemIndex, offsetToValue, arrElement, contextTable)
          end
        end
      end

      GDHandlers.PackedArrayHandlers.PACKED_INT32_ARRAY = function(packedDataArrAddr, packedVectorSize, parent, emitter, contextTable)
        local baseSymbol;
        if contextTable.symbol then baseSymbol = contextTable.symbol end

        for elemIndex = 0, packedVectorSize - 1 do
          local offsetToValue = elemIndex * 0x4
          local arrElement = getAddress(packedDataArrAddr + offsetToValue)
          if contextTable.symbol then contextTable.symbol = makeSymAddr( baseSymbol, offsetToValue ) end

          emitter.emitPackedScalar(parent, 'pck_arr[', elemIndex, offsetToValue, arrElement, vtDword, contextTable)
        end
      end

      GDHandlers.PackedArrayHandlers.PACKED_FLOAT32_ARRAY = function(packedDataArrAddr, packedVectorSize, parent, emitter, contextTable)
        local baseSymbol;
        if contextTable.symbol then baseSymbol = contextTable.symbol end

        for elemIndex = 0, packedVectorSize - 1 do
          local offsetToValue = elemIndex * 0x4
          local arrElement = getAddress(packedDataArrAddr + offsetToValue)
          if contextTable.symbol then contextTable.symbol = makeSymAddr( baseSymbol, offsetToValue ) end

          emitter.emitPackedScalar(parent, 'pck_arr[', elemIndex, offsetToValue, arrElement, vtSingle, contextTable)
        end
      end

      GDHandlers.PackedArrayHandlers.PACKED_INT64_ARRAY = function(packedDataArrAddr, packedVectorSize, parent, emitter, contextTable)
        local baseSymbol;
        if contextTable.symbol then baseSymbol = contextTable.symbol end

        for elemIndex = 0, packedVectorSize - 1 do
          local offsetToValue = elemIndex * GDDEFS.PTRSIZE
          local arrElement = getAddress(packedDataArrAddr + offsetToValue)
          if contextTable.symbol then contextTable.symbol = makeSymAddr( baseSymbol, offsetToValue ) end

          emitter.emitPackedScalar(parent, 'pck_arr[', elemIndex, offsetToValue, arrElement, vtQword, contextTable)
        end
      end

      GDHandlers.PackedArrayHandlers.PACKED_FLOAT64_ARRAY = function(packedDataArrAddr, packedVectorSize, parent, emitter, contextTable)
        local baseSymbol;
        if contextTable.symbol then baseSymbol = contextTable.symbol end

        for elemIndex = 0, packedVectorSize - 1 do
          local offsetToValue = elemIndex * GDDEFS.PTRSIZE
          local arrElement = getAddress(packedDataArrAddr + offsetToValue)
          if contextTable.symbol then contextTable.symbol = makeSymAddr( baseSymbol, offsetToValue ) end

          emitter.emitPackedScalar(parent, 'pck_arr[', elemIndex, offsetToValue, arrElement, vtDouble, contextTable)
        end
      end

      GDHandlers.PackedArrayHandlers.PACKED_BYTE_ARRAY = function(packedDataArrAddr, packedVectorSize, parent, emitter, contextTable)
        local baseSymbol;
        if contextTable.symbol then baseSymbol = contextTable.symbol end

        for elemIndex = 0, packedVectorSize - 1 do
          local offsetToValue = elemIndex * 0x1
          local arrElement = getAddress(packedDataArrAddr + offsetToValue)
          if contextTable.symbol then contextTable.symbol = makeSymAddr( baseSymbol, offsetToValue ) end

          emitter.emitPackedScalar(parent, 'pck_arr[', elemIndex, offsetToValue, arrElement, vtByte, contextTable)
        end
      end

      GDHandlers.PackedArrayHandlers.PACKED_VECTOR2_ARRAY = function(packedDataArrAddr, packedVectorSize, parent, emitter, contextTable)
        local baseSymbol;
        if contextTable.symbol then baseSymbol = contextTable.symbol end

        for elemIndex = 0, packedVectorSize - 1 do
          local offsetToValue = elemIndex * 0x8
          local arrElement = getAddress(packedDataArrAddr + offsetToValue)
          if contextTable.symbol then contextTable.symbol = makeSymAddr( baseSymbol, offsetToValue ) end

          emitter.emitPackedVec2(parent, 'pck_mvec2[', elemIndex, offsetToValue, arrElement, contextTable)
        end
      end

      GDHandlers.PackedArrayHandlers.PACKED_VECTOR3_ARRAY = function(packedDataArrAddr, packedVectorSize, parent, emitter, contextTable)
        local baseSymbol;
        if contextTable.symbol then baseSymbol = contextTable.symbol end

        for elemIndex = 0, packedVectorSize - 1 do
          local offsetToValue = elemIndex * 0xC
          local arrElement = getAddress(packedDataArrAddr + offsetToValue)
          if contextTable.symbol then contextTable.symbol = makeSymAddr( baseSymbol, offsetToValue ) end

          emitter.emitPackedVec3(parent, 'pck_mvec3[', elemIndex, offsetToValue, arrElement, contextTable)
        end
      end

      GDHandlers.PackedArrayHandlers.PACKED_COLOR_ARRAY = function(packedDataArrAddr, packedVectorSize, parent, emitter, contextTable)
        local baseSymbol;
        if contextTable.symbol then baseSymbol = contextTable.symbol end

        for elemIndex = 0, packedVectorSize - 1 do
          local offsetToValue = elemIndex * 0x10
          local arrElement = getAddress(packedDataArrAddr + offsetToValue)
          if contextTable.symbol then contextTable.symbol = makeSymAddr( baseSymbol, offsetToValue ) end

          emitter.emitPackedColor(parent, 'pck_color[', elemIndex, offsetToValue, arrElement, contextTable)
        end
      end

      GDHandlers.PackedArrayHandlers.DEFAULT = function(packedDataArrAddr, packedVectorSize, parent, emitter, contextTable)
        local baseSymbol;
        if contextTable.symbol then baseSymbol = contextTable.symbol end

        for elemIndex = 0, packedVectorSize - 1 do
          local offsetToValue = elemIndex * GDDEFS.PTRSIZE
          local arrElement = getAddress(packedDataArrAddr + offsetToValue)
          if contextTable.symbol then contextTable.symbol = makeSymAddr( baseSymbol, offsetToValue ) end

          emitter.emitPackedScalar(parent, '/U/ pck_arr[', elemIndex, offsetToValue, arrElement, vtPointer, contextTable)
        end
      end
    GDHandlers.ConstVectorHandlers = {}

  -- ///---///--///---///--///---///--///--///---///--///---///--///---///--/// GD preinit

    local function readGodotPckVersion(pckPath)
      local file = io.open(pckPath, "rb")

      if not file then return nil end

      -- Godot PCK magic 47 44 50 43
      local magic = file:read(4)

      if magic ~= "GDPC" then
        file:close()
        return nil
      end

      local formatVersion = readU32LE(file)
      local major = readU32LE(file)
      local minor = readU32LE(file)
      local patch = readU32LE(file)

      file:close()

      return
      {
        -- formatVersion = formatVersion,
        major = major,
        minor = minor,
        patch = patch
      }
    end

    function getExportTableName()
      local base = getAddress(process)

      -- cases when getAddress fails
      if isNullOrNil(base) then
        base = enumModules()[1].Address
      end

      -- first check via PE -- https://wiki.osdev.org/PE
      if isNotNullOrNil(base) then
        local PE = base + readInteger(base + 0x3C) -- MZ.e_lfanew has an offset to PE
        local optPE = PE + 0x18 -- just skip to optional header
        local magic = readSmallInteger(optPE) -- Pe32OptionalHeader.mMagic
        local dataDirOffset = (magic == 0x10B) and 0x60 or 0x70 -- 32/64 bit
        local exportRVA = readInteger(optPE + dataDirOffset) -- skip directly to DataDirectory
        if (exportRVA) and exportRVA ~= 0 then
          local exportVA = base + exportRVA -- jump to exportRVA (.edata)
          local nameRVA = readInteger(exportVA + 0xC) -- 12 is PEExportsTableHeader.mNameRVA, offset to name's virtual address

          return readString((base + nameRVA), 60) or "ExportTableNotFound"
        end
      end
    end

    local function getIsCustomVer()
      local customVerStrAddr = AOBScanModuleUnique(process, "63 75 73 74 6F 6D 5F 62 75 69 6C 64", "-W-X-C") -- custom_build - in most cases it does the trick
      if isNotNullOrNil(customVerStrAddr) then
        return true
      else
        return false
      end
    end

    function getGodotVersionString()
      local reStr = [[Godot\sEngine\s(\(.{4,35}\)\s)?[vV]?(0|[1-9]\d*)(?:\.(0|[1-9]\d*))?(?:\.(0|[1-9]\d*))?(?:[\.-]((?:dev|alpha|beta|rc|stable)\d*))?(?:[\.+-]((?:[\w\-+\.]*)))?]]
      local fallbackreStr = [[[vV]?(0|[1-9]\d*)(?:\.(0|[1-9]\d*))(?:\.(0|[1-9]\d*))(?:[\.]((?:dev|alpha|beta|rc|stable)\d*))(?:[\.+-]((?:[\w\-+\.]*)))?]]
      local godotVersionStringTable, fallbackGDSemVerTable;

      godotVersionStringTable = lregexScan({
        pattern = reStr,
        protection = "RW-E-C", -- sometimes it's not in rdata
        encoding = "ASCII",
        engine = "RE2",
        findOne = true,
        caseSensitive = true,
        minLength = 15,
        maxLength = 60
      }) or {}

      if isNotNullOrNil(godotVersionStringTable[1]) then
        return godotVersionStringTable[1].text
      else
        -- let's test the fallback pattern for now (some 3.0 versions, might adjust for them), e.g. 4D Minesweeper
        fallbackGDSemVerTable = lregexScan({
          pattern = fallbackreStr,
          protection = "R-W-E-C", -- let's assume rdata all the time
          encoding = "ASCII",
          engine = "RE2",
          findOne = true,
          caseSensitive = true,
          minLength = 15,
          maxLength = 60
        }) or {}
        if isNotNullOrNil(fallbackGDSemVerTable) then
          return fallbackGDSemVerTable[1].text
        else
          print("Version string not found")
          return "SEMVER_NOT_FOUND"
        end
      end
    end

    local function getGodotVersionFromMagic()
      local godotMagic = AOBScanModuleUnique(process, "47 44 50 43", "-W-X-C")
      if isNotNullOrNil(godotMagic) then
        local formatVersion = readInteger( godotMagic + 0x4*1 )
        local majorVer = readInteger( godotMagic + 0x4*2 )
        local minorVer = readInteger( godotMagic + 0x4*3 )
        local patchVer = readInteger( godotMagic + 0x4*4 )
        return
        {
          major = majorVer,
          minor = minorVer,
          patch = patchVer
        }

      else
        local pathToExe = enumModules()[1].PathToFile
        local gameDir, exeName = extractFilePath(pathToExe), string.match(extractFileName(pathToExe), "([^/]+)%.exe$")
        -- local pathList = getFileList(gameDir, exeName..".pck" ) -- names may contain unescaped regex chars

        local targetPck = gameDir..exeName..".pck" -- abs path to the pck, if it exists, it will succeed 
        local version = readGodotPckVersion(targetPck)
        if version then
          return
          {
            major = version.major,
            minor = version.minor,
            patch = version.patch
          }
        else
          return nil
        end

        -- if pathList and next(pathList) then
        --   local pckPath = pathList[1]
        --   local version = readGodotPckVersion(pckPath)
        --   if version then
        --     return
        --     {
        --       major = version.major,
        --       minor = version.minor,
        --       patch = version.patch
        --     }
        --   end
        -- else
        --   return nil
        -- end
      end

    end

    --- heuristic to identify whether the process is godot
    local function godotOnProcessOpened(processid, processhandle, caption)
      -- similar to monoscript.lua in implementation
      if GD_OldOnProcessOpened ~= nil then
        GD_OldOnProcessOpened(processid, processhandle, caption)
      end

      if godot_ProcessMonitorThread == nil then
          godot_ProcessMonitorThread = createThread
          (
            function(thr)
              thr.Name = 'GDDumper_ProcessMonitorThread'
              targetIsGodot = false
              -- first check via PE -- https://wiki.osdev.org/PE
              local exportTablename = getExportTableName() or ""
              if (exportTablename):match("([gG][oO][Dd][Oo][Tt])") then
                -- if GDDEFS == nil then GDDEFS = {} end
                -- GDDEFS.GDEXPORT_TABLE = exportTablename
                targetIsGodot = true;
              end

              -- secondly, check if there's a package file, many apps do
              if not targetIsGodot then
                local pathToExe = enumModules()[1].PathToFile
                local gameDir, exeName = extractFilePath(pathToExe), string.match(extractFileName(pathToExe), "([^/]+)%.exe$")
                local pathList = getFileList(gameDir, exeName..".pck" ) -- TODO: regex chars will invalidate the mask

                if pathList and next(pathList) then
                  targetIsGodot = true;
                end
              end

              -- -- via powershell, which also isn't reliable and slow
              -- if not targetIsGodot then
              --     local out, code = runCommand("cmd.exe", { "/c", ([[powershell -NoProfile -Command "(Get-Item '%s').VersionInfo.FileDescription"]]):format(pathToExe) })
              --     if code ~= 0 then targetIsGodot = false
              --     else
              --         if (out or ""):match("([gG][oO][Dd][Oo][Tt])") then targetIsGodot = true; end
              --     end
              -- end

              if targetIsGodot then
                synchronize(buildGDGUI())

              elseif targetIsGodot == false and GDGUIInit == true then
                synchronize(function()
                  disableGDDissect()
                  local mainMenu = getMainForm().Menu
                  for i = 0, mainMenu.Items.Count - 1 do
                    if mainMenu.Items.Item[i].Caption == 'GDDumper' then
                      mainMenu.Items.Item[i].Destroy()
                      break
                    end
                  end
                  GDGUIInit = false
                  MainForm.setCaption("Cheat Engine")
                end)
              end
            end
          )
          godot_ProcessMonitorThread = nil
      end

      return nil
    end

    local function godotRegisterPreinit()
      GD_OldOnProcessOpened = MainForm.OnProcessOpened
      MainForm.OnProcessOpened = godotOnProcessOpened
    end

    local function defineGDVersion()

      local major, minor, patch = 0, 0, 0
      local godotVersionString = nil
      if isNullOrNil(GDDEFS) then GDDEFS = {} end

      local ver = getGodotVersionFromMagic()
      if isNotNullOrNil(ver) and next(ver) then
        GDDEFS.VERSION_STRING = tostring(ver.major) .. '.' .. tostring(ver.minor)
        GDDEFS.MAJOR_VER = ver.major
        GDDEFS.MINOR_VER = ver.minor
        GDDEFS.PATCH_VER = ver.patch
        GDDEFS.FULL_GDVERSION_STRING = "Godot Engine ".. ver.major .. '.' .. ver.minor .. '.' .. ver.patch
      else
        print("getGodotVersionFromMagic: failed to find magic")
      end

      if lregexScan and type(lregexScan) == "function" then
        godotVersionString = getGodotVersionString()
        GDDEFS.FULL_GDVERSION_STRING = godotVersionString
        -- major, minor, patch, tag = (godotVersionString):match("v?(%d+)%.(%d+)%.?(%d*)%-?(%a*)")
        -- if isNullOrNil(major) or isNullOrNil(minor) then major, minor, patch = (godotVersionString):match("Godot Engine v?(%d+)%.(%d+)%.?(%a*)") end
      end

      local exportTableStr = getExportTableName() or ""

      if (exportTableStr):match("debug") then
        GDDEFS.DEBUGVER = true
      else
        GDDEFS.DEBUGVER = false
      end

      if (exportTableStr):match("mono") then
        GDDEFS.MONO = true
      else
        GDDEFS.MONO = false
      end

      -- elseif (exportTableStr):match( "release" ) then -- or "opt" or "dev6"

      if isNullOrNil(godotVersionString) then
        GDDEFS.CUSTOMVER = getIsCustomVer()
      elseif (godotVersionString):match("custom") then
        GDDEFS.CUSTOMVER = true
      else
        GDDEFS.CUSTOMVER = false
      end

      if isNotNullOrNil(major) and isNotNullOrNil(minor) then
        GDDEFS.MAJOR_VER = tonumber(major)
        GDDEFS.MINOR_VER = tonumber(minor)
        GDDEFS.VERSION_STRING = major .. '.' .. minor
      end

      MainForm.setCaption( (GDDEFS.FULL_GDVERSION_STRING or "GD VERSION UNKNOWN") .. (GDDEFS.CUSTOMVER and " C" or '') .. (GDDEFS.DEBUGVER and " D" or '') .. (GDDEFS.MONO and " M" or '') )
    end

    local function getStoredOffsetsFromVersion(majminVersionStr)

      majminVersionStr = majminVersionStr or GDDEFS.VERSION_STRING
      -- offsets in Node/Objects in debug versions are shifted by 0x8 in most cases; function code/constants/globals are shifted less often

      local offsets = {}

      -- VPChildren, VPObjStringName, NodeGDScriptInstance, NodeGDScriptName, GDScriptFunctionMap, GDScriptConstantMap, GDScriptVariantNameHM, oVariantVector, _4x_MoreStableGDScriptVariantNameType, NodeVariantVectorSizeOffset, _3x_GDScriptVariantNamesIndex, GDScriptFunctionCode, GDScriptFunctionCodeConsts, GDScriptFunctionCodeGlobals
      if majminVersionStr == "4.8" then
        GDDEFS.DICT_HEAD = 0x20
        GDDEFS.DICT_TAIL = 0x28
        GDDEFS.DICT_SIZE = 0x34
        GDDEFS.STRING = 0x8 -- we need it for correct addr/struct representation
        GDDEFS.GET_TYPE_INDX = 10

        offsets.VPChildren = 0x140
        offsets.VPObjStringName = 0x190
        offsets.NodeGDScriptInstance = 0x60
        offsets.NodeGDScriptName = 0xF0
        offsets.GDScriptFunctionMap = 0x230
        offsets.GDScriptConstantMap = 0x208
        offsets.GDScriptVariantNameHM = 0x180
        offsets.oVariantVector = 0x28
        offsets.GDScriptVariantNameType = 0x44 -- 4.x
        offsets.NodeVariantVectorSizeOffset = 0x10
        offsets.GDScriptVariantNamesIndex = nil -- 3.x
        offsets.GDScriptFunctionCode = 0x178
        offsets.GDScriptFunctionCodeConsts = 0x198
        offsets.GDScriptFunctionCodeGlobals = 0x1A8
        offsets.GDScriptFunctionCodeArg = 0xA0 -- 0x0 type

        if GDDEFS.DEBUGVER then
          offsets.VPChildren = offsets.VPChildren + 0x8
          offsets.VPObjStringName = offsets.VPObjStringName + 0x8
          offsets.NodeGDScriptInstance = offsets.NodeGDScriptInstance + 0x8
          offsets.NodeGDScriptName = offsets.NodeGDScriptName + 0x8
          offsets.GDScriptFunctionMap = offsets.GDScriptFunctionMap + 0x8
          offsets.GDScriptConstantMap = offsets.GDScriptConstantMap + 0x8
          offsets.GDScriptVariantNameHM = offsets.GDScriptVariantNameHM + 0x8
          offsets.oVariantVector = offsets.oVariantVector + 0x28
          -- offsets.GDScriptVariantNameType = offsets.GDScriptVariantNameType -- 4.x
          -- offsets.NodeVariantVectorSizeOffset = offsets.NodeVariantVectorSizeOffset
          -- offsets.GDScriptVariantNamesIndex = offsets.GDScriptVariantNamesIndex -- 3.x
          -- offsets.GDScriptFunctionCode = offsets.GDScriptFunctionCode
          -- offsets.GDScriptFunctionCodeConsts = offsets.GDScriptFunctionCodeConsts
          -- offsets.GDScriptFunctionCodeGlobals = offsets.GDScriptFunctionCodeGlobals
        end

        if GDDEFS.CUSTOMVER then
          offsets.VPChildren = offsets.VPChildren + 0x48
          offsets.VPObjStringName = offsets.VPObjStringName + 0x48
          -- offsets.NodeGDScriptInstance = offsets.NodeGDScriptInstance
          offsets.NodeGDScriptName = offsets.NodeGDScriptName + 0x48
          offsets.GDScriptFunctionMap = offsets.GDScriptFunctionMap + 0x48
          offsets.GDScriptConstantMap = offsets.GDScriptConstantMap + 0x48
          offsets.GDScriptVariantNameHM = offsets.GDScriptVariantNameHM + 0x48
          -- offsets.oVariantVector = offsets.oVariantVector
          -- offsets.GDScriptVariantNameType = offsets.GDScriptVariantNameType -- 4.x
          -- offsets.NodeVariantVectorSizeOffset = offsets.NodeVariantVectorSizeOffset
          -- offsets.GDScriptVariantNamesIndex = offsets.GDScriptVariantNamesIndex -- 3.x
          -- offsets.GDScriptFunctionCode = offsets.GDScriptFunctionCode
          -- offsets.GDScriptFunctionCodeConsts = offsets.GDScriptFunctionCodeConsts
          -- offsets.GDScriptFunctionCodeGlobals = offsets.GDScriptFunctionCodeGlobals
        end

        return offsets

      elseif majminVersionStr == "4.7" then
        GDDEFS.DICT_HEAD = 0x20
        GDDEFS.DICT_TAIL = 0x28
        GDDEFS.DICT_SIZE = 0x34
        GDDEFS.STRING = 0x8 -- we need it for correct addr/struct representation
        GDDEFS.GET_TYPE_INDX = 10
        -- timer 2D0 time_left | 2D8 isactive | 2C0 waittime

        offsets.VPChildren = 0x140
        offsets.VPObjStringName = 0x190
        offsets.NodeGDScriptInstance = 0x60
        offsets.NodeGDScriptName = 0xF0
        offsets.GDScriptFunctionMap = 0x230
        offsets.GDScriptConstantMap = 0x208
        offsets.GDScriptVariantNameHM = 0x180
        offsets.oVariantVector = 0x28
        offsets.GDScriptVariantNameType = 0x44 -- 4.x
        offsets.NodeVariantVectorSizeOffset = 0x10
        offsets.GDScriptVariantNamesIndex = nil -- 3.x
        offsets.GDScriptFunctionCode = 0x178
        offsets.GDScriptFunctionCodeConsts = 0x198
        offsets.GDScriptFunctionCodeGlobals = 0x1A8
        offsets.GDScriptFunctionCodeArg = 0xA0
        
        if GDDEFS.DEBUGVER then
          offsets.VPChildren = offsets.VPChildren + 0x8
          offsets.VPObjStringName = offsets.VPObjStringName + 0x8
          offsets.NodeGDScriptInstance = offsets.NodeGDScriptInstance + 0x8
          offsets.NodeGDScriptName = offsets.NodeGDScriptName + 0x8
          offsets.GDScriptFunctionMap = offsets.GDScriptFunctionMap + 0x8
          offsets.GDScriptConstantMap = offsets.GDScriptConstantMap + 0x8
          offsets.GDScriptVariantNameHM = offsets.GDScriptVariantNameHM + 0x8
          offsets.oVariantVector = offsets.oVariantVector + 0x28
          -- offsets.GDScriptVariantNameType = offsets.GDScriptVariantNameType -- 4.x
          -- offsets.NodeVariantVectorSizeOffset = offsets.NodeVariantVectorSizeOffset
          -- offsets.GDScriptVariantNamesIndex = offsets.GDScriptVariantNamesIndex -- 3.x
          -- offsets.GDScriptFunctionCode = offsets.GDScriptFunctionCode
          -- offsets.GDScriptFunctionCodeConsts = offsets.GDScriptFunctionCodeConsts
          -- offsets.GDScriptFunctionCodeGlobals = offsets.GDScriptFunctionCodeGlobals
        end

        if GDDEFS.CUSTOMVER then
          offsets.VPChildren = offsets.VPChildren + 0x48
          offsets.VPObjStringName = offsets.VPObjStringName + 0x48
          -- offsets.NodeGDScriptInstance = offsets.NodeGDScriptInstance
          offsets.NodeGDScriptName = offsets.NodeGDScriptName + 0x48
          offsets.GDScriptFunctionMap = offsets.GDScriptFunctionMap + 0x48
          offsets.GDScriptConstantMap = offsets.GDScriptConstantMap + 0x48
          offsets.GDScriptVariantNameHM = offsets.GDScriptVariantNameHM + 0x48
          -- offsets.oVariantVector = offsets.oVariantVector
          -- offsets.GDScriptVariantNameType = offsets.GDScriptVariantNameType -- 4.x
          -- offsets.NodeVariantVectorSizeOffset = offsets.NodeVariantVectorSizeOffset
          -- offsets.GDScriptVariantNamesIndex = offsets.GDScriptVariantNamesIndex -- 3.x
          -- offsets.GDScriptFunctionCode = offsets.GDScriptFunctionCode
          -- offsets.GDScriptFunctionCodeConsts = offsets.GDScriptFunctionCodeConsts
          -- offsets.GDScriptFunctionCodeGlobals = offsets.GDScriptFunctionCodeGlobals
        end

        return offsets
      elseif majminVersionStr == "4.6" then
        
        GDDEFS.STRING = 0x8 -- we need it for correct addr/struct representation
        if GDDEFS._x64bit then
          GDDEFS.DICT_HEAD = 0x20
          GDDEFS.DICT_TAIL = 0x28
          GDDEFS.DICT_SIZE = 0x34 --0x3C
          GDDEFS.GET_TYPE_INDX = 10
          -- timer 2D0 time_left | 2D8 isactive | 2C0 waittime

          -- godot.windows.template_release.x86_64.exe
          -- Godot Engine v4.6.stable.official.89cea1439
          offsets.VPChildren = 0x140
          offsets.VPObjStringName = 0x190
          offsets.NodeGDScriptInstance = 0x60
          offsets.NodeGDScriptName = 0xF0
          offsets.GDScriptFunctionMap = 0x230
          offsets.GDScriptConstantMap = 0x208
          offsets.GDScriptVariantNameHM = 0x180
          offsets.oVariantVector = 0x28
          offsets.GDScriptVariantNameType = 0x44 -- 4.x
          offsets.NodeVariantVectorSizeOffset = 0x10
          offsets.GDScriptVariantNamesIndex = nil -- 3.x
          offsets.GDScriptFunctionCode = 0x178
          offsets.GDScriptFunctionCodeConsts = 0x198
          offsets.GDScriptFunctionCodeGlobals = 0x1A8
          offsets.GDScriptFunctionCodeArg = 0xA0 -- 0xf4 argc
          offsets.GDScriptRealoadIndex = 46

          if GDDEFS.DEBUGVER then
            offsets.VPChildren = offsets.VPChildren + 0x8
            offsets.VPObjStringName = offsets.VPObjStringName + 0x8
            offsets.NodeGDScriptInstance = offsets.NodeGDScriptInstance + 0x8
            offsets.NodeGDScriptName = offsets.NodeGDScriptName + 0x8
            offsets.GDScriptFunctionMap = offsets.GDScriptFunctionMap + 0x8
            offsets.GDScriptConstantMap = offsets.GDScriptConstantMap + 0x8
            offsets.GDScriptVariantNameHM = offsets.GDScriptVariantNameHM + 0x8
            offsets.oVariantVector = offsets.oVariantVector + 0x28
            -- offsets.GDScriptRealoadIndex = offsets.GDScriptRealoadIndex + 0

            -- offsets.GDScriptVariantNameType = offsets.GDScriptVariantNameType -- 4.x
            -- offsets.NodeVariantVectorSizeOffset = offsets.NodeVariantVectorSizeOffset
            -- offsets.GDScriptVariantNamesIndex = offsets.GDScriptVariantNamesIndex -- 3.x
            -- offsets.GDScriptFunctionCode = offsets.GDScriptFunctionCode
            -- offsets.GDScriptFunctionCodeConsts = offsets.GDScriptFunctionCodeConsts
            -- offsets.GDScriptFunctionCodeGlobals = offsets.GDScriptFunctionCodeGlobals
          end

          if GDDEFS.CUSTOMVER then
            offsets.VPChildren = offsets.VPChildren + 0x48
            offsets.VPObjStringName = offsets.VPObjStringName + 0x48
            -- offsets.NodeGDScriptInstance = offsets.NodeGDScriptInstance
            offsets.NodeGDScriptName = offsets.NodeGDScriptName + 0x48
            offsets.GDScriptFunctionMap = offsets.GDScriptFunctionMap + 0x48
            offsets.GDScriptConstantMap = offsets.GDScriptConstantMap + 0x48
            offsets.GDScriptVariantNameHM = offsets.GDScriptVariantNameHM + 0x48
            offsets.GDScriptRealoadIndex = offsets.GDScriptRealoadIndex - 1

            -- offsets.oVariantVector = offsets.oVariantVector
            -- offsets.GDScriptVariantNameType = offsets.GDScriptVariantNameType -- 4.x
            -- offsets.NodeVariantVectorSizeOffset = offsets.NodeVariantVectorSizeOffset
            -- offsets.GDScriptVariantNamesIndex = offsets.GDScriptVariantNamesIndex -- 3.x
            -- offsets.GDScriptFunctionCode = offsets.GDScriptFunctionCode
            -- offsets.GDScriptFunctionCodeConsts = offsets.GDScriptFunctionCodeConsts
            -- offsets.GDScriptFunctionCodeGlobals = offsets.GDScriptFunctionCodeGlobals
          end
        else
          error("Not defined yet")
          GDDEFS.GDSCRIPT_REF = 0x14
          GDDEFS.FUNC_MAPVAL = 0xC
          GDDEFS.CHILDREN_SIZE = 0x8
          GDDEFS.MAP_SIZE = 0xC
          GDDEFS.ARRAY_TOVECTOR = 0x8
          GDDEFS.P_ARRAY_TOARR = 0x18
          GDDEFS.P_ARRAY_SIZE = 0x8
          GDDEFS.DICT_HEAD = GDDEFS.DICT_HEAD or 0x28
          GDDEFS.DICT_TAIL = GDDEFS.DICT_TAIL or 0x30
          GDDEFS.DICT_SIZE = GDDEFS.DICT_SIZE or 0x34
          GDDEFS.DICTELEM_KEYTYPE = 0x10
          GDDEFS.DICTELEM_KEYVAL = 0x18
          GDDEFS.DICTELEM_VALTYPE = 0x28
          GDDEFS.CONSTELEM_KEYVAL = 0x8
          GDDEFS.CONSTELEM_VALTYPE = 0x10
          GDDEFS.VAR_NAMEINDEX_I = 0xC
          GDDEFS.GET_TYPE_INDX = 10

          -- custom
          offsets.VPChildren = 0xF0
          offsets.VPObjStringName = 0x12C
          offsets.NodeGDScriptInstance = 0x40
          offsets.NodeGDScriptName = 0xC4
          offsets.GDScriptFunctionMap = 0x178
          offsets.GDScriptConstantMap = 0x160
          offsets.GDScriptVariantNameHM = 0x110
          offsets.oVariantVector = 0x1C
          offsets.GDScriptVariantNameType = 0x20 -- 4.x
          offsets.NodeVariantVectorSizeOffset = 0x8
          offsets.GDScriptVariantNamesIndex = nil -- 3.x
          offsets.GDScriptFunctionCode = 0xE8
          offsets.GDScriptFunctionCodeConsts = 0xF8
          offsets.GDScriptFunctionCodeGlobals = 0x118
          -- offsets.GDScriptFunctionCodeArg = 0xA0 -- 0xf4 argc

          if GDDEFS.DEBUGVER then
            offsets.VPChildren = offsets.VPChildren + 0x8
            offsets.VPObjStringName = offsets.VPObjStringName + 0x8
            offsets.NodeGDScriptInstance = offsets.NodeGDScriptInstance + 0x8
            offsets.NodeGDScriptName = offsets.NodeGDScriptName + 0x8
            offsets.GDScriptFunctionMap = offsets.GDScriptFunctionMap + 0x8
            offsets.GDScriptConstantMap = offsets.GDScriptConstantMap + 0x8
            offsets.GDScriptVariantNameHM = offsets.GDScriptVariantNameHM + 0x8
            offsets.oVariantVector = offsets.oVariantVector + 0x28
            -- offsets.GDScriptVariantNameType = offsets.GDScriptVariantNameType -- 4.x
            -- offsets.NodeVariantVectorSizeOffset = offsets.NodeVariantVectorSizeOffset
            -- offsets.GDScriptVariantNamesIndex = offsets.GDScriptVariantNamesIndex -- 3.x
            -- offsets.GDScriptFunctionCode = offsets.GDScriptFunctionCode
            -- offsets.GDScriptFunctionCodeConsts = offsets.GDScriptFunctionCodeConsts
            -- offsets.GDScriptFunctionCodeGlobals = offsets.GDScriptFunctionCodeGlobals
          end

          -- if GDDEFS.CUSTOMVER then
          --   offsets.VPChildren = offsets.VPChildren + 0x48
          --   offsets.VPObjStringName = offsets.VPObjStringName + 0x48
          --   -- offsets.NodeGDScriptInstance = offsets.NodeGDScriptInstance
          --   offsets.NodeGDScriptName = offsets.NodeGDScriptName + 0x48
          --   offsets.GDScriptFunctionMap = offsets.GDScriptFunctionMap + 0x48
          --   offsets.GDScriptConstantMap = offsets.GDScriptConstantMap + 0x48
          --   offsets.GDScriptVariantNameHM = offsets.GDScriptVariantNameHM + 0x48
          --   -- offsets.oVariantVector = offsets.oVariantVector
          --   -- offsets.GDScriptVariantNameType = offsets.GDScriptVariantNameType -- 4.x
          --   -- offsets.NodeVariantVectorSizeOffset = offsets.NodeVariantVectorSizeOffset
          --   -- offsets.GDScriptVariantNamesIndex = offsets.GDScriptVariantNamesIndex -- 3.x
          --   -- offsets.GDScriptFunctionCode = offsets.GDScriptFunctionCode
          --   -- offsets.GDScriptFunctionCodeConsts = offsets.GDScriptFunctionCodeConsts
          --   -- offsets.GDScriptFunctionCodeGlobals = offsets.GDScriptFunctionCodeGlobals
          -- end


        end

        return offsets

      elseif majminVersionStr == "4.5" then
        GDDEFS.DICT_HEAD = 0x20
        GDDEFS.DICT_TAIL = 0x28
        GDDEFS.DICT_SIZE = 0x34 -- 0x3C
        GDDEFS.STRING = 0x8 -- we need it for correct addr/struct representation
        GDDEFS.GET_TYPE_INDX = 9
        -- A0 Vector<GDScriptDataType> argument_types; including parameter names
        -- f4 argcount

        -- godot.windows.template_release.x86_64.exe
        -- Godot Engine v4.5.1.stable.official.f62fdbde1
        offsets.VPChildren = 0x170
        offsets.VPObjStringName = 0x1C0
        offsets.NodeGDScriptInstance = 0x68
        offsets.NodeGDScriptName = 0x120
        offsets.GDScriptFunctionMap = 0x268
        offsets.GDScriptConstantMap = 0x208
        offsets.GDScriptVariantNameHM = 0x1B8
        offsets.oVariantVector = 0x28
        offsets.GDScriptVariantNameType = 0x48 -- 4.x
        offsets.NodeVariantVectorSizeOffset = 0x8
        offsets.GDScriptVariantNamesIndex = nil -- 3.x
        offsets.GDScriptFunctionCode = 0x180 -- 0x178
        offsets.GDScriptFunctionCodeConsts = 0x1A0 -- 0x198
        offsets.GDScriptFunctionCodeGlobals = 0x1B0 -- 0x1A8
        offsets.GDScriptFunctionCodeArg = 0xA0 -- 0xF4 argc
        offsets.GDScriptRealoadIndex = 47
        
        if GDDEFS.DEBUGVER then
          -- godot.windows.template_debug.x86_64.exe
          -- Godot Engine v4.5.1.stable.official
          offsets.VPChildren = offsets.VPChildren + 0x8
          offsets.VPObjStringName = offsets.VPObjStringName + 0x8
          offsets.NodeGDScriptInstance = offsets.NodeGDScriptInstance + 0x8
          offsets.NodeGDScriptName = offsets.NodeGDScriptName + 0x8
          offsets.GDScriptFunctionMap = offsets.GDScriptFunctionMap + 0x8
          offsets.GDScriptConstantMap = offsets.GDScriptConstantMap + 0x8
          offsets.GDScriptVariantNameHM = offsets.GDScriptVariantNameHM + 0x8
          offsets.oVariantVector = offsets.oVariantVector + 0x28
          offsets.GDScriptRealoadIndex = offsets.GDScriptRealoadIndex + 19
        end

        if GDDEFS.CUSTOMVER then
          -- godot.windows.template_release.x86_64.exe
          -- Godot Engine v4.5.1.stable.custom_build
          offsets.VPChildren = offsets.VPChildren + 0x48
          offsets.VPObjStringName = offsets.VPObjStringName + 0x48
          offsets.NodeGDScriptName = offsets.NodeGDScriptName + 0x48
          offsets.GDScriptFunctionMap = offsets.GDScriptFunctionMap + 0x48
          offsets.GDScriptConstantMap = offsets.GDScriptConstantMap + 0x48
          offsets.GDScriptVariantNameHM = offsets.GDScriptVariantNameHM + 0x48
          -- offsets.GDScriptRealoadIndex = offsets.GDScriptRealoadIndex + 0
        end

        return offsets

      elseif majminVersionStr == "4.4" then
        GDDEFS.GET_TYPE_INDX = 8
        -- godot.windows.template_release.x86_64.exe
        -- Godot Engine v4.4.stable.official.4c311cbee
        offsets.VPChildren = 0x188
        offsets.VPObjStringName = 0x1E0
        offsets.NodeGDScriptInstance = 0x68
        offsets.NodeGDScriptName = 0x130
        offsets.GDScriptFunctionMap = 0x2D8
        offsets.GDScriptConstantMap = 0x2A8
        offsets.GDScriptVariantNameHM = 0x210
        offsets.oVariantVector = 0x28
        offsets.GDScriptVariantNameType = 0x48 -- 4.x
        offsets.NodeVariantVectorSizeOffset = 0x8
        offsets.GDScriptVariantNamesIndex = nil -- 3.x
        offsets.GDScriptFunctionCode = 0x178
        offsets.GDScriptFunctionCodeConsts = 0x198
        offsets.GDScriptFunctionCodeGlobals = 0x1A8
        -- timer 3B8 time_left | 3C0 isactive | 3A8 waittime
        offsets.GDScriptFunctionCodeArg = 0xA0
        offsets.GDScriptRealoadIndex = 46

        if GDDEFS.DEBUGVER then
          -- godot.windows.template_debug.x86_64.exe
          -- Godot Engine v4.4.1.stable.official
          -- godot.windows.template_debug.x86_64.mono.exe
          -- Godot Engine v4.4.stable.mono.official
          -- GDDEFS.STRING = 0x8
          offsets.VPChildren = offsets.VPChildren + 0x8
          offsets.VPObjStringName = offsets.VPObjStringName + 0x8
          offsets.NodeGDScriptInstance = offsets.NodeGDScriptInstance + 0x8
          offsets.NodeGDScriptName = offsets.NodeGDScriptName + 0x8
          offsets.GDScriptFunctionMap = offsets.GDScriptFunctionMap + 0x8
          offsets.GDScriptConstantMap = offsets.GDScriptConstantMap + 0x8
          offsets.GDScriptVariantNameHM = offsets.GDScriptVariantNameHM + 0x8
          offsets.oVariantVector = offsets.oVariantVector + 0x30
          offsets.GDScriptRealoadIndex = offsets.GDScriptRealoadIndex + 19

        end
        if GDDEFS.CUSTOMVER then
          GDDEFS.STRING = 0x10
          -- godot.windows.template_release.x86_64.exe
          -- Godot Engine v4.4.1.stable.custom_build.49a5bc7b6
          offsets.VPChildren = offsets.VPChildren + 0x48
          offsets.VPObjStringName = offsets.VPObjStringName + 0x48
          offsets.NodeGDScriptName = offsets.NodeGDScriptName + 0x48
          offsets.GDScriptFunctionMap = offsets.GDScriptFunctionMap + 0x48
          offsets.GDScriptConstantMap = offsets.GDScriptConstantMap + 0x48
          offsets.GDScriptVariantNameHM = offsets.GDScriptVariantNameHM + 0x48
          offsets.GDScriptRealoadIndex = offsets.GDScriptRealoadIndex - 1

        end
        return offsets

      elseif majminVersionStr == "4.3" then
        GDDEFS.GET_TYPE_INDX = 8
        -- godot.windows.template_release.x86_64.exe
        -- Godot Engine v4.3.stable.official
        -- 48 8B 03 C7 84 24 ? ? ? ? ? ? ? ? 48 89 DA
        offsets.VPChildren = 0x178
        offsets.VPObjStringName = 0x1D0
        offsets.NodeGDScriptInstance = 0x68
        offsets.NodeGDScriptName = 0x120
        offsets.GDScriptFunctionMap = 0x280
        offsets.GDScriptConstantMap = 0x250
        offsets.GDScriptVariantNameHM = 0x1B8
        offsets.oVariantVector = 0x28
        offsets.GDScriptVariantNameType = 0x40 -- 4.x
        offsets.NodeVariantVectorSizeOffset = 0x8
        offsets.GDScriptVariantNamesIndex = nil -- 3.x
        offsets.GDScriptFunctionCode = 0x178
        offsets.GDScriptFunctionCodeConsts = 0x198
        offsets.GDScriptFunctionCodeGlobals = 0x1A8
        offsets.GDScriptFunctionCodeArg = 0xA0
        offsets.GDScriptRealoadIndex = 44
        
        if GDDEFS.DEBUGVER then
          -- godot.windows.template_debug.x86_64.exe (0x8 string, static names that are ascii)
          -- Godot Engine v4.3.stable.official
          -- GDDEFS.STRING = 0x8
          offsets.VPChildren = offsets.VPChildren + 0x8
          offsets.VPObjStringName = offsets.VPObjStringName + 0x8
          offsets.NodeGDScriptInstance = offsets.NodeGDScriptInstance + 0x8
          offsets.NodeGDScriptName = offsets.NodeGDScriptName + 0x8
          offsets.GDScriptFunctionMap = offsets.GDScriptFunctionMap + 0x8
          offsets.GDScriptConstantMap = offsets.GDScriptConstantMap + 0x8
          offsets.GDScriptVariantNameHM = offsets.GDScriptVariantNameHM + 0x8
          offsets.oVariantVector = offsets.oVariantVector + 0x30
          offsets.GDScriptVariantNameType = offsets.GDScriptVariantNameType + 0x8 -- 4.x

        end
        if GDDEFS.CUSTOMVER then
          -- godot.windows.template_release.x86_64.exe
          -- Godot Engine v4.3.stable.custom_build
          offsets.VPChildren = offsets.VPChildren + 0x48
          offsets.VPObjStringName = offsets.VPObjStringName + 0x48
          offsets.NodeGDScriptName = offsets.NodeGDScriptName + 0x48
          offsets.GDScriptFunctionMap = offsets.GDScriptFunctionMap + 0x48
          offsets.GDScriptConstantMap = offsets.GDScriptConstantMap + 0x48
          offsets.GDScriptVariantNameHM = offsets.GDScriptVariantNameHM + 0x48
          offsets.GDScriptVariantNameType = offsets.GDScriptVariantNameType + 0x8 -- 4.x
          offsets.GDScriptRealoadIndex = offsets.GDScriptRealoadIndex - 1
        end

        return offsets

      elseif majminVersionStr == "4.2" then
        GDDEFS.GET_TYPE_INDX = 8
        -- godot.windows.template_release.x86_64.exe
        -- Godot Engine v4.2.1.stable.official.b09f793f5
        offsets.VPChildren = 0x178
        offsets.VPObjStringName = 0x1D0
        offsets.NodeGDScriptInstance = 0x68
        offsets.NodeGDScriptName = 0x120
        offsets.GDScriptFunctionMap = 0x280
        offsets.GDScriptConstantMap = 0x250
        offsets.GDScriptVariantNameHM = 0x1B8
        offsets.oVariantVector = 0x28
        offsets.GDScriptVariantNameType = 0x40 -- 4.x
        offsets.NodeVariantVectorSizeOffset = 0x4
        offsets.GDScriptVariantNamesIndex = nil -- 3.x
        offsets.GDScriptFunctionCode = 0x170
        offsets.GDScriptFunctionCodeConsts = 0x190
        offsets.GDScriptFunctionCodeGlobals = 0x1A0
        -- timer 3a8 time_left 3b8 waittime 3c0 active
        offsets.GDScriptFunctionCodeArg = 0xA0
        offsets.GDScriptRealoadIndex = 44
        
        if GDDEFS.DEBUGVER then
          -- godot.windows.template_debug.x86_64.exe
          --  Godot Engine v4.2.2.stable.official
          -- GDDEFS.STRING = 0x8
          offsets.VPChildren = offsets.VPChildren + 0x8
          offsets.VPObjStringName = offsets.VPObjStringName + 0x8
          offsets.NodeGDScriptInstance = offsets.NodeGDScriptInstance + 0x8
          offsets.NodeGDScriptName = offsets.NodeGDScriptName + 0x8
          offsets.GDScriptFunctionMap = offsets.GDScriptFunctionMap + 0x8
          offsets.GDScriptConstantMap = offsets.GDScriptConstantMap + 0x8
          offsets.GDScriptVariantNameHM = offsets.GDScriptVariantNameHM + 0x8
          offsets.oVariantVector = offsets.oVariantVector + 0x30
          offsets.GDScriptVariantNameType = offsets.GDScriptVariantNameType + 0x8 -- 4.x
          offsets.GDScriptRealoadIndex = offsets.GDScriptRealoadIndex + 17

        end
        if GDDEFS.CUSTOMVER then
          error("Not defined yet")
          -- GDDEFS.STRING = 0x8
          offsets.VPChildren = offsets.VPChildren + 0x48
          offsets.VPObjStringName = offsets.VPObjStringName + 0x48
          offsets.NodeGDScriptName = offsets.NodeGDScriptName + 0x48
          offsets.GDScriptFunctionMap = offsets.GDScriptFunctionMap + 0x48
          offsets.GDScriptConstantMap = offsets.GDScriptConstantMap + 0x48
          offsets.GDScriptVariantNameHM = offsets.GDScriptVariantNameHM + 0x48
          offsets.GDScriptVariantNameType = offsets.GDScriptVariantNameType + 0x8 -- 4.x
          -- offsets.GDScriptRealoadIndex = offsets.GDScriptRealoadIndex + 0

        end

        return offsets

      elseif majminVersionStr == "4.1" then
        GDDEFS.GET_TYPE_INDX = 8
        -- 4.1.2 has some wild offsets however
        -- godot.windows.template_release.x86_64.exe
        -- Godot Engine v4.2.1.stable.official.b09f793f5
        offsets.VPChildren = 0x178
        offsets.VPObjStringName = 0x1D0
        offsets.NodeGDScriptInstance = 0x68
        offsets.NodeGDScriptName = 0x148
        offsets.GDScriptFunctionMap = 0x260
        offsets.GDScriptConstantMap = 0x1F0
        offsets.GDScriptVariantNameHM = 0x290
        offsets.oVariantVector = 0x28
        offsets.GDScriptVariantNameType = 0x40 -- 4.x
        offsets.NodeVariantVectorSizeOffset = 0x4
        offsets.GDScriptVariantNamesIndex = nil -- 3.x
        offsets.GDScriptFunctionCode = 0x118
        offsets.GDScriptFunctionCodeConsts = 0x100
        offsets.GDScriptFunctionCodeGlobals = 0xF0
        -- timer 3a8 time_left 3b8 waittime 3c0 active
        offsets.GDScriptFunctionCodeArg = 0xA0
        offsets.GDScriptRealoadIndex = 44

        if GDDEFS.DEBUGVER then
          -- godot.windows.template_debug.x86_64.exe
          --  Godot Engine v4.1.1.stable.official
          -- GDDEFS.STRING = 0x8
          offsets.VPChildren = offsets.VPChildren + 0x8
          offsets.VPObjStringName = offsets.VPObjStringName + 0x8
          offsets.NodeGDScriptInstance = offsets.NodeGDScriptInstance + 0x8
          offsets.NodeGDScriptName = offsets.NodeGDScriptName + 0x8
          offsets.GDScriptFunctionMap = offsets.GDScriptFunctionMap + 0x8
          offsets.GDScriptConstantMap = offsets.GDScriptConstantMap + 0x8
          offsets.GDScriptVariantNameHM = offsets.GDScriptVariantNameHM + 0x8
          offsets.oVariantVector = offsets.oVariantVector + 0x30
          -- offsets.GDScriptRealoadIndex = offsets.GDScriptRealoadIndex + 0
        end
        if GDDEFS.CUSTOMVER then
          -- Godot Engine v4.1.2.rc.custom_build
          GDDEFS.STRING = 0x10
          offsets.VPChildren = offsets.VPChildren + 0x48
          offsets.VPObjStringName = offsets.VPObjStringName + 0x48
          offsets.NodeGDScriptName = offsets.NodeGDScriptName + 0x48
          offsets.GDScriptFunctionMap = offsets.GDScriptFunctionMap + 0x48
          offsets.GDScriptConstantMap = offsets.GDScriptConstantMap + 0x48
          offsets.GDScriptVariantNameHM = offsets.GDScriptVariantNameHM + 0x48
          offsets.GDScriptFunctionCodeConsts = offsets.GDScriptFunctionCode + 0x58 -- 0x170
          offsets.GDScriptFunctionCodeGlobals = offsets.GDScriptFunctionCodeConsts + 0x10
          offsets.GDScriptRealoadIndex = offsets.GDScriptRealoadIndex + 2
        end

        return offsets

      elseif majminVersionStr == "4.0" then
        GDDEFS.GET_TYPE_INDX = 8
        offsets.VPChildren = 0x168
        offsets.VPObjStringName = 0x1C0
        offsets.NodeGDScriptInstance = 0x68
        offsets.NodeGDScriptName = 0x178
        offsets.GDScriptFunctionMap = 0x270
        offsets.GDScriptConstantMap = 0x238
        offsets.GDScriptVariantNameHM = 0x2A8
        offsets.oVariantVector = 0x28
        offsets.GDScriptVariantNameType = 0x40 -- 4.x
        offsets.NodeVariantVectorSizeOffset = 0x8
        offsets.GDScriptVariantNamesIndex = nil -- 3.x
        offsets.GDScriptFunctionCode = 0x118
        offsets.GDScriptFunctionCodeConsts = 0x100
        offsets.GDScriptFunctionCodeGlobals = 0xF0
        offsets.GDScriptFunctionCodeArg = 0xA0
        
        if GDDEFS.DEBUGVER then
          -- error("Not defined yet")
          -- GDDEFS.STRING = 0x8
          offsets.VPChildren = offsets.VPChildren + 0x8
          offsets.VPObjStringName = offsets.VPObjStringName + 0x8
          offsets.NodeGDScriptInstance = offsets.NodeGDScriptInstance + 0x8
          offsets.NodeGDScriptName = offsets.NodeGDScriptName + 0x8
          offsets.GDScriptFunctionMap = offsets.GDScriptFunctionMap + 0x8
          offsets.GDScriptConstantMap = offsets.GDScriptConstantMap + 0x8
          offsets.GDScriptVariantNameHM = offsets.GDScriptVariantNameHM + 0x8
          offsets.oVariantVector = offsets.oVariantVector + 0x30
        elseif GDDEFS.CUSTOMVER then
          error("Not defined yet")
          offsets.VPChildren = offsets.VPChildren + 0x48
          offsets.VPObjStringName = offsets.VPObjStringName + 0x48
          offsets.NodeGDScriptName = offsets.NodeGDScriptName + 0x48
          offsets.GDScriptFunctionMap = offsets.GDScriptFunctionMap + 0x48
          offsets.GDScriptConstantMap = offsets.GDScriptConstantMap + 0x48
          offsets.GDScriptVariantNameHM = offsets.GDScriptVariantNameHM + 0x48
        end

          return offsets

      elseif majminVersionStr == "3.6" then
        GDDEFS.GET_TYPE_INDX = 6
        -- godot.windows.opt.64.exe
        --  Godot Engine v3.6.stable.custom_build.de2f0f147
        offsets.VPChildren = 0x108
        offsets.VPObjStringName = 0x130
        offsets.NodeGDScriptInstance = 0x58
        offsets.NodeGDScriptName = 0x108
        offsets.GDScriptFunctionMap = 0x1A8
        offsets.GDScriptConstantMap = 0x190
        offsets.GDScriptVariantNameHM = 0x1C0
        offsets.oVariantVector = 0x20
        offsets.GDScriptVariantNameType = nil -- 4.x
        offsets.NodeVariantVectorSizeOffset = 0x4
        offsets.GDScriptVariantNamesIndex = 0x38 -- 3.x
        offsets.GDScriptFunctionCode = 0x50
        offsets.GDScriptFunctionCodeConsts = 0x20
        offsets.GDScriptFunctionCodeGlobals = 0x30
        offsets.GDScriptFunctionCodeArg = 0xA0
        offsets.GDScriptRealoadIndex = 42
        
        if GDDEFS.DEBUGVER then
          -- godot.windows.opt.debug.64.exe
          -- GDDEFS.STRING = 0x8
          offsets.VPChildren = offsets.VPChildren + 0x8
          offsets.VPObjStringName = offsets.VPObjStringName + 0x8
          offsets.NodeGDScriptInstance = offsets.NodeGDScriptInstance + 0x8
          offsets.NodeGDScriptName = offsets.NodeGDScriptName + 0x8
          offsets.GDScriptFunctionMap = offsets.GDScriptFunctionMap + 0x8
          offsets.GDScriptConstantMap = offsets.GDScriptConstantMap + 0x8
          offsets.GDScriptVariantNameHM = offsets.GDScriptVariantNameHM + 0x8
          offsets.oVariantVector = offsets.oVariantVector + 0x18
        end
        if GDDEFS.CUSTOMVER then
          -- error("Not defined yet")
          GDDEFS.STRING = 0x10
          offsets.VPChildren = offsets.VPChildren --[[+0x48]]
          offsets.VPObjStringName = offsets.VPObjStringName --[[+0x48]]
          offsets.NodeGDScriptName = offsets.NodeGDScriptName --[[+0x48]]
          offsets.GDScriptFunctionMap = offsets.GDScriptFunctionMap --[[+0x48]]
          offsets.GDScriptConstantMap = offsets.GDScriptConstantMap --[[+0x48]]
          offsets.GDScriptVariantNameHM = offsets.GDScriptVariantNameHM --[[+0x48]]
        end

        return offsets

      elseif majminVersionStr == "3.5" then
        GDDEFS.GET_TYPE_INDX = 6
        if GDDEFS._x64bit then
          -- godot.windows.opt.64.exe
          -- Godot Engine v3.5.1.stable.official
          offsets.VPChildren = 0x108
          offsets.VPObjStringName = 0x130
          offsets.NodeGDScriptInstance = 0x58
          offsets.NodeGDScriptName = 0x108
          offsets.GDScriptFunctionMap = 0x1A8
          offsets.GDScriptConstantMap = 0x190
          offsets.GDScriptVariantNameHM = 0x1C0
          offsets.oVariantVector = 0x20
          offsets.GDScriptVariantNameType = nil -- 4.x
          offsets.NodeVariantVectorSizeOffset = 0x4
          offsets.GDScriptVariantNamesIndex = 0x38 -- 3.x
          offsets.GDScriptFunctionCode = 0x50
          offsets.GDScriptFunctionCodeConsts = 0x20
          offsets.GDScriptFunctionCodeGlobals = 0x30
          offsets.GDScriptFunctionCodeArg = 0xA0
          offsets.GDScriptRealoadIndex = 42
        
          if GDDEFS.DEBUGVER then
            -- godot.windows.opt.debug.64.exe
            -- Godot Engine 3.5.2.stable
            -- GDDEFS.STRING = 0x8
            offsets.VPChildren = offsets.VPChildren + 0x8
            offsets.VPObjStringName = offsets.VPObjStringName + 0x8
            offsets.NodeGDScriptInstance = offsets.NodeGDScriptInstance + 0x8
            offsets.NodeGDScriptName = offsets.NodeGDScriptName + 0x8
            offsets.GDScriptFunctionMap = offsets.GDScriptFunctionMap + 0x8
            offsets.GDScriptConstantMap = offsets.GDScriptConstantMap + 0x8
            offsets.GDScriptVariantNameHM = offsets.GDScriptVariantNameHM + 0x8
            offsets.oVariantVector = offsets.oVariantVector + 0x18
            -- offsets.GDScriptRealoadIndex = offsets.GDScriptRealoadIndex
          end
          if GDDEFS.CUSTOMVER then
            -- godot.windows.opt.64.exe
            -- Godot Engine v3.5.1.stable.custom_build.6fed1ffa3
            -- offsets.VPChildren = offsets.VPChildren
            -- offsets.VPObjStringName = offsets.VPObjStringName
            -- offsets.NodeGDScriptName = offsets.NodeGDScriptName
            -- offsets.GDScriptFunctionMap = offsets.GDScriptFunctionMap
            -- offsets.GDScriptConstantMap = offsets.GDScriptConstantMap
            -- offsets.GDScriptVariantNameHM = offsets.GDScriptVariantNameHM
            --  offsets.oVariantVector = offsets.oVariantVector
            offsets.GDScriptRealoadIndex = offsets.GDScriptRealoadIndex - 1
          end
        else
          -- GDDEFS.STRING = 0x8 -- ascii
          GDDEFS.GDSCRIPT_REF = 0x8
          GDDEFS.MAP_SIZE = 0x10
          GDDEFS.MAP_LELEM = 0x8
          GDDEFS.MAP_NEXTELEM = 0x10
          GDDEFS.MAP_KVALUE = 0x18
          GDDEFS.FUNC_MAPVAL = 0x1C
          GDDEFS.DICT_LIST = 0x4
          GDDEFS.DICT_HEAD = 0x0
          GDDEFS.DICT_TAIL = 0x4
          GDDEFS.DICT_SIZE = 0x10
          GDDEFS.DICTELEM_PAIR_NEXT = 0x20
          GDDEFS.DICTELEM_KEYTYPE = 0x0
          GDDEFS.DICTELEM_KEYVAL = 0x8
          GDDEFS.DICTELEM_VALTYPE = 0x8
          GDDEFS.DICTELEM_VALVAL = 0x10
          GDDEFS.ARRAY_TOVECTOR = 0x8
          GDDEFS.P_ARRAY_TOARR = GDDEFS.P_ARRAY_TOARR or 0x4
          GDDEFS.P_ARRAY_SIZE = GDDEFS.P_ARRAY_SIZE or 0xC
          GDDEFS.CONSTELEM_KEYVAL = 0x18
          GDDEFS.CONSTELEM_VALTYPE = 0x20

          -- godot.windows.opt.32.exe
          -- Godot Engine v3.5.3.stable.official
          offsets.VPChildren = 0x90
          offsets.VPObjStringName = 0xB0
          offsets.NodeGDScriptInstance = 0x38
          offsets.NodeGDScriptName = 0x94
          offsets.GDScriptFunctionMap = 0xE8
          offsets.GDScriptConstantMap = 0xDC
          offsets.GDScriptVariantNameHM = 0xF4
          offsets.oVariantVector = 0x10
          offsets.GDScriptVariantNameType = 0x34 -- 4.x
          offsets.NodeVariantVectorSizeOffset = 0x4
          offsets.GDScriptVariantNamesIndex = 0x1C -- 3.x
          offsets.GDScriptFunctionCode = 0x38
          offsets.GDScriptFunctionCodeConsts = 0x20
          offsets.GDScriptFunctionCodeGlobals = 0x28

          if GDDEFS.DEBUGVER then
            error("Not defined yet")
            offsets.VPChildren = offsets.VPChildren + 0x4
            offsets.VPObjStringName = offsets.VPObjStringName + 0x4
            offsets.NodeGDScriptInstance = offsets.NodeGDScriptInstance + 0x4
            offsets.NodeGDScriptName = offsets.NodeGDScriptName + 0x4
            offsets.GDScriptFunctionMap = offsets.GDScriptFunctionMap + 0x4
            offsets.GDScriptConstantMap = offsets.GDScriptConstantMap + 0x4
            offsets.GDScriptVariantNameHM = offsets.GDScriptVariantNameHM + 0x4
            offsets.oVariantVector = offsets.oVariantVector + 0x0C
          elseif GDDEFS.CUSTOMVER then
            error("Not defined yet")
            -- offsets.VPChildren = offsets.VPChildren+0x48
            -- offsets.VPObjStringName = offsets.VPObjStringName+0x48
            -- offsets.NodeGDScriptName = offsets.NodeGDScriptName+0x48
            -- offsets.GDScriptFunctionMap = offsets.GDScriptFunctionMap+0x48
            -- offsets.GDScriptConstantMap = offsets.GDScriptConstantMap+0x48
            -- offsets.GDScriptVariantNameHM = offsets.GDScriptVariantNameHM+0x48
            --  offsets.oVariantVector = offsets.oVariantVector+0x18
          end
        end

        return offsets

      elseif majminVersionStr == "3.4" then
        GDDEFS.GET_TYPE_INDX = 6
        -- godot.windows.opt.64.exe
        -- Godot Engine v3.4.4.stable.official.419e713a2
        offsets.VPChildren = 0x108
        offsets.VPObjStringName = 0x120
        offsets.NodeGDScriptInstance = 0x58
        offsets.NodeGDScriptName = 0x108
        offsets.GDScriptFunctionMap = 0x1A8
        offsets.GDScriptConstantMap = 0x190
        offsets.GDScriptVariantNameHM = 0x1C0
        offsets.oVariantVector = 0x20
        offsets.GDScriptVariantNameType = nil -- 4.x
        offsets.NodeVariantVectorSizeOffset = 0x4
        offsets.GDScriptVariantNamesIndex = 0x38 -- 3.x
        offsets.GDScriptFunctionCode = 0x50
        offsets.GDScriptFunctionCodeConsts = 0x20
        offsets.GDScriptFunctionCodeGlobals = 0x30
        -- timer 1E0 (float) waittime 1E8 time_left 1F0 paused?
        offsets.GDScriptFunctionCodeArg = 0xA0
        offsets.GDScriptRealoadIndex = 42
        
        if GDDEFS.DEBUGVER then
          -- error("Not defined yet")
          -- GDDEFS.STRING = 0x8
          offsets.VPChildren = offsets.VPChildren + 0x8
          offsets.VPObjStringName = offsets.VPObjStringName + 0x8
          offsets.NodeGDScriptInstance = offsets.NodeGDScriptInstance + 0x8
          offsets.NodeGDScriptName = offsets.NodeGDScriptName + 0x8
          offsets.GDScriptFunctionMap = offsets.GDScriptFunctionMap + 0x8
          offsets.GDScriptConstantMap = offsets.GDScriptConstantMap + 0x8
          offsets.GDScriptVariantNameHM = offsets.GDScriptVariantNameHM + 0x8
          offsets.oVariantVector = offsets.oVariantVector + 0x18
        elseif GDDEFS.CUSTOMVER then
          error("Not defined yet")
          -- GDDEFS.STRING = 0x8
          offsets.VPChildren = offsets.VPChildren + 0x48
          offsets.VPObjStringName = offsets.VPObjStringName + 0x48
          offsets.NodeGDScriptName = offsets.NodeGDScriptName + 0x48
          offsets.GDScriptFunctionMap = offsets.GDScriptFunctionMap + 0x48
          offsets.GDScriptConstantMap = offsets.GDScriptConstantMap + 0x48
          offsets.GDScriptVariantNameHM = offsets.GDScriptVariantNameHM + 0x48
          offsets.oVariantVector = offsets.oVariantVector + 0x18
        end

        return offsets

      elseif majminVersionStr == "3.3" then
        GDDEFS.GET_TYPE_INDX = 6
        -- godot.windows.opt.64.exe
        -- Godot Engine v3.3.2.stable.official
        offsets.VPChildren = 0x100
        offsets.VPObjStringName = 0x118
        offsets.NodeGDScriptInstance = 0x50
        offsets.NodeGDScriptName = 0x100
        offsets.GDScriptFunctionMap = 0x1A0
        offsets.GDScriptConstantMap = 0x188
        offsets.GDScriptVariantNameHM = 0x1B8
        offsets.oVariantVector = 0x20
        offsets.GDScriptVariantNameType = nil -- 4.x
        offsets.NodeVariantVectorSizeOffset = 0x4
        offsets.GDScriptVariantNamesIndex = 0x38 -- 3.x
        offsets.GDScriptFunctionCode = 0x50
        offsets.GDScriptFunctionCodeConsts = 0x20
        offsets.GDScriptFunctionCodeGlobals = 0x30
        offsets.GDScriptFunctionCodeArg = 0xA0
        offsets.GDScriptRealoadIndex = 41
        
        if GDDEFS.DEBUGVER then
          -- error("Not defined yet")
          -- GDDEFS.STRING = 0x8
          offsets.VPChildren = offsets.VPChildren + 0x8
          offsets.VPObjStringName = offsets.VPObjStringName + 0x8
          offsets.NodeGDScriptInstance = offsets.NodeGDScriptInstance + 0x8
          offsets.NodeGDScriptName = offsets.NodeGDScriptName + 0x8
          offsets.GDScriptFunctionMap = offsets.GDScriptFunctionMap + 0x8
          offsets.GDScriptConstantMap = offsets.GDScriptConstantMap + 0x8
          offsets.GDScriptVariantNameHM = offsets.GDScriptVariantNameHM + 0x8
          offsets.oVariantVector = offsets.oVariantVector + 0x18
        elseif GDDEFS.CUSTOMVER then
          error("Not defined yet")
          -- GDDEFS.STRING = 0x8
          offsets.VPChildren = offsets.VPChildren + 0x48
          offsets.VPObjStringName = offsets.VPObjStringName + 0x48
          offsets.NodeGDScriptName = offsets.NodeGDScriptName + 0x48
          offsets.GDScriptFunctionMap = offsets.GDScriptFunctionMap + 0x48
          offsets.GDScriptConstantMap = offsets.GDScriptConstantMap + 0x48
          offsets.GDScriptVariantNameHM = offsets.GDScriptVariantNameHM + 0x48
          offsets.oVariantVector = offsets.oVariantVector + 0x18
        end

        return offsets

      elseif majminVersionStr == "3.2" then
        GDDEFS.GET_TYPE_INDX = 6
        -- error("Not defined yet")
        offsets.VPChildren = 0x108
        offsets.VPObjStringName = 0x120
        offsets.NodeGDScriptInstance = 0x50
        offsets.NodeGDScriptName = 0x100
        offsets.GDScriptFunctionMap = 0x1B0
        offsets.GDScriptConstantMap = 0x198
        offsets.GDScriptVariantNameHM = 0x1C8
        offsets.oVariantVector = 0x20
        offsets.GDScriptVariantNameType = nil -- 4.x
        offsets.NodeVariantVectorSizeOffset = 0x4
        offsets.GDScriptVariantNamesIndex = 0x38 -- 3.x
        offsets.GDScriptFunctionCode = 0x50
        offsets.GDScriptFunctionCodeConsts = 0x20
        offsets.GDScriptFunctionCodeGlobals = 0x30
        offsets.GDScriptFunctionCodeArg = 0xA0
        
        if GDDEFS.DEBUGVER then
          error("Not defined yet")
          -- GDDEFS.STRING = 0x8
          offsets.VPChildren = offsets.VPChildren + 0x8
          offsets.VPObjStringName = offsets.VPObjStringName + 0x8
          offsets.NodeGDScriptInstance = offsets.NodeGDScriptInstance + 0x8
          offsets.NodeGDScriptName = offsets.NodeGDScriptName + 0x8
          offsets.GDScriptFunctionMap = offsets.GDScriptFunctionMap + 0x8
          offsets.GDScriptConstantMap = offsets.GDScriptConstantMap + 0x8
          offsets.GDScriptVariantNameHM = offsets.GDScriptVariantNameHM + 0x8
          offsets.oVariantVector = offsets.oVariantVector + 0x18
        end
        if GDDEFS.CUSTOMVER then
          -- godot.windows.opt.64.exe
          -- Godot Engine v3.2.stable.custom_build
          offsets.VPChildren = offsets.VPChildren + 0x8
          offsets.VPObjStringName = offsets.VPObjStringName + 0x8
          -- offsets.NodeGDScriptName = offsets.NodeGDScriptName + 0x8
          offsets.GDScriptFunctionMap = offsets.GDScriptFunctionMap + 0x8
          offsets.GDScriptConstantMap = offsets.GDScriptConstantMap + 0x8
          offsets.GDScriptVariantNameHM = offsets.GDScriptVariantNameHM + 0x8
        end

        return offsets

      elseif majminVersionStr == "3.1" then
        print("No recorded version found")
        error("Not defined yet")
      elseif majminVersionStr == "3.0" then
        -- 3.0.6.stable.official
        GDDEFS.GET_TYPE_INDX = 6
        offsets.VPChildren = 0x100
        offsets.VPObjStringName = 0x118
        offsets.NodeGDScriptInstance = 0x50
        offsets.NodeGDScriptName = 0xF8
        offsets.GDScriptFunctionMap = 0x1B0
        offsets.GDScriptConstantMap = 0x198
        offsets.GDScriptVariantNameHM = 0x1C8
        offsets.oVariantVector = 0x18
        offsets.GDScriptVariantNameType = nil -- 4.x
        offsets.NodeVariantVectorSizeOffset = 0x4
        offsets.GDScriptVariantNamesIndex = 0x38 -- 3.x
        offsets.GDScriptFunctionCode = 0x50
        offsets.GDScriptFunctionCodeConsts = 0x20
        offsets.GDScriptFunctionCodeGlobals = 0x30

        if GDDEFS.DEBUGVER then
          error("Not defined yet")
          offsets.VPChildren = offsets.VPChildren + 0x8
          offsets.VPObjStringName = offsets.VPObjStringName + 0x8
          offsets.NodeGDScriptInstance = offsets.NodeGDScriptInstance + 0x8
          offsets.NodeGDScriptName = offsets.NodeGDScriptName + 0x8
          offsets.GDScriptFunctionMap = offsets.GDScriptFunctionMap + 0x8
          offsets.GDScriptConstantMap = offsets.GDScriptConstantMap + 0x8
          offsets.GDScriptVariantNameHM = offsets.GDScriptVariantNameHM + 0x8
          offsets.oVariantVector = offsets.oVariantVector + 0x18
        end
        if GDDEFS.CUSTOMVER then
          error("Not defined yet")
          offsets.VPChildren = offsets.VPChildren + 0x8
          offsets.VPObjStringName = offsets.VPObjStringName + 0x8
          offsets.NodeGDScriptName = offsets.NodeGDScriptName + 0x8
          offsets.GDScriptFunctionMap = offsets.GDScriptFunctionMap + 0x8
          offsets.GDScriptConstantMap = offsets.GDScriptConstantMap + 0x8
          offsets.GDScriptVariantNameHM = offsets.GDScriptVariantNameHM + 0x8
        end

        return offsets
      elseif majminVersionStr == "2.1" then
        -- Godot Engine v2.1.7.rc.custom_build
        -- godot.windows.opt.64.exe
        error("Not defined yet")

        GDDEFS.GET_TYPE_INDX = 7
        offsets.VPChildren = 0x100
        offsets.VPObjStringName = 0x118
        offsets.NodeGDScriptInstance = 0x50
        offsets.NodeGDScriptName = 0xF8
        offsets.GDScriptFunctionMap = 0x1B0
        offsets.GDScriptConstantMap = 0x198
        offsets.GDScriptVariantNameHM = 0x1C8
        offsets.oVariantVector = 0x18
        offsets.GDScriptVariantNameType = nil -- 4.x
        offsets.NodeVariantVectorSizeOffset = 0x4
        offsets.GDScriptVariantNamesIndex = 0x38 -- 3.x
        offsets.GDScriptFunctionCode = 0x50
        offsets.GDScriptFunctionCodeConsts = 0x20
        offsets.GDScriptFunctionCodeGlobals = 0x30

        if GDDEFS.DEBUGVER then
          error("Not defined yet")
          offsets.VPChildren = offsets.VPChildren + 0x8
          offsets.VPObjStringName = offsets.VPObjStringName + 0x8
          offsets.NodeGDScriptInstance = offsets.NodeGDScriptInstance + 0x8
          offsets.NodeGDScriptName = offsets.NodeGDScriptName + 0x8
          offsets.GDScriptFunctionMap = offsets.GDScriptFunctionMap + 0x8
          offsets.GDScriptConstantMap = offsets.GDScriptConstantMap + 0x8
          offsets.GDScriptVariantNameHM = offsets.GDScriptVariantNameHM + 0x8
          offsets.oVariantVector = offsets.oVariantVector + 0x18
        end
        if GDDEFS.CUSTOMVER then
          error("Not defined yet")
          offsets.VPChildren = offsets.VPChildren + 0x8
          offsets.VPObjStringName = offsets.VPObjStringName + 0x8
          offsets.NodeGDScriptName = offsets.NodeGDScriptName + 0x8
          offsets.GDScriptFunctionMap = offsets.GDScriptFunctionMap + 0x8
          offsets.GDScriptConstantMap = offsets.GDScriptConstantMap + 0x8
          offsets.GDScriptVariantNameHM = offsets.GDScriptVariantNameHM + 0x8
        end

        return offsets

      else
        print("No recorded version found, report here: https://github.com/palepine/GDDumper/issues")
        error("No recorded version found, report here: https://github.com/palepine/GDDumper/issues")
        return offsets
      end
        --[[
          Godot Engine v2.1.4.beta.custom_build
          godot.windows.opt.32.exe
        ]]

    end

  -- ///---///--///---///--///---///--///--///---///--///---///--///---///--/// DEFINE

    --- inits the GDDEFS object
    local function initGDDefs()
      GDDEFS = {} -- for now let it be reinitialized here

      GDDEFS.SCRIPT_TYPES =
        {
          ["UNDEFINED"] = 0,
          ["GD"] = 1,
          ["CS"] = 2
        }

      GDDEFS.STRING = 0x10
      
      gd_dumpedMonitorNodes = {};
      debugPrefix = 1;
      if targetIs64Bit() then
        GDDEFS.PTRSIZE = 0x8
        GDDEFS._x64bit = true
      else
        GDDEFS.PTRSIZE = 0x4
        GDDEFS._x64bit = false
      end -- for auto offsetdef and ptr arithmetics

      local scriptErrors = { [22] = "in use error", [43] = "parse error", [2] = "handler script error", [36] = "compilation error", [1] = "handler warning", }
      GDDEFS.SCRIPT_ERRORS = scriptErrors
    end

    local function initGDVersion(config)
      if config == nil then config = {} end

      if isNotNullOrNil(config.majorVersion) and isNotNullOrNil(config.minorVersion) and
          isNotNullOrNil(config.GDCustomver) and isNotNullOrNil(config.GDDebugVer) then
        GDDEFS.VERSION_STRING = tostring(config.majorVersion) .. '.' .. tostring(config.minorVersion)
        GDDEFS.MAJOR_VER = config.majorVersion
        GDDEFS.MINOR_VER = config.minorVersion
        GDDEFS.DEBUGVER = config.GDDebugVer
        GDDEFS.CUSTOMVER = config.GDCustomver
        GDDEFS.MONO = config.isMonoTarget and config.isMonoTarget or false
      else
        defineGDVersion()
        if isNotNullOrNil(config.GDCustomver) then GDDEFS.CUSTOMVER = config.GDCustomver end
      end
    end

    --- initializes and assigns offsets
    local function defineGDOffsets(config)
      if config == nil then config = {} end

      -- AUTOMATIC START
      if bHardOffsets or config.useHardcoded then
        local offsets = getStoredOffsetsFromVersion(GDDEFS.VERSION_STRING)
        GDDEFS.CHILDREN = offsets.VPChildren
        GDDEFS.OBJ_STRING_NAME = offsets.VPObjStringName
        GDDEFS.GDSCRIPTINSTANCE = offsets.NodeGDScriptInstance
        GDDEFS.GDSCRIPTNAME = offsets.NodeGDScriptName
        GDDEFS.FUNC_MAP = offsets.GDScriptFunctionMap
        GDDEFS.CONST_MAP = offsets.GDScriptConstantMap
        GDDEFS.VAR_NAMEINDEX_MAP = offsets.GDScriptVariantNameHM
        GDDEFS.GDSCRIPT_RELOAD_INDX = offsets.GDScriptRealoadIndex
        GDDEFS.VAR_VECTOR = offsets.oVariantVector
        GDDEFS.VAR_NAMEINDEX_VARTYPE = offsets.GDScriptVariantNameType
        GDDEFS.SIZE_VECTOR = offsets.NodeVariantVectorSizeOffset
        GDDEFS.VAR_NAMEINDEX_I = offsets.GDScriptVariantNamesIndex
        GDDEFS.FUNC_CODE = offsets.GDScriptFunctionCode
        GDDEFS.FUNC_CONST = offsets.GDScriptFunctionCodeConsts
        GDDEFS.FUNC_GLOBNAMEPTR = offsets.GDScriptFunctionCodeGlobals
      -- AUTOMATIC END
      else
      -- MANUAL START
        GDDEFS.CHILDREN = config.offsetNodeChildren or 0x0
        GDDEFS.OBJ_STRING_NAME = config.offsetNodeStringName or 0x0
        GDDEFS.GDSCRIPTINSTANCE = config.offsetGDScriptInstance or 0x0
        GDDEFS.GDSCRIPTNAME = config.offsetGDScriptName or 0x0
        GDDEFS.FUNC_MAP = config.offsetFuncMap or 0x0
        GDDEFS.CONST_MAP = config.offsetConstMap or 0x0
        GDDEFS.VAR_NAMEINDEX_MAP = config.offsetVariantMap or 0x0
        GDDEFS.GDSCRIPT_RELOAD_INDX = config.GDScriptRealoadIndex
        GDDEFS.FUNC_CODE = config.offsetGDFunctionCode or 0x0

        if GDDEFS.MAJOR_VER == 4 then
          GDDEFS.VAR_VECTOR = config.offsetVariantVector or 0x28
          GDDEFS.VAR_NAMEINDEX_VARTYPE = config.offsetVariantMapVarType or 0x48
          GDDEFS.SIZE_VECTOR = config.offsetVariantVectorSize or 0x8
          GDDEFS.FUNC_CONST = config.offsetGDFunctionConst or (GDDEFS.FUNC_CODE + 0x20)
          GDDEFS.FUNC_GLOBNAMEPTR = config.offsetGDFunctionGlobals or (GDDEFS.FUNC_CONST + 0x10) -- there's a Vector of globalnames 0x10 after FUNC_CONST, i.e. 0x1A8, alternatively _globalnames_ptr at 0x2E0 which is the actual referenced array by the VM?
          -- for Object vtable 4.0-4.4 [8] | 4.5 [9] | 4.6 [10]
            if GDDEFS.MINOR_VER <= 4 then -- if config.vtGetClassNameIndex then GDDEFS.GET_TYPE_INDX = config.vtGetClassNameIndex end
              GDDEFS.GET_TYPE_INDX = 8
            elseif GDDEFS.MINOR_VER == 5 then
              GDDEFS.GET_TYPE_INDX = 9
            elseif GDDEFS.MINOR_VER >= 6 then
              GDDEFS.GET_TYPE_INDX = 10
            end
        elseif GDDEFS.MAJOR_VER == 3 then
          GDDEFS.MAJOR_VER = 3
          GDDEFS.VAR_VECTOR = config.offsetVariantVector or 0x20
          GDDEFS.SIZE_VECTOR = config.offsetVariantVectorSize or 0x4
          GDDEFS.VAR_NAMEINDEX_I = config.offsetVariantMapIndex or 0x38
          GDDEFS.FUNC_GLOBNAMEPTR = config.offsetGDFunctionGlobals or (GDDEFS.FUNC_CODE - 0x20)
          GDDEFS.FUNC_CONST = config.offsetGDFunctionConst or (GDDEFS.FUNC_GLOBNAMEPTR - 0x10)
          -- for Object vtable 3.0-3.6 [6]
          GDDEFS.GET_TYPE_INDX = 6
        else
          error("Unexpected version")
        end
      end
      -- MANUAL END

      -- COMMON START
      if GDDEFS.MAJOR_VER == 4 then
        GDDEFS.GDSCRIPT_REF = 0x18
        GDDEFS.MAXTYPE = 39
        GDDEFS.FUNC_MAPVAL = 0x18
        GDDEFS.CHILDREN_SIZE = 0x8
        GDDEFS.MAP_SIZE = 0x14
        GDDEFS.ARRAY_TOVECTOR = 0x10
        GDDEFS.P_ARRAY_TOARR = 0x18
        GDDEFS.P_ARRAY_SIZE = 0x8
        GDDEFS.DICT_HEAD = GDDEFS.DICT_HEAD or 0x28
        GDDEFS.DICT_TAIL = GDDEFS.DICT_TAIL or 0x30
        GDDEFS.DICT_SIZE = GDDEFS.DICT_SIZE or 0x34 -- 0x3C
        GDDEFS.DICTELEM_KEYTYPE = 0x10
        GDDEFS.DICTELEM_KEYVAL = 0x18
        GDDEFS.DICTELEM_VALTYPE = 0x28
        GDDEFS.CONSTELEM_KEYVAL = 0x10
        GDDEFS.CONSTELEM_VALTYPE = 0x18
        GDDEFS.VAR_NAMEINDEX_I = 0x18
        GDDEFS.CLR_PTR = 0x20
        -- GDDEFS.SCRIPTFUNC_STRING = GDFunctionString or 0x60
      elseif GDDEFS.MAJOR_VER == 3 then
        GDDEFS.MAXTYPE = 27
        GDDEFS.GDSCRIPT_REF = GDDEFS.GDSCRIPT_REF or 0x10
        GDDEFS.FUNC_MAPVAL = GDDEFS.FUNC_MAPVAL or 0x38
        GDDEFS.CHILDREN_SIZE = 0x4
        GDDEFS.MAP_SIZE = GDDEFS.MAP_SIZE or 0x10
        GDDEFS.MAP_LELEM = GDDEFS.MAP_LELEM or 0x10
        GDDEFS.MAP_NEXTELEM = GDDEFS.MAP_NEXTELEM or 0x20
        GDDEFS.MAP_KVALUE = GDDEFS.MAP_KVALUE or 0x30
        GDDEFS.DICT_LIST = GDDEFS.DICT_LIST or 0x8
        GDDEFS.DICT_HEAD = GDDEFS.DICT_HEAD or 0x0
        GDDEFS.DICT_TAIL = GDDEFS.DICT_TAIL or 0x8
        GDDEFS.DICT_SIZE = GDDEFS.DICT_SIZE or 0x1C -- GDDEFS.DICT_SIZE = GDDEFS.DICT_SIZE or 0x10
        GDDEFS.DICTELEM_PAIR_NEXT = GDDEFS.DICTELEM_PAIR_NEXT or 0x20
        GDDEFS.DICTELEM_KEYTYPE = GDDEFS.DICTELEM_KEYTYPE or 0x0
        GDDEFS.DICTELEM_KEYVAL = GDDEFS.DICTELEM_KEYVAL or 0x8
        GDDEFS.DICTELEM_VALTYPE = GDDEFS.DICTELEM_VALTYPE or 0x8
        GDDEFS.DICTELEM_VALVAL = GDDEFS.DICTELEM_VALVAL or 0x10
        GDDEFS.ARRAY_TOVECTOR = GDDEFS.ARRAY_TOVECTOR or 0x10
        GDDEFS.P_ARRAY_TOARR = GDDEFS.P_ARRAY_TOARR or 0x8
        GDDEFS.P_ARRAY_SIZE = GDDEFS.P_ARRAY_SIZE or 0x18
        GDDEFS.CONSTELEM_KEYVAL = GDDEFS.CONSTELEM_KEYVAL or 0x30
        GDDEFS.CONSTELEM_VALTYPE = GDDEFS.CONSTELEM_VALTYPE or 0x38
        -- GDDEFS.SCRIPTFUNC_STRING = oGDFunctionString or 0x80
      else
        error("Unexpected version")
      end
      -- COMMON END

      -- GDDEFS.GDSCRIPT_INSTANTIATE_INDX = 40
      -- GDDEFS.GDSCRIPT_SETSRC_INDX = 45
    end

    local function registerGDSymbols()
      registerSymbol('CHILDREN', GDDEFS.CHILDREN, true)
      registerSymbol('OBJ_STRING_NAME', GDDEFS.OBJ_STRING_NAME, true)
      registerSymbol('GDSCRIPTINSTANCE', GDDEFS.GDSCRIPTINSTANCE, true)
      registerSymbol('GDSCRIPTNAME', GDDEFS.GDSCRIPTNAME, true)
      registerSymbol('FUNC_MAP', GDDEFS.FUNC_MAP, true)
      registerSymbol('CONST_MAP', GDDEFS.CONST_MAP, true)
      registerSymbol('VAR_VECTOR', GDDEFS.VAR_VECTOR, true)
      registerSymbol('FUNC_CODE', GDDEFS.FUNC_CODE, true)
      registerSymbol('FUNC_CONST', GDDEFS.FUNC_CONST, true)
      registerSymbol('FUNC_GLOBNAMEPTR', GDDEFS.FUNC_GLOBNAMEPTR, true)
      registerSymbol('GDSCRIPT_REF', GDDEFS.GDSCRIPT_REF, true)
      registerSymbol('FUNC_MAPVAL', GDDEFS.FUNC_MAPVAL, true)
      registerSymbol('ARRAY_TOVECTOR', GDDEFS.ARRAY_TOVECTOR, true)
      registerSymbol('P_ARRAY_TOARR', GDDEFS.P_ARRAY_TOARR, true)
      registerSymbol('DICT_HEAD', GDDEFS.DICT_HEAD, true)
      registerSymbol('DICT_LIST', GDDEFS.DICT_LIST, true)
      registerSymbol('MAP_LELEM', GDDEFS.MAP_LELEM, true)
      registerSymbol('MAP_NEXTELEM', GDDEFS.MAP_NEXTELEM, true)
      registerSymbol('DICTELEM_PAIR_NEXT', GDDEFS.DICTELEM_PAIR_NEXT, true)
      registerSymbol('DICTELEM_VALVAL', GDDEFS.DICTELEM_VALVAL, true)
    end

  -- ///---///--///---///--///---///--///--///---///--///---///--///---///--/// STRING

    --- reads GD strings (1-4 bytes)
    ---@param strAddress number
    ---@param strSize number
    function readUTFString(strAddress, strSize)
      assert(type(strAddress) == 'number', "string address should be a number, instead got: " .. type(strAddress));

      local MAX_CHARS_TO_READ = 1500 * 2

      if strSize and (strSize > MAX_CHARS_TO_READ) then
        return "??" -- "ain\'t reading this"  -- we aren't gonna read novels
      end

      if GDDEFS.MAJOR_VER == 4 then
        if readInteger(strAddress) == 0 then
          return "??" -- "empt str"
        end
      elseif readSmallInteger(strAddress) == 0 then
        return "??" -- "empt str"
      end

      local charTable = {}
      local buff = 0

      if GDDEFS.MAJOR_VER == 3 and (strSize and strSize > 0) then
        return readString(strAddress, strSize * 2, true) or "??" -- '???_INVALID_MEM_CAUGHT_WSIZE'

      elseif GDDEFS.MAJOR_VER == 3 then
        local retString = readString(strAddress, MAX_CHARS_TO_READ, true)

        while MAX_CHARS_TO_READ > 0 and retString == nil do -- https://github.com/cheat-engine/cheat-engine/issues/2602
          MAX_CHARS_TO_READ = MAX_CHARS_TO_READ - 100 -- quite a stride
          retString = readString(strAddress, MAX_CHARS_TO_READ, true)
        end
        return retString or "??" -- '???_INVALID_MEM_CAUGHT'
      end

      if (strSize and strSize > 0) then

        for i = 0, strSize - 1 do
          buff = readInteger(strAddress + i * 0x4) or 0x0
          if buff == 0 then
            break
          end
          charTable[#charTable + 1] = codePointToUTF8(buff)
        end

      else
        -- null terminator
        for i = 0, MAX_CHARS_TO_READ do
          buff = readInteger(strAddress + i * 0x4) or 0x0
          if buff == 0 then
            break
          end
          charTable[#charTable + 1] = codePointToUTF8(buff)
        end
      end

      return table.concat(charTable) or "??" -- '???_UNKNSTR'
    end

    function codePointToUTF8(codePoint)
      if (codePoint < 0 or codePoint > 0x10FFFF) or (codePoint >= 0xD800 and codePoint <= 0xDFFF) then
        return 'w-t-f'
      elseif codePoint <= 0x7F then
        return string.char(codePoint)
      elseif codePoint <= 0x7FF then
        return string.char(0xC0 | (codePoint >> 6), 0x80 | (codePoint & 0x3F))
      elseif codePoint <= 0xFFFF then
        return string.char(0xE0 | (codePoint >> 12), 0x80 | ((codePoint >> 6) & 0x3F), 0x80 | (codePoint & 0x3F))
      else
        return string.char(0xF0 | (codePoint >> 18), 0x80 | ((codePoint >> 12) & 0x3F), 0x80 | ((codePoint >> 6) & 0x3F), 0x80 | (codePoint & 0x3F))
      end
    end

    function UTF8Codepoints(str)
      local i, strSize = 1, #str

      -- closure
      return function()
        if i > strSize then
          return nil
        end
        local byte1 = str:byte(i)

        -- 1-byte (ASCII) | 0x00–0x7F
        if byte1 < 0x80 then
          i = i + 1
          return byte1
        end

        -- invalid lead < C2
        if byte1 < 0xC2 then
          i = i + 1
          return 0xFFFD
        end

          -- 2-byte | 0xC0–0xDF
        if byte1 < 0xE0 then
          if i + 1 > strSize then
            i = strSize + 1;
            return 0xFFFD
          end

          local byte2 = str:byte(i + 1)
          if (byte2 & 0xC0) ~= 0x80 then
            i = i + 1;
            return 0xFFFD
          end -- lead

          local codePoint = ((byte1 & 0x1F) << 6) | (byte2 & 0x3F) -- payload bits
          i = i + 2
          return codePoint

        -- 3-byte | 0xE0–0xEF
        elseif byte1 < 0xF0 then
          if i + 2 > strSize then
            i = strSize + 1;
            return 0xFFFD
          end

          local byte2, byte3 = str:byte(i + 1), str:byte(i + 2)
          if (byte2 & 0xC0) ~= 0x80 or (byte3 & 0xC0) ~= 0x80 then
            i = i + 1;
            return 0xFFFD
          end -- lead

          local codePoint = ((byte1 & 0x0F) << 12) | ((byte2 & 0x3F) << 6) | (byte3 & 0x3F) -- payload bits
          -- reject surrogates
          if codePoint >= 0xD800 and codePoint <= 0xDFFF then
            codePoint = 0xFFFD
          end
          i = i + 3
          return codePoint

        -- 4-byte | 0xF0–0xF7
        elseif byte1 < 0xF5 then
          if i + 3 > strSize then
            i = strSize + 1;
            return 0xFFFD
          end

          local byte2, byte3, byte4 = str:byte(i + 1), str:byte(i + 2), str:byte(i + 3)
          if (byte2 & 0xC0) ~= 0x80 or (byte3 & 0xC0) ~= 0x80 or (byte4 & 0xC0) ~= 0x80 then
            i = i + 1;
            return 0xFFFD
          end

          local codePoint = ((byte1 & 0x07) << 18) | ((byte2 & 0x3F) << 12) | ((byte3 & 0x3F) << 6) | (byte4 & 0x3F)
          if codePoint > 0x10FFFF then
            codePoint = 0xFFFD
          end
          i = i + 4
          return codePoint
          end

          -- anything else is invalid lead
          i = i + 1
        return 0xFFFD
      end
    end

    --- reads a string from StringName
    ---@param stringNameAddr number
    function getStringNameStr(stringNameAddr)
      if isNullOrNil(stringNameAddr) then
        return 'NaN_strname'
      end
      local retStringAddr = readPointer(stringNameAddr + GDDEFS.STRING)

      if isNullOrNil(retStringAddr) or isInvalidPointer(retStringAddr) then
        retStringAddr = readPointer(stringNameAddr + 0x8) -- for cases when StringName holds data at 0x8
        if isNullOrNil(retStringAddr) then
          return '??' -- return an empty string if no string was found
        end

        -- Try ASCII if it's static & in pck
        if isInsideRDataStatic(retStringAddr) then
          -- a static ASCII string's last resort
          return readString(retStringAddr, 100)
        end

        return readUTFString(retStringAddr) or '??'
      end
      return readUTFString(retStringAddr)
    end

  -- ///---///--///---///--///---///--///--///---///--///---///--///---///--/// ROOT

    local function tryRegSceneTree()
      local function resolveRelAddr(aobSignature, offsetToValue, offsetToNextIntr)
        local addr = AOBScanModuleUnique(process, aobSignature, '+X-W-C')
        if addr == 0 or addr == nil then
          return false
        end
        offsetToNextIntr = offsetToNextIntr or getInstructionSize(addr)
        offsetToValue = offsetToValue or (offsetToNextIntr - 4)
        local relativeAddr = readInteger(addr + offsetToValue)
        local nextAddr = getAddress(addr + offsetToNextIntr)
        local resolvedAddr
        if GDDEFS._x64bit then
          resolvedAddr = nextAddr + relativeAddr
        else
          resolvedAddr = relativeAddr -- absolute on 32
        end
        -- sendDebugMessage("[SceneTree] calling a virtual method if I happen to crash:\tstatic ptr: " .. numtohexstr(resolvedAddr))
        local className = getGDObjectName(readPointer(resolvedAddr))
        if className == "SceneTree" then
          sendDebugMessage("[SceneTree] via vtable - success: " .. numtohexstr(resolvedAddr) .. " sig: " .. aobSignature )
          registerSymbol('pSceneTree', resolvedAddr, false)
          return true
        else
          return false
        end
      end
      
      local sigs = {}

      table.insert(sigs, { sig = "48 39 1D ? ? ? ? 75 07 4C 89 35 ? ? ? ? 66 0F 6F 05 ? ? ? ? 4?", toRel = 3 } )
      table.insert(sigs, { sig = "48 83 3D ? ? ? ? 00 0F 84 ? ? ? ? 0F 28 05 ? ? ? ? 4?", toRel = 3 } )
      table.insert(sigs, { sig = "4C 39 ? ? ? ? ? 75 07 ? 89 35 ? ? ? ? 66 0F 6F 05", toRel = 3 } )    
      table.insert(sigs, { sig = "48 83 3D ? ? ? ? 00 48 C7 86 ? ? ? ? 00 00 00 00", toRel = 3 } )
      table.insert(sigs, { sig = "48 8B 15 ? ? ? ? 48 85 D2 74 ? 48 8B 37 4?", toRel = 3 } )
      table.insert(sigs, { sig = "48 83 3D ? ? ? ? 00 75 07 4C 89 35 ? ? ? ? 0F 28 05", toRel = 3 } )
      table.insert(sigs, { sig = "48 8B 15 ? ? ? ? 48 85 D2 74 ? 4C 8B 26", toRel = 3 } )
      table.insert(sigs, { sig = "48 C7 05 ? ? ? ? 00 00 00 00 E9 ? ? ? ? 85 C0", toRel = 3 } )
      table.insert(sigs, { sig = "48 8B 05 ? ? ? ? 48 85 C0 0F 11 85 ? ? ? ? 49 0F ? ? 48 89 05", toRel = 3 } ) -- 4.3
      table.insert(sigs, { sig = "48 8B 05 ? ? ? ? 48 8D 8F ? ? ? ? 48 3B C7 49 0F 44 C7 48 8B 05", toRel = 3 } )
      table.insert(sigs, { sig = "48 8B 05 ? ? ? ? 48 85 C0 74 0D 80 B8 ? ? ? ? 00 0F", toRel = 3 } )

      table.insert(sigs, { sig = "39 0D ? ? ? ? 75 06 89 35 ? ? ? ? 0F 28 05", toRel = 2 } ) -- 32 4.6
      table.insert(sigs, { sig = "48 8B 15 ? ? ? ? 48 85 D2 74 ? 4D 8B 24 24", toRel = 3 } )
      table.insert(sigs, { sig = "48 8B 0D ? ? ? ? E8 ? ? ? ? 90 48 8B 4C 24 ? 48 85 C9 74 ? F0 0F C1 59 ? 83 FB", toRel = 3 } )
      table.insert(sigs, { sig = "48 8B 15 ? ? ? ? 48 85 D2 74 3D", toRel = 3 } )
      table.insert(sigs, { sig = "48 8B 15 ? ? ? ? 48 85 D2 74 3D 4C 8B 2B", toRel = 3 } )
      table.insert(sigs, { sig = "48 8B 15 ? ? ? ? 48 85 D2 74 3D 48 8B 36", toRel = 3 } )
      table.insert(sigs, { sig = "4C 8B 0D ? ? ? ? 4C 89 B4 24", toRel = 3 } )
      table.insert(sigs, { sig = "48 8B 15 ? ? ? ? 48 85 D2 74 ? 4C 8B 2B", toRel = 3 } )
      table.insert(sigs, { sig = "48 83 3D ? ? ? ? 00  49 C7 85 ? ? ? ? 00 00 00 00 49 89 9D", toRel = 3 } )
      table.insert(sigs, { sig = "A1 ? ? ? ? 85 C0 74 ? 8B 35 ? ? ? ? 8B", toRel = 1 } ) -- 3.5 32
      table.insert(sigs, { sig = "C7 05 ? ? ? ? 00 00 00 00 85 C0 0F 84 ? ? ? ? B9", toRel = 2 } ) -- 3.5 32
      table.insert(sigs, { sig = "48 8B 0D ? ? ? ? 48 85 C9 74 ? 48 8D 55 ? E8", toRel = 3 } ) -- 3.2
      table.insert(sigs, { sig = "48 8B 0D ? ? ? ? 48 83 C4 ?   5?", toRel = 3 } ) -- 3.0

      for i, sig in ipairs(sigs) do
        if resolveRelAddr(sig.sig, sig.toRel) then
          return true
        end
      end
      sendDebugMessage("[SceneTree] lookup failed, you are on your own")
      return false
    end

    local function setSTtoVPoffset()

      local sceneTree = readPointer('pSceneTree')
      local ptrsize, steps

      if targetIs64Bit() then
        ptrsize = 0x8
        steps = 0x350 / ptrsize
      else
        ptrsize = 0x4
        steps = 0x250 / ptrsize
      end

      -- isn't elegant either
      for i = 23, steps do
        local candidateAddr = readPointer(sceneTree + i * ptrsize)
        if isNotNullOrNil(candidateAddr) and isVtable(readPointer(candidateAddr)) then

          -- sendDebugMessage("[VP/WIND] calling a virtual method if I happen to crash: ofs\t" .. numtohexstr(i * ptrsize) .. "\taddr: " .. numtohexstr(candidateAddr))
          local className = getGDObjectName(candidateAddr)
          if className == "Viewport" or className == "Window" then
            sendDebugMessage("[VP/WIND] via vtable - success!")
            registerSymbol('oSTtoVP', i * ptrsize, false)
            return true
          end
          -- for j=13, steps do
          --     if readPointer(candidateAddr + j*ptrsize) == sceneTree then
          --         registerSymbol('oSTtoVP', i*ptrsize, false)
          --         sendDebugMessage('nested loop: '..numtohexstr(i*ptrsize))
          --         return true
          --     end
          -- end
        end
      end

      -- the approach based on signatures needs more complexity to be consistent
      local function setVPRVA(aobSignature)
        local addr = AOBScanModuleUnique(process, aobSignature, '+X-W-C')
        if addr == 0 or addr == nil then
          return false
        end
        local relativeAddr = readInteger(addr + 3)
        sendDebugMessage("[VP/WIND] via sigs - success!")
        registerSymbol('oSTtoVP', relativeAddr, false)
        return true
      end
      local sigs = {}
      -- table.insert(sigs, "48 8B 9? ? ? ? ? 4? 31 C0 48 89 E9 E8")
      table.insert(sigs, "48 8B 9? ? ? ? ? 4? 8D 8F ? ? ? ? 45 33 C0 E8")
      table.insert(sigs, "48 8B 9? ? ? ? ? 4? 31 C0 48 89 E9 E8 ? ? ? ? 80 3D ? ? ? ? 00")
      table.insert(sigs, "48 8B B0 ? ? ? ? 80 BB")
      table.insert(sigs, "48 8B 88 ? ? ? ? E8 ? ? ? ? 84 C0 74 ? 48 8B 03")
      table.insert(sigs, "48 8B B9 ? ? ? ? 89 DA")
      table.insert(sigs, "48 8B B0 ? ? ? ? 48 8B 8E")
      table.insert(sigs, "48 8B BF ? ? ? ? 74") -- might be too short
      table.insert(sigs, "48 8B 80 ? ? ? ? 40 38 B8 ? ? ? ? 0F 85")
      table.insert(sigs, "48 8B B0 ? ? ? ? 48 39 BE")
      table.insert(sigs, "48 8B 80 ? ? ? ? 80 B8 ? ? ? ? ? 0F 85 ? ? ? ? 48 8B 03")
      table.insert(sigs, "48 8B 89 ? ? ? ? E9 ? ? ? ? 0F 1F 80 ? ? ? ? 81 FA")
      table.insert(sigs, "48 8B B0 ? ? ? ? 48 8B 8E ? ? ? ? 48 85 C9 74")
      table.insert(sigs, "48 8B 88 ? ? ? ? E8 ? ? ? ? 84 C0 0F 85 ? ? ? ? 48 8B 03")
      table.insert(sigs, "48 8B B0 ? ? ? ? 48 8B 8E ? ? ? ? 48 85 C9 0F 84")
      table.insert(sigs, "48 8B 8? ? ? ? ? E8 ? ? ? ? 48 8B 5C 24 ? 48 83 C4 ? 5F C3 90")
      table.insert(sigs, "48 8B 8B ? ? ? ? BA ? ? ? ? 48 83 C4 ? 5B 5E 5F E9 ? ? ? ? 0F 1F 80")
      table.insert(sigs, "48 8B 8B ? ? ? ? 48 83 C4 ? 5B 5E 5F E9 ? ? ? ? 0F 1F 44 00 ? 48 8B 05")
      table.insert(sigs, "48 8B 8B ? ? ? ? 45 31 C0 48 89 F2 48 89 B3")
      table.insert(sigs, "48 8B 8B ? ? ? ? 45 31 C0 4C 89 E2 4C 89 A3")
      table.insert(sigs, "48 8B 8B ? ? ? ? 48 83 C4 ? 5B 41 5C 41 5D 41 5E")

      table.insert(sigs, "48 3B 90 ? ? ? ? 0F 84 ? ? ? ? 48 8B 83")
      table.insert(sigs, "48 39 82 ? ? ? ? 74 ? 48 8B 83")
      table.insert(sigs, "48 39 86 ? ? ? ? 74 ? C7 44 24")
      table.insert(sigs, "48 8B 8B ? ? ? ? 48 83 C4 ? 5B 5E 5F 5D 41 5C E9 ? ? ? ? 66 2E 0F 1F 84 00")
      table.insert(sigs, "48 8B 8B ? ? ? ? BA ? ? ? ? 48 83 C4 ? 5B 5E 5F 5D 41 5C E9 ? ? ? ? 0F 1F 40")

      
      for i, sig in ipairs(sigs) do
        if setVPRVA(sig) then
          sendDebugMessage('hit at: ' .. tostring(i) .. "\t" .. sig .. "\t value: " .. numtohexstr(getAddress('oSTtoVP')))
          return true
        end
      end
      sendDebugMessage("[VP/WIND] lookup failed, you are on your own")
      return false
    end

    --- returns a valid Viewport pointer
    --- @return number
    function getViewport()
      local viewport = readPointer("ptVP")
      if isNullOrNil(viewport) then
        if inMainThread() then
          print("Viewport pointer is invalid; something's wrong");
          error('viewport pointer is invalid, couldn\'t read')
        else
          getCurrentThreadObject().terminate()
        end
      end
      return viewport
    end

    --- returns a childrenArrayPtr and its size
    ---@return number
    local function getVPChildren()
      local viewport = getViewport()

      local childrenAddr, childrenSize = getNodeChildrenInfo(viewport)

      if isNullOrNil(childrenSize) then
        sendDebugMessage('ChildSize is invalid')
        return;
      end

      return childrenAddr, childrenSize
    end

  -- ///---///--///---///--///---///--///--///---///--///---///--///---///--/// Node


    --- returns a node dictionary
    local function getMainNodeDict()
      local childrenAddr, childrenSize = getVPChildren()
      local nodeDict = {}

      if isNullOrNil(childrenAddr) then return end

      for i = 0, ( (childrenSize or 0) - 1) do

        local nodePtr = readPointer( (childrenAddr or 0) + i * GDDEFS.PTRSIZE)
        if isNullOrNil(nodePtr) then if inMainThread() then error('getMainNodeDict: NO MAIN NODES') else getCurrentThreadObject().terminate() end end

        local nodeNameStr = getNodeName(nodePtr)
        local gdscriptName = getNodeNameFromGDScript(nodePtr)
        registerSymbol(gdscriptName, nodePtr, true)

          nodeDict[nodeNameStr] =
          {
            index = i,
            NAME = nodeNameStr,
            SCRIPTNAME = gdscriptName,
            PTR = nodePtr,
            TYPE = getGDTypeEnumFromName("OBJECT"), -- node
            MEMREC = 0
          }
      end
      return nodeDict
    end

    --- returns a node table
    function getMainNodeTable()
      local childrenAddr, childrenSize = getVPChildren()
      if isNullOrNil(childrenAddr) or isNullOrNil(childrenSize) then error('getMainNodeDict: VP Children not valid') end

      local nodeTable = {}

      for i = 0, (childrenSize - 1) do
        local nodeAddr = readPointer(childrenAddr + i * GDDEFS.PTRSIZE)
        if isNullOrNil(nodeAddr) then
          error('getMainNodeDict: NO MAIN NODES')
        end
        local nodeNameStr = getNodeNameFromGDScript(nodeAddr)
        if nodeNameStr == 'N??' then nodeNameStr = getNodeName(nodeAddr) end
        registerSymbol(nodeNameStr, nodeAddr, true)
        table.insert(nodeTable, nodeAddr)
      end
      return nodeTable
    end

    function processNodeForNodes(nodeAddr, dumpContext)
      if not dumpContext:tryVisitNode(nodeAddr) then return end

      if GDDEFS.MONO and checkScriptType(nodeAddr) == GDDEFS.SCRIPT_TYPES["CS"] then
      elseif checkForGDScript(nodeAddr) then
        iterateVecVarForNodes(nodeAddr, dumpContext)
      end

      if checkIfObjectWithChildren(nodeAddr) then
        iterateNodeChildrenForNodes(nodeAddr, dumpContext)
      end
    end

    --- gets a Node's GDScriptInstance addr
    ---@param nodeAddr number
    function GDAPI.getNodeGDScriptInstance(nodeAddr)
      if isNullOrNil(nodeAddr) then
        return nil
      end

      local gdScriptInstance = readPointer(nodeAddr + GDDEFS.GDSCRIPTINSTANCE)
      if isNullOrNil(gdScriptInstance) then
        return nil
      end
      return gdScriptInstance
    end

    --- gets a Node's GDScriptInstance addr
    ---@param nodeAddr number
    local function getNodeGDScript(nodeAddr)
      if isNullOrNil(nodeAddr) then
        return nil
      end

      local gdScriptInstance = readPointer(nodeAddr + GDDEFS.GDSCRIPTINSTANCE)
      if isNullOrNil(gdScriptInstance) then
        return nil
      end
      local gdScript = readPointer(gdScriptInstance + GDDEFS.GDSCRIPT_REF)
      if isNullOrNil(gdScript) then
        return nil
      end
      return gdScript
    end

    --- get a Node name by addr
    ---@param nodeAddr number
    function GDAPI.getNodeName(nodeAddr)
      if isNullOrNil(nodeAddr) then return 'N??' end

      local nodeNamePtr = readPointer(nodeAddr + GDDEFS.OBJ_STRING_NAME)
      if isNullOrNil(nodeNamePtr) or isInvalidPointer(nodeNamePtr) then
        -- sendDebugMessage('nodeName invalid or not a pointer (?)')
        return 'N??'
      end

      return getStringNameStr(nodeNamePtr)
    end

    function GDAPI.getNodeNameFromGDScript(nodeAddr)
     if isNullOrNil(nodeAddr) then return 'N??' end

      local GDScriptInstanceAddr = readPointer(nodeAddr + GDDEFS.GDSCRIPTINSTANCE)
      if isNullOrNil(GDScriptInstanceAddr) then
        -- sendDebugMessage('ScriptInstance is 0/nil')
        return 'N??'
      end
      local GDScriptAddr = readPointer(GDScriptInstanceAddr + GDDEFS.GDSCRIPT_REF)
      if isNullOrNil(GDScriptAddr) then
        -- sendDebugMessage(' GDScript is 0/nil')
        return 'N??'
      end
      local GDScriptNameAddr = readPointer(GDScriptAddr + GDDEFS.GDSCRIPTNAME)

      if isNullOrNil(GDScriptNameAddr) then
        -- sendDebugMessage('nodeName invalid or not a pointer (?)')
        return 'N??'
      end

      -- immediate String
      local GDScriptName = readUTFString(GDScriptNameAddr)
      if GDScriptName == nil or GDScriptName == '' then
        -- sendDebugMessage('GDScriptName is nil/empty')
        return 'N??'
      end
      local scriptMatch = GDScriptName:match("([^/]+)%.[^.]+$") --"([^/]+)%.gd$"
      if scriptMatch == nil then
        -- sendDebugMessage('GDScriptName is nil/empty')
        return 'N??'
      end


      return scriptMatch
    end

    --- Used to validate an object as a Node with GDScript, returns true if valid
    ---@param nodeAddr number
    ---@return boolean @ if GD/CSScript attached
    ---@return number @ script type enum
    function checkForGDScript(nodeAddr)

      if isNullOrNil(nodeAddr) or not isVtable( readPointer(nodeAddr) ) then
        -- sendDebugMessage('nodeAddr/vtable invalid'.." address "..numtohexstr(nodeAddr))
        return false
      end

      local scriptInstance = readPointer(nodeAddr + GDDEFS.GDSCRIPTINSTANCE)
      if isNullOrNil(scriptInstance) or not isVtable( readPointer(scriptInstance) ) then
        -- sendDebugMessage('ScriptInstance/vtable is 0/nil'.." address "..numtohexstr(nodeAddr))
        return false
      end

      local gdscript = readPointer(scriptInstance + GDDEFS.GDSCRIPT_REF)
      if isNullOrNil(gdscript) or not isVtable( readPointer(gdscript) ) then
        -- sendDebugMessage('GDScript/vtable is 0/nil'.." address "..numtohexstr(nodeAddr))
        return false
      end
      
      local gdScriptName = readPointer(gdscript + GDDEFS.GDSCRIPTNAME)
      if isNullOrNil(gdScriptName) then
        -- sendDebugMessage('gdScriptName invalid')
        return false
      end
      local gdScriptName = readUTFString(gdScriptName)

      if (gdScriptName):sub(1,4) == 'res:' then
        return true
      else
        return false
      end

    end

    function checkScriptType(nodeAddr)
      if GDDEFS.MONO == false then return 0 end;
      if isNullOrNil(nodeAddr) or not isVtable( readPointer(nodeAddr) ) then
      --   -- sendDebugMessage('nodeAddr/vtable invalid'.." address "..numtohexstr(nodeAddr))
        return 0
      end

      local scriptInstance = readPointer(nodeAddr + GDDEFS.GDSCRIPTINSTANCE)
      if isNullOrNil(scriptInstance) or not isVtable( readPointer(scriptInstance) ) then
      --   -- sendDebugMessage('ScriptInstance/vtable is 0/nil'.." address "..numtohexstr(nodeAddr))
        return 0
      end

      local gdscript = readPointer(scriptInstance + GDDEFS.GDSCRIPT_REF)
      if isNullOrNil(gdscript) or not isVtable( readPointer(gdscript) ) then
      --   -- sendDebugMessage('GDScript/vtable is 0/nil'.." address "..numtohexstr(nodeAddr))
        return 0
      end
      
      local gdScriptName = readPointer(gdscript + GDDEFS.GDSCRIPTNAME)
      if isNullOrNil(gdScriptName) then
        -- sendDebugMessage('gdScriptName invalid')
        return 0
      end

      local gdScriptName = readUTFString(gdScriptName)

      if  (gdScriptName):sub(1,4) == 'res:' then
        if      (gdScriptName):sub(-3) == '.gd' then  return GDDEFS.SCRIPT_TYPES["GD"]
        elseif  (gdScriptName):sub(-3) == '.cs' then  return GDDEFS.SCRIPT_TYPES["CS"]
        else                                          return 0
        end
      else
        return 0
      end
    end

    function checkIfObjectWithChildren(objAddr)
      
      if isNullOrNil(objAddr) or not isVtable( readPointer(objAddr) ) then return false end -- if object itself is valid & has a vtable
      local objectChildren, childrenSize = getNodeChildrenInfo(objAddr) -- check children & if it's a valid pointer
      if isNullOrNil(childrenSize) then return false end -- if no children, we don't need it
      local childAddr = readPointer(objectChildren)
      if isNullOrNil(childAddr) or not isVtable( readPointer(childAddr) ) then return false end  -- let's check the 0th object for vtable
      return true
      
    end

    --- builds a structure layout for a node's children array
    ---@param childrenArrStruct userdata
    ---@param nodeAddr number
    function iterateNodeChildrenToStruct(childrenArrStructElem, baseAddress) -- TODO: repurpose for visitor & emitters?

      local childrenAddr, childrenSize = getNodeChildrenInfo(baseAddress)

      if isNullOrNil(childrenSize) then return; end

      for i = 0, (childrenSize - 1) do
        local nodeAddr = readPointer(childrenAddr + (i * GDDEFS.PTRSIZE))
        local nodeName = getNodeName(nodeAddr)
        if nodeName == nil or nodeName == 'N??' then
          nodeName = getNodeNameFromGDScript(nodeAddr)
        end
        local objectTypeName = getGDObjectName(nodeAddr)
        objectTypeName = '<' .. objectTypeName .. '>'

        -- sendDebugMessage("Checking GDScript for "..nodeName)

        if checkForGDScript(nodeAddr) then
          addLayoutStructElem(childrenArrStructElem, objectTypeName .. ' cNode: ' .. nodeName, 0x6C3157, (i * GDDEFS.PTRSIZE), vtPointer)
        else
          addStructureElem(childrenArrStructElem, objectTypeName .. ' cObj: ' .. nodeName, (i * GDDEFS.PTRSIZE), vtPointer)
        end
      end

      return
    end

    function iterateNodeChildrenForNodes(baseAddress, dumpContext)
      if dumpContext:shouldStop() then return end

      local childrenAddr, childrenSize = getNodeChildrenInfo(baseAddress)
      if isNullOrNil(childrenSize) then return; end

      for i = 0, (childrenSize - 1) do
        if dumpContext:shouldStop() then return end
        local childAddr = readPointer(childrenAddr + (i * GDDEFS.PTRSIZE))
        processNodeForNodes(childAddr, dumpContext)
      end
      return
    end

    --- go over child nodes in the main nodes
    ---@param nodeAddr number
    ---@param parent userdata
    function iterateMNodeToAddr(nodeAddr, parent, contextTable)
      assert(type(nodeAddr) == 'number', "node addr has to be a number, instead got: " .. type(nodeAddr))
      assert(type(parent) == "userdata", "parent has to exist")


      local nodeName = getNodeName(nodeAddr)
      local gdscriptName = getNodeNameFromGDScript(nodeAddr)
      sendDebugMessage('MemberNode: ' .. tostring(nodeName))

      for i, storedNode in ipairs(dumpedNodes) do -- check if a node was already dumped
        if storedNode == nodeAddr then
          sendDebugMessage('NODE ' .. tostring(nodeName) .. ' ALREADY DUMPED')

          synchronize(function(parent)
            parent.setDescription(parent.Description .. ' /D/') -- let's note what nodes are copies
            parent.Options = '[moHideChildren]'
          end, parent)

          return
        end
      end
      table.insert(dumpedNodes, nodeAddr)

      synchronize(function(nodeName, parent)
        parent.setDescription(parent.Description .. ' : ' .. tostring(nodeName)) -- append node name
      end, nodeName, parent)

      local nodeContext;
      local newNodeSymStr, GDSIsym, variantVectorSym, GDScriptSym, GDScriptConstMapSym
      newNodeSymStr = contextTable.symbol -- should be wrapped outside
      GDSIsym = wrapBrackets( newNodeSymStr .. '+GDSCRIPTINSTANCE' )
      variantVectorSym = wrapBrackets( GDSIsym .. '+VAR_VECTOR' )
      GDScriptSym = wrapBrackets( GDSIsym .. '+GDSCRIPT_REF' )
      GDScriptConstMapSym = wrapBrackets( GDScriptSym .. '+CONST_MAP' )

      sendDebugMessage('STEP: Constants for: ' .. tostring(nodeName))

      if GDDEFS.CONST_MAP ~= 0 then
        local newConstRec = synchronize(function(parent)
          local addrList = getAddressList()
          local newConstRec = addrList.createMemoryRecord()
          newConstRec.setDescription("Consts:")
          newConstRec.setAddress(0xBABE)
          newConstRec.setType(vtPointer)
          newConstRec.Options = '[moHideChildren, moAllowManualCollapseAndExpand, moManualExpandCollapse]'
          -- newConstRec.DontSave = true
          newConstRec.appendToEntry(parent)
          return newConstRec
        end, parent)

        nodeContext = { addr = nodeAddr, name = nodeName, gdname = gdscriptName, memrec = newConstRec, struct = nil, symbol = GDScriptConstMapSym }
        iterateNodeConstToAddr(nodeContext)
      end

      sendDebugMessage('STEP: VARIANTS for: ' .. tostring(nodeName))

      nodeContext = { addr = nodeAddr, name = nodeName, gdname = gdscriptName, memrec = parent, struct = nil, symbol = variantVectorSym }
      iterateVecVarToAddr(nodeContext)

      return
    end

    --- builds the structure layout for a Node when guessed
    ---@param nodeAddr number
    ---@param scriptInstStructElement userdata
    function iterateNodeToStruct(nodeAddr, scriptInstStructElement)

      local nodeName = getNodeName(nodeAddr) or 'NIL';
      local scriptName = getNodeNameFromGDScript(nodeAddr)

      sendDebugMessage('Node: ' .. tostring(nodeName))
      
      local varVectorStructElem, scriptStructElem, constMapStructElem, functMapStructElem
      local gdScriptInstanceAddr = readPointer(nodeAddr + GDDEFS.GDSCRIPTINSTANCE) or 0x0
      local gdScriptAddr = readPointer(gdScriptInstanceAddr + GDDEFS.GDSCRIPT_REF)
      local varVectorAddr = readPointer(gdScriptInstanceAddr + GDDEFS.VAR_VECTOR)
      local constMapAddr = readPointer(gdScriptAddr + GDDEFS.CONST_MAP)
      local funcMapAddr = readPointer(gdScriptAddr + GDDEFS.FUNC_MAP)

      local nodeContext;
      local newNodeSymStr = scriptName
      local GDSIsym = wrapBrackets( wrapBrackets(newNodeSymStr) .. '+GDSCRIPTINSTANCE' )
      local variantVectorSym = wrapBrackets( GDSIsym .. '+VAR_VECTOR' )
      local GDScriptSym = wrapBrackets( GDSIsym .. '+GDSCRIPT_REF' )
      local GDScriptConstMapSym = wrapBrackets( GDScriptSym .. '+CONST_MAP' )
      local GDScriptFuncMapSym = wrapBrackets( GDScriptSym .. '+FUNC_MAP' )

      scriptStructElem = addLayoutStructElem(scriptInstStructElement, 'GDScript', --[[0x008080]] nil, GDDEFS.GDSCRIPT_REF, vtPointer)

      -- we check if consts, funcs, veriants exist
      if isNotNullOrNil( varVectorAddr ) and isValidPointer( varVectorAddr ) then
        varVectorStructElem = addLayoutStructElem(scriptInstStructElement, 'Variants', --[[0x000080]] nil, GDDEFS.VAR_VECTOR, vtPointer)
        sendDebugMessage('STEP: VARIANTS for: ' .. tostring(nodeName))
        varVectorStructElem.ChildStruct = createStructure('Vars')

        local nodeContext = { addr = nodeAddr, name = nodeName, gdname = scriptName, memrec = nil, struct = varVectorStructElem, symbol = variantVectorSym }
        iterateVecVarToStruct(nodeContext)
      else
        sendDebugMessage('STEP: VARIANTS skipped: nothing to process: ' .. tostring(nodeName))
      end

      if isNotNullOrNil(GDDEFS.CONST_MAP) and isNotNullOrNil( constMapAddr ) and isValidPointer( constMapAddr ) then
        constMapStructElem = addLayoutStructElem(scriptStructElem, 'Consts', --[[0x400000]] nil, GDDEFS.CONST_MAP, vtPointer)
        sendDebugMessage('STEP: CONSTANTS for: ' .. tostring(nodeName))
        constMapStructElem.ChildStruct = createStructure('Consts')
        local nodeContext = { addr = nodeAddr, name = nodeName, gdname = scriptName, memrec = nil, struct = constMapStructElem, symbol = GDScriptConstMapSym }
        iterateNodeConstToStruct(nodeContext)
      else
        sendDebugMessage('STEP: CONSTANTS skipped: nothing to process: ' .. tostring(nodeName))
      end

      if isNotNullOrNil(GDDEFS.FUNC_MAP) and isNotNullOrNil( funcMapAddr ) and isValidPointer( funcMapAddr ) then
        functMapStructElem = addLayoutStructElem(scriptStructElem, 'Func', --[[0x400000]] nil, GDDEFS.FUNC_MAP, vtPointer)
        sendDebugMessage('STEP: Functions for: ' .. tostring(nodeName))
        functMapStructElem.ChildStruct = createStructure('Funcs')
        local nodeContext = { addr = nodeAddr, name = nodeName, gdname = scriptName, memrec = nil, struct = functMapStructElem, symbol = GDScriptFuncMapSym }
        iterateNodeFuncMapToStruct(nodeContext)
      else
        sendDebugMessage('STEP: FUNC skipped: nothing to process: ' .. tostring(nodeName))
      end

      if GDDEFS.MONO then
        if checkScriptType(nodeAddr) == GDDEFS.SCRIPT_TYPES["CS"] then
          sendDebugMessage("Node " .. nodeName .. " has csharp script type")
          local clrPtrElem = createChildStructElem(scriptInstStructElement, "CLRPtr", GDDEFS.CLR_PTR, vtPointer, "CLRPtr")
          -- addStructureElem(clrPtrElem, "CLRData", 0x0, vtPointer)
          local clrDataElem = createChildStructElem(clrPtrElem, "CLRData", 0x0, vtPointer, "CLRData")

          local clrDataAddr = readPointer( readPointer( gdScriptInstanceAddr + GDDEFS.CLR_PTR ) ) or 0x0
          if isNotNullOrNil(clrDataAddr) then
            clrDataElem.ChildStruct.fillFromDotNetAddress(clrDataAddr , true)
          end
        end
      end

      return
    end

    --- gets a GDScript name, best use to return 1st 3 chars for 'res'
    ---@param nodeAddr number
    ---@param strSize number
    function getGDResName(nodeAddr, strSize)
      assert(type(nodeAddr) == 'number', "nodeAddr should be a number, instead got: " .. type(nodeAddr))

      local gdScriptInstance = readPointer(nodeAddr + GDDEFS.GDSCRIPTINSTANCE)
      if isNullOrNil(gdScriptInstance) then
        -- sendDebugMessage('gdScriptInstance invalid')
        return
      end

      local gdScript = readPointer(gdScriptInstance + GDDEFS.GDSCRIPT_REF)
      if isNullOrNil(gdScript) then
        -- sendDebugMessage('gdScript invalid')
        return
      end

      local gdScriptName = readPointer(gdScript + GDDEFS.GDSCRIPTNAME)
      if isNullOrNil(gdScriptName) then
        -- sendDebugMessage('gdScriptName invalid')
        return
      end

      -- it's immediate String
      return readUTFString(gdScriptName, strSize)
    end

    -- this monstrosity is used to check for a valid poitner and its vtable
    ---@param objectPtr number -- a ptr to an object or nullptr
    ---@return number -- returns a more valid pointer to an object
    ---@return boolean -- true if the returned pointer was shifted back to get a valid ptr
    function checkObjectOffset(objectPtr)

      local objectAddr = readPointer(objectPtr) -- it's either an obj ptr or zero

      -- it's the right object
      if isVtable( getVtable(objectAddr) ) then return objectPtr, false end

      -- sendDebugMessage('OBJ addr likely not a ptr, shifting back 0x8: ptr: '..string.format( '%x', tonumber(objectPtr) ) )
      local adjustedObjectPtr = (objectPtr or 0) - GDDEFS.PTRSIZE; -- shift back to get a ptr
      local wrapperAddr = readPointer(adjustedObjectPtr) -- this will be a wrapped obj ptr

      if isNullOrNil(wrapperAddr) or isInvalidPointer(wrapperAddr) then -- check the wrapper
        -- sendDebugMessage('OBJ addr still not an obj  ptr, leave it be')
        return objectPtr, false; -- revert the value, whatever
      end

      objectAddr = readPointer(wrapperAddr)
      if isVtable(getVtable(objectAddr)) then -- check for vtable to be safe
        -- sendDebugMessage('shifted OBJ addr is a ptr, returning it')
        return wrapperAddr, true -- objects at 0x8 offsetToValue are wrapped ptrs, so we return the ptr
      else
        -- sendDebugMessage('OBJ addr still not a ptr, leave it be')
        return objectPtr, false; -- revert the value, whatever
      end
    end

    --- returns a const ptr and its type
    ---@param nodeAddr number
    ---@param constName string
    function GDAPI.getNodeConstPtr(nodeAddr, constName)
      assert(type(nodeAddr) == 'number', "Node addr has to be a number, instead got: " .. type(nodeAddr))
      assert(type(constName) == 'string', "Constant name has to be a string, instead got: " .. type(constName))

      local mapHead = getNodeConstantMap(nodeAddr)
      return findMapEntryByName(mapHead, constName, getNodeConstName, getConstMapLookupResult, getNextMapElement)
    end

    function GDAPI.getNodeChildByGDName(nodeAddr, gdName)
      assert(type(nodeAddr) == 'number', "Node addr has to be a number, instead got: " .. type(nodeAddr))
      assert(type(gdName) == 'string', "Node gdname has to be a string, instead got: " .. type(gdName))
      assert(checkIfObjectWithChildren(nodeAddr), "Node doesn't have children")
      local childrenAddr, childrenSize = getNodeChildrenInfo(nodeAddr) -- children should be valid
      for i = 0, (childrenSize - 1) do
        local childAddr = readPointer(childrenAddr + (i * GDDEFS.PTRSIZE))
        if gdName == getNodeNameFromGDScript(childAddr) then
          return childAddr
        end
      end
      return nil
    end

    function GDAPI.getNodeChildByName(nodeAddr, nodeName)
      assert(type(nodeAddr) == 'number', "Node addr has to be a number, instead got: " .. type(nodeAddr))
      assert(type(nodeName) == 'string', "Node name has to be a string, instead got: " .. type(nodeName))
      assert(checkIfObjectWithChildren(nodeAddr), "Node doesn't have children")
      local childrenAddr, childrenSize = getNodeChildrenInfo(nodeAddr)
      for i = 0, (childrenSize - 1) do
        local childAddr = readPointer(childrenAddr + (i * GDDEFS.PTRSIZE))
        if nodeName == getNodeName(childAddr) then
          return childAddr
        end
      end
      return nil
    end

  -- ///---///--///---///--///---///--///--///---///--///---///--///---///--/// GDScript


    local function findGDExtensionInterfacePtr()
      local function findFuncPointer(aobSignature)
        local addr = AOBScanModuleUnique(process, aobSignature, '+X-W-C')
        if addr == 0 or addr == nil then return false end
        GDDEFS.GDXTENSION_GETPROC = addr
        return true
      end
      local sigs = {}
      table.insert(sigs, "53 48 83 EC ? 45 31 C0 48 89 CA 48 8D 4C 24 ? E8 ? ? ? ? 48 8D 4C 24 ? E8" ) -- 4.6
      table.insert(sigs, "40 53 48 83 EC ? 48 8B D1 45 33 C0 48 8D ? 24 ? E8 ? ? ? ? 48 8D ? 24 ? E8" ) -- 4.6, 4.3 4.1, just a swapped encoding
      table.insert(sigs, "56 53 48 83 EC ? 45 31 C0 48 8D ? 24 ? 48 89 CA 48 89 F1 E8 ? ? ? ? 48 89 F1 E8" ) -- 4.5 4.4

      table.insert(sigs, "41 57 41 56 41 55 41 54 55 57 56 53 48 83 EC ? 4? 8D ? 24 ? 48 89 CA ? 89 ? E8" ) -- merged 4.1 4.2
      table.insert(sigs, "41 57 41 56 41 55 41 54 55 57 56 53 48 83 EC ? 4? 8D ? 24 ? 48 89 CA ? 89 ? 48 89 44 24 ? E8 ? ? ? ? 4C 8B 05 ? ? ? ? 48 8B 6C 24 ? 4D 8B 70 ? 4D 85 F6 OF" ) -- merged 4.3 / 4.1

      for i, sig in ipairs(sigs) do
        if findFuncPointer(sig) then
          sendDebugMessage('[GDExtAPI] via sig - success:' .. "\t" .. sig)
          return true
        end
      end
      sendDebugMessage('[GDExtAPI] lookup failed.')
      return false
    end

    local function findGDNativeAPIStruct()
      local function findViaRDATA(rdataSignature)
        local addr = AOBScanModuleUnique(process, rdataSignature, '-X-W-C', 1, 4)
        if addr == 0 or addr == nil then
          return false
        end
        GDDEFS.GDNATIVE_STRUCT = addr
        return true
      end

      local function findFuncPointer(aobSignature)
        local addr = AOBScanModuleUnique(process, aobSignature, '+X-W-C')
        if addr == 0 or addr == nil then
          return false
        end
        GDDEFS.GDNATIVE_STRUCT = addr
        return true
      end

      -- type, major, minor, 4padd, *next, num_extensions, 4padd, *extensions, funcNum*PTRSIZE
      local structSignature = "00 00 00 00   01 00 00 00   00 00 00 00   00 00 00 00   ? ? ? ? ? ? ? ?   06 00 00 00   00 00 00 00"

      local sigs = {}
      table.insert(sigs, "48 8D 3D ? ? ? ? 66 48 0F 6E C0 66 48 0F 6E C9" )
      table.insert(sigs, "4C 8D 15 ? ? ? ? 48 89 84 24 ? ? ? ? 48 8D 05" )

      -- first via rdata
      if findViaRDATA(structSignature) then
        sendDebugMessage('[NATIVE_API] via rdata success!')
        return true
      end

      -- fallback
      for i, sig in ipairs(sigs) do
        if findFuncPointer(sig) then
          sendDebugMessage('hit at: ' .. tostring(i) .. "\t" .. sig)
          return true
        end
      end
      return false
    end

    -- 3.x extensive gdnative api /docs/api_info/gdnative_api.json
      local GDNative =
        {
          name = "CORE",
          base = nil,
          major = nil,
          minor = nil,
          extensions = nil,
          funcStart = nil,
          inited = false,
        }

        function GDNative:init()
          if self.inited then return end
          self.base = GDDEFS.GDNATIVE_STRUCT
          if self.base == nil then error('API struct not found') end
          self.major, self.minor = self:getSemver( self.base )
          self:initExtensions()
          local offsetToFunc = 0x28
          self.funcStart = self.base + offsetToFunc
          self.inited = true
        end

        function GDNative:initExtensions()
          if self.base == nil then error('Core struct not initialized') end
          local extOffset = 0x20 -- x64
          local toFuncOffset = 0x18
          local numExtensions = 6

          local extArray = readPointer( self.base + extOffset )
          if extArray == nil or extArray == 0 then error('Extension array invalid') end

          local names = { "NATIVESCRIPT", "PLUGINSCRIPT", "ANDROID", "ARVR", "VIDEODECODER", "NET"}
          self.extensions = {}
          for i=0, numExtensions-1 do
            local extension = {}
            extension.name = names[i+1]
            extension.base = readPointer( extArray + GDDEFS.PTRSIZE*i )
            extension.major, extension.minor = self:getSemver( extension.base )
            extension.funcStart = extension.base + toFuncOffset
            table.insert(self.extensions, extension)
          end
        end

        function GDNative:getSemver(struct)
          assert(struct ~= nil and struct ~= 0, 'struct addr has to be valid')
          local major = readInteger(struct + 0x4)
          local minor = readInteger(struct + 0x8)
          return major, minor
        end

        function GDNative:getNextVer(base)
          if not self.inited then error('gdnative not initialized') end
          assert(base ~= nil and base ~= 0, 'struct addr has to be valid')

          local nextOffset = 0x10
          return readPointer(base + nextOffset)
        end

        function GDNative:findStructVer( struct, major, minor)
          if not self.inited then error('gdnative not initialized') end
          assert(struct ~= nil and struct.base ~= nil and struct.base ~= 0, 'struct invalid')
          assert(major ~= nil and minor ~= nil, 'version has to be valid')

          local currBase = struct.base
          repeat
            local currMajor, currMinor = self:getSemver(currBase)
            if currMajor == major and currMinor == minor then return currBase end
            currBase = self:getNextVer(currBase)
          until currBase == nil or currBase == 0
          return nil
        end

        function GDNative:getFuncFromIndex(struct, index)
          if not self.inited then self:init() end
          assert(struct ~= nil and struct ~= 0, 'struct addr has to be valid')
          assert(index ~= nil and index >= 0, 'index invalid')
          return readPointer( struct.funcStart + index*GDDEFS.PTRSIZE )
        end

      local GDNativeInterface = {}

        function GDNativeInterface.godot_string_chars_to_utf8( str )
          assert(type(str) == 'string', 'string must be a string, instead got: ' .. type(str))
          assert(#str > 0, 'string must be of valid size')

          local strlen = str:len()
          local stringCtor = GDNative:getFuncFromIndex(GDNative, 681)
          if isNullOrNil(stringCtor) then error('godot_string_chars_to_utf8 func ptr not found') end

          -- setup cstring content param in the target via CE API
          local strlen = str:len()
          local allocStrSpace = allocateMemory(strlen + 1)
          local ok = writeString(allocStrSpace,str)
          if not ok then deAlloc(allocStrSpace) error('string mapping failed') end
          
          -- local stringSpace = 0x8 -- storage for the dest object

          local objPtr = executeCodeEx(stdcall, timeout, stringCtor, allocStrSpace)
          deAlloc(allocStrSpace)
          return objPtr
        end

        function GDNativeInterface.godot_string_name_new_data( str )
          assert(type(str) == 'string', 'string must be a string, instead got: ' .. type(str))
          assert(#str > 0, 'string must be of valid size')

          local strlen = str:len()
          local stringNameCtor = GDNative:getFuncFromIndex(GDNative, 723)
          if isNullOrNil(stringNameCtor) then error('godot_string_name_new_data func ptr not found') end

          -- setup cstring content param in the target via CE API
          local strlen = str:len()
          local allocStrSpace = allocateMemory(strlen + 1)
          local ok = writeString(allocStrSpace,str)
          if not ok then deAlloc(allocStrSpace) error('string mapping failed') end
          
          -- allocating target memory via GD API
          local objAlloc = allocateMemory(GDDEFS.PTRSIZE)
          if isNullOrNil(objAlloc) then error('mem_alloc failed to allocate') end

          -- construct SName
          executeCodeEx(stdcall, timeout, stringNameCtor, objAlloc, allocStrSpace)
          local objPtr = readPointer(objAlloc)
          deAlloc(allocStrSpace) -- free the string content
          deAlloc(objAlloc)
          return objPtr
        end

        function GDNativeInterface.godot_string_destroy( ptr )
          assert(type(ptr) == 'number', 'stringName ptr must be a number, instead got: ' .. type(ptr))

          local stringDestor = GDNative:getFuncFromIndex(GDNative, 721)
          if isNullOrNil(stringDestor) then error('godot_string_destroy func ptr not found') end

          -- allocating target memory
          local objAlloc = allocateMemory(GDDEFS.PTRSIZE)
          if isNullOrNil(objAlloc) then error('mem_alloc failed to allocate') end
          writePointer(objAlloc, ptr)

          -- destroy SName
          executeCodeEx(stdcall, timeout, stringDestor, objAlloc)
          deAlloc(objAlloc)
        end

        function GDNativeInterface.godot_string_name_destroy( ptr )
          assert(type(ptr) == 'number', 'stringName ptr must be a number, instead got: ' .. type(ptr))

          local stringNameDestor = GDNative:getFuncFromIndex(GDNative, 729)
          if isNullOrNil(stringNameDestor) then error('godot_string_name_destroy func ptr not found') end

          -- allocating target memory
          local objAlloc = allocateMemory(GDDEFS.PTRSIZE)
          if isNullOrNil(objAlloc) then error('mem_alloc failed to allocate') end
          writePointer(objAlloc, ptr)

          -- destroy SName
          executeCodeEx(stdcall, timeout, stringNameDestor, objAlloc)
          deAlloc(objAlloc)
        end

        function GDNativeInterface.godot_alloc( bytes )
          error('not implemented')
        end

        function GDNativeInterface.godot_free( ptr )
          error('not implemented')
        end

    -- 4.x global Godot Engine Extension Interface, /docs/api_info/gdextension_interface.json
      local GDExtendedInterface = {}

        function GDExtendedInterface.getGDExtensionFunc(funcName)
          assert(type(funcName) == "string", 'function name has to be a string, instead got: ' .. type(funcName))
          assert(GDDEFS.MAJOR_VER >= 4 and GDDEFS.MINOR_VER >= 1, "GDExtension Interface is for 4.1+ only")

          -- get func ptr
          if isNullOrNil(GDDEFS.GDXTENSION_GETPROC) then 
            if not findGDExtensionInterfacePtr() then error('getproc func ptr not found') end
          end
          local getProcAddr = GDDEFS.GDXTENSION_GETPROC

          if getProcAddr == nil then error('interface not found') end

          -- allocate space for the string
          local strlen = funcName:len()

          -- allocateMemory(size, BaseAddress OPTIONAL, Protection OPTIONAL) 
          local allocStrSpace = allocateMemory(strlen + 1) -- cstr with nullterminator in the target, but actually callocates 0x1000

          local ok = writeString(allocStrSpace,funcName) -- handles 0-term
          if not ok then deAlloc(allocStrSpace) error('string mapping failed') end
          
          local retFuncPtr = executeCodeEx(stdcall, timeout, getProcAddr, allocStrSpace )
          deAlloc(allocStrSpace) -- free string

          return retFuncPtr
        end

        --- constructs a variant from other variants whenever that's needed
        ---@param gdtypeStr string
        ---@param argTable table @ should fill copy ptr
        function GDExtendedInterface.variant_construct( gdtypeStr, argTable )
          assert(type(gdtypeStr) == 'string', 'gdtype must be a string, instead got: ' .. type(gdtypeStr))
          assert(type(argTable) == "table" and isNotNullOrNil(#argTable), 'argument table must be valid')

          local varGetConstrPtr = GDExtendedInterface.getGDExtensionFunc('variant_construct')
          local mallocPtr = GDExtendedInterface.getGDExtensionFunc('mem_alloc')
          if isNullOrNil(varGetConstrPtr) then error('variant_construct func ptr not found') end
          if isNullOrNil(mallocPtr) then error('mem_alloc func ptr not found') end

          -- setup arguments & space
          if isNotNullOrNil(argTable) and type(argTable) == "table" and isNotNullOrNil(#argTable) then
            setupCallArgs(VariantArena, GDVariant, argTable)
          else 
            error("arg table has to be filled to construct")
          end

          local variantSpaceAlloc = 0x40 -- storage for the dest object
          local objAlloc = executeCodeEx(stdcall, timeout, mallocPtr, variantSpaceAlloc) -- ctor should place the ptr
          if isNullOrNil(objAlloc) then error('mem_alloc failed to allocate') end

          local argListPtr = VariantArena.base + VariantArena.argListOffset
          local typeEnum = getGDTypeEnumFromName(gdtypeStr)
          local argCount = (argTable and #argTable) or 0
          local callError = VariantArena.base + VariantArena.callErrorOffset

          executeCodeEx(stdcall, timeout, varGetConstrPtr, typeEnum, objAlloc, argListPtr, argCount)

          return objAlloc
        end

        function GDExtendedInterface.get_variant_from_type_constructor( gdtypeStr )
          assert(type(gdtypeStr) == 'string', 'gdtype must be a string, instead got: ' .. type(gdtypeStr))
          local varCtorPtr = GDExtendedInterface.getGDExtensionFunc('get_variant_from_type_constructor')
          if isNullOrNil(varCtorPtr) then error('get_variant_from_type_constructor func ptr not found') end
          local typeEnum = getGDTypeEnumFromName(gdtypeStr)
          return executeCodeEx(stdcall, timeout, varCtorPtr, typeEnum)
        end

        function GDExtendedInterface.variant_get_ptr_destructor( gdtypeStr )
          assert(type(gdtypeStr) == 'string', 'gdtype must be a string, instead got: ' .. type(gdtypeStr))
          local varGetConstrPtr = GDExtendedInterface.getGDExtensionFunc('variant_get_ptr_destructor')
          if isNullOrNil(varGetConstrPtr) then error('variant_get_ptr_destructor func ptr not found') end
          local typeEnum = getGDTypeEnumFromName(gdtypeStr)
          return executeCodeEx(stdcall, timeout, varGetConstrPtr, typeEnum)
        end

        function GDExtendedInterface.variant_destroy( gdtypeStr, obj )
          assert(type(gdtypeStr) == 'string', 'gdtype must be a string, instead got: ' .. type(gdtypeStr))
          local varDestructPtr = GDExtendedInterface.variant_get_ptr_destructor(gdtypeStr)
          if isNullOrNil(varDestructPtr) then error('var destructor func ptr not found') end
          local typeEnum = getGDTypeEnumFromName(gdtypeStr)
          return executeCodeEx(stdcall, timeout, varDestructPtr, typeEnum)
        end

        function GDExtendedInterface.variant_get_ptr_constructor( gdtypeStr, constructorID )
          assert(type(gdtypeStr) == 'string', 'gdtype must be a string, instead got: ' .. type(gdtypeStr))
          assert(type(constructorID) == 'number', 'constructorid must be a number, instead got: ' .. type(constructorID))
          local varGetConstrPtr = GDExtendedInterface.getGDExtensionFunc('variant_get_ptr_constructor')
          if isNullOrNil(varGetConstrPtr) then error('variant_get_ptr_constructor func ptr not found') end
          local typeEnum = getGDTypeEnumFromName(gdtypeStr)
          return executeCodeEx(stdcall, timeout, varGetConstrPtr, typeEnum, constructorID)
        end

        function GDExtendedInterface.string_new_with_latin1_chars( str )
          assert(type(str) == 'string', 'string must be a string, instead got: ' .. type(str))
          assert(#str > 0, 'string must be of valid size')

          local strlen = str:len()
          -- local mallocPtr = GDExtendedInterface.getGDExtensionFunc('mem_alloc') -- since we get the pointer, there's barely any need to allocate internally
          local stringCtor = GDExtendedInterface.getGDExtensionFunc('string_new_with_latin1_chars')
          if isNullOrNil(stringCtor) then error('string_new_with_latin1_chars func ptr not found') end
          -- if isNullOrNil(mallocPtr) then error('mem_alloc func ptr not found') end

          -- setup cstring content param in the target via CE API
          local strlen = str:len()
          local allocStrSpace = allocateMemory(strlen + 1) -- well, 0x1000 calloced if less anyways
          local ok = writeString(allocStrSpace,str) -- handles 0-term
          if not ok then deAlloc(allocStrSpace) error('string mapping failed') end
          
          -- local stringSpace = 0x8 -- storage for the dest object
          -- local objAlloc = executeCodeEx(stdcall, timeout, mallocPtr, stringSpace ) -- ctor should place the ptr
          local objAlloc = allocateMemory(GDDEFS.PTRSIZE)
          -- if isNullOrNil(objAlloc) then error('mem_alloc failed to allocate') end

          executeCodeEx(stdcall, timeout, stringCtor, objAlloc, allocStrSpace) -- this does placement new alloc
          local objPtr = readPointer(objAlloc)
          deAlloc(allocStrSpace)
          deAlloc(objAlloc)
          return objPtr
        end

        function GDExtendedInterface.string_name_new_with_latin1_chars( str )
          assert(type(str) == 'string', 'string must be a string, instead got: ' .. type(str))
          assert(#str > 0, 'string must be of valid size')

          -- find pointers, otherwise early exit
          -- local mallocPtr = GDExtendedInterface.getGDExtensionFunc('mem_alloc')
          -- local deallocPtr = GDExtendedInterface.getGDExtensionFunc('mem_free')
          local stringCtor = GDExtendedInterface.getGDExtensionFunc('string_name_new_with_latin1_chars')
          -- if isNullOrNil(mallocPtr) then error('mem_alloc func ptr not found') end
          if isNullOrNil(stringCtor) then error('string_name_new_with_latin1_chars func ptr not found') end

          -- setup cstring content param in the target via CE API
          local strlen = str:len()
          local allocStrSpace = allocateMemory(strlen + 1) -- well, 0x1000 calloced if less anyways
          local ok = writeString(allocStrSpace,str) -- handles 0-term
          if not ok then deAlloc(allocStrSpace) error('string mapping failed') end

          -- local SNameSpace = 0x8 -- storage for the dest object
          local isStatic = 0 -- we never do static which is 'The StringName will reuse the `p_contents` buffer instead of copying it', there's no reason to handle ownership of that

          -- allocating target memory via GD API
          -- local objAlloc = executeCodeEx(stdcall, timeout, mallocPtr, SNameSpace) -- ctor should place the ptr
          local objAlloc = allocateMemory(GDDEFS.PTRSIZE)
          if isNullOrNil(objAlloc) then error('mem_alloc failed to allocate') end
          
          -- construct SName
          executeCodeEx(stdcall, timeout, stringCtor, objAlloc, allocStrSpace, isStatic) -- this does placement new alloc
          local objPtr = readPointer(objAlloc)
          deAlloc(allocStrSpace) -- free the string content
          deAlloc(objAlloc)
          return objPtr
        end

        function GDExtendedInterface.string_name_destroy( ptr )
          assert(type(ptr) == 'number', 'stringName ptr must be a number, instead got: ' .. type(ptr))

          local stringNameDestor = GDExtendedInterface.variant_get_ptr_destructor('STRING_NAME')
          if isNullOrNil(stringNameDestor) then error('string_name destructor func ptr not found') end

          -- allocating target memory
          local objAlloc = allocateMemory(GDDEFS.PTRSIZE)
          if isNullOrNil(objAlloc) then error('mem_alloc failed to allocate') end
          writePointer(objAlloc, ptr)

          -- destroy SName
          executeCodeEx(stdcall, timeout, stringNameDestor, objAlloc)
          deAlloc(objAlloc)
        end

        function GDExtendedInterface.string_destroy( ptr )
          assert(type(ptr) == 'number', 'string ptr must be a number, instead got: ' .. type(ptr))

          local stringDestor = GDExtendedInterface.variant_get_ptr_destructor('STRING')
          if isNullOrNil(stringDestor) then error('string destructor func ptr not found') end

          -- allocating target memory
          local objAlloc = allocateMemory(GDDEFS.PTRSIZE)
          if isNullOrNil(objAlloc) then error('mem_alloc failed to allocate') end
          writePointer(objAlloc, ptr)

          -- destroy SName
          executeCodeEx(stdcall, timeout, stringDestor, objAlloc)
          deAlloc(objAlloc)
        end 

        function GDExtendedInterface.mem_alloc(size)
          assert(type(size) == 'number', 'size must be a number, instead got: ' .. type(size))
          assert(size > 0, 'size must be a valid size')

          local funcPtr = GDExtendedInterface.getGDExtensionFunc('mem_alloc')
          if isNullOrNil(funcPtr) then error('mem_alloc func ptr not found') end
          local alloc = executeCodeEx(stdcall, timeout, funcPtr, size)
          if isNullOrNil(alloc) then error('mem_alloc failed to allocate') end
          return alloc
        end

        function GDExtendedInterface.mem_free(allocPtr)
          assert(type(allocPtr) == 'number', 'pointer must be a number, instead got: ' .. type(allocPtr))
          assert(allocPtr ~= 0, 'pointer mustnt be null')

          local funcPtr = GDExtendedInterface.getGDExtensionFunc('mem_free')
          if isNullOrNil(funcPtr) then error('mem_free func ptr not found') end
          -- local allocSpace = allocateMemory(GDDEFS.PTRSIZE)
          -- writePointer(allocSpace, allocPtr)
          executeCodeEx(stdcall, timeout, funcPtr, allocPtr)
          -- deAlloc(allocSpace)
        end

    -- exposed interfaces
    GDI = {}

      -- we own the thing, it's not tracking refs however
      GDI.constructed = {}

      function GDI.construct_string( str )
        local retObj
        if GDDEFS.MAJOR_VER == 3 then
          retObj = GDNativeInterface.godot_string_chars_to_utf8( str )
        else
          retObj = GDExtendedInterface.string_new_with_latin1_chars( str )
        end
        if retObj then GDI.constructed[retObj] = 'STRING' end
        return retObj
      end

      function GDI.construct_string_name( str )
        local retObj
        if GDDEFS.MAJOR_VER == 3 then
          retObj = GDNativeInterface.godot_string_name_new_data( str )
        else
          retObj = GDExtendedInterface.string_name_new_with_latin1_chars( str )
        end
        if retObj then GDI.constructed[retObj] = 'STRING_NAME' end
        return retObj
      end

      function GDI.construct_string_name_variant( str )
        local objAlloc

        if GDDEFS.MAJOR_VER == 3 then
          error('doesnt exist')
        else
          local stringPtr = GDI.construct_string_name(str)
          local varCtorPtr = GDExtendedInterface.get_variant_from_type_constructor('STRING_NAME')
          local mallocPtr = GDExtendedInterface.getGDExtensionFunc('mem_alloc')
          if isNullOrNil(mallocPtr) then error('mem_alloc func ptr not found') end
          if isNullOrNil(varCtorPtr) then error('get_variant_from_type_constructor func ptr not found') end
        
          -- malloc
          local variantSpaceAlloc = 0x40 -- uninit dest store
          objAlloc = executeCodeEx(stdcall, timeout, mallocPtr, variantSpaceAlloc) -- where the object will be stored
          if isNullOrNil(objAlloc) then error('mem_alloc failed to allocate') end
          
          -- constructing variant string name
          local ptrContainer = allocateMemory(GDDEFS.PTRSIZE)
          writePointer(ptrContainer, stringPtr)
          executeCodeEx(stdcall, timeout, varCtorPtr, objAlloc, ptrContainer)
          deAlloc(ptrContainer)
        end
        if objAlloc then GDI.constructed[objAlloc] = 'STRING_NAME' end
        return objAlloc
      end

      function GDI.construct_string_variant( str )
        local objAlloc
        local stringPtr = GDI.construct_string(str)
        
        if GDDEFS.MAJOR_VER == 3 then
          local varCtorPtr = GDNative:getFuncFromIndex(GDNative, 514)
          local mallocPtr = GDNative:getFuncFromIndex(GDNative, 738)
          if isNullOrNil(mallocPtr) then error('mem_alloc func ptr not found') end
          if isNullOrNil(varCtorPtr) then error('get_variant_from_type_constructor func ptr not found') end
        
          -- malloc
          local variantSpaceAlloc = 0x18 -- uninit dest store
          objAlloc = executeCodeEx(stdcall, timeout, mallocPtr, variantSpaceAlloc)
          if isNullOrNil(objAlloc) then error('mem_alloc failed to allocate') end

          -- constructing variant string name
          local ptrContainer = allocateMemory(GDDEFS.PTRSIZE)
          writePointer(ptrContainer, stringPtr)
          executeCodeEx(stdcall, timeout, varCtorPtr, objAlloc, ptrContainer)
          deAlloc(ptrContainer)
        else
          local varCtorPtr = GDExtendedInterface.get_variant_from_type_constructor('STRING')
          local mallocPtr = GDExtendedInterface.getGDExtensionFunc('mem_alloc')
          if isNullOrNil(mallocPtr) then error('mem_alloc func ptr not found') end
          if isNullOrNil(varCtorPtr) then error('get_variant_from_type_constructor func ptr not found') end
        
          -- malloc
          local variantSpaceAlloc = 0x40 -- uninit dest store
          objAlloc = executeCodeEx(stdcall, timeout, mallocPtr, variantSpaceAlloc)
          if isNullOrNil(objAlloc) then error('mem_alloc failed to allocate') end

          -- constructing variant string name
          local ptrContainer = allocateMemory(GDDEFS.PTRSIZE)
          writePointer(ptrContainer, stringPtr)
          executeCodeEx(stdcall, timeout, varCtorPtr, objAlloc, ptrContainer)
          deAlloc(ptrContainer)
        end
        if objAlloc then GDI.constructed[objAlloc] = 'STRING' end
        return objAlloc
      end

      function GDI.get_variant_from_type_constructor( gdTypeName )
        local constructor

        if GDDEFS.MAJOR_VER == 3 then
          error('not implemented')
        else
          constructor = GDExtendedInterface.get_variant_from_type_constructor( gdTypeName )
        end
        return constructor
      end

      function GDI.variant_construct( gdTypeName, value )
        error('not implemented')
      end


      function GDI.destroy_string( ptr )
        if GDDEFS.MAJOR_VER == 3 then
          GDNativeInterface.godot_string_name_destroy( ptr )
        else
          GDExtendedInterface.string_name_destroy( ptr )
        end
        if ptr then GDI.constructed[ptr] = nil end
      end

      function GDI.destroy_string_name( ptr )
        if GDDEFS.MAJOR_VER == 3 then
          GDNativeInterface.godot_string_name_destroy( ptr )
        else
          GDExtendedInterface.string_destroy( ptr )
        end
        if ptr then GDI.constructed[ptr] = nil end
      end

      function GDI.destroy_variant( ptr )
        if GDDEFS.MAJOR_VER == 3 then
          error('not implemented')
        else
          error('not implemented')
        end
        if ptr then GDI.constructed[ptr] = nil end
      end

      function GDI.destroy_stored( ptr )
        error('not implemented')
      end

    local function resolveGDTokenOffset(gdscriptVtable)
      if isNullOrNil(GDDEFS.GDSCRIPT_RELOAD_INDX) then sendDebugMessage('[GDReload] reload index not defined - failed') return false end
      -- by having a vtable method, we can assume the source and binary token offset
      local setScriptMethodAddr = readPointer(gdscriptVtable + (GDDEFS.GDSCRIPT_RELOAD_INDX*GDDEFS.PTRSIZE) - GDDEFS.PTRSIZE) -- previous method
      local instrSteps = 14 -- how many instructions we check
      local instrPointer = setScriptMethodAddr -- initial pos
      local sourceOffset

      -- we walk instr by instr and check the first lea for the source offset
      for i=0, instrSteps-1 do
        local instrSize = getInstructionSize(instrPointer)
        local extra, opcode, bytes, address = splitDisassembledString( disassemble(instrPointer) )

        -- ~lea rcx,[rcx+XXX]
        local offsetStr = opcode:match("lea r..,%[rcx%+([%x]+)%]")
        if isNotNullOrNil(offsetStr) then
          sourceOffset = tonumber(offsetStr, 16)
          GDDEFS.GDSCRIPT_SRC = sourceOffset
          GDDEFS.GDSCRIPT_BINARYTOKENS = sourceOffset + 2*GDDEFS.PTRSIZE -- not sure about alignment on x32
          sendDebugMessage('[GDReload] vtable heuristic success.')
          return true
        end
        instrPointer = instrPointer+instrSize -- next instruction
      end
      sendDebugMessage('[GDReload] failed to find the source offset')
      return false
    end

    function GDAPI.recompileGDScript(nodeAddr, fileName)
      assert(type(nodeAddr)=='number', 'Node addr has to be a number, instead got: '..type(nodeAddr))
      assert(type(fileName)=='string', 'Script file name has to be a string, instead got: '..type(fileName))
      assert(isNotNullOrNil(GDDEFS.GDSCRIPT_RELOAD_INDX), 'vMethod index has to be defined')
      assert(checkForGDScript(nodeAddr), 'Node doesnt have gdscript')

      -- passing strings won't work, gotta stream the attached files
      local newScript = streamFileToString(fileName)
      if isNullOrNil(newScript) then error('attached file wasnt found') end

      -- get gdscript and its vtable
      local gdscript = getNodeGDScript(nodeAddr) or 0
      local gdscriptVtable = readPointer(gdscript)

      -- figure out the obj offsets
      if isNullOrNil(GDDEFS.GDSCRIPT_SRC) then
        if not resolveGDTokenOffset(gdscriptVtable) then error('offset hunt heuristic failed') end
      end

      -- get reload method
      local reloadMethodPtr = readPointer(gdscriptVtable + GDDEFS.GDSCRIPT_RELOAD_INDX*GDDEFS.PTRSIZE)
      if isNullOrNil(reloadMethodPtr) then error('method not found') end

      -- first check if source is present
      local hasSource, hasTokens = false, false
      local sourceAddr = readPointer(gdscript + GDDEFS.GDSCRIPT_SRC)
      if isValidPointer(sourceAddr) then hasSource = true end

      local binaryTockensAddr
      if GDDEFS.MAJOR_VER >= 4 then
        binaryTockensAddr = readPointer(gdscript + GDDEFS.GDSCRIPT_BINARYTOKENS)
        if isNullOrNil(binaryTockensAddr) then error('tokens invalid') end
        if isValidPointer(binaryTockensAddr) then
          hasTokens = true
          -- making it nullptr is seemingly less messier to avoid !binary_tokens.is_empty()
          writePointer(gdscript + GDDEFS.GDSCRIPT_BINARYTOKENS, 0)
        end
      end

      -- construct a managed string from the streamed script file and set it to the script
      local newScriptAddr = GDI.construct_string(newScript)
      writePointer(gdscript + GDDEFS.GDSCRIPT_SRC , newScriptAddr )

      -- hotreload the new script, it doesn't create Script Instances, introducing new members leads to UB without instance swapping
      local eError = executeCodeEx(stdcall, timeout, reloadMethodPtr, gdscript, 1) -- Error GDScript::reload(bool p_keep_state) -- p_keep_state = true allows existing instances

      -- to revert later
      if GDDEFS.MAJOR_VER >= 4 then
        if hasTokens then writePointer(gdscript + GDDEFS.GDSCRIPT_BINARYTOKENS, binaryTockensAddr) end
      end

      if hasSource then
        writePointer(gdscript + GDDEFS.GDSCRIPT_SRC, sourceAddr)
      else
        writePointer(gdscript + GDDEFS.GDSCRIPT_SRC, 0 )
      end

      GDI.destroy_string(newScriptAddr)

      -- 0 OK, 22 ERR_ALREADY_IN_USE, 43 ERR_PARSE_ERROR, 2 ERR_HANDLER_SCRIPT, 36 ERR_COMPILATION_FAILED, 1 ERR_HANDLER_WARNING
      return eError
    end

    function GDAPI.reloadScriptInstance(nodeAddr)
      assert(type(nodeAddr)=='number', 'Node addr has to be a number, instead got: '..type(nodeAddr))
      assert(checkForGDScript(nodeAddr), 'Node doesnt have gdscript')

      -- get Node's callp virtual
      
      -- construct bound method StringName
      -- local methodSName = GDI.construct_string( 'set_script' )

      -- setup Script OBJECT Variant (via mocking or constructor, which is potentially less painful)

      -- hotreload the SI of a node
      -- node->callp("set_script", args, 1, err) // Object::set_script(const Variant &p_script)
      -- local ret = executeCodeEx(stdcall, timeout, nodeAddr, args, error)

      -- GDI.destroy_string_name(methodSName)

      -- return error
    end

    --- reloads from the binary tokens
    ---@param nodeAddr number
    function GDAPI.revertGDScript(nodeAddr)
      assert(type(nodeAddr)=='number', 'Node addr has to be a number, instead got: '..type(nodeAddr))
      assert(isNotNullOrNil(GDDEFS.GDSCRIPT_RELOAD_INDX), 'vMethod index has to be defined')
      assert(checkForGDScript(nodeAddr), 'Node doesnt have gdscript')

      -- get gdscript and its vtable
      local gdscript = getNodeGDScript(nodeAddr) or 0
      local gdscriptVtable = readPointer(gdscript)

      -- get reload method
      local reloadMethodPtr = readPointer(gdscriptVtable + GDDEFS.GDSCRIPT_RELOAD_INDX*GDDEFS.PTRSIZE)
      if isNullOrNil(reloadMethodPtr) then error('method not found') end

      return executeCodeEx(0,nil,reloadMethodPtr,gdscript,1)
    end

  -- ///---///--///---///--///---///--///--///---///--///---///--///---///--/// Func

    --- returns a lua string for a map element
    ---@param mapElement number
    function getGDFunctionName(mapElement)
      local mapElementValue = readPointer(mapElement + GDDEFS.PTRSIZE * 2) -- it's after next and prev
      if isNullOrNil(mapElementValue) then
        sendDebugMessage('(hash)mapElementKey invalid');
        return 'F??'
      end

      return getStringNameStr(mapElementValue)
    end

    function getFuncObjectCodeAddr(funcAddr)
      assert(type(funcAddr) == 'number', "Func addr has to be a number, instead got: " .. type(funcAddr))
      return readPointer(funcAddr + GDDEFS.FUNC_CODE)
    end

    function getFuncObjectConstAddr(funcAddr)
      assert(type(funcAddr) == 'number', "Func addr has to be a number, instead got: " .. type(funcAddr))
      return readPointer(funcAddr + GDDEFS.FUNC_CONST)
    end

    --- returns a head element, tail element and (hash)Map size
    ---@param nodeAddr number
    function getNodeFuncMap(nodeContext)
      assert(type(nodeContext.addr) == 'number', "NodePtr should be a number, instead got: " .. type(nodeContext.addr))

      local scriptInstanceAddr = readPointer(nodeContext.addr + GDDEFS.GDSCRIPTINSTANCE)
      if isNullOrNil(scriptInstanceAddr) then
        sendDebugMessage('scriptInstance is invalid')
        return
      end

      local gdScriptAddr = readPointer(scriptInstanceAddr + GDDEFS.GDSCRIPT_REF)
      if isNullOrNil(gdScriptAddr) then
        sendDebugMessage('GDScript is invalid');
        return;
      end

      local mainElement = readPointer(gdScriptAddr + GDDEFS.FUNC_MAP) -- head or root depending on the version
      local lastElement = readPointer(gdScriptAddr + GDDEFS.FUNC_MAP + GDDEFS.PTRSIZE) -- tail or end
      local mapSize = readInteger(gdScriptAddr + GDDEFS.FUNC_MAP + GDDEFS.MAP_SIZE) -- hashmap or map
      if isNullOrNil(mainElement) or isNullOrNil(lastElement) or isNullOrNil(mapSize) then
        sendDebugMessage('Const: (hash)map is not found')
        return; -- return to skip if the const map is absent
      end
      if GDDEFS.MAJOR_VER == 4 then
        return mainElement, lastElement, mapSize, nodeContext
      else
        if funcStructElement then
          funcStructElement.ChildStruct = createStructure('ConstMapRes')
        end
        return getLeftmostMapElem(mainElement, lastElement, mapSize, nodeContext)
      end
    end

    --- gets a functionPtr by nodename (root children) and funcname
    ---@param nodeAddr number
    ---@param funcName string
    function GDAPI.getGDFunctionFromNode(nodeAddr, funcName)
      assert(type(nodeAddr) == 'number', "Node addr has to be a number, instead got: " .. type(nodeAddr))
      assert(type(funcName) == 'string', "Func name has to be a string, instead got: " .. type(funcName))
      assert(checkForGDScript(nodeAddr) == true, "Node addr doesn't have a GDScript" )

      local gdScriptName = getNodeNameFromGDScript(nodeAddr) or "N??"
      local nodeMapContext = { addr = nodeAddr, name = '', gdname = '', memrec = nil, struct = nil, symbol = funcName or '' }
      local headElement, tailElement, mapSize, currentContainer = getNodeFuncMap(nodeMapContext)
      return findMapEntryByName(headElement, funcName, getFunctionMapName, getFunctionMapLookupResult, advanceFunctionMapElement)
    end

    --- patch a function's code with the bytes starting at an arbitrary pos
    ---@param funcObjAddr number
    ---@param patchToBytes table
    ---@param startPos number @0-based position to start patching from
    function GDAPI.patchGDFunction( funcObjAddr, patchToBytes, startPos  )
      assert(type(funcObjAddr) == 'number', "Func addr has to be a number, instead got: " .. type(funcObjAddr))
      assert(type(patchToBytes) == 'table', "Patch Bytes have to be a table, instead got: " .. type(patchToBytes))

      local position = startPos or 0x0
      local funcCode = getFuncObjectCodeAddr(funcObjAddr)
      if isNullOrNil(funcCode) then error("function code is invalid") end

      for _, opcode in ipairs(patchToBytes) do
        writeInteger( funcCode + position*4, opcode )
        position=position+1
      end
    end

    --- patch a function's constant with a value
    ---@param funcObjAddr number
    ---@param constIndex number@0-based position to start patching from
    ---@param CEvalueType number@type must match
    ---@param value number
    function GDAPI.patchGDFunctionConst( funcObjAddr, constIndex, CEvalueType, value  )
      assert(type(funcObjAddr) == 'number', "Func addr has to be a number, instead got: " .. type(funcObjAddr))
      assert(type(constIndex) == 'number', "Const index must be a number, instead got: " .. type(constIndex))
      assert(type(value) == 'number', "value has to be a number, instead got: " .. type(value))
      assert(type(CEvalueType) == 'number', "ce value type has to be a number, instead got: " .. type(CEvalueType))

      local funcConstAddr = getFuncObjectConstAddr(funcObjAddr)
      if isNullOrNil(funcConstAddr) then error("function const addr is invalid") end

      local vectorSize = readInteger(funcConstAddr - GDDEFS.SIZE_VECTOR)
      local sizeOfVariant, ok = redefineVariantSizeByVector(funcConstAddr, vectorSize)
      if not ok then error("size refedinition failed") end
      local targetConstAddr = getVariantByIndex(funcConstAddr, constIndex, sizeOfVariant)

      -- todo: base it on handlers
      if vtByte then
        writeByte(targetConstAddr, value)
      elseif vtDword then
        writeInteger(targetConstAddr, value, true)
      elseif vtDouble then
        writeDouble(targetConstAddr, value)
      elseif vtQword then
        writeQword(targetConstAddr, value)
      else
        error("yet unhandled type")
      end
    end

    --- iterates a function map and adds it to a struct
    ---@param nodeAddr number
    ---@param funcStructElement userdata
    function iterateNodeFuncMapToStruct(nodeContext)
      assert(type(nodeContext.addr) == 'number', 'nodeAddr has to be a number, instead got: ' .. type(nodeContext.addr))

      local nodeMapContext = { addr = nodeContext.addr, name = nodeContext.name, gdname = nodeContext.gdname, memrec = nodeContext.memrec, struct = nodeContext.struct, symbol = nodeContext.symbol }
      local headElement, tailElement, mapSize, nodeMapContext = getNodeFuncMap(nodeMapContext)
      if isNullOrNil(headElement) or isNullOrNil(mapSize) then
        sendDebugMessage('(hash)map empty?: ' .. " Address " .. numtohexstr(nodeContext.addr))
        return;
      end
      local mapElement = headElement
      local index = 0;

      repeat
        -- sendDebugMessage('Looping '.." mapElemAddr: "..numtohexstr(mapElement))

        local funcName = getFunctionMapName(mapElement) or "UNKNOWN" -- the layout is similar to constant map's

        emitFunctionStructEntry(nodeMapContext.struct, mapElement, funcName)

        index = index + 1
        mapElement = advanceFunctionMapElement(mapElement)
        if mapElement ~= 0 then
          nodeMapContext.struct = createNextFunctionContainer(nodeMapContext.struct, index)
        end
      until (mapElement == 0)

      return
    end

    function iterateFuncConstantsToStruct(funcConstantVect, funcConstantStructElem)

      if isNullOrNil(funcConstantVect) then
        sendDebugMessage('func vector invalid')
        return
      end

      local vectorSize = readInteger(funcConstantVect - GDDEFS.SIZE_VECTOR)
      if isNullOrNil(vectorSize) then
        sendDebugMessage('vector size invalid')
        return;
      end

      local variantSize, ok = redefineVariantSizeByVector(funcConstantVect, vectorSize)

      if not ok then
        sendDebugMessage("Variant resize failed")
        return
      end
      local emitter = GDEmitters.StructEmitter

      for variantIndex = 0, (vectorSize - 1) do
        local entry = readFunctionConstantEntry(funcConstantVect, variantIndex, variantSize)
        local contextTable =
        {
          nodeAddr = 0,
          nodeName = "FunctionConst",
          baseAddress = entry.variantPtr,
          symbol = ''
        }
        local handler = GDHandlers.VariantHandlers[entry.typeName] or GDHandlers.VariantHandlers.DEFAULT
        handler(entry, emitter, funcConstantStructElem, contextTable)
      end

      return;
    end

    function iterateFuncGlobalsToStruct(funcGlobalVect, funcGlobalNameStructElem)
      if isNullOrNil(funcGlobalVect) then
        sendDebugMessage('funcGlobalVect invalid')
        return;
      end

      local vectorSize = readInteger(funcGlobalVect - GDDEFS.SIZE_VECTOR)
      if isNullOrNil(vectorSize) then
        sendDebugMessage('vector size invalid')
        return;
      end

      for variantIndex = 0, (vectorSize - 1) do
        local entryOffset = variantIndex * GDDEFS.PTRSIZE
        local label = "GlobName[" .. variantIndex .. "] stringName"
        local stringFieldLabel = "GlobName[" .. variantIndex .. "] string"
        local stringNamePtr = readPointer(funcGlobalVect + entryOffset)
        local bUniShift = false

        if isPointerNotNull(stringNamePtr) then
          bUniShift = isPointerNotNull(stringNamePtr + GDDEFS.STRING)
        end

        -- sendDebugMessage('Looping: label: '..label.." funcVector: "..numtohexstr(funcGlobalVect))

        emitStringNameStruct(funcGlobalNameStructElem, label, entryOffset, stringFieldLabel, bUniShift)
      end

      return;
    end

    local function defineGDFunctionEnums()
      GDF = {}

      local function buildReverseTable(tab)
        local reversedTable = {}
        for i, v in ipairs(tab) do
          reversedTable[v] = i - 1
        end
        return reversedTable
      end

      local function cloneArray(tabl)
        local result = {}
        for i, val in ipairs(tabl) do
          result[i] = val
        end
        return result
      end

      local function insertValueBefore(list, anchor, valueToInsert)
        for i, val in ipairs(list) do
          if val == anchor then
            table.insert(list, i, valueToInsert)
            return
          end
        end
        error("insertValueBefore: anchor not found: " .. tostring(anchor))
      end

      local function insertValueAfter(list, anchor, valueToInsert)
        for i, val in ipairs(list) do
          if val == anchor then
            table.insert(list, i + 1, valueToInsert)
            return
          end
        end
        error("insertValueAfter: anchor not found: " .. tostring(anchor))
      end

      local function removeValue(list, valueToRemove)
        for i, v in ipairs(list) do
          if v == valueToRemove then
            table.remove(list, i)
            return
          end
        end
        error("removeValue: value not found: " .. tostring(valueToRemove))
      end

      local function applyPatchOnList(list, patch)
        if patch.kind == "insertValueBefore" then
          insertValueBefore(list, patch.anchor, patch.value)
        elseif patch.kind == "insertValueAfter" then
          insertValueAfter(list, patch.anchor, patch.value)
        elseif patch.kind == "removeValue" then
          removeValue(list, patch.value)
        else
          error("Unknown patch kind: " .. tostring(patch.kind))
        end
      end

      local function prepareProfileSpec(version, bVisited)
        local spec = GDF.ProfileSpecs[version]
        if not spec then
          error("Unknown version: " .. tostring(version))
        end

        bVisited = bVisited or {}
        if bVisited[version] then
          error("Circular profile inheritance for version: " .. tostring(version))
        end
        bVisited[version] = true

        local resolvedProfileSpec =
        {
          version = version,
          decoderName = spec.decoderName,
          orderedOpcodes = nil
        }

        if spec.base then
          local parent = prepareProfileSpec(spec.base, bVisited)
          resolvedProfileSpec.orderedOpcodes = cloneArray(parent.orderedOpcodes)

          if spec.patches then
            for _, patch in ipairs(spec.patches) do
              applyPatchOnList(resolvedProfileSpec.orderedOpcodes, patch)
            end
          end
        else
          resolvedProfileSpec.orderedOpcodes = cloneArray(spec.orderedOpcodes or {})
        end

        return resolvedProfileSpec
      end

      local function createProfileFromVersion(version)
        local resolvedProfileSpec = prepareProfileSpec(version)
        local decoder = GDF.Decoders[resolvedProfileSpec.decoderName]

        if not decoder then
          error("Unknown decoder: " .. tostring(resolvedProfileSpec.decoderName))
        end

        local profile =
        {
          version = version,
          decoder = decoder,
          orderedOpcodes = cloneArray(resolvedProfileSpec.orderedOpcodes),
          OPHandlerDefFromOPEnum = {},
          OPEnumFromInternalOPID = {},
          opNameFromOPEnum = {}
        }

        for i, internalOpcodeID in ipairs(profile.orderedOpcodes) do
          local opcodeEnum = i - 1
          local disasmHandlerDef = GDF.DisasmHandlers[internalOpcodeID]

          if not disasmHandlerDef then
            error("Missing DisasmHandlers entry for internalOpcodeID: " .. tostring(internalOpcodeID))
          end

          profile.OPHandlerDefFromOPEnum[opcodeEnum] = disasmHandlerDef
          profile.OPEnumFromInternalOPID[internalOpcodeID] = opcodeEnum
          profile.opNameFromOPEnum[opcodeEnum] = disasmHandlerDef.name
        end

        return profile
      end

      function GDF.createDisassemblerFromVersion(version)
        local profile = GDF.CompiledProfiles[version]
        if not profile then
          error("Unsupported version: " .. tostring(version))
        end

        local newDisassembler = {}
        newDisassembler.version = version
        newDisassembler.profile = profile

        function newDisassembler:getOPNameFromOPEnum(opcodeEnum)
          local handlerDef = self.profile.OPHandlerDefFromOPEnum[opcodeEnum]
          return handlerDef and handlerDef.name or nil
        end

        function newDisassembler:getOPEnumFromInternalOPID(internalOpcodeID)
          return self.profile.OPEnumFromInternalOPID[internalOpcodeID]
        end

        function newDisassembler:disassembleBytecode(codeInts, codeStructElement, instrPointer)
          local disasmContext =
          {
            opcodeName = '',
            codeStructElement = codeStructElement,
            instrPointer = 1,
            codeInts = codeInts,
            opcodeEnumRaw = nil,
            profile = self.profile
          }

          while disasmContext.instrPointer <= #disasmContext.codeInts do

            disasmContext.opcodeEnumRaw = disasmContext.codeInts[disasmContext.instrPointer]
            if disasmContext.opcodeEnumRaw == nil then
              break
            end

            local opcodeHandlerDef = self.profile.decoder.resolveOPHandlerDefFromProfile(self.profile, disasmContext.opcodeEnumRaw)
              if not opcodeHandlerDef then
                sendDebugMessage('handler not retrieved opcode: ' .. (disasmContext.opcodeEnumRaw or -1) .. (" | hex: %x"):format(disasmContext.opcodeEnumRaw or -1))
              end
              sendDebugMessage(("\topcode: %-4d\thex: %-4x\tname: %s"):format( (disasmContext.opcodeEnumRaw or -1), (disasmContext.opcodeEnumRaw or -1), (opcodeHandlerDef.name or "??")))
              disasmContext.opcodeName = opcodeHandlerDef.name
              local nextInstrPointer = opcodeHandlerDef.handler(disasmContext)
              if nextInstrPointer == nil then
                error( "Opcode handler returned nil for opcode: " .. disasmContext.opcodeName .. " at InstrPtr " .. disasmContext.instrPointer)
              end
              disasmContext.instrPointer = nextInstrPointer
          end

          return
        end

        return newDisassembler
      end

      if GDDEFS.MAJOR_VER == 4 then
        GDF.OP =
          {
            OPCODE_OPERATOR = "OPCODE_OPERATOR",
            OPCODE_OPERATOR_VALIDATED = "OPCODE_OPERATOR_VALIDATED",
            OPCODE_TYPE_TEST_BUILTIN = "OPCODE_TYPE_TEST_BUILTIN",
            OPCODE_TYPE_TEST_ARRAY = "OPCODE_TYPE_TEST_ARRAY",
            OPCODE_TYPE_TEST_DICTIONARY = "OPCODE_TYPE_TEST_DICTIONARY",
            OPCODE_TYPE_TEST_NATIVE = "OPCODE_TYPE_TEST_NATIVE",
            OPCODE_TYPE_TEST_SCRIPT = "OPCODE_TYPE_TEST_SCRIPT",
            OPCODE_SET_KEYED = "OPCODE_SET_KEYED",
            OPCODE_SET_KEYED_VALIDATED = "OPCODE_SET_KEYED_VALIDATED",
            OPCODE_SET_INDEXED_VALIDATED = "OPCODE_SET_INDEXED_VALIDATED",
            OPCODE_GET_KEYED = "OPCODE_GET_KEYED",
            OPCODE_GET_KEYED_VALIDATED = "OPCODE_GET_KEYED_VALIDATED",
            OPCODE_GET_INDEXED_VALIDATED = "OPCODE_GET_INDEXED_VALIDATED",
            OPCODE_SET_NAMED = "OPCODE_SET_NAMED",
            OPCODE_SET_NAMED_VALIDATED = "OPCODE_SET_NAMED_VALIDATED",
            OPCODE_GET_NAMED = "OPCODE_GET_NAMED",
            OPCODE_GET_NAMED_VALIDATED = "OPCODE_GET_NAMED_VALIDATED",
            OPCODE_SET_MEMBER = "OPCODE_SET_MEMBER",
            OPCODE_GET_MEMBER = "OPCODE_GET_MEMBER",
            OPCODE_SET_STATIC_VARIABLE = "OPCODE_SET_STATIC_VARIABLE",
            OPCODE_GET_STATIC_VARIABLE = "OPCODE_GET_STATIC_VARIABLE",
            OPCODE_ASSIGN = "OPCODE_ASSIGN",
            OPCODE_ASSIGN_NULL = "OPCODE_ASSIGN_NULL",
            OPCODE_ASSIGN_TRUE = "OPCODE_ASSIGN_TRUE",
            OPCODE_ASSIGN_FALSE = "OPCODE_ASSIGN_FALSE",
            OPCODE_ASSIGN_TYPED_BUILTIN = "OPCODE_ASSIGN_TYPED_BUILTIN",
            OPCODE_ASSIGN_TYPED_ARRAY = "OPCODE_ASSIGN_TYPED_ARRAY",
            OPCODE_ASSIGN_TYPED_DICTIONARY = "OPCODE_ASSIGN_TYPED_DICTIONARY",
            OPCODE_ASSIGN_TYPED_NATIVE = "OPCODE_ASSIGN_TYPED_NATIVE",
            OPCODE_ASSIGN_TYPED_SCRIPT = "OPCODE_ASSIGN_TYPED_SCRIPT",
            OPCODE_CAST_TO_BUILTIN = "OPCODE_CAST_TO_BUILTIN",
            OPCODE_CAST_TO_NATIVE = "OPCODE_CAST_TO_NATIVE",
            OPCODE_CAST_TO_SCRIPT = "OPCODE_CAST_TO_SCRIPT",
            OPCODE_CONSTRUCT = "OPCODE_CONSTRUCT",
            OPCODE_CONSTRUCT_VALIDATED = "OPCODE_CONSTRUCT_VALIDATED",
            OPCODE_CONSTRUCT_ARRAY = "OPCODE_CONSTRUCT_ARRAY",
            OPCODE_CONSTRUCT_TYPED_ARRAY = "OPCODE_CONSTRUCT_TYPED_ARRAY",
            OPCODE_CONSTRUCT_DICTIONARY = "OPCODE_CONSTRUCT_DICTIONARY",
            OPCODE_CONSTRUCT_TYPED_DICTIONARY = "OPCODE_CONSTRUCT_TYPED_DICTIONARY",
            OPCODE_CALL = "OPCODE_CALL",
            OPCODE_CALL_RETURN = "OPCODE_CALL_RETURN",
            OPCODE_CALL_ASYNC = "OPCODE_CALL_ASYNC",
            OPCODE_CALL_UTILITY = "OPCODE_CALL_UTILITY",
            OPCODE_CALL_UTILITY_VALIDATED = "OPCODE_CALL_UTILITY_VALIDATED",
            OPCODE_CALL_GDSCRIPT_UTILITY = "OPCODE_CALL_GDSCRIPT_UTILITY",
            OPCODE_CALL_BUILTIN_TYPE_VALIDATED = "OPCODE_CALL_BUILTIN_TYPE_VALIDATED",
            OPCODE_CALL_SELF_BASE = "OPCODE_CALL_SELF_BASE",
            OPCODE_CALL_METHOD_BIND = "OPCODE_CALL_METHOD_BIND",
            OPCODE_CALL_METHOD_BIND_RET = "OPCODE_CALL_METHOD_BIND_RET",
            OPCODE_CALL_BUILTIN_STATIC = "OPCODE_CALL_BUILTIN_STATIC",
            OPCODE_CALL_NATIVE_STATIC = "OPCODE_CALL_NATIVE_STATIC",
            OPCODE_CALL_NATIVE_STATIC_VALIDATED_RETURN = "OPCODE_CALL_NATIVE_STATIC_VALIDATED_RETURN",
            OPCODE_CALL_NATIVE_STATIC_VALIDATED_NO_RETURN = "OPCODE_CALL_NATIVE_STATIC_VALIDATED_NO_RETURN",
            OPCODE_CALL_METHOD_BIND_VALIDATED_RETURN = "OPCODE_CALL_METHOD_BIND_VALIDATED_RETURN",
            OPCODE_CALL_METHOD_BIND_VALIDATED_NO_RETURN = "OPCODE_CALL_METHOD_BIND_VALIDATED_NO_RETURN",
            OPCODE_AWAIT = "OPCODE_AWAIT",
            OPCODE_AWAIT_RESUME = "OPCODE_AWAIT_RESUME",
            OPCODE_CREATE_LAMBDA = "OPCODE_CREATE_LAMBDA",
            OPCODE_CREATE_SELF_LAMBDA = "OPCODE_CREATE_SELF_LAMBDA",
            OPCODE_JUMP = "OPCODE_JUMP",
            OPCODE_JUMP_IF = "OPCODE_JUMP_IF",
            OPCODE_JUMP_IF_NOT = "OPCODE_JUMP_IF_NOT",
            OPCODE_JUMP_TO_DEF_ARGUMENT = "OPCODE_JUMP_TO_DEF_ARGUMENT",
            OPCODE_JUMP_IF_SHARED = "OPCODE_JUMP_IF_SHARED",
            OPCODE_RETURN = "OPCODE_RETURN",
            OPCODE_RETURN_TYPED_BUILTIN = "OPCODE_RETURN_TYPED_BUILTIN",
            OPCODE_RETURN_TYPED_ARRAY = "OPCODE_RETURN_TYPED_ARRAY",
            OPCODE_RETURN_TYPED_DICTIONARY = "OPCODE_RETURN_TYPED_DICTIONARY",
            OPCODE_RETURN_TYPED_NATIVE = "OPCODE_RETURN_TYPED_NATIVE",
            OPCODE_RETURN_TYPED_SCRIPT = "OPCODE_RETURN_TYPED_SCRIPT",
            OPCODE_ITERATE_BEGIN = "OPCODE_ITERATE_BEGIN",
            OPCODE_ITERATE_BEGIN_INT = "OPCODE_ITERATE_BEGIN_INT",
            OPCODE_ITERATE_BEGIN_FLOAT = "OPCODE_ITERATE_BEGIN_FLOAT",
            OPCODE_ITERATE_BEGIN_VECTOR2 = "OPCODE_ITERATE_BEGIN_VECTOR2",
            OPCODE_ITERATE_BEGIN_VECTOR2I = "OPCODE_ITERATE_BEGIN_VECTOR2I",
            OPCODE_ITERATE_BEGIN_VECTOR3 = "OPCODE_ITERATE_BEGIN_VECTOR3",
            OPCODE_ITERATE_BEGIN_VECTOR3I = "OPCODE_ITERATE_BEGIN_VECTOR3I",
            OPCODE_ITERATE_BEGIN_STRING = "OPCODE_ITERATE_BEGIN_STRING",
            OPCODE_ITERATE_BEGIN_DICTIONARY = "OPCODE_ITERATE_BEGIN_DICTIONARY",
            OPCODE_ITERATE_BEGIN_ARRAY = "OPCODE_ITERATE_BEGIN_ARRAY",
            OPCODE_ITERATE_BEGIN_PACKED_BYTE_ARRAY = "OPCODE_ITERATE_BEGIN_PACKED_BYTE_ARRAY",
            OPCODE_ITERATE_BEGIN_PACKED_INT32_ARRAY = "OPCODE_ITERATE_BEGIN_PACKED_INT32_ARRAY",
            OPCODE_ITERATE_BEGIN_PACKED_INT64_ARRAY = "OPCODE_ITERATE_BEGIN_PACKED_INT64_ARRAY",
            OPCODE_ITERATE_BEGIN_PACKED_FLOAT32_ARRAY = "OPCODE_ITERATE_BEGIN_PACKED_FLOAT32_ARRAY",
            OPCODE_ITERATE_BEGIN_PACKED_FLOAT64_ARRAY = "OPCODE_ITERATE_BEGIN_PACKED_FLOAT64_ARRAY",
            OPCODE_ITERATE_BEGIN_PACKED_STRING_ARRAY = "OPCODE_ITERATE_BEGIN_PACKED_STRING_ARRAY",
            OPCODE_ITERATE_BEGIN_PACKED_VECTOR2_ARRAY = "OPCODE_ITERATE_BEGIN_PACKED_VECTOR2_ARRAY",
            OPCODE_ITERATE_BEGIN_PACKED_VECTOR3_ARRAY = "OPCODE_ITERATE_BEGIN_PACKED_VECTOR3_ARRAY",
            OPCODE_ITERATE_BEGIN_PACKED_COLOR_ARRAY = "OPCODE_ITERATE_BEGIN_PACKED_COLOR_ARRAY",
            OPCODE_ITERATE_BEGIN_PACKED_VECTOR4_ARRAY = "OPCODE_ITERATE_BEGIN_PACKED_VECTOR4_ARRAY",
            OPCODE_ITERATE_BEGIN_OBJECT = "OPCODE_ITERATE_BEGIN_OBJECT",
            OPCODE_ITERATE_BEGIN_RANGE = "OPCODE_ITERATE_BEGIN_RANGE",
            OPCODE_ITERATE = "OPCODE_ITERATE",
            OPCODE_ITERATE_INT = "OPCODE_ITERATE_INT",
            OPCODE_ITERATE_FLOAT = "OPCODE_ITERATE_FLOAT",
            OPCODE_ITERATE_VECTOR2 = "OPCODE_ITERATE_VECTOR2",
            OPCODE_ITERATE_VECTOR2I = "OPCODE_ITERATE_VECTOR2I",
            OPCODE_ITERATE_VECTOR3 = "OPCODE_ITERATE_VECTOR3",
            OPCODE_ITERATE_VECTOR3I = "OPCODE_ITERATE_VECTOR3I",
            OPCODE_ITERATE_STRING = "OPCODE_ITERATE_STRING",
            OPCODE_ITERATE_DICTIONARY = "OPCODE_ITERATE_DICTIONARY",
            OPCODE_ITERATE_ARRAY = "OPCODE_ITERATE_ARRAY",
            OPCODE_ITERATE_PACKED_BYTE_ARRAY = "OPCODE_ITERATE_PACKED_BYTE_ARRAY",
            OPCODE_ITERATE_PACKED_INT32_ARRAY = "OPCODE_ITERATE_PACKED_INT32_ARRAY",
            OPCODE_ITERATE_PACKED_INT64_ARRAY = "OPCODE_ITERATE_PACKED_INT64_ARRAY",
            OPCODE_ITERATE_PACKED_FLOAT32_ARRAY = "OPCODE_ITERATE_PACKED_FLOAT32_ARRAY",
            OPCODE_ITERATE_PACKED_FLOAT64_ARRAY = "OPCODE_ITERATE_PACKED_FLOAT64_ARRAY",
            OPCODE_ITERATE_PACKED_STRING_ARRAY = "OPCODE_ITERATE_PACKED_STRING_ARRAY",
            OPCODE_ITERATE_PACKED_VECTOR2_ARRAY = "OPCODE_ITERATE_PACKED_VECTOR2_ARRAY",
            OPCODE_ITERATE_PACKED_VECTOR3_ARRAY = "OPCODE_ITERATE_PACKED_VECTOR3_ARRAY",
            OPCODE_ITERATE_PACKED_COLOR_ARRAY = "OPCODE_ITERATE_PACKED_COLOR_ARRAY",
            OPCODE_ITERATE_PACKED_VECTOR4_ARRAY = "OPCODE_ITERATE_PACKED_VECTOR4_ARRAY",
            OPCODE_ITERATE_OBJECT = "OPCODE_ITERATE_OBJECT",
            OPCODE_ITERATE_RANGE = "OPCODE_ITERATE_RANGE",
            OPCODE_STORE_GLOBAL = "OPCODE_STORE_GLOBAL",
            OPCODE_STORE_NAMED_GLOBAL = "OPCODE_STORE_NAMED_GLOBAL",
            OPCODE_TYPE_ADJUST_BOOL = "OPCODE_TYPE_ADJUST_BOOL",
            OPCODE_TYPE_ADJUST_INT = "OPCODE_TYPE_ADJUST_INT",
            OPCODE_TYPE_ADJUST_FLOAT = "OPCODE_TYPE_ADJUST_FLOAT",
            OPCODE_TYPE_ADJUST_STRING = "OPCODE_TYPE_ADJUST_STRING",
            OPCODE_TYPE_ADJUST_VECTOR2 = "OPCODE_TYPE_ADJUST_VECTOR2",
            OPCODE_TYPE_ADJUST_VECTOR2I = "OPCODE_TYPE_ADJUST_VECTOR2I",
            OPCODE_TYPE_ADJUST_RECT2 = "OPCODE_TYPE_ADJUST_RECT2",
            OPCODE_TYPE_ADJUST_RECT2I = "OPCODE_TYPE_ADJUST_RECT2I",
            OPCODE_TYPE_ADJUST_VECTOR3 = "OPCODE_TYPE_ADJUST_VECTOR3",
            OPCODE_TYPE_ADJUST_VECTOR3I = "OPCODE_TYPE_ADJUST_VECTOR3I",
            OPCODE_TYPE_ADJUST_TRANSFORM2D = "OPCODE_TYPE_ADJUST_TRANSFORM2D",
            OPCODE_TYPE_ADJUST_VECTOR4 = "OPCODE_TYPE_ADJUST_VECTOR4",
            OPCODE_TYPE_ADJUST_VECTOR4I = "OPCODE_TYPE_ADJUST_VECTOR4I",
            OPCODE_TYPE_ADJUST_PLANE = "OPCODE_TYPE_ADJUST_PLANE",
            OPCODE_TYPE_ADJUST_QUATERNION = "OPCODE_TYPE_ADJUST_QUATERNION",
            OPCODE_TYPE_ADJUST_AABB = "OPCODE_TYPE_ADJUST_AABB",
            OPCODE_TYPE_ADJUST_BASIS = "OPCODE_TYPE_ADJUST_BASIS",
            OPCODE_TYPE_ADJUST_TRANSFORM3D = "OPCODE_TYPE_ADJUST_TRANSFORM3D",
            OPCODE_TYPE_ADJUST_PROJECTION = "OPCODE_TYPE_ADJUST_PROJECTION",
            OPCODE_TYPE_ADJUST_COLOR = "OPCODE_TYPE_ADJUST_COLOR",
            OPCODE_TYPE_ADJUST_STRING_NAME = "OPCODE_TYPE_ADJUST_STRING_NAME",
            OPCODE_TYPE_ADJUST_NODE_PATH = "OPCODE_TYPE_ADJUST_NODE_PATH",
            OPCODE_TYPE_ADJUST_RID = "OPCODE_TYPE_ADJUST_RID",
            OPCODE_TYPE_ADJUST_OBJECT = "OPCODE_TYPE_ADJUST_OBJECT",
            OPCODE_TYPE_ADJUST_CALLABLE = "OPCODE_TYPE_ADJUST_CALLABLE",
            OPCODE_TYPE_ADJUST_SIGNAL = "OPCODE_TYPE_ADJUST_SIGNAL",
            OPCODE_TYPE_ADJUST_DICTIONARY = "OPCODE_TYPE_ADJUST_DICTIONARY",
            OPCODE_TYPE_ADJUST_ARRAY = "OPCODE_TYPE_ADJUST_ARRAY",
            OPCODE_TYPE_ADJUST_PACKED_BYTE_ARRAY = "OPCODE_TYPE_ADJUST_PACKED_BYTE_ARRAY",
            OPCODE_TYPE_ADJUST_PACKED_INT32_ARRAY = "OPCODE_TYPE_ADJUST_PACKED_INT32_ARRAY",
            OPCODE_TYPE_ADJUST_PACKED_INT64_ARRAY = "OPCODE_TYPE_ADJUST_PACKED_INT64_ARRAY",
            OPCODE_TYPE_ADJUST_PACKED_FLOAT32_ARRAY = "OPCODE_TYPE_ADJUST_PACKED_FLOAT32_ARRAY",
            OPCODE_TYPE_ADJUST_PACKED_FLOAT64_ARRAY = "OPCODE_TYPE_ADJUST_PACKED_FLOAT64_ARRAY",
            OPCODE_TYPE_ADJUST_PACKED_STRING_ARRAY = "OPCODE_TYPE_ADJUST_PACKED_STRING_ARRAY",
            OPCODE_TYPE_ADJUST_PACKED_VECTOR2_ARRAY = "OPCODE_TYPE_ADJUST_PACKED_VECTOR2_ARRAY",
            OPCODE_TYPE_ADJUST_PACKED_VECTOR3_ARRAY = "OPCODE_TYPE_ADJUST_PACKED_VECTOR3_ARRAY",
            OPCODE_TYPE_ADJUST_PACKED_COLOR_ARRAY = "OPCODE_TYPE_ADJUST_PACKED_COLOR_ARRAY",
            OPCODE_TYPE_ADJUST_PACKED_VECTOR4_ARRAY = "OPCODE_TYPE_ADJUST_PACKED_VECTOR4_ARRAY",
            OPCODE_ASSERT = "OPCODE_ASSERT",
            OPCODE_BREAKPOINT = "OPCODE_BREAKPOINT",
            OPCODE_LINE = "OPCODE_LINE",
            OPCODE_END = "OPCODE_END",

            OPCODE_CALL_PTRCALL_NO_RETURN = "OPCODE_CALL_PTRCALL_NO_RETURN",
            OPCODE_CALL_PTRCALL_BOOL = "OPCODE_CALL_PTRCALL_BOOL",
            OPCODE_CALL_PTRCALL_INT = "OPCODE_CALL_PTRCALL_INT",
            OPCODE_CALL_PTRCALL_FLOAT = "OPCODE_CALL_PTRCALL_FLOAT",
            OPCODE_CALL_PTRCALL_STRING = "OPCODE_CALL_PTRCALL_STRING",
            OPCODE_CALL_PTRCALL_VECTOR2 = "OPCODE_CALL_PTRCALL_VECTOR2",
            OPCODE_CALL_PTRCALL_VECTOR2I = "OPCODE_CALL_PTRCALL_VECTOR2I",
            OPCODE_CALL_PTRCALL_RECT2 = "OPCODE_CALL_PTRCALL_RECT2",
            OPCODE_CALL_PTRCALL_RECT2I = "OPCODE_CALL_PTRCALL_RECT2I",
            OPCODE_CALL_PTRCALL_VECTOR3 = "OPCODE_CALL_PTRCALL_VECTOR3",
            OPCODE_CALL_PTRCALL_VECTOR3I = "OPCODE_CALL_PTRCALL_VECTOR3I",
            OPCODE_CALL_PTRCALL_TRANSFORM2D = "OPCODE_CALL_PTRCALL_TRANSFORM2D",
            OPCODE_CALL_PTRCALL_VECTOR4 = "OPCODE_CALL_PTRCALL_VECTOR4",
            OPCODE_CALL_PTRCALL_VECTOR4I = "OPCODE_CALL_PTRCALL_VECTOR4I",
            OPCODE_CALL_PTRCALL_PLANE = "OPCODE_CALL_PTRCALL_PLANE",
            OPCODE_CALL_PTRCALL_QUATERNION = "OPCODE_CALL_PTRCALL_QUATERNION",
            OPCODE_CALL_PTRCALL_AABB = "OPCODE_CALL_PTRCALL_AABB",
            OPCODE_CALL_PTRCALL_BASIS = "OPCODE_CALL_PTRCALL_BASIS",
            OPCODE_CALL_PTRCALL_TRANSFORM3D = "OPCODE_CALL_PTRCALL_TRANSFORM3D",
            OPCODE_CALL_PTRCALL_PROJECTION = "OPCODE_CALL_PTRCALL_PROJECTION",
            OPCODE_CALL_PTRCALL_COLOR = "OPCODE_CALL_PTRCALL_COLOR",
            OPCODE_CALL_PTRCALL_STRING_NAME = "OPCODE_CALL_PTRCALL_STRING_NAME",
            OPCODE_CALL_PTRCALL_NODE_PATH = "OPCODE_CALL_PTRCALL_NODE_PATH",
            OPCODE_CALL_PTRCALL_RID = "OPCODE_CALL_PTRCALL_RID",
            OPCODE_CALL_PTRCALL_OBJECT = "OPCODE_CALL_PTRCALL_OBJECT",
            OPCODE_CALL_PTRCALL_CALLABLE = "OPCODE_CALL_PTRCALL_CALLABLE",
            OPCODE_CALL_PTRCALL_SIGNAL = "OPCODE_CALL_PTRCALL_SIGNAL",
            OPCODE_CALL_PTRCALL_DICTIONARY = "OPCODE_CALL_PTRCALL_DICTIONARY",
            OPCODE_CALL_PTRCALL_ARRAY = "OPCODE_CALL_PTRCALL_ARRAY",
            OPCODE_CALL_PTRCALL_PACKED_BYTE_ARRAY = "OPCODE_CALL_PTRCALL_PACKED_BYTE_ARRAY",
            OPCODE_CALL_PTRCALL_PACKED_INT32_ARRAY = "OPCODE_CALL_PTRCALL_PACKED_INT32_ARRAY",
            OPCODE_CALL_PTRCALL_PACKED_INT64_ARRAY = "OPCODE_CALL_PTRCALL_PACKED_INT64_ARRAY",
            OPCODE_CALL_PTRCALL_PACKED_FLOAT32_ARRAY = "OPCODE_CALL_PTRCALL_PACKED_FLOAT32_ARRAY",
            OPCODE_CALL_PTRCALL_PACKED_FLOAT64_ARRAY = "OPCODE_CALL_PTRCALL_PACKED_FLOAT64_ARRAY",
            OPCODE_CALL_PTRCALL_PACKED_STRING_ARRAY = "OPCODE_CALL_PTRCALL_PACKED_STRING_ARRAY",
            OPCODE_CALL_PTRCALL_PACKED_VECTOR2_ARRAY = "OPCODE_CALL_PTRCALL_PACKED_VECTOR2_ARRAY",
            OPCODE_CALL_PTRCALL_PACKED_VECTOR3_ARRAY = "OPCODE_CALL_PTRCALL_PACKED_VECTOR3_ARRAY",
            OPCODE_CALL_PTRCALL_PACKED_COLOR_ARRAY = "OPCODE_CALL_PTRCALL_PACKED_COLOR_ARRAY"
          }
        GDF.DisasmHandlers = {}

          GDF.DisasmHandlers[GDF.OP.OPCODE_OPERATOR] =
            {
              name = "OPCODE_OPERATOR",
              handler = function(contextTable)
                local _pointer_size = GDDEFS.PTRSIZE / 0x4

                local operation = contextTable.codeInts[contextTable.instrPointer + 4] -- operator is 4*0x4 after
                addStructureElem(contextTable.codeStructElement, 'Operator: ', (contextTable.instrPointer - 1 + 4) * 0x4, vtDword)

                local operationName = GDF.OPERATOR_NAME[operation + 1] or 'UNKNOWN_OPERATOR'
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)
                local operand3 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 3]) -- where to store
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand3 .. ' = ' .. operand1 .. ' ' .. operationName .. ' ' .. operand2
                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 7 + _pointer_size -- incr += 5; in 4.0
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_OPERATOR_VALIDATED] =
            {
              name = "OPCODE_OPERATOR_VALIDATED",
              handler = function(contextTable)

                local operation = contextTable.codeInts[contextTable.instrPointer + 4] -- operator is 4*0x4 after
                addStructureElem(contextTable.codeStructElement, 'Operator: ', (contextTable.instrPointer - 1 + 4) * 0x4, vtDword)

                local operationName = GDF.OPERATOR_NAME[operation + 1] or 'UNKNOWN_OPERATOR' -- TODO not sure, is that the same thing: operator_names[_code_ptr[ip + 4]];
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)
                local operand3 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 3]) -- where to store
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3) * 0x4, vtDword)
                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand3 .. ' = ' .. operand1 .. ' ' .. operationName .. ' ' .. operand2
                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 5
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_TEST_BUILTIN] =
            {
              name = "OPCODE_TYPE_TEST_BUILTIN",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)
                local operand3 = getGDTypeName(contextTable.codeInts[contextTable.instrPointer + 3])
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3) * 0x4, vtDword)
                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand1 .. ' = ' .. operand2 .. ' is ' .. operand3
                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)
                return contextTable.instrPointer + 4
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_TEST_ARRAY] =
            {
              name = "OPCODE_TYPE_TEST_ARRAY",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)

                -- TODO create function constants lookup for disassembling
                local operand3 = getGDTypeName(contextTable.codeInts[contextTable.instrPointer + 4])
                -- Ref<Script> script_type = get_constant(_code_ptr[ip + 3] & ADDR_MASK);
                -- Variant::Type builtin_type = (Variant::Type)_code_ptr[ip + 4];
                -- StringName native_type = get_global_name(_code_ptr[ip + 5]);

                -- if (script_type.is_valid() && script_type->is_valid()) {
                --     text += "script(";
                --     text += GDScript::debug_get_script_name(script_type);
                --     text += ")";
                -- } else if (native_type != StringName()) {
                --     text += native_type;
                -- } else {
                --     text += Variant::get_type_name(builtin_type);
                -- }
                addStructureElem(contextTable.codeStructElement, 'script_type', (contextTable.instrPointer - 1 + 3) * 0x4, vtDword)
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 4) * 0x4, vtDword)
                addStructureElem(contextTable.codeStructElement, 'native_type', (contextTable.instrPointer - 1 + 5) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand1 .. ' = ' .. operand2 .. ' is Dictionary[' .. operand3 .. ']'
                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 6
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_TEST_DICTIONARY] =
            {
              name = "OPCODE_TYPE_TEST_DICTIONARY",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)

                local operand5 = getGDTypeName(contextTable.codeInts[contextTable.instrPointer + 5])
                local operand7 = getGDTypeName(contextTable.codeInts[contextTable.instrPointer + 7])
                -- Ref<Script> key_script_type = get_constant(_code_ptr[ip + 3] & ADDR_MASK);
                -- Variant::Type key_builtin_type = (Variant::Type)_code_ptr[ip + 5];
                -- StringName key_native_type = get_global_name(_code_ptr[ip + 6]);

                -- if (key_script_type.is_valid() && key_script_type->is_valid()) {
                --                 text += "script(";
                --                 text += GDScript::debug_get_script_name(key_script_type);
                --                 text += ")";
                -- } else if (key_native_type != StringName()) {
                --                 text += key_native_type;
                -- } else {
                --                 text += Variant::get_type_name(key_builtin_type);
                -- }

                -- Ref<Script> value_script_type = get_constant(_code_ptr[ip + 4] & ADDR_MASK);
                -- Variant::Type value_builtin_type = (Variant::Type)_code_ptr[ip + 7];
                -- StringName value_native_type = get_global_name(_code_ptr[ip + 8]);

                -- if (value_script_type.is_valid() && value_script_type->is_valid()) {
                --     text += "script(";
                --     text += GDScript::debug_get_script_name(value_script_type);
                --     text += ")";
                -- } else if (value_native_type != StringName()) {
                --     text += value_native_type;
                -- } else {
                --     text += Variant::get_type_name(value_builtin_type);
                -- }

                addStructureElem(contextTable.codeStructElement, 'key_script_type', (contextTable.instrPointer - 1 + 3) * 0x4, vtDword)
                addStructureElem(contextTable.codeStructElement, operand5, (contextTable.instrPointer - 1 + 5) * 0x4, vtDword)
                addStructureElem(contextTable.codeStructElement, 'value_script_type', (contextTable.instrPointer - 1 + 4) * 0x4, vtDword)
                addStructureElem(contextTable.codeStructElement, operand7, (contextTable.instrPointer - 1 + 7) * 0x4, vtDword)
                addStructureElem(contextTable.codeStructElement, 'value_native_type', (contextTable.instrPointer - 1 + 8) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand1 .. ' = ' .. operand2 .. ' is Dictionary[' .. operand5 .. ']' .. ', ' .. operand7 .. ']'
                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)
                return contextTable.instrPointer + 9

              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_TEST_NATIVE] =
            {
              name = "OPCODE_TYPE_TEST_NATIVE",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)

                local operand3 = 'get_global_name(' .. (contextTable.codeInts[contextTable.instrPointer + 3]) .. ')'
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand1 .. ' = ' .. operand2 .. ' is ' .. operand3

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)
                return contextTable.instrPointer + 4
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_TEST_SCRIPT] =
            {
              name = "OPCODE_TYPE_TEST_SCRIPT",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword) -- dest
                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword) -- value
                local operand3 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 3])
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3) * 0x4, vtDword)
                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand1 .. ' = ' .. operand2 .. ' is ' .. operand3
                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)
                return contextTable.instrPointer + 4

              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_SET_KEYED] = 
            {
              name = "OPCODE_SET_KEYED",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)
                local operand3 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 3])
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3) * 0x4, vtDword)
                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand1 .. '[' .. operand2 .. '] = ' .. operand3
                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)
                return contextTable.instrPointer + 4
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_SET_KEYED_VALIDATED] = 
            {
              name = "OPCODE_SET_KEYED_VALIDATED",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)
                local operand3 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 3])
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand1 .. '[' .. operand2 .. '] = ' .. operand3

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)
                return contextTable.instrPointer + 5
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_SET_INDEXED_VALIDATED] = 
            {
              name = "OPCODE_SET_INDEXED_VALIDATED",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)
                local operand3 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 3])
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand1 .. '[' .. operand2 .. '] = ' .. operand3

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)
                return contextTable.instrPointer + 5
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_GET_KEYED] = 
            {
              name = "OPCODE_GET_KEYED",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)
                local operand3 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 3])
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand3 .. '[' .. operand1 .. '] = ' .. operand2

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 4
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_GET_KEYED_VALIDATED] = 
            {
              name = "OPCODE_GET_KEYED_VALIDATED",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)
                local operand3 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 3])
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand3 .. '[' .. operand1 .. '] = ' .. operand2

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 5
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_GET_INDEXED_VALIDATED] = 
            {
              name = "OPCODE_GET_INDEXED_VALIDATED",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)
                local operand3 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 3])
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand3 .. '[' .. operand1 .. '] = ' .. operand2

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 5
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_SET_NAMED] = 
            {
              name = "OPCODE_SET_NAMED",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)
                local operand3 = 'Globals[' .. contextTable.codeInts[contextTable.instrPointer + 3] .. ']'
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand1 .. '["' .. operand3 .. '"] = ' .. operand2

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 4
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_SET_NAMED_VALIDATED] = 
            {
              name = "OPCODE_SET_NAMED_VALIDATED",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)
                local operand3 = 'setter_names[' .. (contextTable.codeInts[contextTable.instrPointer + 3]) .. ']'
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3) * 0x4, vtDword)

                contextTable.opcodeName =
                    contextTable.opcodeName .. ' ' .. operand1 .. '["' .. operand3 .. '"] = ' .. operand2

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 4
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_GET_NAMED] = 
            {
              name = "OPCODE_GET_NAMED",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)
                local operand3 = 'Globals[' .. contextTable.codeInts[contextTable.instrPointer + 3] .. ']'
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand2 .. ' = ' .. operand1 .. '["' .. operand3 .. '"]'

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 4
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_GET_NAMED_VALIDATED] = 
            {
              name = "OPCODE_GET_NAMED_VALIDATED",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)
                local operand3 = 'getter_names[operand3]' -- TODO
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand2 .. ' = ' .. operand1 .. '["' .. operand3 .. '"]'

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 4
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_SET_MEMBER] = 
            {
              name = "OPCODE_SET_MEMBER",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                local operand2 = 'Globals[' .. contextTable.codeInts[contextTable.instrPointer + 2] .. ']'
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. '["' .. operand2 .. '"] = ' .. operand1

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 3
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_GET_MEMBER] = 
            {
              name = "OPCODE_GET_MEMBER",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                local operand2 = 'Globals[' .. contextTable.codeInts[contextTable.instrPointer + 2] .. ']'
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand1 .. ' = ["' .. operand2 .. '"]'

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 3
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_SET_STATIC_VARIABLE] = 
            {
              name = "OPCODE_SET_STATIC_VARIABLE",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                local operand2 = 'gdscript' -- TODO
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)
                local operand3 = 'debug_get_static_var_by_index(operand3)'
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' script(scriptname)[' .. operand3 .. '] = ' .. operand1

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 4
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_GET_STATIC_VARIABLE] = 
            {
              name = "OPCODE_GET_STATIC_VARIABLE",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                local operand2 = 'gdscript' -- TODO
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)
                local operand3 = 'debug_get_static_var_by_index(operand3)'
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand1 .. ' = script(scriptname)[' .. operand3 .. ']'

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 4
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ASSIGN] = 
            {
              name = "OPCODE_ASSIGN",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand1 .. ' = ' .. operand2

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 3
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ASSIGN_NULL] = 
            {
              name = "OPCODE_ASSIGN_NULL",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand1 .. ' = NULL'

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 2
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ASSIGN_TRUE] = 
            {
              name = "OPCODE_ASSIGN_TRUE",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand1 .. ' = TRUE'

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 2
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ASSIGN_FALSE] = 
            {
              name = "OPCODE_ASSIGN_FALSE",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand1 .. ' = FALSE'

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 2
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ASSIGN_TYPED_BUILTIN] = 
            {
              name = "OPCODE_ASSIGN_TYPED_BUILTIN",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)
                local operand3 = getGDTypeName(contextTable.codeInts[contextTable.instrPointer + 3])
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' (' .. operand3 .. ') ' .. operand1 .. ' = ' .. operand2

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 4
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ASSIGN_TYPED_ARRAY] = 
            {
              name = "OPCODE_ASSIGN_TYPED_ARRAY",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand1 .. ' = ' .. operand2

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 6
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ASSIGN_TYPED_DICTIONARY] = 
            {
              name = "OPCODE_ASSIGN_TYPED_DICTIONARY",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand1 .. ' = ' .. operand2

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 9
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ASSIGN_TYPED_NATIVE] = 
            {
              name = "OPCODE_ASSIGN_TYPED_NATIVE",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)
                local operand3 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 3])
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' (' .. operand3 .. ')' .. operand1 .. ' = ' .. operand2

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 4
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ASSIGN_TYPED_SCRIPT] = 
            {
              name = "OPCODE_ASSIGN_TYPED_SCRIPT",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)
                local operand3 = 'debug_get_script_name(get_constant(operand3))' -- TODO
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' (' .. operand3 .. ') ' .. operand1 .. ' = ' .. operand2

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 4
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CAST_TO_BUILTIN] = 
            {
              name = "OPCODE_CAST_TO_BUILTIN",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)
                local operand1_n = getGDTypeName(contextTable.codeInts[contextTable.instrPointer + 1])

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand2 .. ' = ' .. operand1 .. ' as ' .. operand1_n

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 4
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CAST_TO_NATIVE] = 
            {
              name = "OPCODE_CAST_TO_NATIVE",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)
                local operand3 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 3])
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand2 .. ' = ' .. operand1 .. ' as ' .. operand3

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 4
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CAST_TO_SCRIPT] = 
            {
              name = "OPCODE_CAST_TO_SCRIPT",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)
                local operand3 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 3])
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand2 .. ' = ' .. operand1 .. ' as ' .. operand3

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 4
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CONSTRUCT] = 
            {
              name = "OPCODE_CONSTRUCT",
              handler = function(contextTable)
                contextTable.instrPointer = contextTable.instrPointer + 1
                local instr_var_args = contextTable.codeInts[contextTable.instrPointer]
                addStructureElem(contextTable.codeStructElement, 'instr_var_args:', (contextTable.instrPointer - 1) * 0x4, vtDword)

                local typeName = getGDTypeName(contextTable.codeInts[contextTable.instrPointer + 3 + instr_var_args])
                addStructureElem(contextTable.codeStructElement, typeName, (contextTable.instrPointer - 1 + 3 + instr_var_args) * 0x4, vtDword)
                local argc = contextTable.codeInts[contextTable.instrPointer + 1 + instr_var_args]
                addStructureElem(contextTable.codeStructElement, 'argc:', (contextTable.instrPointer - 1 + 1 + instr_var_args) * 0x4, vtDword)

                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1 + argc])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1 + argc) * 0x4, vtDword)
                local operandArg = '';

                for i = 0, argc - 1 do
                  if i > 0 then
                    operandArg = operandArg .. ', '
                  end
                  operandArg = operandArg .. formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + i + 1])
                  addStructureElem(contextTable.codeStructElement, 'arg: ' .. formatDisassembledAddress(contextTable.codeInts[i + 1]), (contextTable.instrPointer - 1 + i + 1) * 0x4, vtDword)
                end

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand1 .. ' = ' .. typeName .. '(' .. operandArg .. ')'

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1 - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 3 + instr_var_args

              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CONSTRUCT_VALIDATED] = 
            {
              name = "OPCODE_CONSTRUCT_VALIDATED",
              handler = function(contextTable)
                contextTable.instrPointer = contextTable.instrPointer + 1
                local instr_var_args = contextTable.codeInts[contextTable.instrPointer]
                addStructureElem(contextTable.codeStructElement, 'instr_var_args:', (contextTable.instrPointer - 1) * 0x4, vtDword)
                local argc = contextTable.codeInts[contextTable.instrPointer + 1 + instr_var_args]
                addStructureElem(contextTable.codeStructElement, 'argc:', (contextTable.instrPointer - 1 + 1 + instr_var_args) * 0x4, vtDword)

                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1 + argc])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1 + argc) * 0x4, vtDword)
                local operandArg = '';
                local operand3 = 'constructors_names[' .. (contextTable.codeInts[contextTable.instrPointer + 3 + argc]) .. ']'
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3 + argc) * 0x4, vtDword)

                for i = 0, argc - 1 do
                  if i > 0 then
                    operandArg = operandArg .. ', '
                  end
                  operandArg = operandArg .. formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + i + 1] )
                  addStructureElem(contextTable.codeStructElement, 'arg: ' .. formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + i + 1]), (contextTable.instrPointer - 1 + i + 1) * 0x4, vtDword)
                end

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand1 .. ' = ' .. operand3 .. '(' .. operandArg .. ')'

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1 - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 3 + instr_var_args

              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CONSTRUCT_ARRAY] = 
            {
              name = "OPCODE_CONSTRUCT_ARRAY",
              handler = function(contextTable)
                contextTable.instrPointer = contextTable.instrPointer + 1
                local instr_var_args = contextTable.codeInts[contextTable.instrPointer]
                addStructureElem(contextTable.codeStructElement, 'instr_var_args:', (contextTable.instrPointer - 1) * 0x4, vtDword) -- offset to argc (hops over args and dest)
                local argc = contextTable.codeInts[contextTable.instrPointer + 1 + instr_var_args]
                addStructureElem(contextTable.codeStructElement, 'argc:', (contextTable.instrPointer - 1 + 1 + instr_var_args) * 0x4, vtDword)

                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1 + argc])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1 + argc) * 0x4, vtDword) -- dest
                local operandArg = '';

                for i = 0, argc - 1 do
                  if i > 0 then
                    operandArg = operandArg .. ', '
                  end
                  operandArg = operandArg .. formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + i + 1])
                  addStructureElem(contextTable.codeStructElement, 'arg: ' .. formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + i + 1]), (contextTable.instrPointer - 1 + i + 1) * 0x4, vtDword)
                end

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand1 .. ' = ' .. '[' .. operandArg .. ']'

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1 - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 3 + argc
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CONSTRUCT_TYPED_ARRAY] = 
            {
              name = "OPCODE_CONSTRUCT_TYPED_ARRAY",
              handler = function(contextTable)
                contextTable.instrPointer = contextTable.instrPointer + 1
                local instr_var_args = contextTable.codeInts[contextTable.instrPointer]
                addStructureElem(contextTable.codeStructElement, 'instr_var_args:', (contextTable.instrPointer - 1) * 0x4, vtDword)
                local argc = contextTable.codeInts[contextTable.instrPointer + 1 + instr_var_args]
                addStructureElem(contextTable.codeStructElement, 'argc:', (contextTable.instrPointer - 1 + 1 + instr_var_args) * 0x4, vtDword)

                local operand2 = 'get_constant(' .. (contextTable.codeInts[contextTable.instrPointer + argc + 2] & GDF.EADDRESS["ADDR_MASK"]) .. ')'
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + argc + 2) * 0x4, vtDword)
                local operand4 = getGDTypeName(contextTable.codeInts[contextTable.instrPointer + argc + 4])
                addStructureElem(contextTable.codeStructElement, operand4, (contextTable.instrPointer - 1 + argc + 4) * 0x4, vtDword)
                local operand5 = 'get_global_name(' .. (contextTable.codeInts[contextTable.instrPointer + argc + 5]) .. ')'
                addStructureElem(contextTable.codeStructElement, operand5, (contextTable.instrPointer - 1 + argc + 5) * 0x4, vtDword)

                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1 + argc])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1 + argc) * 0x4, vtDword)
                local operandArg = '';

                for i = 0, argc - 1 do
                  if i > 0 then
                    operandArg = operandArg .. ', '
                  end
                  operandArg = operandArg .. formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + i + 1])
                  addStructureElem(contextTable.codeStructElement, 'arg: ' .. formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + i + 1]), (contextTable.instrPointer - 1 + i + 1) * 0x4, vtDword)
                end

                contextTable.opcodeName = contextTable.opcodeName .. ' (' .. operand4 .. ') ' .. operand1 .. ' = ' .. '[' .. operandArg .. ']'

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1 - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 6 + argc
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CONSTRUCT_DICTIONARY] = 
            {
              name = "OPCODE_CONSTRUCT_DICTIONARY",
              handler = function(contextTable)
                contextTable.instrPointer = contextTable.instrPointer + 1
                local instr_var_args = contextTable.codeInts[contextTable.instrPointer]
                addStructureElem(contextTable.codeStructElement, 'instr_var_args:', (contextTable.instrPointer - 1) * 0x4, vtDword)
                local argc = contextTable.codeInts[contextTable.instrPointer + 1 + instr_var_args]
                addStructureElem(contextTable.codeStructElement, 'argc:', (contextTable.instrPointer - 1 + 1 + instr_var_args) * 0x4, vtDword)

                local operand3 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1 + argc * 2])
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 1 + argc * 2) * 0x4, vtDword)

                local operandArg = '';

                for i = 0, argc - 1 do
                  if i > 0 then
                    operandArg = operandArg .. ', '
                  end
                  operandArg = operandArg .. formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1 + i * 2 + 0])
                  addStructureElem(contextTable.codeStructElement, 'argK: ' .. formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1 + i * 2 + 0]), (contextTable.instrPointer - 1 + 1 + i * 2 + 0) * 0x4, vtDword)
                  operandArg = operandArg .. ': ' .. formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1 + i * 2 + 1])
                  addStructureElem(contextTable.codeStructElement, 'argV: ' .. formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1 + i * 2 + 1]), (contextTable.instrPointer - 1 + 1 + i * 2 + 1) * 0x4, vtDword)
                end

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand3 .. ' =  {' .. operandArg .. '  }'

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1 - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 3 + argc * 2

              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CONSTRUCT_TYPED_DICTIONARY] = 
            {
              name = "OPCODE_CONSTRUCT_TYPED_DICTIONARY",
              handler = function(contextTable)
                contextTable.instrPointer = contextTable.instrPointer + 1
                local instr_var_args = contextTable.codeInts[contextTable.instrPointer]
                addStructureElem(contextTable.codeStructElement, 'instr_var_args:', (contextTable.instrPointer - 1) * 0x4, vtDword)
                local argc = contextTable.codeInts[contextTable.instrPointer + 1 + instr_var_args]
                addStructureElem(contextTable.codeStructElement, 'argc:', (contextTable.instrPointer - 1 + 1 + instr_var_args) * 0x4, vtDword)

                local operand2_2 = 'get_constant(' .. (contextTable.codeInts[contextTable.instrPointer + argc * 2 + 2] & GDF.EADDRESS["ADDR_MASK"]) .. ')'
                addStructureElem(contextTable.codeStructElement, operand2_2, (contextTable.instrPointer - 1 + argc * 2 + 2) * 0x4, vtDword)
                local operand2_5 = getGDTypeName(contextTable.codeInts[contextTable.instrPointer + argc * 2 + 5])
                addStructureElem(contextTable.codeStructElement, operand2_5, (contextTable.instrPointer - 1 + argc * 2 + 5) * 0x4, vtDword)
                local operand2_6 = 'get_global_name(' .. (contextTable.codeInts[contextTable.instrPointer + argc * 2 + 6]) .. ')'
                addStructureElem(contextTable.codeStructElement, operand2_6, (contextTable.instrPointer - 1 + argc * 2 + 6) * 0x4, vtDword)

                local operand2_3 = 'get_constant(' .. (contextTable.codeInts[contextTable.instrPointer + argc * 2 + 3] & GDF.EADDRESS["ADDR_MASK"]) .. ')'
                addStructureElem(contextTable.codeStructElement, operand2_3, (contextTable.instrPointer - 1 + argc * 2 + 3) * 0x4, vtDword)
                local operand2_7 = getGDTypeName(contextTable.codeInts[contextTable.instrPointer + argc * 2 + 7])
                addStructureElem(contextTable.codeStructElement, operand2_7, (contextTable.instrPointer - 1 + argc * 2 + 7) * 0x4, vtDword)
                local operand2_8 = 'get_global_name(' .. (contextTable.codeInts[contextTable.instrPointer + argc * 2 + 8]) .. ')'
                addStructureElem(contextTable.codeStructElement, operand2_8, (contextTable.instrPointer - 1 + argc * 2 + 8) * 0x4, vtDword)

                local operand2 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1 + argc * 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 1 + argc * 2) * 0x4, vtDword)

                local operandArg = '';

                for i = 0, argc - 1 do
                  if i > 0 then
                    operandArg = operandArg .. ', '
                  end
                    operandArg = operandArg .. formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1 + i * 2 + 0])
                    addStructureElem(contextTable.codeStructElement, 'argK: ' .. formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1 + i * 2 + 0]), (contextTable.instrPointer - 1 + 1 + i * 2 + 0) * 0x4, vtDword)
                    operandArg = operandArg .. ': ' .. formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1 + i * 2 + 1])
                    addStructureElem(contextTable.codeStructElement, 'argV: ' .. formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1 + i * 2 + 1]), (contextTable.instrPointer - 1 + 1 + i * 2 + 1) * 0x4, vtDword)
                end

                contextTable.opcodeName = contextTable.opcodeName .. ' (' .. operand2_5 .. ', ' .. operand2_7 .. ') ' .. operand2 .. ' =  {' .. operandArg .. '  }'

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1 - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 9 + argc * 2
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL] = 
            {
              name = "OPCODE_CALL",
              handler = function(contextTable)
                local ret = contextTable.codeInts[contextTable.instrPointer] == GDF.CurrentDisassembler:getOPEnumFromInternalOPID(GDF.OP.OPCODE_CALL_RETURN)
                local async = contextTable.codeInts[contextTable.instrPointer] == GDF.CurrentDisassembler:getOPEnumFromInternalOPID(GDF.OP.OPCODE_CALL_ASYNC)

                contextTable.instrPointer = contextTable.instrPointer + 1
                local instr_var_args = contextTable.codeInts[contextTable.instrPointer]
                addStructureElem(contextTable.codeStructElement, 'instr_var_args:', (contextTable.instrPointer - 1) * 0x4, vtDword)

                local operand2 = '';
                local argc = contextTable.codeInts[contextTable.instrPointer + 1 + instr_var_args]
                addStructureElem(contextTable.codeStructElement, 'argc:', (contextTable.instrPointer - 1 + 1 + instr_var_args) * 0x4, vtDword)

                if (ret or async) then
                  operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + argc + 2])
                  addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + argc + 2) * 0x4, vtDword)
                  operand2 = operand2 .. ' = '
                end

                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1 + argc])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1 + argc) * 0x4, vtDword)
                operand1 = operand1 .. '.'

                local operandArg = '';

                for i = 0, argc - 1 do
                  if i > 0 then
                    operandArg = operandArg .. ', '
                  end
                  operandArg = operandArg .. formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + i + 1])
                  addStructureElem(contextTable.codeStructElement, 'arg: ' .. formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + i + 1]), (contextTable.instrPointer - 1 + i + 1) * 0x4, vtDword)
                end

                local operand3 = 'Globals[' .. (contextTable.codeInts[contextTable.instrPointer + instr_var_args + 2]) .. ']'
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + instr_var_args + 2) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand2 .. operand1 .. operand3 .. ']' .. '(' .. operandArg .. ')' -- original representation 'GlobalNames[FuncCode['..(contextTable.instrPointer-1 + instr_var_args+2)..']]'

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1 - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 5 + argc
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_RETURN] = 
            {
              name = "OPCODE_CALL_RETURN",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_ASYNC] = 
            {
              name = "OPCODE_CALL_ASYNC",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_UTILITY] = 
            {
              name = "OPCODE_CALL_UTILITY",
              handler = function(contextTable)
                contextTable.instrPointer = contextTable.instrPointer + 1
                local instr_var_args = contextTable.codeInts[contextTable.instrPointer]
                addStructureElem(contextTable.codeStructElement, 'instr_var_args:', (contextTable.instrPointer - 1) * 0x4, vtDword)
                local argc = contextTable.codeInts[contextTable.instrPointer + 1 + instr_var_args]
                addStructureElem(contextTable.codeStructElement, 'argc:', (contextTable.instrPointer - 1 + 1 + instr_var_args) * 0x4, vtDword)

                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1 + argc])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1 + argc) * 0x4, vtDword)

                local operandArg = '';

                for i = 0, argc - 1 do
                  if i > 0 then
                    operandArg = operandArg .. ', '
                  end
                  operandArg = operandArg .. formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + i + 1])
                  addStructureElem(contextTable.codeStructElement, 'arg: ' .. formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + i + 1]), (contextTable.instrPointer - 1 + i + 1) * 0x4, vtDword)
                end

                local operand2 = 'Globals[' .. contextTable.codeInts[contextTable.instrPointer + 2 + instr_var_args] .. ']'
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2 + instr_var_args) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand1 .. ' = ' .. operand2 .. '(' .. operandArg .. ')'

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1 - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 4 + argc

              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_UTILITY_VALIDATED] = 
            {
              name = "OPCODE_CALL_UTILITY_VALIDATED",
              handler = function(contextTable)
                contextTable.instrPointer = contextTable.instrPointer + 1
                local instr_var_args = contextTable.codeInts[contextTable.instrPointer]
                addStructureElem(contextTable.codeStructElement, 'instr_var_args:', (contextTable.instrPointer - 1) * 0x4, vtDword)
                local argc = contextTable.codeInts[contextTable.instrPointer + 1 + instr_var_args]
                addStructureElem(contextTable.codeStructElement, 'argc:', (contextTable.instrPointer - 1 + 1 + instr_var_args) * 0x4, vtDword)

                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1 + argc])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1 + argc) * 0x4, vtDword)

                local operandArg = '';

                for i = 0, argc - 1 do
                  if i > 0 then
                    operandArg = operandArg .. ', '
                  end
                  operandArg = operandArg .. formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + i + 1])
                  addStructureElem(contextTable.codeStructElement, 'arg: ' .. formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + i + 1]), (contextTable.instrPointer - 1 + i + 1) * 0x4, vtDword)
                end

                local operand3 = 'utilities_names[' .. contextTable.codeInts[contextTable.instrPointer + 3 + argc] .. ']'
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3 + argc) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand1 .. ' = ' .. operand3 .. '(' .. operandArg .. ')'

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1 - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 4 + argc
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_GDSCRIPT_UTILITY] = 
            {
              name = "OPCODE_CALL_GDSCRIPT_UTILITY",
              handler = function(contextTable)
                contextTable.instrPointer = contextTable.instrPointer + 1
                local instr_var_args = contextTable.codeInts[contextTable.instrPointer]
                addStructureElem(contextTable.codeStructElement, 'instr_var_args:', (contextTable.instrPointer - 1) * 0x4, vtDword)
                local argc = contextTable.codeInts[contextTable.instrPointer + 1 + instr_var_args]
                addStructureElem(contextTable.codeStructElement, 'argc:', (contextTable.instrPointer - 1 + 1 + instr_var_args) * 0x4, vtDword)
                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1 + argc])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1 + argc) * 0x4, vtDword)

                local operandArg = '';

                for i = 0, argc - 1 do
                  if i > 0 then
                    operandArg = operandArg .. ', '
                  end
                  operandArg = operandArg .. formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + i + 1])
                  addStructureElem(contextTable.codeStructElement, 'arg: ' .. formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + i + 1]), (contextTable.instrPointer - 1 + i + 1) * 0x4, vtDword)
                end

                local operand3 = 'gds_utilities_names[' .. contextTable.codeInts[contextTable.instrPointer + 3 + argc] .. ']'
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3 + argc) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand1 .. ' = ' .. operand3 .. '(' .. operandArg .. ')'
                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1 - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 4 + argc
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_BUILTIN_TYPE_VALIDATED] = 
            {
              name = "OPCODE_CALL_BUILTIN_TYPE_VALIDATED",
              handler = function(contextTable)
                contextTable.instrPointer = contextTable.instrPointer + 1
                local instr_var_args = contextTable.codeInts[contextTable.instrPointer]
                addStructureElem(contextTable.codeStructElement, 'instr_var_args:', (contextTable.instrPointer - 1) * 0x4, vtDword)
                local argc = contextTable.codeInts[contextTable.instrPointer + 1 + instr_var_args]
                addStructureElem(contextTable.codeStructElement, 'argc:', (contextTable.instrPointer - 1 + 1 + instr_var_args) * 0x4, vtDword)

                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                local operand2 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 2 + argc])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2 + argc) * 0x4, vtDword)

                local operandArg = '';

                for i = 0, argc - 1 do
                  if i > 0 then
                    operandArg = operandArg .. ', '
                  end
                  operandArg = operandArg .. formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + i + 1])
                  addStructureElem(contextTable.codeStructElement, 'arg: ' .. formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + i + 1]), (contextTable.instrPointer - 1 + i + 1) * 0x4, vtDword)
                end

                local operand4 = 'builtin_methods_names[' .. (contextTable.codeInts[contextTable.instrPointer + 4 + argc]) .. ']'
                addStructureElem(contextTable.codeStructElement, operand4, (contextTable.instrPointer - 1 + 4 + argc) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand2 .. ' = ' .. operand1 .. '.' .. operand4 .. '(' .. operandArg .. ')'

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1 - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 5 + argc
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_SELF_BASE] = 
            {
              name = "OPCODE_CALL_SELF_BASE",
              handler = function(contextTable)
                contextTable.instrPointer = contextTable.instrPointer + 1
                local instr_var_args = contextTable.codeInts[contextTable.instrPointer]
                addStructureElem(contextTable.codeStructElement, 'instr_var_args:', (contextTable.instrPointer - 1) * 0x4, vtDword)
                local argc = contextTable.codeInts[contextTable.instrPointer + 1 + instr_var_args]
                addStructureElem(contextTable.codeStructElement, 'argc:', (contextTable.instrPointer - 1 + 1 + instr_var_args) * 0x4, vtDword)
                local operand2 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 2 + argc])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2 + argc) * 0x4, vtDword)

                local operandArg = '';

                for i = 0, argc - 1 do
                  if i > 0 then
                    operandArg = operandArg .. ', '
                  end
                  operandArg = operandArg .. formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + i + 1])
                  addStructureElem(contextTable.codeStructElement, 'arg: ' .. formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + i + 1]), (contextTable.instrPointer - 1 + i + 1) * 0x4, vtDword)
                end

                local operand3 = 'Globals[' .. contextTable.codeInts[contextTable.instrPointer + 2 + instr_var_args] .. ']'
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 2 + instr_var_args) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand2 .. ' = ' .. operand3 .. '(' .. operandArg .. ')'
                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1 - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 4 + argc
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_METHOD_BIND] = 
            {
              name = "OPCODE_CALL_METHOD_BIND",
              handler = function(contextTable)
                local ret = contextTable.codeInts[contextTable.instrPointer] == GDF.CurrentDisassembler:getOPEnumFromInternalOPID(GDF.OP.OPCODE_CALL_METHOD_BIND_RET)
                contextTable.instrPointer = contextTable.instrPointer + 1
                local instr_var_args = contextTable.codeInts[contextTable.instrPointer]
                addStructureElem(contextTable.codeStructElement, 'instr_var_args:', (contextTable.instrPointer - 1) * 0x4, vtDword)
                local operand2 = '';
                local argc = contextTable.codeInts[contextTable.instrPointer + 1 + instr_var_args]
                addStructureElem(contextTable.codeStructElement, 'argc:', (contextTable.instrPointer - 1 + 1 + instr_var_args) * 0x4, vtDword)

                if (ret) then
                  operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + argc + 2])
                  addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + argc + 2) * 0x4, vtDword)
                  operand2 = operand2 .. ' = '
                end

                local operand3 = '_methods_ptr[' .. contextTable.codeInts[contextTable.instrPointer + 2 + instr_var_args] .. ']' -- TODO: workaround
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 2 + instr_var_args) * 0x4, vtDword)

                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1 + argc])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1 + argc) * 0x4, vtDword)
                operand1 = operand1 .. '.'
                operand1 = operand1 .. operand3 .. '->get_name' -- TODO
                local operandArg = '';

                for i = 0, argc - 1 do
                  if i > 0 then
                    operandArg = operandArg .. ', '
                  end
                  operandArg = operandArg .. formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + i + 1])
                  addStructureElem(contextTable.codeStructElement, 'arg: ' .. formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + i + 1]),     (contextTable.instrPointer - 1 + i + 1) * 0x4, vtDword)
                end

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand2 .. operand1 .. '(' .. operandArg .. ')' -- TODO retrieve the funciton name
                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1 - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 5 + argc
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_METHOD_BIND_RET] = 
            {
              name = "OPCODE_CALL_METHOD_BIND_RET",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_METHOD_BIND].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_BUILTIN_STATIC] = 
            {
              name = "OPCODE_CALL_BUILTIN_STATIC",
              handler = function(contextTable)
                contextTable.instrPointer = contextTable.instrPointer + 1
                local instr_var_args = contextTable.codeInts[contextTable.instrPointer]
                addStructureElem(contextTable.codeStructElement, 'instr_var_args:', (contextTable.instrPointer - 1) * 0x4, vtDword)
                local typeName = getGDTypeName(contextTable.codeInts[contextTable.instrPointer + 1 + instr_var_args])
                addStructureElem(contextTable.codeStructElement, 'typeName:', (contextTable.instrPointer - 1 + 3 + instr_var_args) * 0x4, vtDword)

                local argc = contextTable.codeInts[contextTable.instrPointer + 1 + instr_var_args]
                addStructureElem(contextTable.codeStructElement, 'argc:', (contextTable.instrPointer - 1 + 1 + instr_var_args) * 0x4, vtDword)

                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1 + argc])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1 + argc) * 0x4, vtDword)
                local operandArg = '';

                for i = 0, argc - 1 do
                  if i > 0 then
                    operandArg = operandArg .. ', '
                  end
                  operandArg = operandArg .. formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + i + 1])
                  addStructureElem(contextTable.codeStructElement, 'arg: ' .. formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + i + 1]), (contextTable.instrPointer - 1 + i + 1) * 0x4, vtDword)
                end

                local operand2 = 'Globals[' .. contextTable.codeInts[contextTable.instrPointer + 2 + instr_var_args] .. ']'
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2 + instr_var_args) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand1 .. ' = ' .. typeName .. '.' .. operand2 .. '.operator String()' .. '(' .. operandArg .. ')'

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1 - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 5 + argc
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_NATIVE_STATIC] = 
            {
              name = "OPCODE_CALL_NATIVE_STATIC",
              handler = function(contextTable)
                contextTable.instrPointer = contextTable.instrPointer + 1
                local instr_var_args = contextTable.codeInts[contextTable.instrPointer]
                addStructureElem(contextTable.codeStructElement, 'instr_var_args:', (contextTable.instrPointer - 1) * 0x4, vtDword)
                local argc = contextTable.codeInts[contextTable.instrPointer + 2 + instr_var_args]
                addStructureElem(contextTable.codeStructElement, 'argc:', (contextTable.instrPointer - 1 + 2 + instr_var_args) * 0x4, vtDword)

                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1 + argc])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1 + argc) * 0x4, vtDword)
                local operandArg = '';

                for i = 0, argc - 1 do
                  if i > 0 then
                    operandArg = operandArg .. ', '
                  end
                  operandArg = operandArg .. formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + i + 1])
                  addStructureElem(contextTable.codeStructElement, 'arg: ' .. formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + i + 1]), (contextTable.instrPointer - 1 + i + 1) * 0x4, vtDword)
                end

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand1 .. ' = ' .. 'method->get_instance_class()' .. '.' .. 'method->get_name' .. '(' .. operandArg .. ')'

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1 - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 4 + argc
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_NATIVE_STATIC_VALIDATED_RETURN] = 
            {
              name = "OPCODE_CALL_NATIVE_STATIC_VALIDATED_RETURN",
              handler = function(contextTable)
                contextTable.instrPointer = contextTable.instrPointer + 1
                local instr_var_args = contextTable.codeInts[contextTable.instrPointer]
                addStructureElem(contextTable.codeStructElement, 'instr_var_args:', (contextTable.instrPointer - 1) * 0x4, vtDword)
                local argc = contextTable.codeInts[contextTable.instrPointer + 1 + instr_var_args]
                addStructureElem(contextTable.codeStructElement, 'argc:', (contextTable.instrPointer - 1 + 1 + instr_var_args) * 0x4, vtDword)

                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1 + argc])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1 + argc) * 0x4, vtDword)
                local operandArg = '';

                for i = 0, argc - 1 do
                  if i > 0 then
                    operandArg = operandArg .. ', '
                  end
                  operandArg = operandArg .. formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + i + 1])
                  addStructureElem(contextTable.codeStructElement, 'arg: ' .. formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + i + 1]), (contextTable.instrPointer - 1 + i + 1) * 0x4, vtDword)
                end

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand1 .. ' = ' .. 'method->get_instance_class()' .. '.' .. 'method->get_name' .. '(' .. operandArg .. ')'

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1 - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 4 + argc

              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_NATIVE_STATIC_VALIDATED_NO_RETURN] = 
            {
              name = "OPCODE_CALL_NATIVE_STATIC_VALIDATED_NO_RETURN",
              handler = function(contextTable)
                contextTable.instrPointer = contextTable.instrPointer + 1
                local instr_var_args = contextTable.codeInts[contextTable.instrPointer]
                addStructureElem(contextTable.codeStructElement, 'instr_var_args:', (contextTable.instrPointer - 1) * 0x4, vtDword)
                local argc = contextTable.codeInts[contextTable.instrPointer + 1 + instr_var_args]
                addStructureElem(contextTable.codeStructElement, 'argc:', (contextTable.instrPointer - 1 + 1 + instr_var_args) * 0x4, vtDword)

                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1 + argc])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1 + argc) * 0x4, vtDword)
                local operandArg = '';

                for i = 0, argc - 1 do
                  if i > 0 then
                    operandArg = operandArg .. ', '
                  end
                  operandArg = operandArg .. formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + i + 1])
                  addStructureElem(contextTable.codeStructElement, 'arg: ' .. formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + i + 1]), (contextTable.instrPointer - 1 + i + 1) * 0x4, vtDword)
                end

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand1 .. ' = ' .. 'method->get_instance_class()' .. '.' .. 'method->get_name' .. '(' .. operandArg .. ')'

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1 - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 4 + argc
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_METHOD_BIND_VALIDATED_RETURN] = 
            {
              name = "OPCODE_CALL_METHOD_BIND_VALIDATED_RETURN",
              handler = function(contextTable)
                contextTable.instrPointer = contextTable.instrPointer + 1
                local instr_var_args = contextTable.codeInts[contextTable.instrPointer]
                addStructureElem(contextTable.codeStructElement, 'instr_var_args:', (contextTable.instrPointer - 1) * 0x4, vtDword)
                local argc = contextTable.codeInts[contextTable.instrPointer + 1 + instr_var_args]
                addStructureElem(contextTable.codeStructElement, 'argc:', (contextTable.instrPointer - 1 + 1 + instr_var_args) * 0x4, vtDword)

                local operand2 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 2 + argc])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2 + argc) * 0x4, vtDword)

                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1 + argc])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1 + argc) * 0x4, vtDword)
                local operandArg = '';

                for i = 0, argc - 1 do
                  if i > 0 then
                    operandArg = operandArg .. ', '
                  end
                  operandArg = operandArg .. formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + i + 1])
                  addStructureElem(contextTable.codeStructElement, 'arg: ' .. formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + i + 1]), (contextTable.instrPointer - 1 + i + 1) * 0x4, vtDword)
                end

                local operand3 = '_methods_ptr[' .. contextTable.codeInts[contextTable.instrPointer + 2 + instr_var_args] .. ']' -- TODO: workaround
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 2 + instr_var_args) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand2 .. ' = ' .. operand1 .. '.' .. operand3 .. '->get_name' .. '(' .. operandArg .. ')'

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1 - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 5 + argc
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_METHOD_BIND_VALIDATED_NO_RETURN] = 
            {
              name = "OPCODE_CALL_METHOD_BIND_VALIDATED_NO_RETURN",
              handler = function(contextTable)
                contextTable.instrPointer = contextTable.instrPointer + 1
                local instr_var_args = contextTable.codeInts[contextTable.instrPointer]
                addStructureElem(contextTable.codeStructElement, 'instr_var_args:', (contextTable.instrPointer - 1) * 0x4, vtDword)
                local argc = contextTable.codeInts[contextTable.instrPointer + 1 + instr_var_args]
                addStructureElem(contextTable.codeStructElement, 'argc:', (contextTable.instrPointer - 1 + 1 + instr_var_args) * 0x4, vtDword)

                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1 + argc])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1 + argc) * 0x4, vtDword)
                local operandArg = '';

                for i = 0, argc - 1 do
                  if i > 0 then
                    operandArg = operandArg .. ', '
                  end
                  operandArg = operandArg .. formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + i + 1])
                  addStructureElem(contextTable.codeStructElement, 'arg: ' .. formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + i + 1]), (contextTable.instrPointer - 1 + i + 1) * 0x4, vtDword)
                end

                local operand3 = '_methods_ptr[' .. contextTable.codeInts[contextTable.instrPointer + 2 + instr_var_args] .. ']' -- TODO: workaround
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 2 + instr_var_args) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand1 .. '.' .. operand3 .. '->get_name' .. '(' .. operandArg .. ')'

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1 - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 5 + argc
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_AWAIT] = 
            {
              name = "OPCODE_AWAIT",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand1

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)
                return contextTable.instrPointer + 2
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_AWAIT_RESUME] = 
            {
              name = "OPCODE_AWAIT_RESUME",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_AWAIT].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CREATE_LAMBDA] = 
            {
              name = "OPCODE_CREATE_LAMBDA",
              handler = function(contextTable)
                contextTable.instrPointer = contextTable.instrPointer + 1
                local instr_var_args = contextTable.codeInts[contextTable.instrPointer]
                addStructureElem(contextTable.codeStructElement, 'instr_var_args:', (contextTable.instrPointer - 1) * 0x4, vtDword)

                local operand2 = '_lambdas_ptr[' .. (contextTable.codeInts[contextTable.instrPointer + 2 + instr_var_args]) .. ']'
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2 + instr_var_args) * 0x4, vtDword)
                local captures_count = contextTable.codeInts[contextTable.instrPointer + 1 + instr_var_args]
                addStructureElem(contextTable.codeStructElement, 'argc:', (contextTable.instrPointer - 1 + 1 + instr_var_args) * 0x4, vtDword)
                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1 + captures_count])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1 + captures_count) * 0x4, vtDword)

                local operandArg = '';

                for i = 0, captures_count - 1 do
                  if i > 0 then
                    operandArg = operandArg .. ', '
                  end
                  operandArg = operandArg .. formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + i + 1])
                  addStructureElem(contextTable.codeStructElement, 'captures_count: ' .. formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + i + 1]), (contextTable.instrPointer - 1 + i + 1) * 0x4, vtDword)
                end

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand1 .. ' create lambda from ' .. operand2 .. '->name.operator String()' .. ' function, captures (' .. operandArg .. ')'
                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1 - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 4 + captures_count
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CREATE_SELF_LAMBDA] = 
            {
              name = "OPCODE_CREATE_SELF_LAMBDA",
              handler = function(contextTable)
                contextTable.instrPointer = contextTable.instrPointer + 1
                local instr_var_args = contextTable.codeInts[contextTable.instrPointer]
                addStructureElem(contextTable.codeStructElement, 'instr_var_args:', (contextTable.instrPointer - 1) * 0x4, vtDword)
                local operand2 = '_lambdas_ptr[' .. (contextTable.codeInts[contextTable.instrPointer + 2 + instr_var_args]) .. ']'
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2 + instr_var_args) * 0x4, vtDword)
                local captures_count = contextTable.codeInts[contextTable.instrPointer + 1 + instr_var_args]
                addStructureElem(contextTable.codeStructElement, 'argc:', (contextTable.instrPointer - 1 + 1 + instr_var_args) * 0x4, vtDword)
                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1 + captures_count])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1 + captures_count) * 0x4, vtDword)

                local operandArg = '';

                for i = 0, captures_count - 1 do
                  if i > 0 then
                    operandArg = operandArg .. ', '
                  end
                  operandArg = operandArg .. formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + i + 1])
                  addStructureElem(contextTable.codeStructElement, 'captures_count: ' .. formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + i + 1]),     (contextTable.instrPointer - 1 + i + 1) * 0x4, vtDword)
                end

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand1 .. ' create lambda from ' .. operand2 .. '->name.operator String()' .. ' function, captures (' .. operandArg .. ')'
                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1 - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 4 + captures_count

              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_JUMP] = 
            {
              name = "OPCODE_JUMP",
              handler = function(contextTable)
                local operand1 = numtohexstr(contextTable.codeInts[contextTable.instrPointer + 1] * 0x4) -- where to jump in hex representation, 4byte step
                local elem = addStructureElem(contextTable.codeStructElement, "JUMP to " .. operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                elem.DisplayMethod = 'dtHexadecimal'
                elem.ShowAsHex = true
                contextTable.opcodeName = contextTable.opcodeName .. ' -> ' .. operand1

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 2
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_JUMP_IF] = 
            {
              name = "OPCODE_JUMP_IF",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)

                local operand2 = numtohexstr(contextTable.codeInts[contextTable.instrPointer + 2] * 0x4) -- where to jump
                local elem = addStructureElem(contextTable.codeStructElement, "JUMP to " .. operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)
                elem.DisplayMethod = 'dtHexadecimal'
                elem.ShowAsHex = true
                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand1 .. ' -> ' .. operand2

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 3
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_JUMP_IF_NOT] = 
            {
              name = "OPCODE_JUMP_IF_NOT",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_JUMP_IF].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_JUMP_TO_DEF_ARGUMENT] = 
            {
              name = "OPCODE_JUMP_TO_DEF_ARGUMENT",
              handler = function(contextTable)
                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)
                return contextTable.instrPointer + 1
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_JUMP_IF_SHARED] = 
            {
              name = "OPCODE_JUMP_IF_SHARED",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_JUMP_IF].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_RETURN] = 
            {
              name = "OPCODE_RETURN",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand1
                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 2
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_RETURN_TYPED_BUILTIN] = 
            {
              name = "OPCODE_RETURN_TYPED_BUILTIN",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                local operand2 = getGDTypeName(contextTable.codeInts[contextTable.instrPointer + 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' (' .. operand2 .. ')' .. ' ' .. operand1
                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 3
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_RETURN_TYPED_ARRAY] = 
            {
              name = "OPCODE_RETURN_TYPED_ARRAY",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand1
                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 5
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_RETURN_TYPED_DICTIONARY] = 
            {
              name = "OPCODE_RETURN_TYPED_DICTIONARY",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand1
                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 8
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_RETURN_TYPED_NATIVE] = 
            {
              name = "OPCODE_RETURN_TYPED_NATIVE",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' (' .. operand2 .. ') ' .. operand1
                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 3

              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_RETURN_TYPED_SCRIPT] = 
            {
              name = "OPCODE_RETURN_TYPED_SCRIPT",
              handler = function(contextTable)
                local operand2 = 'get_constant(' .. (contextTable.codeInts[contextTable.instrPointer + 2] & GDF.EADDRESS["ADDR_MASK"]) .. ')'
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)

                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' (' .. 'GDScript::debug_get_script_name(' .. operand2 .. ')' .. ') ' .. operand1
                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 3
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN] = 
            {
              name = "OPCODE_ITERATE_BEGIN",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)
                local operand3 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 3])
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3) * 0x4, vtDword)
                addStructureElem(contextTable.codeStructElement, 'end: ', (contextTable.instrPointer - 1 + 4) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' for-init ' .. operand3 .. ' in ' .. operand2 .. ' counter ' .. operand1 .. ' end ' .. tostring(contextTable.codeInts[contextTable.instrPointer + 4])
                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 5
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_INT] = 
            {
              name = "OPCODE_ITERATE_BEGIN_INT",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)
                local operand3 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 3])
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3) * 0x4, vtDword)
                addStructureElem(contextTable.codeStructElement, 'end: ', (contextTable.instrPointer - 1 + 4) * 0x4, vtDword)

                local opcodeType = contextTable.opcodeName:gsub('OPCODE_ITERATE_BEGIN_', '')
                contextTable.opcodeName = contextTable.opcodeName .. ' for-init (typed ' .. opcodeType .. ') ' .. operand3 .. ' in ' .. operand2 .. ' counter ' .. operand1 .. ' end ' .. tostring(contextTable.codeInts[contextTable.instrPointer + 4])
                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 5
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_FLOAT] = 
            {
              name = "OPCODE_ITERATE_BEGIN_FLOAT",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_INT].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_VECTOR2] = 
            {
              name = "OPCODE_ITERATE_BEGIN_VECTOR2",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_INT].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_VECTOR2I] = 
            {
              name = "OPCODE_ITERATE_BEGIN_VECTOR2I",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_INT].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_VECTOR3] = 
            {
              name = "OPCODE_ITERATE_BEGIN_VECTOR3",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_INT].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_VECTOR3I] = 
            {
              name = "OPCODE_ITERATE_BEGIN_VECTOR3I",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_INT].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_STRING] = 
            {
              name = "OPCODE_ITERATE_BEGIN_STRING",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_INT].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_DICTIONARY] = 
            {
              name = "OPCODE_ITERATE_BEGIN_DICTIONARY",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_INT].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_ARRAY] = 
            {
              name = "OPCODE_ITERATE_BEGIN_ARRAY",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_INT].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_PACKED_BYTE_ARRAY] = 
            {
              name = "OPCODE_ITERATE_BEGIN_PACKED_BYTE_ARRAY",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_INT].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_PACKED_INT32_ARRAY] = 
            {
              name = "OPCODE_ITERATE_BEGIN_PACKED_INT32_ARRAY",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_INT].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_PACKED_INT64_ARRAY] = 
            {
              name = "OPCODE_ITERATE_BEGIN_PACKED_INT64_ARRAY",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_INT].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_PACKED_FLOAT32_ARRAY] = 
            {
              name = "OPCODE_ITERATE_BEGIN_PACKED_FLOAT32_ARRAY",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_INT].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_PACKED_FLOAT64_ARRAY] = 
            {
              name = "OPCODE_ITERATE_BEGIN_PACKED_FLOAT64_ARRAY",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_INT].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_PACKED_STRING_ARRAY] = 
            {
              name = "OPCODE_ITERATE_BEGIN_PACKED_STRING_ARRAY",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_INT].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_PACKED_VECTOR2_ARRAY] = 
            {
              name = "OPCODE_ITERATE_BEGIN_PACKED_VECTOR2_ARRAY",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_INT].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_PACKED_VECTOR3_ARRAY] = 
            {
              name = "OPCODE_ITERATE_BEGIN_PACKED_VECTOR3_ARRAY",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_INT].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_PACKED_COLOR_ARRAY] = 
            {
              name = "OPCODE_ITERATE_BEGIN_PACKED_COLOR_ARRAY",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_INT].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_PACKED_VECTOR4_ARRAY] = 
            {
              name = "OPCODE_ITERATE_BEGIN_PACKED_VECTOR4_ARRAY",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_INT].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_OBJECT] = 
            {
              name = "OPCODE_ITERATE_BEGIN_OBJECT",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_INT].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_RANGE] =
            {
              name = "OPCODE_ITERATE_BEGIN_RANGE",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)

                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)

                local operand3 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 3])
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3) * 0x4, vtDword)

                local operand4 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 4])
                addStructureElem(contextTable.codeStructElement, operand4, (contextTable.instrPointer - 1 + 4) * 0x4, vtDword)

                local operand5 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 5])
                addStructureElem(contextTable.codeStructElement, operand5, (contextTable.instrPointer - 1 + 5) * 0x4, vtDword)

                addStructureElem(contextTable.codeStructElement, 'end: ', (contextTable.instrPointer - 1 + 4) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' for-init ' .. operand5 .. ' in range from ' .. operand2 .. ' to ' .. operand3 .. ' step ' .. operand4 .. ' counter ' .. operand1 .. ' end ' .. tostring(contextTable.codeInts[contextTable.instrPointer + 4])
                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 7

              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE] =
            {
              name = "OPCODE_ITERATE",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)
                local operand3 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 3])
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3) * 0x4, vtDword)
                addStructureElem(contextTable.codeStructElement, 'end: ', (contextTable.instrPointer - 1 + 4) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' for-loop ' .. operand2 .. ' in ' .. operand2 .. ' counter ' .. operand1 .. ' end ' .. tostring(contextTable.codeInts[contextTable.instrPointer + 4])
                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 5
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_INT] =
            {
              name = "OPCODE_ITERATE_INT",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)
                local operand3 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 3])
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3) * 0x4, vtDword)
                addStructureElem(contextTable.codeStructElement, 'end: ', (contextTable.instrPointer - 1 + 4) * 0x4, vtDword)

                local opcodeType = contextTable.opcodeName:gsub('OPCODE_ITERATE_', '')
                contextTable.opcodeName = contextTable.opcodeName .. ' for-init (typed ' .. opcodeType .. ') ' .. operand3 .. ' in ' .. operand2 .. ' counter ' .. operand1 .. ' end ' .. tostring(contextTable.codeInts[contextTable.instrPointer + 4])
                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 5
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_FLOAT] = 
            {
              name = "OPCODE_ITERATE_FLOAT",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_INT].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_VECTOR2] = 
            {
              name = "OPCODE_ITERATE_VECTOR2",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_INT].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_VECTOR2I] = 
            {
              name = "OPCODE_ITERATE_VECTOR2I",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_INT].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_VECTOR3] = 
            {
              name = "OPCODE_ITERATE_VECTOR3",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_INT].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_VECTOR3I] = 
            {
              name = "OPCODE_ITERATE_VECTOR3I",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_INT].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_STRING] = 
            {
              name = "OPCODE_ITERATE_STRING",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_INT].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_DICTIONARY] = 
            {
              name = "OPCODE_ITERATE_DICTIONARY",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_INT].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_ARRAY] = 
            {
              name = "OPCODE_ITERATE_ARRAY",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_INT].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_PACKED_BYTE_ARRAY] = 
            {
              name = "OPCODE_ITERATE_PACKED_BYTE_ARRAY",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_INT].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_PACKED_INT32_ARRAY] = 
            {
              name = "OPCODE_ITERATE_PACKED_INT32_ARRAY",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_INT].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_PACKED_INT64_ARRAY] = 
            {
              name = "OPCODE_ITERATE_PACKED_INT64_ARRAY",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_INT].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_PACKED_FLOAT32_ARRAY] = 
            {
              name = "OPCODE_ITERATE_PACKED_FLOAT32_ARRAY",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_INT].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_PACKED_FLOAT64_ARRAY] = 
            {
              name = "OPCODE_ITERATE_PACKED_FLOAT64_ARRAY",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_INT].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_PACKED_STRING_ARRAY] = 
            {
              name = "OPCODE_ITERATE_PACKED_STRING_ARRAY",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_INT].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_PACKED_VECTOR2_ARRAY] = 
            {
              name = "OPCODE_ITERATE_PACKED_VECTOR2_ARRAY",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_INT].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_PACKED_VECTOR3_ARRAY] = 
            {
              name = "OPCODE_ITERATE_PACKED_VECTOR3_ARRAY",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_INT].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_PACKED_COLOR_ARRAY] = 
            {
              name = "OPCODE_ITERATE_PACKED_COLOR_ARRAY",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_INT].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_PACKED_VECTOR4_ARRAY] = 
            {
              name = "OPCODE_ITERATE_PACKED_VECTOR4_ARRAY",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_INT].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_OBJECT] = 
            {
              name = "OPCODE_ITERATE_OBJECT",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_INT].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_RANGE] =
            {
              name = "OPCODE_ITERATE_RANGE",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)

                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)

                local operand3 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 3])
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3) * 0x4, vtDword)

                local operand4 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 4])
                addStructureElem(contextTable.codeStructElement, operand4, (contextTable.instrPointer - 1 + 4) * 0x4, vtDword)

                addStructureElem(contextTable.codeStructElement, 'end: ', (contextTable.instrPointer - 1 + 4) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' for-loop ' .. operand4 .. ' in range to ' .. operand2 .. ' step ' .. operand3 .. ' counter ' .. operand1 .. ' end ' .. tostring(contextTable.codeInts[contextTable.instrPointer + 4])
                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 6
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_STORE_GLOBAL] =
            {
              name = "OPCODE_STORE_GLOBAL",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)

                local operand2 = (contextTable.codeInts[contextTable.instrPointer + 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)
                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand1 .. ' = ' .. operand2
                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 3

              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_STORE_NAMED_GLOBAL] =
            {
              name = "OPCODE_STORE_NAMED_GLOBAL",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                local operand2 = 'Globals[' .. contextTable.codeInts[contextTable.instrPointer + 2] .. ']'
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)
                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand1 .. ' = ' .. operand2
                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)
                return contextTable.instrPointer + 3
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL] =
            {
              name = "OPCODE_TYPE_ADJUST_BOOL",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                local opcodeType = contextTable.opcodeName:gsub('OPCODE_TYPE_ADJUST_', '')
                contextTable.opcodeName = contextTable.opcodeName .. ' (' .. opcodeType .. ') ' .. operand1
                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)
                return contextTable.instrPointer + 2

              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_INT] = 
            {
              name = "OPCODE_TYPE_ADJUST_INT",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_FLOAT] = 
            {
              name = "OPCODE_TYPE_ADJUST_FLOAT",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_STRING] = 
            {
              name = "OPCODE_TYPE_ADJUST_STRING",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_VECTOR2] = 
            {
              name = "OPCODE_TYPE_ADJUST_VECTOR2",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_VECTOR2I] = 
            {
              name = "OPCODE_TYPE_ADJUST_VECTOR2I",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_RECT2] = 
            {
              name = "OPCODE_TYPE_ADJUST_RECT2",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_RECT2I] = 
            {
              name = "OPCODE_TYPE_ADJUST_RECT2I",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_VECTOR3] = 
            {
              name = "OPCODE_TYPE_ADJUST_VECTOR3",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_VECTOR3I] = 
            {
              name = "OPCODE_TYPE_ADJUST_VECTOR3I",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_TRANSFORM2D] = 
            {
              name = "OPCODE_TYPE_ADJUST_TRANSFORM2D",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_VECTOR4] = 
            {
              name = "OPCODE_TYPE_ADJUST_VECTOR4",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_VECTOR4I] = 
            {
              name = "OPCODE_TYPE_ADJUST_VECTOR4I",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_PLANE] = 
            {
              name = "OPCODE_TYPE_ADJUST_PLANE",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_QUATERNION] = 
            {
              name = "OPCODE_TYPE_ADJUST_QUATERNION",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_AABB] = 
            {
              name = "OPCODE_TYPE_ADJUST_AABB",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BASIS] = 
            {
              name = "OPCODE_TYPE_ADJUST_BASIS",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_TRANSFORM3D] = 
            {
              name = "OPCODE_TYPE_ADJUST_TRANSFORM3D",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_PROJECTION] = 
            {
              name = "OPCODE_TYPE_ADJUST_PROJECTION",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_COLOR] = 
            {
              name = "OPCODE_TYPE_ADJUST_COLOR",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_STRING_NAME] = 
            {
              name = "OPCODE_TYPE_ADJUST_STRING_NAME",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_NODE_PATH] = 
            {
              name = "OPCODE_TYPE_ADJUST_NODE_PATH",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_RID] = 
            {
              name = "OPCODE_TYPE_ADJUST_RID",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_OBJECT] = 
            {
              name = "OPCODE_TYPE_ADJUST_OBJECT",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_CALLABLE] = 
            {
              name = "OPCODE_TYPE_ADJUST_CALLABLE",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_SIGNAL] = 
            {
              name = "OPCODE_TYPE_ADJUST_SIGNAL",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_DICTIONARY] = 
            {
              name = "OPCODE_TYPE_ADJUST_DICTIONARY",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_ARRAY] = 
            {
              name = "OPCODE_TYPE_ADJUST_ARRAY",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_PACKED_BYTE_ARRAY] = 
            {
              name = "OPCODE_TYPE_ADJUST_PACKED_BYTE_ARRAY",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_PACKED_INT32_ARRAY] = 
            {
              name = "OPCODE_TYPE_ADJUST_PACKED_INT32_ARRAY",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_PACKED_INT64_ARRAY] = 
            {
              name = "OPCODE_TYPE_ADJUST_PACKED_INT64_ARRAY",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_PACKED_FLOAT32_ARRAY] = 
            {
              name = "OPCODE_TYPE_ADJUST_PACKED_FLOAT32_ARRAY",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_PACKED_FLOAT64_ARRAY] = 
            {
              name = "OPCODE_TYPE_ADJUST_PACKED_FLOAT64_ARRAY",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_PACKED_STRING_ARRAY] = 
            {
              name = "OPCODE_TYPE_ADJUST_PACKED_STRING_ARRAY",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_PACKED_VECTOR2_ARRAY] = 
            {
              name = "OPCODE_TYPE_ADJUST_PACKED_VECTOR2_ARRAY",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_PACKED_VECTOR3_ARRAY] = 
            {
              name = "OPCODE_TYPE_ADJUST_PACKED_VECTOR3_ARRAY",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_PACKED_COLOR_ARRAY] = 
            {
              name = "OPCODE_TYPE_ADJUST_PACKED_COLOR_ARRAY",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_PACKED_VECTOR4_ARRAY] = 
            {
              name = "OPCODE_TYPE_ADJUST_PACKED_VECTOR4_ARRAY",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ASSERT] =
            {
              name = "OPCODE_ASSERT",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' (' .. operand1 .. ', ' .. operand2 .. ')'

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)
                return contextTable.instrPointer + 3
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_BREAKPOINT] =
            {
              name = "OPCODE_BREAKPOINT",
              handler = function(contextTable)
                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)
                return contextTable.instrPointer + 1
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_LINE] =
            {
              name = "OPCODE_LINE",
              handler = function(contextTable)
                local line = contextTable.codeInts[contextTable.instrPointer + 1] - 1
                if line > 0 --[[and line < p_code_lines.size()]] then
                  contextTable.opcodeName = contextTable.opcodeName .. ' ' .. tostring(line + 1) .. ': '
                else
                  contextTable.opcodeName = ''
                end
                addStructureElem(contextTable.codeStructElement, 'line: ', (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)
                return contextTable.instrPointer + 2
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_END] =
            {
              name = "OPCODE_END",
              handler = function(contextTable)
                addLayoutStructElem(contextTable.codeStructElement, '>>>END.', GDTEAL_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)
                return contextTable.instrPointer + 1
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_NO_RETURN] =
            {
              name = "OPCODE_CALL_PTRCALL_NO_RETURN",
              handler = function(contextTable)

                contextTable.instrPointer = contextTable.instrPointer + 1
                local instr_var_args = contextTable.codeInts[contextTable.instrPointer]
                addStructureElem(contextTable.codeStructElement, 'instr_var_args:', (contextTable.instrPointer - 1) * 0x4, vtDword)
                local argc = contextTable.codeInts[contextTable.instrPointer + 1 + instr_var_args]
                addStructureElem(contextTable.codeStructElement, 'argc:', (contextTable.instrPointer - 1 + 1 + instr_var_args) * 0x4, vtDword)

                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1 + argc])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1 + argc) * 0x4, vtDword)
                operand1 = operand1 .. '.'

                local operandArg = '';

                for i = 0, argc - 1 do
                  if i > 0 then
                    operandArg = operandArg .. ', '
                  end
                  operandArg = operandArg .. formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + i + 1])
                  addStructureElem(contextTable.codeStructElement, 'arg: ' .. formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + i + 1]), (contextTable.instrPointer - 1 + i + 1) * 0x4, vtDword)
                end

                local operand3 = '_methods_ptr[' .. contextTable.codeInts[contextTable.instrPointer + 2 + instr_var_args] .. ']' -- TODO: workaround
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 2 + instr_var_args) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand1 .. operand3 .. '->getname()' .. '(' .. operandArg .. ')' -- TODO: retrieve the funciton name

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1 - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 5 + argc

              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL] =
            {
              name = "OPCODE_CALL_PTRCALL_BOOL",
              handler = function(contextTable)

                contextTable.instrPointer = contextTable.instrPointer + 1
                local instr_var_args = contextTable.codeInts[contextTable.instrPointer]
                addStructureElem(contextTable.codeStructElement, 'instr_var_args:', (contextTable.instrPointer - 1) * 0x4, vtDword)

                local argc = contextTable.codeInts[contextTable.instrPointer + 1 + instr_var_args]
                addStructureElem(contextTable.codeStructElement, 'argc:', (contextTable.instrPointer - 1 + 1 + instr_var_args) * 0x4, vtDword)

                local operand2 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 2 + argc])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)

                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1 + argc])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1 + argc) * 0x4, vtDword)
                operand1 = operand1 .. '.'

                local operandArg = '';

                for i = 0, argc - 1 do
                  if i > 0 then
                    operandArg = operandArg .. ', '
                  end
                  operandArg = operandArg .. formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + i + 1])
                  addStructureElem(contextTable.codeStructElement, 'arg: ' .. formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + i + 1]), (contextTable.instrPointer - 1 + i + 1) * 0x4, vtDword)
                end

                local operand3 = '_methods_ptr[' .. contextTable.codeInts[contextTable.instrPointer + 2 + instr_var_args] .. ']' -- TODO: workaround
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 2 + instr_var_args) * 0x4, vtDword)

                local opcodeType = contextTable.opcodeName:gsub('OPCODE_TYPE_ADJUST_', '')
                contextTable.opcodeName = contextTable.opcodeName .. '(return ' .. opcodeType .. ') ' .. operand2 .. ' = ' .. operand1 .. operand3 .. '->getname()' .. '(' .. operandArg .. ')'
                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1 - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 5 + argc
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_INT] = 
            {
              name = "OPCODE_CALL_PTRCALL_INT",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_FLOAT] = 
            {
              name = "OPCODE_CALL_PTRCALL_FLOAT",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_STRING] = 
            {
              name = "OPCODE_CALL_PTRCALL_STRING",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_VECTOR2] = 
            {
              name = "OPCODE_CALL_PTRCALL_VECTOR2",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_VECTOR2I] = 
            {
              name = "OPCODE_CALL_PTRCALL_VECTOR2I",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_RECT2] = 
            {
              name = "OPCODE_CALL_PTRCALL_RECT2",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_RECT2I] = 
            {
              name = "OPCODE_CALL_PTRCALL_RECT2I",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_VECTOR3] = 
            {
              name = "OPCODE_CALL_PTRCALL_VECTOR3",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_VECTOR3I] = 
            {
              name = "OPCODE_CALL_PTRCALL_VECTOR3I",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_TRANSFORM2D] = 
            {
              name = "OPCODE_CALL_PTRCALL_TRANSFORM2D",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_VECTOR4] = 
            {
              name = "OPCODE_CALL_PTRCALL_VECTOR4",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_VECTOR4I] = 
            {
              name = "OPCODE_CALL_PTRCALL_VECTOR4I",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_PLANE] = 
            {
              name = "OPCODE_CALL_PTRCALL_PLANE",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_QUATERNION] = 
            {
              name = "OPCODE_CALL_PTRCALL_QUATERNION",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_AABB] = 
            {
              name = "OPCODE_CALL_PTRCALL_AABB",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BASIS] = 
            {
              name = "OPCODE_CALL_PTRCALL_BASIS",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_TRANSFORM3D] = 
            {
              name = "OPCODE_CALL_PTRCALL_TRANSFORM3D",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_PROJECTION] = 
            {
              name = "OPCODE_CALL_PTRCALL_PROJECTION",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_COLOR] = 
            {
              name = "OPCODE_CALL_PTRCALL_COLOR",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_STRING_NAME] = 
            {
              name = "OPCODE_CALL_PTRCALL_STRING_NAME",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_NODE_PATH] = 
            {
              name = "OPCODE_CALL_PTRCALL_NODE_PATH",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_RID] = 
            {
              name = "OPCODE_CALL_PTRCALL_RID",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_OBJECT] = 
            {
              name = "OPCODE_CALL_PTRCALL_OBJECT",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_CALLABLE] = 
            {
              name = "OPCODE_CALL_PTRCALL_CALLABLE",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_SIGNAL] = 
            {
              name = "OPCODE_CALL_PTRCALL_SIGNAL",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_DICTIONARY] = 
            {
              name = "OPCODE_CALL_PTRCALL_DICTIONARY",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_ARRAY] = 
            {
              name = "OPCODE_CALL_PTRCALL_ARRAY",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_PACKED_BYTE_ARRAY] = 
            {
              name = "OPCODE_CALL_PTRCALL_PACKED_BYTE_ARRAY",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_PACKED_INT32_ARRAY] = 
            {
              name = "OPCODE_CALL_PTRCALL_PACKED_INT32_ARRAY",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_PACKED_INT64_ARRAY] = 
            {
              name = "OPCODE_CALL_PTRCALL_PACKED_INT64_ARRAY",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_PACKED_FLOAT32_ARRAY] = 
            {
              name = "OPCODE_CALL_PTRCALL_PACKED_FLOAT32_ARRAY",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_PACKED_FLOAT64_ARRAY] = 
            {
              name = "OPCODE_CALL_PTRCALL_PACKED_FLOAT64_ARRAY",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_PACKED_STRING_ARRAY] = 
            {
              name = "OPCODE_CALL_PTRCALL_PACKED_STRING_ARRAY",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_PACKED_VECTOR2_ARRAY] = 
            {
              name = "OPCODE_CALL_PTRCALL_PACKED_VECTOR2_ARRAY",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_PACKED_VECTOR3_ARRAY] = 
            {
              name = "OPCODE_CALL_PTRCALL_PACKED_VECTOR3_ARRAY",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_PACKED_COLOR_ARRAY] = 
            {
              name = "OPCODE_CALL_PTRCALL_PACKED_COLOR_ARRAY",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
            }

        GDF.Decoders = {}

          GDF.Decoders.BytecodeV0 =
            {
              name = "BytecodeV0",
              resolveOPHandlerDefFromProfile = function(profile, opcodeEnum)
                if profile.OPEnumFromInternalOPID[GDF.OP.OPCODE_OPERATOR] == opcodeEnum then
                if profile.OPEnumFromInternalOPID[GDF.OP.OPCODE_OPERATOR] == opcodeEnum then
                  local base = profile.OPHandlerDefFromOPEnum[opcodeEnum]
                  profile.OPHandlerDefFromOPEnum[opcodeEnum] = {
                    name = base.name,
                    handler = function(contextTable)
                      local _pointer_size = GDDEFS.PTRSIZE / 0x4
                      local operation = contextTable.codeInts[contextTable.instrPointer + 4] -- operator is 4*0x4 after
                      addStructureElem(contextTable.codeStructElement, 'Operator: ', (contextTable.instrPointer - 1 + 4) * 0x4, vtDword)
                      local operationName = GDF.OPERATOR_NAME[operation + 1] or 'UNKNOWN_OPERATOR'
                      local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                      addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                      local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2])
                      addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)
                      local operand3 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 3]) -- where to store
                      addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3) * 0x4, vtDword)
                      contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand3 .. ' = ' .. operand1 .. ' ' .. operationName .. ' ' .. operand2
                      addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)
                      return contextTable.instrPointer + 5
                    end
                  }
                end
                end
                return profile.OPHandlerDefFromOPEnum[opcodeEnum]
              end
            }
          GDF.Decoders.BytecodeV1 =
            {
              name = "BytecodeV1",
              resolveOPHandlerDefFromProfile = function(profile, opcodeEnum)
                if profile.OPEnumFromInternalOPID[GDF.OP.OPCODE_OPERATOR] == opcodeEnum then
                  local base = profile.OPHandlerDefFromOPEnum[opcodeEnum]
                  profile.OPHandlerDefFromOPEnum[opcodeEnum] = {
                    name = base.name,
                    handler = function(contextTable)
                      local _pointer_size = GDDEFS.PTRSIZE / 0x4
                      local operation = contextTable.codeInts[contextTable.instrPointer + 4] -- operator is 4*0x4 after
                      addStructureElem(contextTable.codeStructElement, 'Operator: ', (contextTable.instrPointer - 1 + 4) * 0x4, vtDword)
                      local operationName = GDF.OPERATOR_NAME[operation + 1] or 'UNKNOWN_OPERATOR'
                      local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                      addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                      local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2])
                      addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)
                      local operand3 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 3]) -- where to store
                      addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3) * 0x4, vtDword)
                      contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand3 .. ' = ' .. operand1 .. ' ' .. operationName .. ' ' .. operand2
                      addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)
                      return contextTable.instrPointer + 7 + _pointer_size
                    end
                  }
                end

                return profile.OPHandlerDefFromOPEnum[opcodeEnum]
              end
            }

        GDF.ProfileSpecs =
          {
            ["4.0"] =
              {
                decoderName = "BytecodeV0",
                orderedOpcodes =
                {
                  GDF.OP.OPCODE_OPERATOR,
                  GDF.OP.OPCODE_OPERATOR_VALIDATED,
                  GDF.OP.OPCODE_TYPE_TEST_BUILTIN,
                  GDF.OP.OPCODE_TYPE_TEST_ARRAY,
                  GDF.OP.OPCODE_TYPE_TEST_NATIVE,
                  GDF.OP.OPCODE_TYPE_TEST_SCRIPT,
                  GDF.OP.OPCODE_SET_KEYED,
                  GDF.OP.OPCODE_SET_KEYED_VALIDATED,
                  GDF.OP.OPCODE_SET_INDEXED_VALIDATED,
                  GDF.OP.OPCODE_GET_KEYED,
                  GDF.OP.OPCODE_GET_KEYED_VALIDATED,
                  GDF.OP.OPCODE_GET_INDEXED_VALIDATED,
                  GDF.OP.OPCODE_SET_NAMED,
                  GDF.OP.OPCODE_SET_NAMED_VALIDATED,
                  GDF.OP.OPCODE_GET_NAMED,
                  GDF.OP.OPCODE_GET_NAMED_VALIDATED,
                  GDF.OP.OPCODE_SET_MEMBER,
                  GDF.OP.OPCODE_GET_MEMBER,
                  GDF.OP.OPCODE_ASSIGN,
                  GDF.OP.OPCODE_ASSIGN_TRUE,
                  GDF.OP.OPCODE_ASSIGN_FALSE,
                  GDF.OP.OPCODE_ASSIGN_TYPED_BUILTIN,
                  GDF.OP.OPCODE_ASSIGN_TYPED_ARRAY,
                  GDF.OP.OPCODE_ASSIGN_TYPED_NATIVE,
                  GDF.OP.OPCODE_ASSIGN_TYPED_SCRIPT,
                  GDF.OP.OPCODE_CAST_TO_BUILTIN,
                  GDF.OP.OPCODE_CAST_TO_NATIVE,
                  GDF.OP.OPCODE_CAST_TO_SCRIPT,
                  GDF.OP.OPCODE_CONSTRUCT,
                  GDF.OP.OPCODE_CONSTRUCT_VALIDATED,
                  GDF.OP.OPCODE_CONSTRUCT_ARRAY,
                  GDF.OP.OPCODE_CONSTRUCT_TYPED_ARRAY,
                  GDF.OP.OPCODE_CONSTRUCT_DICTIONARY,
                  GDF.OP.OPCODE_CALL,
                  GDF.OP.OPCODE_CALL_RETURN,
                  GDF.OP.OPCODE_CALL_ASYNC,
                  GDF.OP.OPCODE_CALL_UTILITY,
                  GDF.OP.OPCODE_CALL_UTILITY_VALIDATED,
                  GDF.OP.OPCODE_CALL_GDSCRIPT_UTILITY,
                  GDF.OP.OPCODE_CALL_BUILTIN_TYPE_VALIDATED,
                  GDF.OP.OPCODE_CALL_SELF_BASE,
                  GDF.OP.OPCODE_CALL_METHOD_BIND,
                  GDF.OP.OPCODE_CALL_METHOD_BIND_RET,
                  GDF.OP.OPCODE_CALL_BUILTIN_STATIC,
                  GDF.OP.OPCODE_CALL_NATIVE_STATIC,
                  GDF.OP.OPCODE_CALL_PTRCALL_NO_RETURN,
                  GDF.OP.OPCODE_CALL_PTRCALL_BOOL,
                  GDF.OP.OPCODE_CALL_PTRCALL_INT,
                  GDF.OP.OPCODE_CALL_PTRCALL_FLOAT,
                  GDF.OP.OPCODE_CALL_PTRCALL_STRING,
                  GDF.OP.OPCODE_CALL_PTRCALL_VECTOR2,
                  GDF.OP.OPCODE_CALL_PTRCALL_VECTOR2I,
                  GDF.OP.OPCODE_CALL_PTRCALL_RECT2,
                  GDF.OP.OPCODE_CALL_PTRCALL_RECT2I,
                  GDF.OP.OPCODE_CALL_PTRCALL_VECTOR3,
                  GDF.OP.OPCODE_CALL_PTRCALL_VECTOR3I,
                  GDF.OP.OPCODE_CALL_PTRCALL_TRANSFORM2D,
                  GDF.OP.OPCODE_CALL_PTRCALL_VECTOR4,
                  GDF.OP.OPCODE_CALL_PTRCALL_VECTOR4I,
                  GDF.OP.OPCODE_CALL_PTRCALL_PLANE,
                  GDF.OP.OPCODE_CALL_PTRCALL_QUATERNION,
                  GDF.OP.OPCODE_CALL_PTRCALL_AABB,
                  GDF.OP.OPCODE_CALL_PTRCALL_BASIS,
                  GDF.OP.OPCODE_CALL_PTRCALL_TRANSFORM3D,
                  GDF.OP.OPCODE_CALL_PTRCALL_PROJECTION,
                  GDF.OP.OPCODE_CALL_PTRCALL_COLOR,
                  GDF.OP.OPCODE_CALL_PTRCALL_STRING_NAME,
                  GDF.OP.OPCODE_CALL_PTRCALL_NODE_PATH,
                  GDF.OP.OPCODE_CALL_PTRCALL_RID,
                  GDF.OP.OPCODE_CALL_PTRCALL_OBJECT,
                  GDF.OP.OPCODE_CALL_PTRCALL_CALLABLE,
                  GDF.OP.OPCODE_CALL_PTRCALL_SIGNAL,
                  GDF.OP.OPCODE_CALL_PTRCALL_DICTIONARY,
                  GDF.OP.OPCODE_CALL_PTRCALL_ARRAY,
                  GDF.OP.OPCODE_CALL_PTRCALL_PACKED_BYTE_ARRAY,
                  GDF.OP.OPCODE_CALL_PTRCALL_PACKED_INT32_ARRAY,
                  GDF.OP.OPCODE_CALL_PTRCALL_PACKED_INT64_ARRAY,
                  GDF.OP.OPCODE_CALL_PTRCALL_PACKED_FLOAT32_ARRAY,
                  GDF.OP.OPCODE_CALL_PTRCALL_PACKED_FLOAT64_ARRAY,
                  GDF.OP.OPCODE_CALL_PTRCALL_PACKED_STRING_ARRAY,
                  GDF.OP.OPCODE_CALL_PTRCALL_PACKED_VECTOR2_ARRAY,
                  GDF.OP.OPCODE_CALL_PTRCALL_PACKED_VECTOR3_ARRAY,
                  GDF.OP.OPCODE_CALL_PTRCALL_PACKED_COLOR_ARRAY,
                  GDF.OP.OPCODE_AWAIT,
                  GDF.OP.OPCODE_AWAIT_RESUME,
                  GDF.OP.OPCODE_CREATE_LAMBDA,
                  GDF.OP.OPCODE_CREATE_SELF_LAMBDA,
                  GDF.OP.OPCODE_JUMP,
                  GDF.OP.OPCODE_JUMP_IF,
                  GDF.OP.OPCODE_JUMP_IF_NOT,
                  GDF.OP.OPCODE_JUMP_TO_DEF_ARGUMENT,
                  GDF.OP.OPCODE_JUMP_IF_SHARED,
                  GDF.OP.OPCODE_RETURN,
                  GDF.OP.OPCODE_RETURN_TYPED_BUILTIN,
                  GDF.OP.OPCODE_RETURN_TYPED_ARRAY,
                  GDF.OP.OPCODE_RETURN_TYPED_NATIVE,
                  GDF.OP.OPCODE_RETURN_TYPED_SCRIPT,
                  GDF.OP.OPCODE_ITERATE_BEGIN,
                  GDF.OP.OPCODE_ITERATE_BEGIN_INT,
                  GDF.OP.OPCODE_ITERATE_BEGIN_FLOAT,
                  GDF.OP.OPCODE_ITERATE_BEGIN_VECTOR2,
                  GDF.OP.OPCODE_ITERATE_BEGIN_VECTOR2I,
                  GDF.OP.OPCODE_ITERATE_BEGIN_VECTOR3,
                  GDF.OP.OPCODE_ITERATE_BEGIN_VECTOR3I,
                  GDF.OP.OPCODE_ITERATE_BEGIN_STRING,
                  GDF.OP.OPCODE_ITERATE_BEGIN_DICTIONARY,
                  GDF.OP.OPCODE_ITERATE_BEGIN_ARRAY,
                  GDF.OP.OPCODE_ITERATE_BEGIN_PACKED_BYTE_ARRAY,
                  GDF.OP.OPCODE_ITERATE_BEGIN_PACKED_INT32_ARRAY,
                  GDF.OP.OPCODE_ITERATE_BEGIN_PACKED_INT64_ARRAY,
                  GDF.OP.OPCODE_ITERATE_BEGIN_PACKED_FLOAT32_ARRAY,
                  GDF.OP.OPCODE_ITERATE_BEGIN_PACKED_FLOAT64_ARRAY,
                  GDF.OP.OPCODE_ITERATE_BEGIN_PACKED_STRING_ARRAY,
                  GDF.OP.OPCODE_ITERATE_BEGIN_PACKED_VECTOR2_ARRAY,
                  GDF.OP.OPCODE_ITERATE_BEGIN_PACKED_VECTOR3_ARRAY,
                  GDF.OP.OPCODE_ITERATE_BEGIN_PACKED_COLOR_ARRAY,
                  GDF.OP.OPCODE_ITERATE_BEGIN_OBJECT,
                  GDF.OP.OPCODE_ITERATE,
                  GDF.OP.OPCODE_ITERATE_INT,
                  GDF.OP.OPCODE_ITERATE_FLOAT,
                  GDF.OP.OPCODE_ITERATE_VECTOR2,
                  GDF.OP.OPCODE_ITERATE_VECTOR2I,
                  GDF.OP.OPCODE_ITERATE_VECTOR3,
                  GDF.OP.OPCODE_ITERATE_VECTOR3I,
                  GDF.OP.OPCODE_ITERATE_STRING,
                  GDF.OP.OPCODE_ITERATE_DICTIONARY,
                  GDF.OP.OPCODE_ITERATE_ARRAY,
                  GDF.OP.OPCODE_ITERATE_PACKED_BYTE_ARRAY,
                  GDF.OP.OPCODE_ITERATE_PACKED_INT32_ARRAY,
                  GDF.OP.OPCODE_ITERATE_PACKED_INT64_ARRAY,
                  GDF.OP.OPCODE_ITERATE_PACKED_FLOAT32_ARRAY,
                  GDF.OP.OPCODE_ITERATE_PACKED_FLOAT64_ARRAY,
                  GDF.OP.OPCODE_ITERATE_PACKED_STRING_ARRAY,
                  GDF.OP.OPCODE_ITERATE_PACKED_VECTOR2_ARRAY,
                  GDF.OP.OPCODE_ITERATE_PACKED_VECTOR3_ARRAY,
                  GDF.OP.OPCODE_ITERATE_PACKED_COLOR_ARRAY,
                  GDF.OP.OPCODE_ITERATE_OBJECT,
                  GDF.OP.OPCODE_STORE_GLOBAL,
                  GDF.OP.OPCODE_STORE_NAMED_GLOBAL,
                  GDF.OP.OPCODE_TYPE_ADJUST_BOOL,
                  GDF.OP.OPCODE_TYPE_ADJUST_INT,
                  GDF.OP.OPCODE_TYPE_ADJUST_FLOAT,
                  GDF.OP.OPCODE_TYPE_ADJUST_STRING,
                  GDF.OP.OPCODE_TYPE_ADJUST_VECTOR2,
                  GDF.OP.OPCODE_TYPE_ADJUST_VECTOR2I,
                  GDF.OP.OPCODE_TYPE_ADJUST_RECT2,
                  GDF.OP.OPCODE_TYPE_ADJUST_RECT2I,
                  GDF.OP.OPCODE_TYPE_ADJUST_VECTOR3,
                  GDF.OP.OPCODE_TYPE_ADJUST_VECTOR3I,
                  GDF.OP.OPCODE_TYPE_ADJUST_TRANSFORM2D,
                  GDF.OP.OPCODE_TYPE_ADJUST_VECTOR4,
                  GDF.OP.OPCODE_TYPE_ADJUST_VECTOR4I,
                  GDF.OP.OPCODE_TYPE_ADJUST_PLANE,
                  GDF.OP.OPCODE_TYPE_ADJUST_QUATERNION,
                  GDF.OP.OPCODE_TYPE_ADJUST_AABB,
                  GDF.OP.OPCODE_TYPE_ADJUST_BASIS,
                  GDF.OP.OPCODE_TYPE_ADJUST_TRANSFORM3D,
                  GDF.OP.OPCODE_TYPE_ADJUST_PROJECTION,
                  GDF.OP.OPCODE_TYPE_ADJUST_COLOR,
                  GDF.OP.OPCODE_TYPE_ADJUST_STRING_NAME,
                  GDF.OP.OPCODE_TYPE_ADJUST_NODE_PATH,
                  GDF.OP.OPCODE_TYPE_ADJUST_RID,
                  GDF.OP.OPCODE_TYPE_ADJUST_OBJECT,
                  GDF.OP.OPCODE_TYPE_ADJUST_CALLABLE,
                  GDF.OP.OPCODE_TYPE_ADJUST_SIGNAL,
                  GDF.OP.OPCODE_TYPE_ADJUST_DICTIONARY,
                  GDF.OP.OPCODE_TYPE_ADJUST_ARRAY,
                  GDF.OP.OPCODE_TYPE_ADJUST_PACKED_BYTE_ARRAY,
                  GDF.OP.OPCODE_TYPE_ADJUST_PACKED_INT32_ARRAY,
                  GDF.OP.OPCODE_TYPE_ADJUST_PACKED_INT64_ARRAY,
                  GDF.OP.OPCODE_TYPE_ADJUST_PACKED_FLOAT32_ARRAY,
                  GDF.OP.OPCODE_TYPE_ADJUST_PACKED_FLOAT64_ARRAY,
                  GDF.OP.OPCODE_TYPE_ADJUST_PACKED_STRING_ARRAY,
                  GDF.OP.OPCODE_TYPE_ADJUST_PACKED_VECTOR2_ARRAY,
                  GDF.OP.OPCODE_TYPE_ADJUST_PACKED_VECTOR3_ARRAY,
                  GDF.OP.OPCODE_TYPE_ADJUST_PACKED_COLOR_ARRAY,
                  GDF.OP.OPCODE_ASSERT,
                  GDF.OP.OPCODE_BREAKPOINT,
                  GDF.OP.OPCODE_LINE,
                  GDF.OP.OPCODE_END
                }
              },

            ["4.1"] =
              {
                base = "4.0",
                decoderName = "BytecodeV0",
                patches = 
                {
                  {
                    kind = "insertValueAfter",
                    anchor = GDF.OP.OPCODE_GET_MEMBER,
                    value = GDF.OP.OPCODE_SET_STATIC_VARIABLE
                  },
                  {
                    kind = "insertValueAfter",
                    anchor = GDF.OP.OPCODE_SET_STATIC_VARIABLE,
                    value = GDF.OP.OPCODE_GET_STATIC_VARIABLE
                  }
                }
              },

            ["4.2"] =
              {
                base = "4.1",
                decoderName = "BytecodeV1",
                patches =
                {
                  {
                    kind = "insertValueAfter",
                    anchor = GDF.OP.OPCODE_CALL_NATIVE_STATIC,
                    value = GDF.OP.OPCODE_CALL_METHOD_BIND_VALIDATED_RETURN
                  },
                  {
                    kind = "insertValueAfter",
                    anchor = GDF.OP.OPCODE_CALL_METHOD_BIND_VALIDATED_RETURN,
                    value = GDF.OP.OPCODE_CALL_METHOD_BIND_VALIDATED_NO_RETURN
                  },
                  {
                    kind = "removeValue",
                    value = GDF.OP.OPCODE_CALL_PTRCALL_NO_RETURN
                  },
                  {
                    kind = "removeValue",
                    value = GDF.OP.OPCODE_CALL_PTRCALL_BOOL
                  },
                  {
                    kind = "removeValue",
                    value = GDF.OP.OPCODE_CALL_PTRCALL_INT
                  },
                  {
                    kind = "removeValue",
                    value = GDF.OP.OPCODE_CALL_PTRCALL_FLOAT
                  },
                  {
                    kind = "removeValue",
                    value = GDF.OP.OPCODE_CALL_PTRCALL_STRING
                  },
                  {
                    kind = "removeValue",
                    value = GDF.OP.OPCODE_CALL_PTRCALL_VECTOR2
                  },
                  {
                    kind = "removeValue",
                    value = GDF.OP.OPCODE_CALL_PTRCALL_VECTOR2I
                  },
                  {
                    kind = "removeValue",
                    value = GDF.OP.OPCODE_CALL_PTRCALL_RECT2
                  },
                  {
                    kind = "removeValue",
                    value = GDF.OP.OPCODE_CALL_PTRCALL_RECT2I
                  },
                  {
                    kind = "removeValue",
                    value = GDF.OP.OPCODE_CALL_PTRCALL_VECTOR3
                  },
                  {
                    kind = "removeValue",
                    value = GDF.OP.OPCODE_CALL_PTRCALL_VECTOR3I
                  },
                  {
                    kind = "removeValue",
                    value = GDF.OP.OPCODE_CALL_PTRCALL_TRANSFORM2D
                  },
                  {
                    kind = "removeValue",
                    value = GDF.OP.OPCODE_CALL_PTRCALL_VECTOR4
                  },
                  {
                    kind = "removeValue",
                    value = GDF.OP.OPCODE_CALL_PTRCALL_VECTOR4I
                  },
                  {
                    kind = "removeValue",
                    value = GDF.OP.OPCODE_CALL_PTRCALL_PLANE
                  },
                  {
                    kind = "removeValue",
                    value = GDF.OP.OPCODE_CALL_PTRCALL_QUATERNION
                  },
                  {
                    kind = "removeValue",
                    value = GDF.OP.OPCODE_CALL_PTRCALL_AABB
                  },
                  {
                    kind = "removeValue",
                    value = GDF.OP.OPCODE_CALL_PTRCALL_BASIS
                  },
                  {
                    kind = "removeValue",
                    value = GDF.OP.OPCODE_CALL_PTRCALL_TRANSFORM3D
                  },
                  {
                    kind = "removeValue",
                    value = GDF.OP.OPCODE_CALL_PTRCALL_PROJECTION
                  },
                  {
                    kind = "removeValue",
                    value = GDF.OP.OPCODE_CALL_PTRCALL_COLOR
                  },
                  {
                    kind = "removeValue",
                    value = GDF.OP.OPCODE_CALL_PTRCALL_STRING_NAME
                  },
                  {
                    kind = "removeValue",
                    value = GDF.OP.OPCODE_CALL_PTRCALL_NODE_PATH
                  },
                  {
                    kind = "removeValue",
                    value = GDF.OP.OPCODE_CALL_PTRCALL_RID
                  },
                  {
                    kind = "removeValue",
                    value = GDF.OP.OPCODE_CALL_PTRCALL_OBJECT
                  },
                  {
                    kind = "removeValue",
                    value = GDF.OP.OPCODE_CALL_PTRCALL_CALLABLE
                  },
                  {
                    kind = "removeValue",
                    value = GDF.OP.OPCODE_CALL_PTRCALL_SIGNAL
                  },
                  {
                    kind = "removeValue",
                    value = GDF.OP.OPCODE_CALL_PTRCALL_DICTIONARY
                  },
                  {
                    kind = "removeValue",
                    value = GDF.OP.OPCODE_CALL_PTRCALL_ARRAY
                  },
                  {
                    kind = "removeValue",
                    value = GDF.OP.OPCODE_CALL_PTRCALL_PACKED_BYTE_ARRAY
                  },
                  {
                    kind = "removeValue",
                    value = GDF.OP.OPCODE_CALL_PTRCALL_PACKED_INT32_ARRAY
                  },
                  {
                    kind = "removeValue",
                    value = GDF.OP.OPCODE_CALL_PTRCALL_PACKED_INT64_ARRAY
                  },
                  {
                    kind = "removeValue",
                    value = GDF.OP.OPCODE_CALL_PTRCALL_PACKED_FLOAT32_ARRAY
                  },
                  {
                    kind = "removeValue",
                    value = GDF.OP.OPCODE_CALL_PTRCALL_PACKED_FLOAT64_ARRAY
                  },
                  {
                    kind = "removeValue",
                    value = GDF.OP.OPCODE_CALL_PTRCALL_PACKED_STRING_ARRAY
                  },
                  {
                    kind = "removeValue",
                    value = GDF.OP.OPCODE_CALL_PTRCALL_PACKED_VECTOR2_ARRAY
                  },
                  {
                    kind = "removeValue",
                    value = GDF.OP.OPCODE_CALL_PTRCALL_PACKED_VECTOR3_ARRAY
                  },
                  {
                    kind = "removeValue",
                    value = GDF.OP.OPCODE_CALL_PTRCALL_PACKED_COLOR_ARRAY
                
                  }
                }
              },

            ["4.3"] =
              {
                base = "4.2",
                decoderName = "BytecodeV1",
                patches =
                {
                  {
                    kind = "insertValueAfter",
                    anchor = GDF.OP.OPCODE_ASSIGN,
                    value = GDF.OP.OPCODE_ASSIGN_NULL
                  },
                  {
                    kind = "insertValueAfter",
                    anchor = GDF.OP.OPCODE_CALL_NATIVE_STATIC,
                    value = GDF.OP.OPCODE_CALL_NATIVE_STATIC_VALIDATED_RETURN
                  },
                  {
                    kind = "insertValueAfter",
                    anchor = GDF.OP.OPCODE_CALL_NATIVE_STATIC_VALIDATED_RETURN,
                    value = GDF.OP.OPCODE_CALL_NATIVE_STATIC_VALIDATED_NO_RETURN
                  },
                  {
                    kind = "insertValueAfter",
                    anchor = GDF.OP.OPCODE_ITERATE_BEGIN_PACKED_COLOR_ARRAY,
                    value = GDF.OP.OPCODE_ITERATE_BEGIN_PACKED_VECTOR4_ARRAY
                  },
                  {
                    kind = "insertValueAfter",
                    anchor = GDF.OP.OPCODE_ITERATE_PACKED_COLOR_ARRAY,
                    value = GDF.OP.OPCODE_ITERATE_PACKED_VECTOR4_ARRAY
                  },
                  {
                    kind = "insertValueAfter",
                    anchor = GDF.OP.OPCODE_TYPE_ADJUST_PACKED_COLOR_ARRAY,
                    value = GDF.OP.OPCODE_TYPE_ADJUST_PACKED_VECTOR4_ARRAY
                  }
                }
              },

            ["4.4"] =
              {
                base = "4.3",
                decoderName = "BytecodeV1",
                patches =
                {
                  {
                    kind = "insertValueAfter",
                    anchor = GDF.OP.OPCODE_TYPE_TEST_ARRAY,
                    value = GDF.OP.OPCODE_TYPE_TEST_DICTIONARY
                  },
                  {
                    kind = "insertValueAfter",
                    anchor = GDF.OP.OPCODE_ASSIGN_TYPED_ARRAY,
                    value = GDF.OP.OPCODE_ASSIGN_TYPED_DICTIONARY
                  },
                  {
                    kind = "insertValueAfter",
                    anchor = GDF.OP.OPCODE_CONSTRUCT_DICTIONARY,
                    value = GDF.OP.OPCODE_CONSTRUCT_TYPED_DICTIONARY
                  },
                  {
                    kind = "insertValueAfter",
                    anchor = GDF.OP.OPCODE_RETURN_TYPED_ARRAY,
                    value = GDF.OP.OPCODE_RETURN_TYPED_DICTIONARY
                  }
                }
              },

            ["4.5"] =
              {
                base = "4.4",
                decoderName = "BytecodeV1",
                patches =
                {
                  {
                    kind = "insertValueAfter",
                    anchor = GDF.OP.OPCODE_ITERATE_BEGIN_OBJECT,
                    value = GDF.OP.OPCODE_ITERATE_BEGIN_RANGE
                  },
                  {
                    kind = "insertValueAfter",
                    anchor = GDF.OP.OPCODE_ITERATE_OBJECT,
                    value = GDF.OP.OPCODE_ITERATE_RANGE
                  }
                }
              },

            ["4.6"] =
              {
                base = "4.5",
                decoderName = "BytecodeV1",
                patches = {}
              },
            ["4.7"] =
              {
                base = "4.6",
                decoderName = "BytecodeV1",
                patches = {}
              },
            ["4.8"] =
              {
                base = "4.7",
                decoderName = "BytecodeV1",
                patches = {}
              }
          }
        GDF.CompiledProfiles = {}
        GDF.EADDRESS =
          {
            ['ADDR_BITS'] = 24,
            ['ADDR_MASK'] = ((1 << 24) - 1), -- ((1 << ADDR_BITS) - 1)
            ['ADDR_TYPE_MASK'] = ~((1 << 24) - 1),
            ['ADDR_TYPE_STACK'] = 0,
            ['ADDR_TYPE_CONSTANT'] = 1,
            ['ADDR_TYPE_MEMBER'] = 2,
            ['ADDR_TYPE_MAX'] = 3
          }
        GDF.EFIXEDADDRESSES =
          {
            ['ADDR_STACK_SELF'] = 0,
            ['ADDR_STACK_CLASS'] = 1,
            ['ADDR_STACK_NIL'] = 2,
            ['FIXED_ADDRESSES_MAX'] = 3,
            ['ADDR_SELF'] = 0 | GDF.EADDRESS['ADDR_TYPE_STACK'] << GDF.EADDRESS['ADDR_BITS'],
            ['ADDR_CLASS'] = 1 | GDF.EADDRESS['ADDR_TYPE_STACK'] << GDF.EADDRESS['ADDR_BITS'],
            ['ADDR_NIL'] = 2 | GDF.EADDRESS['ADDR_TYPE_STACK'] << GDF.EADDRESS['ADDR_BITS']
          }
        GDF.OPERATOR_NAME =
          {
            -- comparison
            "OP_EQUAL",
            "OP_NOT_EQUAL",
            "OP_LESS",
            "OP_LESS_EQUAL",
            "OP_GREATER",
            "OP_GREATER_EQUAL",
            -- mathematic
            "OP_ADD",
            "OP_SUBTRACT",
            "OP_MULTIPLY",
            "OP_DIVIDE",
            "OP_NEGATE",
            "OP_POSITIVE", 
            "OP_MODULE",
            "OP_POWER",
            -- bitwise
            "OP_SHIFT_LEFT",
            "OP_SHIFT_RIGHT",
            "OP_BIT_AND",
            "OP_BIT_OR",
            "OP_BIT_XOR",
            "OP_BIT_NEGATE",
            -- logic
            "OP_AND",
            "OP_OR",
            "OP_XOR",
            "OP_NOT",
            -- containment
            "OP_IN",
            "OP_MAX" -- 25
          }

        for version, _ in pairs(GDF.ProfileSpecs) do
          GDF.CompiledProfiles[version] = createProfileFromVersion(version)
        end

        if GDDEFS.VERSION_STRING then
          GDF.CurrentDisassembler = GDF.createDisassemblerFromVersion(GDDEFS.VERSION_STRING)
        end

      else--if GDDEFS.MAJOR_VER == 3 then

        function formatDisassembledAddress(addrInt) -- redefined for 3.x
          local addrIndex = addrInt & (GDF.EADDRESS['ADDR_MASK']) -- address, lower 24 bits are indices
          local addrType = ( (addrInt & GDF.EADDRESS['ADDR_TYPE_MASK']) >> GDF.EADDRESS['ADDR_BITS']) -- the higher 8 would be types: shift to the beginning and mask

          if addrType == 0 and (addrIndex >= 0 and addrIndex <= 3) then
            if addrIndex == GDF.EADDRESS['ADDR_TYPE_SELF'] then    return "stack(self)" end -- return &self;
            if addrIndex == GDF.EADDRESS['ADDR_TYPE_CLASS'] then   return "stack(class)" end -- &static_ref;
            if addrIndex == GDF.EADDRESS['ADDR_TYPE_NIL'] then     return "stack(nil)" end -- return &nil
                                                                    return 'stack[' .. tostring(addrIndex) .. ']'
          end

          if (addrType == GDF.EADDRESS['ADDR_TYPE_STACK']) then               return ("stack[%d]"):format(addrIndex) -- return &p_stack[address];
          elseif (addrType == GDF.EADDRESS['ADDR_TYPE_STACK_VARIABLE']) then  return ("stack[%d]"):format(addrIndex) -- return &p_stack[address];
          elseif (addrType == GDF.EADDRESS['ADDR_TYPE_CLASS_CONSTANT']) then  return ("Node Constants[%d]"):format(addrIndex) -- Map<StringName, Variant>::Element *E = o->constants.find(*sn); return &E->get();
          elseif (addrType == GDF.EADDRESS['ADDR_TYPE_LOCAL_CONSTANT']) then  return ("Constants[%d]"):format(addrIndex) -- return &_constants_ptr[address];
          elseif (addrType == GDF.EADDRESS['ADDR_TYPE_GLOBAL']) then          return ("ScriptLang::GlobArray[%d]"):format(addrIndex) -- return &GDScriptLanguage::get_singleton()->get_global_array()[address];
          elseif (addrType == GDF.EADDRESS['ADDR_TYPE_MEMBER']) then          return ("Variants[%d]"):format(addrIndex) -- for clarity ("member[%d]"):format(addrIndex)
          else                                                                return ("addr?(0x%08X)"):format(addrInt)
          end
        end

        GDF.OP =
          {
            OPCODE_OPERATOR = "OPCODE_OPERATOR", -- 0
            OPCODE_EXTENDS_TEST = "OPCODE_EXTENDS_TEST", -- 1
            OPCODE_IS_BUILTIN = "OPCODE_IS_BUILTIN", -- 2
            OPCODE_SET = "OPCODE_SET", -- 3
            OPCODE_GET = "OPCODE_GET", -- 4
            OPCODE_SET_NAMED = "OPCODE_SET_NAMED", -- 5
            OPCODE_GET_NAMED = "OPCODE_GET_NAMED", -- 6
            OPCODE_SET_MEMBER = "OPCODE_SET_MEMBER", -- 7
            OPCODE_GET_MEMBER = "OPCODE_GET_MEMBER", -- 8
            OPCODE_ASSIGN = "OPCODE_ASSIGN", -- 9
            OPCODE_ASSIGN_TRUE = "OPCODE_ASSIGN_TRUE", -- 10
            OPCODE_ASSIGN_FALSE = "OPCODE_ASSIGN_FALSE", -- 11
            OPCODE_ASSIGN_TYPED_BUILTIN = "OPCODE_ASSIGN_TYPED_BUILTIN", -- 12
            OPCODE_ASSIGN_TYPED_NATIVE = "OPCODE_ASSIGN_TYPED_NATIVE", -- 13
            OPCODE_ASSIGN_TYPED_SCRIPT = "OPCODE_ASSIGN_TYPED_SCRIPT", -- 14
            OPCODE_CAST_TO_BUILTIN = "OPCODE_CAST_TO_BUILTIN", -- 15
            OPCODE_CAST_TO_NATIVE = "OPCODE_CAST_TO_NATIVE", -- 16
            OPCODE_CAST_TO_SCRIPT = "OPCODE_CAST_TO_SCRIPT", -- 17
            OPCODE_CONSTRUCT = "OPCODE_CONSTRUCT", -- 18
            OPCODE_CONSTRUCT_ARRAY = "OPCODE_CONSTRUCT_ARRAY", -- 19
            OPCODE_CONSTRUCT_DICTIONARY = "OPCODE_CONSTRUCT_DICTIONARY", -- 20
            OPCODE_CALL = "OPCODE_CALL", -- 21
            OPCODE_CALL_RETURN = "OPCODE_CALL_RETURN", -- 22
            OPCODE_CALL_BUILT_IN = "OPCODE_CALL_BUILT_IN", -- 23
            OPCODE_CALL_SELF = "OPCODE_CALL_SELF", -- 24
            OPCODE_CALL_SELF_BASE = "OPCODE_CALL_SELF_BASE", -- 25
            OPCODE_YIELD = "OPCODE_YIELD", -- 26
            OPCODE_YIELD_SIGNAL = "OPCODE_YIELD_SIGNAL", -- 27
            OPCODE_YIELD_RESUME = "OPCODE_YIELD_RESUME", -- 28
            OPCODE_JUMP = "OPCODE_JUMP", -- 29
            OPCODE_JUMP_IF = "OPCODE_JUMP_IF", -- 30
            OPCODE_JUMP_IF_NOT = "OPCODE_JUMP_IF_NOT", -- 31
            OPCODE_JUMP_TO_DEF_ARGUMENT = "OPCODE_JUMP_TO_DEF_ARGUMENT", -- 32
            OPCODE_RETURN = "OPCODE_RETURN", -- 33
            OPCODE_ITERATE_BEGIN = "OPCODE_ITERATE_BEGIN", -- 34
            OPCODE_ITERATE = "OPCODE_ITERATE", -- 35
            OPCODE_ASSERT = "OPCODE_ASSERT", -- 36
            OPCODE_BREAKPOINT = "OPCODE_BREAKPOINT", -- 37
            OPCODE_LINE = "OPCODE_LINE", -- 38
            OPCODE_END = "OPCODE_END" -- 39 (enum)
          }
        
        GDF.DisasmHandlers = {}

          GDF.DisasmHandlers[GDF.OP.OPCODE_OPERATOR] =
            {

              name = "OPCODE_OPERATOR",
              handler = function(contextTable)

                local operation = contextTable.codeInts[contextTable.instrPointer + 1] -- operator is 4*0x4 after
                addStructureElem(contextTable.codeStructElement, 'Operator: ', (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)

                local operationName = GDF.OPERATOR_NAME[operation + 1] or 'UNKNOWN_OPERATOR'
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2]) -- a
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)
                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 3]) -- b
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 3) * 0x4, vtDword)
                local operand3 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 4]) -- dest
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 4) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand3 .. ' = ' .. operand1 .. ' ' .. operationName .. ' ' .. operand2
                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 5
              end
            }

          GDF.DisasmHandlers[GDF.OP.OPCODE_EXTENDS_TEST] =
            {

              name = "OPCODE_EXTENDS_TEST",
              handler = function(contextTable)

                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)
                local operand3 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 3]) -- dest
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand3 .. ' = ' .. operand1 .. ' extends' .. ' ' .. operand2 .. ' ?'
                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 4
              end
            }

          GDF.DisasmHandlers[GDF.OP.OPCODE_IS_BUILTIN] =
            {

              name = "OPCODE_IS_BUILTIN",
              handler = function(contextTable)

                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1]) -- value
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                local operand2 = getGDTypeName(contextTable.codeInts[contextTable.instrPointer + 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)
                local operand3 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 3]) -- dest
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand3 .. ' = ' .. operand1 .. ' is built-in type ' .. ' ' .. operand2 .. ' ?'
                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 4
              end
            }

          GDF.DisasmHandlers[GDF.OP.OPCODE_SET] = 
            {
              name = "OPCODE_SET",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1]) -- dest
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2]) -- index
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)
                local operand3 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 3]) -- value
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3) * 0x4, vtDword)
                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand1 .. '[' .. operand2 .. '] = ' .. operand3
                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)
                return contextTable.instrPointer + 4
              end
            }


          GDF.DisasmHandlers[GDF.OP.OPCODE_GET] = 
            {
              name = "OPCODE_GET",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1]) -- src
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2]) -- index
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)
                local operand3 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 3]) -- dest
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand3 .. ' = ' .. operand1 .. '[' .. operand2 .. ']'

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 4
              end
            }

          GDF.DisasmHandlers[GDF.OP.OPCODE_SET_NAMED] = 
            {
              name = "OPCODE_SET_NAMED",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1]) -- dest
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                local operand2 = 'Globals[' .. contextTable.codeInts[contextTable.instrPointer + 2] .. ']' -- globals index
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)
                local operand3 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 3]) -- value
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand1 .. '= ["' .. operand2 .. '"] = ' .. operand3

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 4
              end
            }

          GDF.DisasmHandlers[GDF.OP.OPCODE_GET_NAMED] = 
            {
              name = "OPCODE_GET_NAMED",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1]) -- source
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                local operand2 = 'Globals[' .. contextTable.codeInts[contextTable.instrPointer + 2] .. ']' -- globals index
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)
                local operand3 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 3]) -- dest
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand3 .. ' = ' .. operand1 .. '["' .. operand2 .. '"]'

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 4
              end
            }

          GDF.DisasmHandlers[GDF.OP.OPCODE_SET_MEMBER] = 
            {
              name = "OPCODE_SET_MEMBER",
              handler = function(contextTable)
                
                local operand1 = 'Globals[' .. contextTable.codeInts[contextTable.instrPointer + 1] .. ']' -- index
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2]) -- src
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. '["' .. operand1 .. '"] = ' .. operand2

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 3
              end
            }

          GDF.DisasmHandlers[GDF.OP.OPCODE_GET_MEMBER] = 
            {
              name = "OPCODE_GET_MEMBER",
              handler = function(contextTable)
                local operand1 = 'Globals[' .. contextTable.codeInts[contextTable.instrPointer + 1] .. ']' -- index
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2]) -- dest
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand2 .. ' = ["' .. operand1 .. '"]'

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 3
              end
            }

          GDF.DisasmHandlers[GDF.OP.OPCODE_ASSIGN] = 
            {
              name = "OPCODE_ASSIGN",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1]) -- dest
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2]) -- src
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand1 .. ' = ' .. operand2

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 3
              end
            }

          GDF.DisasmHandlers[GDF.OP.OPCODE_ASSIGN_TRUE] = 
            {
              name = "OPCODE_ASSIGN_TRUE",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand1 .. ' = TRUE'
                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)
                return contextTable.instrPointer + 2
              end
            }

          GDF.DisasmHandlers[GDF.OP.OPCODE_ASSIGN_FALSE] = 
            {
              name = "OPCODE_ASSIGN_FALSE",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand1 .. ' = FALSE'

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 2
              end
            }

            GDF.DisasmHandlers[GDF.OP.OPCODE_ASSIGN_TYPED_BUILTIN] = 
              {
                name = "OPCODE_ASSIGN_TYPED_BUILTIN",
                handler = function(contextTable)
                  local operand1 = getGDTypeName(contextTable.codeInts[contextTable.instrPointer + 1])
                  addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword) -- type
                  local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2])
                  addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)  -- dest
                  local operand3 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 3])
                  addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3) * 0x4, vtDword) -- src

                  contextTable.opcodeName = contextTable.opcodeName .. ' (' .. operand1 .. ') ' .. operand2 .. ' = ' .. operand3

                  addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                  return contextTable.instrPointer + 4
                end
              }

          GDF.DisasmHandlers[GDF.OP.OPCODE_ASSIGN_TYPED_NATIVE] = 
            {
              name = "OPCODE_ASSIGN_TYPED_NATIVE",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword) -- type
                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword) -- dest
                local operand3 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 3])
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3) * 0x4, vtDword) -- src

                contextTable.opcodeName = contextTable.opcodeName .. ' (' .. operand1 .. ')' .. operand2 .. ' = ' .. operand3

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 4
              end
            }

          GDF.DisasmHandlers[GDF.OP.OPCODE_ASSIGN_TYPED_SCRIPT] = 
            {
              name = "OPCODE_ASSIGN_TYPED_SCRIPT",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword) -- script type
                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword) -- dest
                local operand3 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 3])
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3) * 0x4, vtDword) -- src

                contextTable.opcodeName = contextTable.opcodeName .. ' (' .. operand1 .. ') ' .. operand2 .. ' = ' .. operand3

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 4
              end
            }

          GDF.DisasmHandlers[GDF.OP.OPCODE_CAST_TO_BUILTIN] = 
            {
              name = "OPCODE_CAST_TO_BUILTIN",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword) -- to_type
                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword) -- src
                local operand3 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 3])
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3) * 0x4, vtDword) -- dest

                local operand1_n = getGDTypeName(contextTable.codeInts[contextTable.instrPointer + 1])

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand3 .. ' = ' .. operand2 .. ' as ' .. operand1_n

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 4
              end
            }

          GDF.DisasmHandlers[GDF.OP.OPCODE_CAST_TO_NATIVE] = 
            {
              name = "OPCODE_CAST_TO_NATIVE",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword) -- to_type
                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword) -- src
                local operand3 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 3])
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3) * 0x4, vtDword) -- dest

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand3 .. ' = ' .. operand2 .. ' as GDScriptNativeClass ' .. operand1

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 4
              end
            }

          GDF.DisasmHandlers[GDF.OP.OPCODE_CAST_TO_SCRIPT] = 
            {
              name = "OPCODE_CAST_TO_SCRIPT",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword) -- to_type
                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword) -- src
                local operand3 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 3])
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3) * 0x4, vtDword) -- dest

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand3 .. ' = ' .. operand2 .. ' as Script ' .. operand1

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 4
              end
            }

          GDF.DisasmHandlers[GDF.OP.OPCODE_CONSTRUCT] = 
            {
              name = "OPCODE_CONSTRUCT",
              handler = function(contextTable)
                
                local typeName = getGDTypeName(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, typeName, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword) -- Variant::Type

                local argc = contextTable.codeInts[contextTable.instrPointer + 2]
                addStructureElem(contextTable.codeStructElement, 'argc:', (contextTable.instrPointer - 1 + 2) * 0x4, vtDword) -- argc

                local operand3 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 3 + argc])
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3 + argc) * 0x4, vtDword) -- dest
                local operandArg = '';

                for i = 0, argc - 1 do
                  if i > 0 then
                    operandArg = operandArg .. ', '
                  end
                  operandArg = operandArg .. formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 3 + i]) -- argptrs[i] = Arg;
                  addStructureElem(contextTable.codeStructElement, 'arg: ' .. formatDisassembledAddress(contextTable.codeInts[3 + i]), (contextTable.instrPointer - 1 + 3 + i) * 0x4, vtDword)
                end

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand3 .. ' = ' .. typeName .. '(' .. operandArg .. ')'

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 4 + argc
              end
            }

          GDF.DisasmHandlers[GDF.OP.OPCODE_CONSTRUCT_ARRAY] = 
            {
              name = "OPCODE_CONSTRUCT_ARRAY",
              handler = function(contextTable)

                local argc = contextTable.codeInts[contextTable.instrPointer + 1]
                addStructureElem(contextTable.codeStructElement, 'argc:', (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)

                local operandArg = '';

                for i = 0, argc - 1 do
                  if i > 0 then
                    operandArg = operandArg .. ', '
                  end
                  operandArg = operandArg .. formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 2 + i])
                  addStructureElem(contextTable.codeStructElement, 'arg: ' .. formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2 + i]), (contextTable.instrPointer - 1 + 2 + i) * 0x4, vtDword)
                end

                local operand2 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 2 + argc])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2 + argc) * 0x4, vtDword) -- dest

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand2 .. ' = ' .. '[' .. operandArg .. ']'

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 3 + argc
              end
            }

          GDF.DisasmHandlers[GDF.OP.OPCODE_CONSTRUCT_DICTIONARY] = 
            {
              name = "OPCODE_CONSTRUCT_DICTIONARY",
              handler = function(contextTable)
                -- contextTable.instrPointer = contextTable.instrPointer + 1
                
                local argc = contextTable.codeInts[contextTable.instrPointer + 1]
                addStructureElem(contextTable.codeStructElement, 'argc:', (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)

                local operand2 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + argc * 2 + 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + argc * 2 + 2) * 0x4, vtDword)

                local operandArg = '';

                for i = 0, argc - 1 do
                  if i > 0 then
                    operandArg = operandArg .. ', '
                  end
                  operandArg = operandArg .. formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 2 + i * 2 + 0])
                  addStructureElem(contextTable.codeStructElement, 'argK: ' .. formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2 + i * 2 + 0]), (contextTable.instrPointer - 1 + 2 + i * 2 + 0) * 0x4, vtDword)
                  operandArg = operandArg .. ': ' .. formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 2 + i * 2 + 1])
                  addStructureElem(contextTable.codeStructElement, 'argV: ' .. formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2 + i * 2 + 1]), (contextTable.instrPointer - 1 + 2 + i * 2 + 1) * 0x4, vtDword)
                end

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand2 .. ' =  {' .. operandArg .. '  }'

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 3 + argc * 2

              end
            }

          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL] = 
            {
              name = "OPCODE_CALL",
              handler = function(contextTable)

                local ret = contextTable.codeInts[contextTable.instrPointer] == GDF.CurrentDisassembler:getOPEnumFromInternalOPID(GDF.OP.OPCODE_CALL_RETURN)

                local argc = contextTable.codeInts[contextTable.instrPointer + 1]
                addStructureElem(contextTable.codeStructElement, 'argc:', (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)

                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword) -- base

                local operand3 = 'Globals[' .. (contextTable.codeInts[contextTable.instrPointer + 3]) .. ']'
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3) * 0x4, vtDword) -- nameg then *methodname

                contextTable.instrPointer = contextTable.instrPointer + 4

                local operandArg = '';
                for i = 0, argc - 1 do
                  if i > 0 then
                    operandArg = operandArg .. ', '
                  end
                  operandArg = operandArg .. formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + i])
                  addStructureElem(contextTable.codeStructElement, 'arg: ' .. formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + i]), (contextTable.instrPointer - 1 + i) * 0x4, vtDword)
                end

                local operand_arg = ''
                if (ret) then
                  operand_arg = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + argc])
                  addStructureElem(contextTable.codeStructElement, operand_arg, (contextTable.instrPointer - 1 + argc) * 0x4, vtDword)
                  operand_arg = operand_arg .. ' = '
                end

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand_arg .. operand2 .. '.' .. '[' .. operand3 .. ']' .. '(' .. operandArg .. ')' -- base->call_ptr(*methodname, (const Variant **)argptrs, argc, nullptr, err);
                
                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1 - 4) * 0x4, vtDword) -- decrementing to get the original instruction
                
                return contextTable.instrPointer + argc + 1
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_RETURN] =
            {
              name = "OPCODE_CALL_RETURN",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL].handler
            }

          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_BUILT_IN] = 
            {
              name = "OPCODE_CALL_BUILT_IN",
              handler = function(contextTable)

                local operand1 = contextTable.codeInts[contextTable.instrPointer + 1]
                operand1 = "GDScriptFunctions::Function(" .. operand1 .. ")"
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword) -- func   GDScriptFunctions::Function func = GDScriptFunctions::Function(_code_ptr[ip + 1]);

                local argc = contextTable.codeInts[contextTable.instrPointer + 2]
                addStructureElem(contextTable.codeStructElement, 'argc:', (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)

                contextTable.instrPointer = contextTable.instrPointer + 3

                local operand_argc = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + argc])
                addStructureElem(contextTable.codeStructElement, operand_argc, (contextTable.instrPointer - 1 + argc) * 0x4, vtDword) -- dest

                local operandArg = '';

                for i = 0, argc - 1 do
                  if i > 0 then
                    operandArg = operandArg .. ', '
                  end
                  operandArg = operandArg .. formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + i])
                  addStructureElem(contextTable.codeStructElement, 'arg: ' .. formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + i]), (contextTable.instrPointer - 1 + i) * 0x4, vtDword)
                end

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand_argc .. ' = ' .. "builtin_methods_names[" .. operand1 .. "]" .. '(' .. operandArg .. ')' -- GDScriptFunctions::call(func, (const Variant **)argptrs, argc, *dst, err);
                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1 - 3) * 0x4, vtDword) -- decrement what's been incremented

                return contextTable.instrPointer + argc + 1
              end
            }

          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_SELF] = 
            {
              name = "OPCODE_CALL_SELF",
              handler = function(contextTable)
                -- nothing, should break?
                return contextTable.instrPointer -- + 1
              end
            }

          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_SELF_BASE] = 
            {
              name = "OPCODE_CALL_SELF_BASE",
              handler = function(contextTable)

                local operand1 = 'Globals[' .. contextTable.codeInts[contextTable.instrPointer + 1] .. ']'
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword) -- self_fun then *methodname which is then used to look up member_functions or MethodBind *mb = ClassDB::get_method(gds->native->get_name(), *methodname);

                local argc = contextTable.codeInts[contextTable.instrPointer + 2]
                addStructureElem(contextTable.codeStructElement, 'argc:', (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)

                local operandArg = '';
                for i = 0, argc - 1 do
                  if i > 0 then
                    operandArg = operandArg .. ', '
                  end
                  operandArg = operandArg .. formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + i + 3])
                  addStructureElem(contextTable.codeStructElement, 'arg: ' .. formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + i + 3]), (contextTable.instrPointer - 1 + i + 3) * 0x4, vtDword)
                end

                local operand3 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + argc + 3])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + argc + 3) * 0x4, vtDword) -- dest

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand3 .. ' = ' .. operand1 .. '(' .. operandArg .. ')'
                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 4 + argc
              end
            }

          GDF.DisasmHandlers[GDF.OP.OPCODE_YIELD] = 
            {
              name = "OPCODE_YIELD",
              handler = function(contextTable)

                local operand1 = ''
                local operand2 = ''
                local ipofs = 1
                local signal = contextTable.codeInts[contextTable.instrPointer] == GDF.CurrentDisassembler:getOPEnumFromInternalOPID(GDF.OP.OPCODE_YIELD_SIGNAL)
                if signal then
                  ipofs = ipofs+2
                  local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                  operand1 = "argobj " .. operand1
                  addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)

                  local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2])
                  operand2 = "argname " .. operand2
                  addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)
                  -- obj->connect(signal, gdfs.ptr(), "_signal_callback", varray(gdfs), Object::CONNECT_ONESHOT);
                end
                -- 2 + 2 if signal; 2 otherwise
        
                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand1 .. ' ' .. operand2
                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 1 + ipofs -- opcode + whatever offset, though it's yielded
              end
            }

          GDF.DisasmHandlers[GDF.OP.OPCODE_YIELD_SIGNAL] = 
            {
              name = "OPCODE_YIELD_SIGNAL",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_YIELD].handler
            }

          GDF.DisasmHandlers[GDF.OP.OPCODE_YIELD_RESUME] = 
            {
              name = "OPCODE_YIELD_RESUME",
              handler = function(contextTable)

                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword) -- self_fun then *methodname which is then used to look up member_functions or MethodBind *mb = ClassDB::get_method(gds->native->get_name(), *methodname);
        
                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. 'result' .. operand1
                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 2
              end
            }

          GDF.DisasmHandlers[GDF.OP.OPCODE_JUMP] = 
            {
              name = "OPCODE_JUMP",
              handler = function(contextTable)
                local operand1 = numtohexstr(contextTable.codeInts[contextTable.instrPointer + 1] * 0x4) -- where to jump in hex representation, 4byte step
                local elem = addStructureElem(contextTable.codeStructElement, "JUMP to " .. operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                elem.DisplayMethod = 'dtHexadecimal'
                elem.ShowAsHex = true
                contextTable.opcodeName = contextTable.opcodeName .. ' -> ' .. operand1

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 2
              end
            }

          GDF.DisasmHandlers[GDF.OP.OPCODE_JUMP_IF] = 
            {
              name = "OPCODE_JUMP_IF",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1]) -- test, boolenized
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)

                local operand2 = numtohexstr(contextTable.codeInts[contextTable.instrPointer + 2] * 0x4) -- where to jump
                local elem = addStructureElem(contextTable.codeStructElement, "JUMP to " .. operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)
                elem.DisplayMethod = 'dtHexadecimal'
                elem.ShowAsHex = true
                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand1 .. ' -> ' .. operand2

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 3
              end
            }

          GDF.DisasmHandlers[GDF.OP.OPCODE_JUMP_IF_NOT] = 
            {
              name = "OPCODE_JUMP_IF_NOT",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_JUMP_IF].handler
            }

          GDF.DisasmHandlers[GDF.OP.OPCODE_JUMP_TO_DEF_ARGUMENT] = 
            {
              name = "OPCODE_JUMP_TO_DEF_ARGUMENT",
              handler = function(contextTable)
                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)
                return contextTable.instrPointer + 1
              end
            }

          GDF.DisasmHandlers[GDF.OP.OPCODE_RETURN] = 
            {
              name = "OPCODE_RETURN",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword) -- retvalue
                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand1
                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 2
              end
            }

          GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN] = 
            {
              name = "OPCODE_ITERATE_BEGIN",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword) -- counter
                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword) -- container
                local operand3 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 3])
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3) * 0x4, vtDword) -- jumpto
                local operand4 = tostring(contextTable.codeInts[contextTable.instrPointer + 4])
                addStructureElem(contextTable.codeStructElement, 'end: ', (contextTable.instrPointer - 1 + 4) * 0x4, vtDword) -- iterator

                contextTable.opcodeName = contextTable.opcodeName .. ' for-init ' .. operand3 .. ' in ' .. operand2 .. ' counter ' .. operand1 .. ' end: ' .. operand4
                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 5
              end
            }

          GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE] =
            {
              name = "OPCODE_ITERATE",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword) -- counter
                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword) -- container
                local operand3 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 3])
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3) * 0x4, vtDword) -- jumpto
                local operand4 = tostring(contextTable.codeInts[contextTable.instrPointer + 4])
                addStructureElem(contextTable.codeStructElement, 'end: ', (contextTable.instrPointer - 1 + 4) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' for-loop ' .. operand2 .. ' in ' .. operand2 .. ' counter ' .. operand1 .. ' end: ' .. operand4
                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 5
              end
            }

          GDF.DisasmHandlers[GDF.OP.OPCODE_ASSERT] =
            {
              name = "OPCODE_ASSERT",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword) -- test
                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword) -- message

                contextTable.opcodeName = contextTable.opcodeName .. ' (' .. operand1 .. ', ' .. operand2 .. ')'

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)
                return contextTable.instrPointer + 3
              end
            }

          GDF.DisasmHandlers[GDF.OP.OPCODE_BREAKPOINT] =
            {
              name = "OPCODE_BREAKPOINT",
              handler = function(contextTable)
                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)
                return contextTable.instrPointer + 1
              end
            }

          GDF.DisasmHandlers[GDF.OP.OPCODE_LINE] =
            {
              name = "OPCODE_LINE",
              handler = function(contextTable)
                local line = contextTable.codeInts[contextTable.instrPointer + 1] - 1
                if line > 0 --[[and line < p_code_lines.size()]] then
                  contextTable.opcodeName = contextTable.opcodeName .. ' ' .. tostring(line + 1) .. ': '
                else
                  contextTable.opcodeName = ''
                end
                addStructureElem(contextTable.codeStructElement, 'line: ', (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GDTEAL_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)
                return contextTable.instrPointer + 2
              end
            }

          GDF.DisasmHandlers[GDF.OP.OPCODE_END] =
            {
              name = "OPCODE_END",
              handler = function(contextTable)
                addLayoutStructElem(contextTable.codeStructElement, '>>>END.', GDTEAL_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)
                return contextTable.instrPointer + 1
              end
            }

        GDF.Decoders = {}
          GDF.Decoders.BytecodeV0 =
            {
              name = "BytecodeV0",
              resolveOPHandlerDefFromProfile = function(profile, opcodeEnum)
                return profile.OPHandlerDefFromOPEnum[opcodeEnum]
              end
            }
          GDF.Decoders.BytecodeV1 =
            {
              name = "BytecodeV1",
              resolveOPHandlerDefFromProfile = function(profile, opcodeEnum)
                -- for other versions redefine the handler on the fly
                return profile.OPHandlerDefFromOPEnum[opcodeEnum]
              end
            }

        
        GDF.ProfileSpecs =
          {
            ["3.0"] =
              {
                decoderName = "BytecodeV0",
                orderedOpcodes =
                  {
                    GDF.OP.OPCODE_OPERATOR,
                    GDF.OP.OPCODE_EXTENDS_TEST,
                    GDF.OP.OPCODE_SET,
                    GDF.OP.OPCODE_GET,
                    GDF.OP.OPCODE_SET_NAMED,
                    GDF.OP.OPCODE_GET_NAMED,
                    GDF.OP.OPCODE_SET_MEMBER,
                    GDF.OP.OPCODE_GET_MEMBER,
                    GDF.OP.OPCODE_ASSIGN,
                    GDF.OP.OPCODE_ASSIGN_TRUE,
                    GDF.OP.OPCODE_ASSIGN_FALSE,
                    GDF.OP.OPCODE_CONSTRUCT,
                    GDF.OP.OPCODE_CONSTRUCT_ARRAY,
                    GDF.OP.OPCODE_CONSTRUCT_DICTIONARY,
                    GDF.OP.OPCODE_CALL,
                    GDF.OP.OPCODE_CALL_RETURN,
                    GDF.OP.OPCODE_CALL_BUILT_IN,
                    GDF.OP.OPCODE_CALL_SELF,
                    GDF.OP.OPCODE_CALL_SELF_BASE,
                    GDF.OP.OPCODE_YIELD,
                    GDF.OP.OPCODE_YIELD_SIGNAL,
                    GDF.OP.OPCODE_YIELD_RESUME,
                    GDF.OP.OPCODE_JUMP,
                    GDF.OP.OPCODE_JUMP_IF,
                    GDF.OP.OPCODE_JUMP_IF_NOT,
                    GDF.OP.OPCODE_JUMP_TO_DEF_ARGUMENT,
                    GDF.OP.OPCODE_RETURN,
                    GDF.OP.OPCODE_ITERATE_BEGIN,
                    GDF.OP.OPCODE_ITERATE,
                    GDF.OP.OPCODE_ASSERT,
                    GDF.OP.OPCODE_BREAKPOINT,
                    GDF.OP.OPCODE_LINE,
                    GDF.OP.OPCODE_END
                  }
              },

            ["3.1"] =
              {
                base = "3.0",
                decoderName = "BytecodeV0",
                patches = 
                {
                  {
                    kind = "insertValueAfter",
                    anchor = GDF.OP.OPCODE_EXTENDS_TEST,
                    value = GDF.OP.OPCODE_IS_BUILTIN
                  },
                  {
                    kind = "insertValueAfter",
                    anchor = GDF.OP.OPCODE_ASSIGN_FALSE,
                    value = GDF.OP.OPCODE_ASSIGN_TYPED_BUILTIN
                  },
                  {
                    kind = "insertValueAfter",
                    anchor = GDF.OP.OPCODE_ASSIGN_TYPED_BUILTIN,
                    value = GDF.OP.OPCODE_ASSIGN_TYPED_NATIVE
                  },
                  {
                    kind = "insertValueAfter",
                    anchor = GDF.OP.OPCODE_ASSIGN_TYPED_NATIVE,
                    value = GDF.OP.OPCODE_ASSIGN_TYPED_SCRIPT
                  },
                  {
                    kind = "insertValueAfter",
                    anchor = GDF.OP.OPCODE_ASSIGN_TYPED_SCRIPT,
                    value = GDF.OP.OPCODE_CAST_TO_BUILTIN
                  },
                  {
                    kind = "insertValueAfter",
                    anchor = GDF.OP.OPCODE_CAST_TO_BUILTIN,
                    value = GDF.OP.OPCODE_CAST_TO_NATIVE
                  },
                  {
                    kind = "insertValueAfter",
                    anchor = GDF.OP.OPCODE_CAST_TO_NATIVE,
                    value = GDF.OP.OPCODE_CAST_TO_SCRIPT
                  },
                }
              },

            ["3.2"] =
              {
                base = "3.1",
                decoderName = "BytecodeV0",
                patches = {}
              },

            ["3.3"] =
              {
                base = "3.2",
                decoderName = "BytecodeV0",
                patches = {}
              },

            ["3.4"] =
              {
                base = "3.3",
                decoderName = "BytecodeV0",
                patches = {}
              },

            ["3.5"] =
              {
                base = "3.4",
                decoderName = "BytecodeV0",
                patches = {}
              },

            ["3.6"] =
              {
                base = "3.5",
                decoderName = "BytecodeV0",
                patches = {}
              }
          }
        GDF.CompiledProfiles = {}
        GDF.EADDRESS =
          {
            ['ADDR_BITS'] = 24,
            ['ADDR_MASK'] = ((1 << 24) - 1), -- ((1 << ADDR_BITS) - 1)
            ['ADDR_TYPE_MASK'] = ~((1 << 24) - 1),
            ['ADDR_TYPE_SELF'] = 0,
            ['ADDR_TYPE_CLASS'] = 1,
            ['ADDR_TYPE_MEMBER'] = 2,
            ['ADDR_TYPE_CLASS_CONSTANT'] = 3,
            ['ADDR_TYPE_LOCAL_CONSTANT'] = 4,
            ['ADDR_TYPE_STACK'] = 5,
            ['ADDR_TYPE_STACK_VARIABLE'] = 6,
            ['ADDR_TYPE_GLOBAL'] = 7,
            ['ADDR_TYPE_NIL'] = 8
            --ADDR_TYPE_NAMED_GLOBAL on tools enabled
          }

        GDF.OPERATOR_NAME =
          {
            -- comparison
            "OP_EQUAL",
            "OP_NOT_EQUAL",
            "OP_LESS",
            "OP_LESS_EQUAL",
            "OP_GREATER",
            "OP_GREATER_EQUAL",
            -- mathematic
            "OP_ADD",
            "OP_SUBTRACT",
            "OP_MULTIPLY",
            "OP_DIVIDE",
            "OP_NEGATE",
            "OP_POSITIVE", 
            "OP_MODULE",
            "OP_STRING_CONCAT",
            -- bitwise
            "OP_SHIFT_LEFT",
            "OP_SHIFT_RIGHT",
            "OP_BIT_AND",
            "OP_BIT_OR",
            "OP_BIT_XOR",
            "OP_BIT_NEGATE",
            -- logic
            "OP_AND",
            "OP_OR",
            "OP_XOR",
            "OP_NOT",
            -- containment
            "OP_IN",
            "OP_MAX" -- 25
          }

        for version, _ in pairs(GDF.ProfileSpecs) do
          GDF.CompiledProfiles[version] = createProfileFromVersion(version)
        end

        if GDDEFS.VERSION_STRING then
          GDF.CurrentDisassembler = GDF.createDisassemblerFromVersion(GDDEFS.VERSION_STRING)
        end

      end
    end

    function disassembleGDFunctionCodeToStruct(funcAddr, funcStruct)
      assert((type(funcAddr) == 'number') and (funcAddr ~= 0), 'funcAddr has to be a valid pointer, instead got: ' .. type(funcAddr))

      if GDF == nil then
        defineGDFunctionEnums()
      end

      local codeAddr = readPointer(funcAddr + GDDEFS.FUNC_CODE) -- TODO: resolve that with a a helper
      funcStruct.Name = 'ScriptFunc'
      local codeStructElement = funcStruct.addElement()
      codeStructElement.Name = 'FuncCode'
      codeStructElement.Offset = GDDEFS.FUNC_CODE
      codeStructElement.VarType = vtPointer
      codeStructElement.ChildStruct = createStructure('FuncCode')

      local funcConstantStructElem = funcStruct.addElement()
      funcConstantStructElem.Name = 'Constants'
      funcConstantStructElem.Offset = GDDEFS.FUNC_CONST
      funcConstantStructElem.VarType = vtPointer
      funcConstantStructElem.ChildStruct = createStructure('GDFConst')
      local funcConstAddr = readPointer(funcAddr + GDDEFS.FUNC_CONST)
      iterateFuncConstantsToStruct(funcConstAddr, funcConstantStructElem)

      local funcGlobalNameStructElem = funcStruct.addElement()
      funcGlobalNameStructElem.Name = 'Globals'
      funcGlobalNameStructElem.Offset = GDDEFS.FUNC_GLOBNAMEPTR
      funcGlobalNameStructElem.VarType = vtPointer
      funcGlobalNameStructElem.ChildStruct = createStructure('GDFGlobals')
      local funcGlobalAddr = readPointer(funcAddr + GDDEFS.FUNC_GLOBNAMEPTR)
      iterateFuncGlobalsToStruct(funcGlobalAddr, funcGlobalNameStructElem)

      local codeInts = {}
      local codeSize, currIndx, currOpcode = 0, 0, 0
      while true do
        codeSize = codeSize + 1
        currOpcode = readInteger(codeAddr + currIndx * 0x4)
        table.insert(codeInts, currOpcode)

        if currOpcode == GDF.CurrentDisassembler:getOPEnumFromInternalOPID(GDF.OP.OPCODE_END) then
          break
        end
        currIndx = currIndx + 1
      end
      sendDebugMessage('codeSize: ' .. tostring(codeSize))

      GDF.CurrentDisassembler:disassembleBytecode(codeInts, codeStructElement)

      return
    end

    function formatDisassembledAddress(addrInt)
      local addrIndex = addrInt & (GDF.EADDRESS['ADDR_MASK']) -- lower 24 bits are indices
      local addrType = (addrInt >> GDF.EADDRESS['ADDR_BITS']) -- the higher 8 would be types: shift to the beginning and mask

      if addrType == 0 and (addrIndex >= 0 and addrIndex <= 2) then
        if addrIndex == GDF.EFIXEDADDRESSES['ADDR_STACK_SELF'] then   return "stack(self)" end
        if addrIndex == GDF.EFIXEDADDRESSES['ADDR_STACK_CLASS'] then  return "stack(class)" end
        if addrIndex == GDF.EFIXEDADDRESSES['ADDR_STACK_NIL'] then    return "stack(nil)" end
                                                                      return 'stack[' .. tostring(addrIndex) .. ']'
      end

      if (addrType == GDF.EADDRESS['ADDR_TYPE_STACK']) then         return ("stack[%d]"):format(addrIndex)
      elseif (addrType == GDF.EADDRESS['ADDR_TYPE_CONSTANT']) then  return ("Constants[%d]"):format(addrIndex)
      elseif (addrType == GDF.EADDRESS['ADDR_TYPE_MEMBER']) then    return ("Variants[%d]"):format(addrIndex) -- for clarity ("member[%d]"):format(addrIndex)
      else                                                          return ("addr?(0x%08X)"):format(addrInt)
      end
    end

    function checkIfGDFunction(funcAddr)
      local funcStringNameAddr, funcResStringNameAddr, funcCodeAddr, firstOpcode
      local OPCODEMAX = 250
      if GDDEFS.MAJOR_VER == 3 or GDDEFS.VERSION_STRING == "4.1" then
        funcResStringNameAddr = readPointer(funcAddr) -- StringName source at 0x0;
        funcStringNameAddr = 0xDEADBEEF -- just a placeholder
      else
        funcStringNameAddr = readPointer(funcAddr) -- StringName funct name;
        funcResStringNameAddr = readPointer(funcAddr + GDDEFS.PTRSIZE) -- StringName source;
      end

      funcCodeAddr = readPointer(funcAddr + GDDEFS.FUNC_CODE)
      firstOpcode = readInteger(funcCodeAddr) or 0

      if isNotNullOrNil(funcResStringNameAddr) and isNotNullOrNil(funcStringNameAddr) and (firstOpcode < OPCODEMAX) then

        if not (getStringNameStr(funcResStringNameAddr)):match("res://") then
          return false
        end

        if GDDEFS.MAJOR_VER ~= 3 and GDDEFS.VERSION_STRING ~= "4.1" then
          local funcStringAddr = readPointer(funcStringNameAddr + GDDEFS.STRING)
          if isNullOrNil(funcStringAddr) then
            funcStringAddr = readPointer(funcStringNameAddr + 0x8)
            if isNullOrNil(funcStringAddr) then
              return false
            end
          end
        end

        return true
      end

      return false
    end

    local function findGDVMCallPtr()
      local function resolveVM_RELA(aobSignature, sigByteLength, offsetToNextIntr)
        local function resolveAddress(instructionAddr, sigByteLength, offsetToNextIntr)
          local callInstr = instructionAddr + sigByteLength - 1
          local relativeAddr = readInteger(callInstr + 1)
          local nextAddr = getAddress(callInstr + offsetToNextIntr)
          local relativeAddr = readInteger(instructionAddr + sigByteLength)
          GDDEFS.VM_CALL = (nextAddr + relativeAddr)
          registerSymbol('GDFunctionCall', (nextAddr + relativeAddr), false)
        end
        local addr = AOBScanModuleUnique(process, aobSignature, '+X-W-C')
        if addr == 0 or addr == nil then return false end
        resolveAddress(addr, sigByteLength, 5)
        return true
      end

      local sigs = {}
      table.insert(sigs, { isheavy = true,  sig = "4C 89 ? 24 28 89 44 24 20 4C 8B 8C 24 ? ? ? ? 48 89 F9 49 89 E8 E8", sigsize = 24 }) -- 4.6 ret 64<
      table.insert(sigs, { isheavy = false, sig = "48 89 44 24 ? 89 44 24 68 48 8D 44 24 ? 48 89 44 24 28 C7 44 24 20 ? ? ? ? E8", sigsize = 28 }) -- 4.6 ret 64>
      table.insert(sigs, { isheavy = false, sig = "48 8B 84 24 ? ? ? ?     48 C7 44 24 30 00 00 00 00    48 89 44 24 28 8B 84 24 ? ? ? ? 89 44 24 20 E8", sigsize = 34 }) -- 4.5
      table.insert(sigs, { isheavy = true,  sig = "4C 89 7C 24 28 89 44 24 20 48 89 ? >48 89 ? >48 89 ? E8", sigsize = 19 }) -- 4.5 ret 64<
      table.insert(sigs, { isheavy = false, sig = "4C 89 74 24 28 89 44 24 20 48 89 D9 49 89 F9 49 89 F0 E8", sigsize = 19 }) -- 4.4
      table.insert(sigs, { isheavy = false, sig = "4C 89 64 24 28 89 44 24 20 48 89 D9 49 89 F9 49 89 F0 E8", sigsize = 19 }) -- 4.3
      table.insert(sigs, { isheavy = false, sig = "4C 89 64 24 30      48 8B D6 48 89 44 24 28 8B 84 24 ? ? ? ? 89 44 24 20 E8", sigsize = 25 }) -- 4.3 ret 64<
      table.insert(sigs, { isheavy = false, sig = "4C 89 ? 24 28 89 44 24 20 48 89 D9 49 89 F9 49 89 F0 E8", sigsize = 19 }) -- 4.4-4.3
      table.insert(sigs, { isheavy = false, sig = "4C 89 ? 24 28 89 44 24 20 48 89 F1 49 89 D8 E8", sigsize = 16 }) -- 4.2
      table.insert(sigs, { isheavy = true,  sig = "4C 89 74 24 28 89 44 24 20 49 89 D8 49 89 E9 E8", sigsize = 16 }) -- 4.2 Godot Engine v4.2.2.stable.official.15073afe3

      table.insert(sigs, { isheavy = false, sig = "4C 89 ? 24 28 44 89 6C 24 20 4D 8B CC 4C 8B C5 48 8B D6 48 8B 49 ? E8", sigsize = 24 }) -- 4.1
      table.insert(sigs, { isheavy = false, sig = "48 89 44 24 28 8B 84 24 ? ? ? ? 48 8B 8C 24 ? ? ? ? 89 44 24 20 E8 ? ? ? ? EB", sigsize = 30 }) -- 4.1
      table.insert(sigs, { isheavy = false, sig = "48 89 7C 24 28 49 89 F0 48 89 D9 48 C7 44 24 30 ? 00 00 00 8B 84 24 ? ? 00 00 89 44 24 20 E8", sigsize = 32 }) -- 3.6
      table.insert(sigs, { isheavy = false, sig = "4C 89 7C 24 30 48 8D 44 24 ?     48 89 44 24 28 44 89 74 24 20 4C 8B CD 4C 8B C6 48 8D 54 24 ? 48 8B 49 ? E8", sigsize = 36 }) -- 3.5
      table.insert(sigs, { isheavy = true, sig = "48 C7 44 24 30 ? 00 00 00   48 89 44 24 28 8B 44 24 ? 89 44 24 20 E8", sigsize = 23 }) -- 3.3 - 3.4 - 3.5
      table.insert(sigs, { isheavy = true,  sig = "4C 89 6C 24 28 44 89 64 24 20 49 89 F0 48 89 F9 E8", sigsize = 17 }) -- 3.0 prefixed by 48 C7 44 24 30 ? 000000

      for i, sign in ipairs(sigs) do
        if resolveVM_RELA(sign.sig, sign.sigsize) then
          sendDebugMessage('[VM_CALL] via sig - success: ' .. "\t" .. sign.sig)
          if sign.isheavy then GDDEFS.VM_CALL_HEAVY = true end
          return true
        end
      end
      return false
    end

    function GDAPI.executeGDFunction(func_this, GDScriptInstanceAddr, argTable)
      assert( isNotNullOrNil(func_this) , "this ptr invalid" )
      assert( isNotNullOrNil(GDScriptInstanceAddr) , "GDSI invalid" )
      -- so far the calling conventions match seamlessly

      -- we need the dummy stack even when no arguments
      if not VariantArena:init() then error("'stack' space isn't alloced") end

      local vmCallAddr
      if isNullOrNil(GDDEFS.VM_CALL) then
        findGDVMCallPtr()
        vmCallAddr = GDDEFS.VM_CALL
      else
        vmCallAddr = GDDEFS.VM_CALL
      end
      
      if isNullOrNil(vmCallAddr) then error("::call() isn't found") end

      -- setup arguments & space
      if isNotNullOrNil(argTable) and type(argTable) == "table" and isNotNullOrNil(#argTable) then
        setupCallArgs(VariantArena, GDVariant, argTable)
      end

      local int_t = 0
      local argCount = (argTable and #argTable) or 0
      local _rcx, _rdx, _r8, _r8, _r9, _st1, _st2, _st3, _rax
      if GDDEFS.VM_CALL_HEAVY then
        _rcx = { type = int_t, value = VariantArena.base + VariantArena.returnBufOffset } -- return buffer ptr
        _rdx = { type = int_t, value = func_this }
      else
        _rcx = { type = int_t, value = func_this }
        _rdx = { type = int_t, value = VariantArena.base + VariantArena.excptOffset } -- *someexcval
      end

      _r8 =   { type = int_t, value = GDScriptInstanceAddr } -- GDScriptInstance *p_instance
      _r9 =   { type = int_t, value = VariantArena.base + VariantArena.argListOffset } -- const Variant **p_args
      _st1 =  { type = int_t, value = argCount } -- int p_argcount
      _st2 =  { type = int_t, value = VariantArena.base + VariantArena.callErrorOffset } -- Callable::CallError &r_err
      _st3 =  { type = int_t, value = 0x0 } -- CallState *p_state
      _rax =  { type = int_t, value = VariantArena.base } -- lastArgument

      local returned = executeCodeEx(stdcall, timeout, vmCallAddr, _rcx, _rdx, _r8, _r9, _st1, _st2, _st3, _rax)

      if GDDEFS.VM_CALL_HEAVY then
        return VariantArena.base + VariantArena.returnBufOffset, true
      end

      -- needs testing
      return returned, true

      --[[
        Variant GDScriptFunction::call(GDScriptInstance *p_instance, const Variant **p_args, int p_argcount, Callable::CallError &r_err, CallState *p_state)
        rcx  *this
        rdx  value (on stack) passed to _get_default_variant_for_data_type()
        r8   GDScriptInstance* p_instance
        r9   Variant** p_args (on stack)
        -- the rest are mov'd to stack after shallow space
        [rsp+20] int32_t p_argcount
        [rsp+28] Callable::CallError *r_err (on stack)
        [rsp+30] CallState *p_state (on stack, usually nullptr)

        in case the return-by-value doesnt fit __ 64bit< Variant __ , return buffer ptr goes to rcx, else shift accordingly
        --https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention?view=msvc-170#return-values
        rcx - buffer ptr (Variant)
        rdx this
        r8 GDScriptInstance* p_instance
        r9   Variant** p_args (on stack)
        [rsp+20] int32_t p_argcount
        [rsp+28] Callable::CallError *r_err (on stack)
        [rsp+30] CallState *p_state (on stack, usually nullptr)
        ]]
    end

    function setupCallArgs(arena, handler, args)
      arena:init() -- should be calloced already
      arena:reset()

      local argPtrs = {}

      for i, arg in ipairs(args) do
        local typehandler = handler[ arg.type ]
        if typehandler then
          argPtrs[i] = typehandler( arena, arg.value, arg.copy )
        else
          error("unsupported Variant arg type: " .. tostring(arg.type))
        end
      end

      -- this is an array of ptrs we fill, Variant **p_args
      local argArray = arena.base + arena.argListOffset

      for i, ptr in ipairs(argPtrs) do
        writePointer( argArray + ((i - 1) * GDDEFS.PTRSIZE) , ptr)
      end
    end

    function GDAPI.callGDFunctionFromNode(nodeAddr, funcName, argTable)
      assert(isNotNullOrNil(nodeAddr), "Node Addr must be valid")
      assert(type(funcName) == 'string', "function name must be a string, instead got: " .. type(funcName))

      local gdScriptInstance = getNodeGDScriptInstance(nodeAddr)
      if isNullOrNil(gdScriptInstance) then error("Nodes' script instance not found") end

      local functionAddr = getGDFunctionFromNode( nodeAddr, funcName )
      if isNullOrNil(functionAddr) then error("Function address not found") end

      return GDAPI.executeGDFunction(functionAddr, gdScriptInstance, argTable)
    end

  -- ///---///--///---///--///---///--///--///---///--///---///--///---///--/// Const

    --- returns a head element, tail element and (hash)Map size
    local function getNodeConstMap(nodeContext)
      assert(type(nodeContext.addr) == 'number', "NodePtr should be a number, instead got: " .. type(nodeContext.addr))

      local scriptInstanceAddr = readPointer(nodeContext.addr + GDDEFS.GDSCRIPTINSTANCE)
      if isNullOrNil(scriptInstanceAddr) then
        sendDebugMessage('scriptInstance is invalid');
        return;
      end

      local gdScriptAddr = readPointer(scriptInstanceAddr + GDDEFS.GDSCRIPT_REF)
      if isNullOrNil(gdScriptAddr) then
        sendDebugMessage('GDScript is invalid')
        return;
      end

      local mainElement = readPointer(gdScriptAddr + GDDEFS.CONST_MAP) -- head or root depending on the version
      local lastElement = readPointer(gdScriptAddr + GDDEFS.CONST_MAP + GDDEFS.PTRSIZE) -- tail or end
      local mapSize = readInteger(gdScriptAddr + GDDEFS.CONST_MAP + GDDEFS.MAP_SIZE) -- hashmap or map
      if isNullOrNil(mainElement) or isNullOrNil(lastElement) or isNullOrNil(mapSize) then
        sendDebugMessage('Const: (hash)map is not found')
        return;
      end

      if GDDEFS.MAJOR_VER == 4 then
        return mainElement, lastElement, mapSize, nodeContext
      else
        if nodeContext.struct then
          nodeContext.struct.ChildStruct = createStructure('ConstMapRes')
        end
        return getLeftmostMapElem(mainElement, lastElement, mapSize, nodeContext)
      end
    end

    --- returns a lua string for const name
    ---@param mapElement number
    function getNodeConstName(mapElement)

      local mapElementKey = readPointer(mapElement + GDDEFS.CONSTELEM_KEYVAL)
      if isNullOrNil(mapElementKey) then
        sendDebugMessage('(hash)mapElementKey invalid');
        return 'C??'
      end

      return getStringNameStr(mapElementKey)
    end

    -- iterates over const (hash)map of a node and creates addresses for it
    function iterateNodeConstToAddr(nodeContext)
      assert(type(nodeContext.addr) == 'number', "Node addr has to be a number, instead got: " .. type(nodeContext.addr))

      if not checkForGDScript(nodeContext.addr) then
        sendDebugMessage("Node " .. nodeContext.name .. " with NO GDScript")
        synchronize(function(parent)
          parent.Destroy()
        end, nodeContext.memrec)
        return;
      end

      local nodeMapContext = { addr = nodeContext.addr, name = nodeContext.name, gdname = nodeContext.gdname, memrec = nodeContext.memrec, struct = nodeContext.struct, symbol = nodeContext.symbol }

      local headElement, tailElement, mapSize, nodeMapContext = getNodeConstMap(nodeMapContext)
      if isNullOrNil(headElement) or isNullOrNil(mapSize) then
        sendDebugMessage('(hash)map empty?: ' .. 'Address: ' .. numtohexstr(nodeContext.addr))
        synchronize(function(parent)
          parent.Destroy()
        end, nodeContext.memrec)
        return;
      end

      local emitter = GDEmitters.AddrEmitter
      local mapElement = headElement
      local currentSymbol = nodeMapContext.symbol
      -- local index = 0;

      repeat
        local entry = readNodeConstEntry(mapElement)
        entry.name = "const: " .. entry.name
        local contextTable =
        {
          nodeAddr = nodeMapContext.addr,
          nodeName = nodeMapContext.name or "UnknownNode",
          scriptName = nodeMapContext.gdname,
          baseAddress = entry.variantPtr,
          symbol = currentSymbol
        }
        local handler = GDHandlers.VariantHandlers[entry.typeName] or GDHandlers.VariantHandlers.DEFAULT
        handler(entry, emitter, nodeContext.memrec, contextTable)
        mapElement = getNextMapElement(mapElement)
        -- index = index + 1

        if mapElement ~= 0 then
          currentSymbol = createNextConstSymbol(currentSymbol)
        end

      until (mapElement == 0)
      return
    end

    -- iterates over const (hash)map of a node and builds the structure for it
    ---@param nodeAddr number
    ---@param constStructElement userdata
    function iterateNodeConstToStruct(nodeContext)
      assert(type(nodeContext.addr) == 'number', "Node addr has to be a number, instead got: " .. type(nodeContext.addr))
      if GDDEFS.MONO and (checkScriptType(nodeContext.addr)==GDDEFS.SCRIPT_TYPES["CS"]) then return; end -- for mono targets
      
      local nodeMapContext = { addr = nodeContext.addr, name = nodeContext.name, gdname = nodeContext.gdname, memrec = nodeContext.memrec, struct = nodeContext.struct, symbol = nodeContext.symbol }

      local headElement, _, mapSize, nodeMapContext = getNodeConstMap(nodeMapContext)
      if isNullOrNil(headElement) or isNullOrNil(mapSize) then
        sendDebugMessage('(hash)map empty?: ' .. 'Address: ' .. numtohexstr(nodeContext.addr)) return;
      end

      local mapElement = headElement
      local emitter = GDEmitters.StructEmitter
      local currentContainer = nodeMapContext.struct
      local currentSymbol = nodeMapContext.symbol
      local index = 0;
      local nodeName = getNodeName(nodeMapContext.addr) or "UnknownNode"
      if nodeName == 'N??' then nodeName = getNodeNameFromGDScript(nodeMapContext.addr) end

      repeat
        local entry = readNodeConstEntry(mapElement)
        entry.name = "CONST: " .. entry.name
        local contextTable =
        {
          nodeAddr = nodeMapContext.addr,
          nodeName = nodeMapContext.name,
          scriptName = nodeMapContext.gdname,
          baseAddress = entry.variantPtr,
          symbol = nodeMapContext.symbol
        }
        local handler = GDHandlers.VariantHandlers[entry.typeName] or GDHandlers.VariantHandlers.DEFAULT
        handler(entry, emitter, currentContainer, contextTable)

        mapElement = getNextMapElement(mapElement)
        index = index + 1

        if mapElement ~= 0 then
          currentContainer = createNextConstContainer(currentContainer, index)
          currentSymbol = createNextConstSymbol(currentSymbol)
        end

      until (mapElement == 0)
      return
    end

  -- ///---///--///---///--///---///--///--///---///--///---///--///---///--/// Dictionary

    function iterateDictionary(dictHead, parent, emitter, options, contextSeed)

      options = options or {}
      local mapElement = dictHead
      local currentContainer = parent
      local currentSymbol = contextSeed and contextSeed.symbol
      local index = 0

      repeat
          local entry = readDictionaryContainerEntry(mapElement)
          local formatted = formatDictionaryEntry(entry)
          local contextTable =
          {
            nodeAddr = contextSeed and contextSeed.nodeAddr or 0,
            nodeName = contextSeed and contextSeed.nodeName or "Dictionary",
            baseAddress = entry.variantPtr,
            symbol = currentSymbol
          }

          local handler = GDHandlers.VariantHandlers[formatted.typeName] or GDHandlers.VariantHandlers.DEFAULT
          handler(formatted, emitter, currentContainer, contextTable)

          mapElement = getDictElemPairNext(mapElement)
          index = index + 1

          if isNotNullOrNil(mapElement) and options.nextContainerFactory then
            currentContainer = options.nextContainerFactory(currentContainer, index)
          end
          currentSymbol = options.nextSymbolFactory(currentSymbol)

      until (mapElement == 0)
      return
    end

    --- iterates a dictionary and adds it to a class
    ---@param dictAddr number
    ---@param parent userdata
    function iterateDictionaryToAddr(dictAddr, parent, contextTable)
      assert(type(dictAddr) == 'number', 'dictAddr has to be a number, instead got: ' .. type(dictAddr))

      local dictRoot, dictSize, dictHead, dictTail = getDictionaryInfo(dictAddr)
      if isNullOrNil(dictRoot) or isNullOrNil(dictSize) then return end
      
      if GDDEFS.MAJOR_VER == 3 then
        contextTable.symbol = wrapBrackets( wrapBrackets( contextTable.symbol ) .. '+DICT_LIST' )
      end

      contextTable.symbol = wrapBrackets( wrapBrackets( contextTable.symbol ) .. '+DICT_HEAD' )
      
      iterateDictionary(dictHead, parent, GDEmitters.AddrEmitter, { bNeedStructOffset = false, nextContainerFactory = nil, nextSymbolFactory = createNextSymbol }, { nodeAddr = 0, nodeName = "Dictionary", symbol = contextTable.symbol })
      return
    end

    --- iterates a dictionary and adds it to a struct
    ---@param dictAddr number
    ---@param dictStructElement userdata
    function iterateDictionaryToStruct(dictAddr, dictStructElement, contextTable)

      local dictRoot, dictSize, dictHead, dictTail = getDictionaryInfo(dictAddr)
      if isNullOrNil(dictRoot) then return
      end
      local currentRoot = dictStructElement

      if GDDEFS.MAJOR_VER == 3 then
        currentRoot = createChildStructElem(currentRoot, 'dictList', GDDEFS.DICT_LIST, vtPointer, 'dictList')
        contextTable.symbol = wrapBrackets( contextTable.symbol .. '+DICT_LIST' )
      end

      local headContainer = createChildStructElem(currentRoot, 'dictHead', GDDEFS.DICT_HEAD, vtPointer, 'dictHead')
      contextTable.symbol = wrapBrackets( contextTable.symbol .. '+DICT_HEAD' )

      iterateDictionary(dictHead, headContainer, GDEmitters.StructEmitter, { bNeedStructOffset = true, nextContainerFactory = createNextDictContainer, nextSymbolFactory = createNextSymbol }, { nodeAddr = 0, nodeName = "Dictionary", symbol = contextTable.symbol })
      return
    end

    --- iterates a dictionary for nodes
    ---@param dictAddr number
    function iterateDictionaryForNodes(dictAddr, dumpContext)
      if dumpContext:shouldStop() or isNullOrNil(dictAddr) then return end -- if (not (dictAddr > 0)) then return; end

      local dictRoot = dictAddr
      if GDDEFS.MAJOR_VER == 3 then
        dictRoot = readPointer( (dictAddr or 0) + GDDEFS.DICT_LIST) -- for 3.x it's dictList actually
      end

      local dictSize = readInteger( (dictAddr or 0) + GDDEFS.DICT_SIZE)
      if isNullOrNil(dictSize) then return; end

      local mapElement = readPointer( (dictRoot or 0) + GDDEFS.DICT_HEAD)
      if isNullOrNil(mapElement) then return end

      local visitor = NodeVisitor

      repeat
        if dumpContext:shouldStop() then return end
        local entry = readDictionaryValueEntry(mapElement)
        local handler = GDHandlers.NodeDiscoveryHandlers[entry.typeName]
        if handler then
          handler(entry, visitor, dumpContext)
        end
        mapElement = getDictElemPairNext(mapElement)
      until (mapElement == 0)
    end

  -- ///---///--///---///--///---///--///--///---///--///---///--///---///--/// Array

    function iterateArray(arrVectorAddr, arrVectorSize, variantArrSize, parent, emitter, options, contextSeed)
      assert(type(arrVectorAddr) == 'number', "arrayAddr has to be a number, instead got: " .. type(arrVectorAddr))

      options = options or {}
      for varIndex = 0, arrVectorSize - 1 do
        local entry = readArrayContainerEntry(arrVectorAddr, varIndex, variantArrSize, options.bNeedStructOffset)
        if isNullOrNil(entry.variantPtr) then
          goto continue
        end
        local formatted = formatArrayEntry(entry)
        local contextTable =
        {
          nodeAddr = contextSeed and contextSeed.nodeAddr or 0,
          nodeName = contextSeed and contextSeed.nodeName or "Array",
          baseAddress = entry.variantPtr,
          symbol = contextSeed and contextSeed.symbol or ''
        }
        local handler = GDHandlers.VariantHandlers[formatted.typeName] or GDHandlers.VariantHandlers.DEFAULT
        handler(formatted, emitter, parent, contextTable)

        ::continue::
      end
    end

    --- takes in an array address and address owner to append to
    ---@param arrayAddr number
    ---@param parent userdata
    function iterateArrayToAddr(arrayAddr, parent, contextTable)
      assert(type(arrayAddr) == 'number', "Array " .. tostring(arrayAddr) .. " has to be a number, instead got: " .. type(arrayAddr))

      local arrVectorAddr, arrVectorSize, variantArrSize = getArrayVectorInfo(arrayAddr)
      if isNullOrNil(arrVectorAddr) then return; end

      contextTable.symbol = wrapBrackets( contextTable.symbol .. '+ARRAY_TOVECTOR' )
      iterateArray(arrVectorAddr, arrVectorSize, variantArrSize, parent, GDEmitters.AddrEmitter, { bNeedStructOffset = false }, { nodeAddr = 0, nodeName = "Array", symbol = contextTable.symbol })
      return
    end

    --- takes in an array address and struct owner to append to
    ---@param arrayAddr number
    ---@param parent userdata
    function iterateArrayToStruct(arrayAddr, arrayStructElement, contextTable)
      assert(type(arrayAddr) == 'number', "Array " .. tostring(arrayAddr) .. " has to be a number, instead got: " .. type(arrayAddr))

      local arrVectorAddr, arrVectorSize, variantArrSize = getArrayVectorInfo(arrayAddr)
      if isNullOrNil(arrVectorAddr) then return; end

      arrayStructElement = addStructureElem(arrayStructElement, 'VectorArray', GDDEFS.ARRAY_TOVECTOR, vtPointer)
      arrayStructElement.ChildStruct = createStructure('ArrayData')
      contextTable.symbol = wrapBrackets( contextTable.symbol .. '+ARRAY_TOVECTOR' )
      iterateArray(arrVectorAddr, arrVectorSize, variantArrSize, arrayStructElement, GDEmitters.StructEmitter, { bNeedStructOffset = true }, { nodeAddr = 0, nodeName = "Array", symbol = contextTable.symbol })
      return
    end

    --- iterates an array for nodes
    ---@param arrayAddr number
    function iterateArrayForNodes(arrayAddr, dumpContext)
      if dumpContext:shouldStop() or isNullOrNil(arrayAddr) then return end

      local arrVectorAddr = readPointer( (arrayAddr or 0) + GDDEFS.ARRAY_TOVECTOR)
      if isNullOrNil(arrVectorAddr) then return; end
      local arrVectorSize = readInteger( (arrVectorAddr or 0) - GDDEFS.SIZE_VECTOR)
      if isNullOrNil(arrVectorSize) then return; end

      local variantArrSize, ok = redefineVariantSizeByVector(arrVectorAddr, arrVectorSize)
      if not ok then return; end

      local visitor = NodeVisitor

      for varIndex = 0, arrVectorSize - 1 do
        if dumpContext:shouldStop() then return end
        local entry = readArrayValueEntry(arrVectorAddr, varIndex, variantArrSize)

        if isNotNullOrNil(entry.variantPtr) then
          local handler = GDHandlers.NodeDiscoveryHandlers[entry.typeName]
          if handler then
            handler(entry, visitor, dumpContext)
          end
        end
      end
    end

    --- iterates a packed array and adds it to a class
    ---@param packedArrayAddr number
    ---@param packedTypeName string
    ---@param parent userdata
    function iteratePackedArrayToAddr(packedArrayAddr, packedTypeName, parent, contextTable)
      assert(type(packedArrayAddr) == 'number', "Packed Array has to be a number, instead got: " .. type(packedArrayAddr))
      assert(type(packedTypeName) == 'string', "TypeName has to be a string, instead got: " .. type(packedTypeName))

      local packedDataArrAddr, packedVectorSize = getPackedArrayInfo(packedArrayAddr)
      if isNullOrNil(packedDataArrAddr) then return end

      contextTable.symbol = wrapBrackets( contextTable.symbol .. '+P_ARRAY_TOARR' )
      iteratePackedArrayCore(packedDataArrAddr, packedVectorSize, packedTypeName, parent, GDEmitters.PackedAddrEmitter, contextTable)
      return
    end

    --- iterates a packed array and adds it to a struct
    ---@param packedArrayAddr number
    ---@param packedTypeName string
    ---@param pArrayStructElement userdata
    function iteratePackedArrayToStruct(packedArrayAddr, packedTypeName, pArrayStructElement, contextTable)
      assert(type(packedArrayAddr) == 'number', "Packed Array " .. tostring(packedArrayAddr) .. " has to be a number, instead got: " .. type(packedArrayAddr))
      assert(type(packedTypeName) == 'string', "TypeName " .. tostring(packedTypeName) .. " has to be a string, instead got: " .. type(packedTypeName))

      local packedDataArrAddr, packedVectorSize = getPackedArrayInfo(packedArrayAddr)
      if isNullOrNil(packedDataArrAddr) then return end
      pArrayStructElement = addStructureElem(pArrayStructElement, 'PckArray', GDDEFS.P_ARRAY_TOARR, vtPointer)
      pArrayStructElement.ChildStruct = createStructure('PArrayData')
      contextTable.symbol = wrapBrackets( contextTable.symbol .. '+P_ARRAY_TOARR' )
      iteratePackedArrayCore(packedDataArrAddr, packedVectorSize, packedTypeName, pArrayStructElement, GDEmitters.PackedStructEmitter, contextTable)
      return
    end

  -- ///---///--///---///--///---///--///--///---///--///---///--///---///--/// Variant

    ---@param nodeAddr number
    ---@param parent userdata
    ---@param emitter table
    ---@param options table
    function iterateVectorVariants(nodeContext, emitter, options)
      assert(type(nodeContext.addr) == 'number', "Node addr has to be a number, instead got: " .. type(nodeContext.addr));

      options = options or {}

      if options.requireGDScript and not checkForGDScript(nodeContext.addr) then
        
        sendDebugMessage("Node has NO GDScript: " .. nodeContext.name)
        if emitter == GDEmitters.AddrEmitter then
          synchronize(function(parent) parent.Destroy() end, nodeContext.memrec )
        end
        return;
      end

      if GDDEFS.MONO and (checkScriptType(nodeContext.addr)==GDDEFS.SCRIPT_TYPES["CS"]) then return; end -- for mono targets

      local headElement, tailElement, mapSize = getNodeVariantMap(nodeContext.addr)
      if isNullOrNil(headElement) or isNullOrNil(mapSize) then
        sendDebugMessage('(hash)Map empty?: ' .. nodeContext.name)
        return;
      end

      local variantVector, vectorSize = getNodeVariantVector(nodeContext.addr)
      local variantSize, ok = redefineVariantSizeByVector(variantVector, vectorSize)
      if not ok then
        sendDebugMessage("Variant resize strangely failed")
        return;
      end

      local mapElement = headElement

      repeat
        local entry = readNodeVariantEntry(mapElement, variantVector, variantSize, options.bNeedStructOffset)
        local contextTable =
        {
          nodeAddr = nodeContext.addr,
          nodeName = nodeContext.name,
          baseAddress = entry.variantPtr,
          symbol = nodeContext.symbol
        }
        local handler = GDHandlers.VariantHandlers[entry.typeName] or GDHandlers.VariantHandlers.DEFAULT;
        local parentContainer = getContainerFromEmitterAndContext(emitter, nodeContext)
        handler(entry, emitter, parentContainer, contextTable);

        mapElement = getNextMapElement(mapElement)
      until (mapElement == 0)

      return
    end

    function iterateVectorVariantsForFields(nodeAddr)
      if isNullOrNil(nodeAddr) then return nil end
      -- if not checkForGDScript(nodeAddr) then return; end
      local headElement, tailElement, mapSize = getNodeVariantMap(nodeAddr)
      if isNullOrNil(headElement) or isNullOrNil(mapSize) then return nil end

      local variantVector, vectorSize = getNodeVariantVector(nodeAddr)
      local sizeOfVariant, ok = redefineVariantSizeByVector(variantVector, vectorSize)
      if not ok then return nil end

      local mapElement = headElement
      local fields = {}
      local index = 0

      repeat
        local entry = readNodeVariantEntry(mapElement, variantVector, sizeOfVariant)
        fields[index] = {}
        -- fields[index].index = entry.index
        -- fields[index].name = entry.name
        fields[index].Name = entry.name
        -- fields[index].offset = entry.offsetToValue
        fields[index].Offset = entry.offsetToValue
        -- fields[index].sizeof = sizeOfVariant
        fields[index].Sizeof = sizeOfVariant
        -- fields[index].type = entry.typeId
        fields[index].Type = entry.typeId

        mapElement = getNextMapElement(mapElement)
        index = index+1
      until (mapElement == 0)

      return fields
    end

    --- nodeAddr and owner to append to
    function iterateVecVarToAddr(nodeContext)
      local options =
      {
        bNeedStructOffset = false,
        requireGDScript = true
      };
      iterateVectorVariants(nodeContext, GDEmitters.AddrEmitter, options);
    end

    --- nodeAddr and ownerStruct to append to
    function iterateVecVarToStruct(nodeContext)
        local options =
        {
          bNeedStructOffset = true,
          requireGDScript = false
        }
        iterateVectorVariants(nodeContext, GDEmitters.StructEmitter, options)
    end

    --- iterate nodes only
    ---@param nodeAddr number
    function iterateVecVarForNodes(nodeAddr, dumpContext)
      if dumpContext:shouldStop() then return end
      if isNullOrNil(nodeAddr) then return; end
      -- if not checkForGDScript(nodeAddr) then return; end -- should be checked at this point

      local variantVector, vectorSize = getNodeVariantVector(nodeAddr)
      if isNullOrNil(vectorSize) --[[or vectorSize > 1500]] then return; end

      local variantSize, ok = redefineVariantSizeByVector(variantVector, vectorSize)
      if not ok then return; end

      local visitor = NodeVisitor

      for variantIndex = 0, vectorSize - 1 do
        if dumpContext:shouldStop() then return end
        local entry = readVectorVariantEntry(variantVector, variantIndex, variantSize)
        local handler = GDHandlers.NodeDiscoveryHandlers[entry.typeName]
        if handler then
          handler(entry, visitor, dumpContext)
        end
      end
    end

    --- returns a vector pointer and its size via
    ---@param nodeAddr number
    function getNodeVariantVector(nodeAddr)
      if isNullOrNil(nodeAddr) then return; end -- assert(type(nodeAddr) == 'number', "nodeAddr should be a number, instead got: " .. type(nodeAddr))

      local scriptInstance = readPointer( (nodeAddr or 0) + GDDEFS.GDSCRIPTINSTANCE)
      if isNullOrNil(scriptInstance) then
        -- sendDebugMessage('scriptInstance is absent for ' .. string.format(' %x', nodeAddr))
        return;
      end

      local vectorPtr = readPointer( ( scriptInstance or 0) + GDDEFS.VAR_VECTOR)
      local vectorSize = readInteger( (vectorPtr or 0) - GDDEFS.SIZE_VECTOR)

      if isNullOrNil(vectorPtr) then
        -- sendDebugMessage('vector is absent for ' .. string.format(' %x', nodeAddr))
        return;
      end
      if isNullOrNil(vectorSize) then
        -- sendDebugMessage('vector size is 0/nil, node ' .. string.format(' %x', nodeAddr))
        return;
      end

      return vectorPtr, vectorSize
    end

    --- returns a VariantData's (hash) map head, tail and size via a nodeAddr
    ---@param nodeAddr number
    function getNodeVariantMap(nodeAddr)
      assert(type(nodeAddr) == 'number', "nodeAddr should be a number, instead got: " .. type(nodeAddr))

      local scriptInstanceAddr = readPointer(nodeAddr + GDDEFS.GDSCRIPTINSTANCE)
      if isNullOrNil(scriptInstanceAddr) then
        sendDebugMessage('scriptInstance is absent for ' .. string.format(' %x', nodeAddr));
        return;
      end

      local gdScriptAddr = readPointer(scriptInstanceAddr + GDDEFS.GDSCRIPT_REF)
      if isNullOrNil(gdScriptAddr) then
        sendDebugMessage('GDScript is absent for ' .. string.format(' %x', nodeAddr));
        return;
      end

      local mainElement = readPointer(gdScriptAddr + GDDEFS.VAR_NAMEINDEX_MAP) -- head / root
      local endElement = readPointer(gdScriptAddr + GDDEFS.VAR_NAMEINDEX_MAP + GDDEFS.PTRSIZE) -- tail / end
      local mapSize = readInteger(gdScriptAddr + GDDEFS.VAR_NAMEINDEX_MAP + GDDEFS.MAP_SIZE)

      if isNullOrNil(mainElement) or isNullOrNil(endElement) or isNullOrNil(mapSize) then
        sendDebugMessage('Variant: (hash)map is not found')
        return;
      end

      if GDDEFS.MAJOR_VER == 4 then
        return mainElement, endElement, mapSize
      else
        return getLeftmostMapElem(mainElement, endElement, mapSize, { silentLeftWalk = true })
      end
    end

    --- returns a pointer to the variant's value and its type for a sanity check
    ---@param vectorAddr number
    ---@param index number
    ---@param varSize number
    ---@param bOffsetret boolean
    function getVariantByIndex(vectorAddr, index, varSize--[[, bPushOffset]])
      assert(type(vectorAddr) == 'number', "vector addr should be a number, instead got: " .. type(vectorAddr))
      assert((type(index) == 'number') and (index >= 0), "index should be a valid number, instead got: " .. type(index))

      -- if index > readInteger( ( (vectorAddr or 0) - GDDEFS.SIZE_VECTOR) ) or 0 - 1 then
      --   sendDebugMessage("index is out of vector size, pass index: " .. tostring(index) .. ' VecSize: ' .. tostring( (index > (readInteger( ( (vectorAddr or 0) - GDDEFS.SIZE_VECTOR) or 0 ) - 1)) ))
      -- end

      local variantType = readInteger(vectorAddr + varSize * index)
      local offsetToValue = getVariantValueOffset(variantType)

      local offset = varSize * index + offsetToValue
      local variantAddr = getAddress(vectorAddr + offset)

      if (variantType == nil) or (variantAddr == nil) then -- variantType == 0 -- zero is nil which happens for uninitialized -- zero is possible for uninitialized variantPtr == 0 or
        sendDebugMessage('variant ptr or type invalid');
        -- if inMainThread() then error('variant ptr or type invalid') else return 0,0,0 end
        return 0,0,0
      end

      -- if bPushOffset then
        return variantAddr, variantType, offset
      -- else
      --   return variantAddr, variantType
      -- end
    end

    VariantArena =
      { -- TODO: optimize space
        base = nil, -- alloc ptr
        size = 0x2000, -- allocated space
        cursor = 0, -- current offset
        variantSize = 0x40, -- for enough padding
        argListOffset = 0x100, -- where const Variant **p_args
        scratchStart = 0x500, -- space before is reserved
        scratchEnd = 0x1F00, -- should suffice

        excptOffset = 0x48,
        returnBufOffset = 0x0,
        callErrorOffset = 0x1B0,
        inited = false,
      }

      function VariantArena:init()
        if not self.inited then
          self.base = allocateMemory(self.size)
          self.inited = true
        end
        if isNullOrNil(self.base) then error("alloc failed") end
        self.cursor = self.scratchStart
        return true
      end

      function VariantArena:reset()
        self.cursor = self.scratchStart
      end

      function VariantArena:align(alignment)
        local remaining = self.cursor % alignment -- get remaining bytes for alignment
        if remaining ~= 0 then self.cursor = self.cursor + (alignment - remaining) end
      end

      function VariantArena:alloc(bytes, align)
        self:align(align or 8)

        -- just in case overflow happens
        if self.cursor + bytes > self.scratchEnd then
          error( ("VariantArena overflow: need 0x%X bytes, cursor=0x%X"):format(bytes, self.cursor) )
        end

        -- borrow space w/ ptr
        local ptr = self.base + self.cursor
        -- adjust the position
        self.cursor = self.cursor + bytes
        return ptr
      end

      function VariantArena:allocVariant()
        local ptr = self:alloc(self.variantSize, GDDEFS.PTRSIZE)

        -- clear the slot so stale data from previous calls cannot leak into a new Variant
        for off = 0, self.variantSize - 1, 8 do
          writePointer(ptr + off, 0)
        end

        return ptr
      end

    GDVariant = {}

      -- non-managed
      function GDVariant.BOOL(arena, value, copy)
        if isValidPointer(copy) then return copy end
        local v = arena:allocVariant()
        writeInteger(v + 0x0, getGDTypeEnumFromName('BOOL') )
        writeByte(v + 0x8, value and 1 or 0)
        return v
      end

      function GDVariant.INT(arena, value, copy)
        if isValidPointer(copy) then return copy end
        local v = arena:allocVariant()
        writeInteger(v + 0x0, getGDTypeEnumFromName('INT') )
        writeQword(v + 0x8, value) -- int64_t
        return v
      end

      function GDVariant.FLOAT(arena, value, copy)
        if isValidPointer(copy) then return copy end
        local v = arena:allocVariant()
        writeInteger(v + 0x0, getGDTypeEnumFromName('FLOAT') )
        writeDouble(v + 0x8, value)
        return v
      end

      function GDVariant.VECTOR2(arena, value, copy)
        if isValidPointer(copy) then return copy end
        local v = arena:allocVariant()
        writeInteger(v + 0x0, getGDTypeEnumFromName('VECTOR2') )
        writeFloat(v + 0x8, value.x)
        writeFloat(v + 0xC, value.y)
        return v
      end

      function GDVariant.VECTOR2I(arena, value, copy)
        if isValidPointer(copy) then return copy end
        local v = arena:allocVariant()
        writeInteger(v + 0x0, getGDTypeEnumFromName('VECTOR2I') )
        writeInteger(v + 0x8, value.x)
        writeInteger(v + 0xC, value.y)
        return v
      end

      function GDVariant.RECT2(arena, value, copy)
        if isValidPointer(copy) then return copy end
        local v = arena:allocVariant()
        writeInteger(v + 0x0, getGDTypeEnumFromName('RECT2') )
        writeFloat(v + 0x8, value.x)
        writeFloat(v + 0xC, value.y)
        writeFloat(v + 0x10, value.w)
        writeFloat(v + 0x14, value.h)
        return v
      end

      function GDVariant.RECT2I(arena, value, copy)
        if isValidPointer(copy) then return copy end
        local v = arena:allocVariant()
        writeInteger(v + 0x0, getGDTypeEnumFromName('RECT2I') )
        writeInteger(v + 0x8, value.x)
        writeInteger(v + 0xC, value.y)
        writeInteger(v + 0x10, value.w)
        writeInteger(v + 0x14, value.h)
        return v
      end

      function GDVariant.VECTOR3(arena, value, copy)
        if isValidPointer(copy) then return copy end
        local v = arena:allocVariant()
        writeInteger(v + 0x0, getGDTypeEnumFromName('VECTOR3') )
        writeFloat(v + 0x8, value.x)
        writeFloat(v + 0xC, value.y)
        writeFloat(v + 0x10, value.z)
        return v
      end

      function GDVariant.VECTOR3I(arena, value, copy)
        if isValidPointer(copy) then return copy end
        local v = arena:allocVariant()
        writeInteger(v + 0x0, getGDTypeEnumFromName('VECTOR3I') )
        writeInteger(v + 0x8, value.x)
        writeInteger(v + 0xC, value.y)
        writeInteger(v + 0x10, value.z)
        return v
      end

      function GDVariant.VECTOR4(arena, value, copy)
        if isValidPointer(copy) then return copy end
        local v = arena:allocVariant()
        writeInteger(v + 0x0, getGDTypeEnumFromName('VECTOR4') )
        writeFloat(v + 0x8, value.x)
        writeFloat(v + 0xC, value.y)
        writeFloat(v + 0x10, value.z)
        writeFloat(v + 0x14, value.w)
        return v
      end

      function GDVariant.VECTOR4I(arena, value, copy)
        if isValidPointer(copy) then return copy end
        local v = arena:allocVariant()
        writeInteger(v + 0x0, getGDTypeEnumFromName('VECTOR4I') )
        writeInteger(v + 0x8, value.x)
        writeInteger(v + 0xC, value.y)
        writeInteger(v + 0x10, value.z)
        writeInteger(v + 0x14, value.w)
        return v
      end

      function GDVariant.PLANE(arena, value, copy)
        if isValidPointer(copy) then return copy end
        error("not implemented yet")
        local v = arena:allocVariant()
        writeInteger(v + 0x0, getGDTypeEnumFromName('PLANE') )
        return v
      end

      function GDVariant.QUATERNION(arena, value, copy)
        if isValidPointer(copy) then return copy end
        error("not implemented yet")
        local v = arena:allocVariant()
        writeInteger(v + 0x0, getGDTypeEnumFromName('QUATERNION') )
        return v
      end

      function GDVariant.COLOR(arena, value, copy)
        if isValidPointer(copy) then return copy end
        local v = arena:allocVariant()
        writeInteger(v + 0x0, getGDTypeEnumFromName('COLOR') )
        writeFloat(v + 0x8, value.r)
        writeFloat(v + 0xC, value.g)
        writeFloat(v + 0x10, value.b)
        writeFloat(v + 0x14, value.a)
        return v
      end

      function GDVariant.RID(arena, value, copy)
        if isValidPointer(copy) then return copy end
        error("not implemented yet")
        local v = arena:allocVariant()
        writeInteger(v + 0x0, getGDTypeEnumFromName('RID') )
        return v
      end

      -- managed
      function GDVariant.OBJECT(arena, value, copy)
        if isValidPointer(copy) then return copy end
        if isNotNullOrNil(value) then error("object value invalid") end
        local v = arena:allocVariant()
        writeInteger(v + 0x0, getGDTypeEnumFromName('OBJECT') )
        writeInteger(v + 0x8, value.id)
        writePointer(v + 0x10, value.obj)
        return v
      end

      function GDVariant.STRING(arena, value, copy)
        if isValidPointer(copy) then return copy end
        -- value is a lua string, the ctor checks it, it will copy the string
        return GDI.construct_string_variant( value )
      end

      function GDVariant.STRING_NAME(arena, value, copy)
        if isValidPointer(copy) then return copy end
        return GDI.construct_string_name_variant( value )
      end

      function GDVariant.NODE_PATH(arena, value, copy)
        if isValidPointer(copy) then return copy end
        error('not implemented yet')
        return 
      end

      function GDVariant.CALLABLE(arena, value, copy)
        if isValidPointer(copy) then return copy end
        error('not implemented yet')
      end

      function GDVariant.SIGNAL(arena, value, copy)
        if isValidPointer(copy) then return copy end
        error('not implemented yet')
      end

      function GDVariant.DICTIONARY(arena, value, copy)
        if isValidPointer(copy) then return copy end
        error('not implemented yet')
      end

      function GDVariant.ARRAY(arena, value, copy)
        if isValidPointer(copy) then return copy end
        error('not implemented yet')
      end

      function GDVariant.PACKED_BYTE_ARRAY(arena, value, copy)
        if isValidPointer(copy) then return copy end
        error("not implemented yet")
      end

      function GDVariant.PACKED_INT32_ARRAY(arena, value, copy)
        if isValidPointer(copy) then return copy end
        error("not implemented yet")
      end

      function GDVariant.PACKED_INT64_ARRAY(arena, value, copy)
        if isValidPointer(copy) then return copy end
        error("not implemented yet")
      end

      function GDVariant.PACKED_FLOAT32_ARRAY(arena, value, copy)
        if isValidPointer(copy) then return copy end
        error("not implemented yet")
      end

      function GDVariant.PACKED_FLOAT64_ARRAY(arena, value, copy)
        if isValidPointer(copy) then return copy end
        error("not implemented yet")
      end

      function GDVariant.PACKED_STRING_ARRAY(arena, value, copy)
        if isValidPointer(copy) then return copy end
        error("not implemented yet")
      end

      function GDVariant.PACKED_VECTOR2_ARRAY(arena, value, copy)
        if isValidPointer(copy) then return copy end
        error("not implemented yet")
      end

      function GDVariant.PACKED_VECTOR3_ARRAY(arena, value, copy)
        if isValidPointer(copy) then return copy end
        error("not implemented yet")
      end

      function GDVariant.PACKED_COLOR_ARRAY(arena, value, copy)
        if isValidPointer(copy) then return copy end
        error("not implemented yet")
      end

      function GDVariant.PACKED_VECTOR4_ARRAY(arena, value, copy)
        if isValidPointer(copy) then return copy end
        error("not implemented yet")
      end

      function GDVariant.TRANSFORM2D(arena, value, copy)
        if isValidPointer(copy) then return copy end
        error("not implemented yet")
      end

      function GDVariant.AABB(arena, value, copy)
        if isValidPointer(copy) then return copy end
        error("not implemented yet")
      end

      function GDVariant.BASIS(arena, value, copy)
        if isValidPointer(copy) then return copy end
        error("not implemented yet")
      end

      function GDVariant.TRANSFORM3D(arena, value, copy)
        if isValidPointer(copy) then return copy end
        error("not implemented yet")
      end

      function GDVariant.PROJECTION(arena, value, copy)
        if isValidPointer(copy) then return copy end
        error("not implemented yet")
      end


  -- ///---///--///---///--///---///--///--///---///--///---///--///---///--/// Dumper

    function GDAPI.registerNodeOffsets(nodeName, namespace)
      local nodeAddr = getDumpedNode( nodeName )
      if isNullOrNil(nodeAddr) then error('node addr not found') end
      namespace = (namespace and namespace ~= '' and namespace .. '.') or ''

      local classFields = {}
      if GDDEFS.MONO and checkScriptType(nodeAddr) == GDDEFS.SCRIPT_TYPES["CS"] then
        local GDSI = getNodeGDScriptInstance(nodeAddr) or 0x0
        local clrDataAddr = readPointer( readPointer( GDSI + GDDEFS.CLR_PTR ) )
        if isNullOrNil(clrDataAddr) then error('clr data invalid') end
        if DataSource.DotNetDataCollector==nil then
          DataSource={}
          DataSource.DotNetDataCollector = getDotNetDataCollector() -- shouldn't get messy?
        end
        local dotnetObjInfo = DataSource.DotNetDataCollector.getAddressData( clrDataAddr ) -- dotnetinfo.lua
        for _, v in ipairs(dotnetObjInfo.Fields) do
          if not v.IsStatic then table.insert(classFields, v) end
        end
      else -- GD script
        classFields = godot_node_enumVariants( nodeAddr )
      end

      if not (classFields) or next(classFields)==nil then error('node isn\'t dumped or constructed yet, try again later') end

      for _ , field in pairs(classFields) do
        registerSymbol( namespace .. nodeName .. '.' .. field.Name , field.Offset , false ) -- save them
      end
    end

    --- gets a dumped Node by name
    ---@param nodeName string
    function GDAPI.getDumpedNode(nodeName)
      assert(type(nodeName) == "string", 'Node name should be a string, instead got: ' .. type(nodeName))
      if not (gdOffsetsDefined) then print('define the offsets first, silly') return; end

      if (not gd_dumpedMonitorNodes) or next(gd_dumpedMonitorNodes) == nil then return; end

      return gd_dumpedMonitorNodes[nodeName]
    end

    --- prints all gathered nodeNames
    function GDAPI.printDumpedNodes()
      if not (gdOffsetsDefined) then print('define the offsets first, silly') return end

      if (not gd_dumpedMonitorNodes) or next(gd_dumpedMonitorNodes) == nil then return; end

      for k, nodeAddr in pairs(gd_dumpedMonitorNodes) do
        -- local GDScriptName = getNodeNameFromGDScript(nodeAddr) or ''
        local nodeNameStr = getNodeName(nodeAddr) or ''
        printf(">Node Scriptname: %-50sname: %-50s \t Node addr: %X", k, nodeNameStr, tonumber(nodeAddr))
      end
    end

    local function unregisterNodes()
      if (not gd_registeredNodes) or next(gd_registeredNodes) == nil then return; end
      for i, k in ipairs(gd_registeredNodes) do
        unregisterSymbol(k)
      end
      gd_registeredNodes = {}
    end

    local function registerDumpedNodes()
      if (not gd_dumpedMonitorNodes) or next(gd_dumpedMonitorNodes) == nil then return; end
      unregisterNodes() -- unregister the current & freed nodes
      for k, nodeAddr in pairs(gd_dumpedMonitorNodes) do
        table.insert(gd_registeredNodes, k)
        registerSymbol(k, nodeAddr, true)
      end
    end

    local function nodeMonitorThread(thr)
      thr.Name = "GD Monitor Thread"
      thr.freeOnTerminate(false) -- we do it ourselves
      local dumpContext =
        {
          startedAt = getTickCount(),
          dumped = {}, -- only nodes with GDScript
          visited = {}, -- every encountered node
          budgetMs = GD_MONITOR_BUDGET_MS or 45*1000,
          thread = thr,
        }

      function dumpContext:tryVisitNode(addr)
        if isNullOrNil(addr) then return false end
        if self.visited[addr] then return false end
        self.visited[addr] = true
        if checkForGDScript(addr) then
          table.insert(self.dumped, addr)
          -- will (un)register twice, but early, potentially
          local name = getNodeNameFromGDScript(addr)
          registerSymbol(name, addr, true)
          table.insert(gd_registeredNodes, name)
        end
        return true
      end

      function dumpContext:shouldStop()
        return self.thread.Terminated or (getTickCount() - self.startedAt) > self.budgetMs
      end

      local function cloneArrayAsMap(tabl)
        local result = {} -- { name : addr }
        for i, val in ipairs(tabl) do
          result[ getNodeNameFromGDScript(val) ] = val
        end
        return result
      end

      local mainNodeDict = getMainNodeDict() or {}

      for _, value in pairs(mainNodeDict) do
        processNodeForNodes(value.PTR, dumpContext)
      end

      gd_dumpedMonitorNodes = cloneArrayAsMap(dumpContext.dumped)
      registerDumpedNodes()
    end

    local function nodeMonitorService(thr)
      thr.Name = "GD Node Monitor Service"
      thr.freeOnTerminate(false) -- we do it ourselves
      -- bMonitorNodes = true
      gd_dumpedMonitorNodes = {};
      gd_registeredNodes = {};
      local counter = 0

      while not thr.Terminated do
        local startedAt = getTickCount()
        local gd_currNodeMonitorThread = createThread(nodeMonitorThread)
        gd_currNodeMonitorThread.waitfor()
        gd_currNodeMonitorThread.terminate()
        sleep( gd_nodeMonitorCD )
        counter = counter+1
        local timeDelta = getTickCount() - startedAt or 0

        if #enumModules() == 0 and not thr.Terminated then  -- if we aren't attached, kill this thread
          if not gd_currNodeMonitorThread.Terminated then gd_currNodeMonitorThread.terminate() end
          thr.terminate()
          return
        end
        thr.Name = "GD Node Monitor Service | lastDiff " .. timeDelta .. " ms " .. " | iter " .. counter
      end
    end

    -- toggles the node monitor thread
    function NodeMonitorServiceSwitch()
      if not (gdOffsetsDefined) or isNullOrNil(NodeMonitorServiceThread) then
        error("can't switch, uninitialized")
      end

      bMonitorNodes = not bMonitorNodes
      if bMonitorNodes then
        NodeMonitorServiceThread.suspend()
      else
        NodeMonitorServiceThread.resume()
      end
    end

    --- dump for a specific node and append to the parent
    ---@param parentMemrec userdata
    ---@param nodeAddr number
    ---@param bDoConstants number
    function GDAPI.DumpNodeToAddr(parentMemrec, nodeAddr, bDoConstants)
      assert(type(parentMemrec) == "userdata", 'Parent address has to be userdata, instead got: ' .. type(parentMemrec))
      assert(type(nodeAddr) == "number", 'Node address has to be a number, instead got: ' .. type(nodeAddr))
      if not (gdOffsetsDefined) then
        print('define the offsets first, silly')
        return
      end

      debugPrefix = 1; -- reset debug prefix, don't use that while running Node threads
      dumpedNodes = {}; -- let's start from scratch for single node dumps | there might be race conditions, not a big issue for most cases
      table.insert(dumpedNodes, nodeAddr)

      local nodeNameStr = getNodeName(nodeAddr)
      local gdscriptName = getNodeNameFromGDScript(nodeAddr)

      if not checkForGDScript(nodeAddr) then
        -- sendDebugMessage('node '..nodeNameStr..' doesnt have GDScript/Inst')
        return
      end
      -- sendDebugMessage('node '..tostring(nodeNameStr)..'addr: '..numtohexstr(nodeAddr) )

      synchronize(function(parentMemrec)
        if parentMemrec.Count ~= 0 then -- let's clear all children
          while parentMemrec.Child[0] ~= nil do
            parentMemrec.Child[0].Destroy()
          end
        end
      end, parentMemrec)
      
      local newNodeSymStr, GDSIsym, variantVectorSym, GDScriptSym, GDScriptConstMapSym
      local nodeContext;

      newNodeSymStr = gdscriptName
      GDSIsym = wrapBrackets( newNodeSymStr .. '+GDSCRIPTINSTANCE' )                                            -- [[[nodename+CHILDREN]+i*ptrsize]+GDSCRIPTINSTANCE]
      variantVectorSym = wrapBrackets( GDSIsym .. '+VAR_VECTOR' )                                               -- [[[[[nodename+CHILDREN]+i*ptrsize]+GDSCRIPTINSTANCE]+VAR_VECTOR]
      GDScriptSym = wrapBrackets( GDSIsym .. '+GDSCRIPT_REF' )                                                  -- [[[[[nodename+CHILDREN]+i*ptrsize]+GDSCRIPTINSTANCE]+GDSCRIPT_REF]
      GDScriptConstMapSym = wrapBrackets( GDScriptSym .. '+CONST_MAP' )                                         -- [[[[[[[nodename+CHILDREN]+i*ptrsize]+GDSCRIPTINSTANCE]+GDSCRIPT_REF]+CONST_MAP]

      if bDoConstants and (GDDEFS.CONST_MAP ~= 0) then
        -- sendDebugMessage('constants for node: '..tostring(nodeNameStr) )

        local newConstRec = synchronize(function(parentMemrec)
          local newConstRec = getAddressList().createMemoryRecord()
          newConstRec.setDescription("Consts:")
          newConstRec.setAddress(0xBABE)
          newConstRec.setType(vtPointer)
          newConstRec.Options = '[moHideChildren, moAllowManualCollapseAndExpand, moManualExpandCollapse]'
          -- newConstRec.DontSave = true
          newConstRec.appendToEntry(parentMemrec)
          return newConstRec
        end, parentMemrec)
        nodeContext = { addr = nodeAddr, name = nodeNameStr, gdname = gdscriptName, memrec = newConstRec, struct = nil, symbol = GDScriptConstMapSym }
        iterateNodeConstToAddr(nodeContext)

      end
      -- sendDebugMessage('variants for node: '..tostring(nodeNameStr) )

      nodeContext = { addr = nodeAddr, name = nodeNameStr, gdname = gdscriptName, memrec = parentMemrec, struct = nil, symbol = variantVectorSym }
      iterateVecVarToAddr(nodeContext)
      debugPrefix = 1; -- reset debug prefix
    end

    --- dumps all the active objects to the Address List
    function GDAPI.DumpAllNodesToAddr(thr)
      if not (gdOffsetsDefined) then
        print('define the offsets first, silly')
        return
      end

      print('MAIN: DUMP PROCESS STARTED')
      debugPrefix = 1; -- reset debug prefix
      dumpedNodes = {}; -- mutually linked nodes may end up in endless recursion + we use it for API | an obvious race condition if a user calls that on different nodes at the same time, don't care much
      local parentRec

      parentRec = synchronize(function()
        local addrList = getAddressList()
        local mainAddr = addrList.getMemoryRecordByDescription("DUMPED:")
        if mainAddr then
            mainAddr.Destroy()
        end

        local parentRec = addrList.createMemoryRecord()
        parentRec.setDescription("DUMPED:")
        parentRec.setAddress(0xBABE)
        parentRec.setType(vtPointer)
        parentRec.Options = '[moHideChildren, moAllowManualCollapseAndExpand, moManualExpandCollapse]'
        -- parentRec.DontSave = true
        return parentRec
      end)

      local mainNodeDict = getMainNodeDict()

      local symbolToChildren = '[[ptVP]+CHILDREN]' -- .. '+' .. numtohexstr(GDDEFS.CHILDREN)
      local newNodeSymStr, GDSIsym, variantVectorSym, GDScriptSym, GDScriptConstMapSym
      local nodeContext;

      for key, value in pairs(mainNodeDict) do
        newNodeSymStr = symbolToChildren .. '+' .. numtohexstr(value.index) .. "*" .. numtohexstr(GDDEFS.PTRSIZE) -- [[ptVP]+CHILDREN]+i*ptrsize
        GDSIsym = wrapBrackets( wrapBrackets(newNodeSymStr) .. '+GDSCRIPTINSTANCE' )                              -- [[[[ptVP]+CHILDREN]+i*ptrsize]+GDSCRIPTINSTANCE]
        variantVectorSym = wrapBrackets( GDSIsym .. '+VAR_VECTOR' )                                               -- [[[[[ptVP]+CHILDREN]+i*ptrsize]+GDSCRIPTINSTANCE]+VAR_VECTOR]
        GDScriptSym = wrapBrackets( GDSIsym .. '+GDSCRIPT_REF' )                                                  -- [[[[[ptVP]+CHILDREN]+i*ptrsize]+GDSCRIPTINSTANCE]+GDSCRIPT_REF]
        GDScriptConstMapSym = wrapBrackets( GDScriptSym .. '+CONST_MAP' )                                         -- [[[[[[[ptVP]+CHILDREN]+i*ptrsize]+GDSCRIPTINSTANCE]+GDSCRIPT_REF]+CONST_MAP]

        value.MEMREC = synchronize(function(value, key, parentRec)
          local newNodeMemRec = addMemRecTo(key, value.PTR, getCETypeFromGD(value.TYPE), parentRec)
          newNodeMemRec.Options = '[moHideChildren, moAllowManualCollapseAndExpand, moManualExpandCollapse]'
          return newNodeMemRec
        end, value, key, parentRec)

        table.insert(dumpedNodes, value.PTR)
        sendDebugMessage('MAIN: loop. STEP: Constants for: ' .. key)

        if GDDEFS.CONST_MAP ~= 0 then
          local newConstRec = synchronize(function(value)
            local newConstRec = getAddressList().createMemoryRecord()
            newConstRec.setDescription("Consts:")
            newConstRec.setAddress(0xBABE)
            newConstRec.setType(vtPointer)
            newConstRec.Options = '[moHideChildren, moAllowManualCollapseAndExpand, moManualExpandCollapse]'
            -- newConstRec.DontSave = true
            newConstRec.appendToEntry(value.MEMREC)
            return newConstRec
          end, value)
          nodeContext = { addr = value.PTR, name = value.NAME, gdname = value.SCRIPTNAME, memrec = newConstRec, struct = nil, symbol = GDScriptConstMapSym }
          iterateNodeConstToAddr(nodeContext)
        end

        sendDebugMessage('MAIN: loop. STEP: VARIANTS for: ' .. key)
        nodeContext = { addr = value.PTR, name = value.NAME, gdname = value.SCRIPTNAME, memrec = value.MEMREC, struct = nil, symbol = variantVectorSym }
        iterateVecVarToAddr(nodeContext)
      end

      debugPrefix = 1;
      print('MAIN: DUMP PROCESS FINISHED')

    end

    function GDAPI.initDumper(config)
      -- if not (targetIsGodot) then return; end

      -- init global
      initGDDefs()

      -- essential version definition
      initGDVersion(config)

      -- define version and offsets
      defineGDOffsets(config)
      gdOffsetsDefined = true

      -- register symbols for pointer resolution
      registerGDSymbols()

      -- try finding SceneTree and Viewport/Window
      if tryRegSceneTree() and setSTtoVPoffset() then
        registerSymbol('ptVP', '[pSceneTree]+oSTtoVP', false)
      end

      -- define type conversion helpers
      defineVariantTypeProfile()



      -- check if UTF32LE string type reged, otherwise define it
      checkGDStringType()

      -- build the correct disassembler profile
      defineGDFunctionEnums()
      bDisasmFunc= true -- whether to disasm functions, on by default

      -- disable show on print
      fuckoffPrint()

      -- exposing relevant API
      if GDDEFS.MAJOR_VER >= 4 and GDDEFS.MINOR_VER >= 1 then
        if findGDExtensionInterfacePtr() then GDI.Extension = GDExtendedInterface end
      end
      if GDDEFS.MAJOR_VER == 3 then
        if findGDNativeAPIStruct() then GDI.GDNative = GDNativeInterface end
      end

      -- find GDScriptFunctions::call()
      if not findGDVMCallPtr() then sendDebugMessage('[VM_CALL] lookup failed.') end

      -- wait between thread runs in millis
      gd_nodeMonitorCD = 100

      -- this guy will monitor threads and register them, isn't quite optimized non-intrusive solution
      NodeMonitorServiceThread = createThread(nodeMonitorService)
    end
    godotRegisterPreinit()

  
-- ///---///--///---///--///---///--///--///---///--///---///--///---///--///--///--/// API
  
  buildGDGUI = GDAPI.buildGDGUI  
  printDumpedNodes = GDAPI.printDumpedNodes
  getDumpedNode = GDAPI.getDumpedNode
  registerNodeOffsets = GDAPI.registerNodeOffsets
  getGDObjectName = GDAPI.getGDObjectName
  executeGDFunction = GDAPI.executeGDFunction
  callGDFunctionFromNode = GDAPI.callGDFunctionFromNode
  patchGDFunctionConst = GDAPI.patchGDFunctionConst
  patchGDFunction = GDAPI.patchGDFunction
  getGDFunctionFromNode = GDAPI.getGDFunctionFromNode
  getNodeConstPtr = GDAPI.getNodeConstPtr
  getNodeNameFromGDScript = GDAPI.getNodeNameFromGDScript
  getNodeName = GDAPI.getNodeName
  getNodeGDScriptInstance = GDAPI.getNodeGDScriptInstance
  godot_node_enumVariants = GDAPI.godot_node_enumVariants
  godotAA_GETNODESTRUCT = GDAPI.godotAA_GETNODESTRUCT
  gd_monitorProfile = GDAPI.gd_monitorProfile
  printGDConfig = GDAPI.printGDConfig
  getGDSemver = GDAPI.getGDSemver
  DumpNodeToAddr = GDAPI.DumpNodeToAddr
  DumpAllNodesToAddr = GDAPI.DumpAllNodesToAddr
  initDumper = GDAPI.initDumper
  getNodeChildByGDName = GDAPI.getNodeChildByGDName
  getNodeChildByName = GDAPI.getNodeChildByName
  getSectionBounds = GDAPI.getSectionBounds

  recompileGDScript = GDAPI.recompileGDScript
  revertGDScript = GDAPI.revertGDScript