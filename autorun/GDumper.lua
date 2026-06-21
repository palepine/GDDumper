-- This script was created by palepine. Support me: https://ko-fi.com/vesperpallens
-- I'd like to thank cfemen for some basic insights about the godot engine which saved me from reading much of the Godot Engine source code initially.
-- Source code on github: https://github.com/palepine/GDDumper
-- ///---///--///---///--///---///--///--///---///--///---///--///---///--/// TODOS
  -- TODO addresslist should include node's children of children
  -- TODO tree view form with polling
  -- TODO more offsets for non-GDI objects
  -- TODO doxygen comments
  -- TODO: explore how timeconsuming would it be to pull off what gdsdecomp does with token streams for runtime decompilation and runtime re-compilation
  -- TODO: ObjectDB inspection

-- ///---///--///---///--///---///--///--///---///--///---///--///---///--///--///--/// FORWARD DECLARATIONS
  local GDAPI = {}

  local getExportTableName
  local getGodotVersionString
  
  local readUTFString
  local codePointToUTF8
  local getStringNameStr
  local UTF8Codepoints

  local getViewport
  
  local rootOffset
  local fieldOffset
  
  local checkForGDScript
  local checkScriptType
  local checkIfObjectWithChildren
  local iterateNodeChildrenToStruct
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
  local checkIfGDFunction
  local setupCallArgs

  local getNodeConstName
  local iterateNodeConstToAddr
  local iterateNodeConstToStruct

  local iterateDictionary
  local iterateDictionaryToAddr
  local iterateDictionaryToStruct
  local iterateArray
  local iterateArrayToAddr
  local iterateArrayToStruct
  local iteratePackedArrayToAddr
  local iteratePackedArrayToStruct
  local iterateVectorVariants
  local iterateVectorVariantsForFields
  local iterateVectorVariantsForNamedField
  local iterateVecVarToAddr
  local iterateVecVarToStruct
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

  local GDAOB
  local getStoredOffsetsFromVersion
  local defineVariantTypeProfile

  local getMainModuleInfo

  local bGDDebug = false
  local bHardOffsets = false

-- ///---///--///---///--///---///--///--///---///--///---///--///---///--///--///--/// DUMPER CODE
  -- ///---///--///---///--///---///--///--///---///--///---///--///---///--/// CE & UTILS
    -- ///---///--///---///--///---/// POINTER HANDLERS

      --- checks if the value is a valid pointer
      ---@param addr number
      ---@return boolean
      function isValidPointer(addr)
        local success, result = pcall(readPointer, addr)
        return success and result ~= nil
      end

      function isInvalidPointer(addr)
        return isValidPointer(addr) == false
      end

      --- checks if the value is a valid pointer and not nullptr
      ---@param addr number
      ---@return boolean
      function isPointerNotNull(addr)
        return isValidPointer(addr) and readPointer(addr) ~= 0
      end

      --- gets some section info (bounds)
      ---@param sectionName number
      ---@return table
      local function getSectionBounds(sectionName)
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
        if VTAddr == nil or VTAddr == 0 then
          return false
        end
        if not GDDEFS._MAIN_MODULE_INFO then
          GDDEFS._MAIN_MODULE_INFO = getMainModuleInfo()
          GDDEFS._TEXT_SECTIONINFO = getSectionBounds(".text")
          if GDDEFS._TEXT_SECTIONINFO == nil then return false end
        end

        if GDDEFS._MAIN_MODULE_INFO.moduleStart < VTAddr and VTAddr < GDDEFS._MAIN_MODULE_INFO.moduleEnd then
          -- iterate a few pointers and confirm if they are executable
          local pmethod = readPointer(VTAddr) -- just check the first
          for i = 0, 3 do
            local pmethod = readPointer(VTAddr + GDDEFS.PTRSIZE * i)
            if not isInsideSectionRange(pmethod, GDDEFS._TEXT_SECTIONINFO) then
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

      -- global
      function alignOffset(offset, alignment)
        local remaining = offset % alignment -- get remaining bytes for alignment
        if remaining ~= 0 then
          offset = offset + (alignment - remaining)
        end
        return offset
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
        if index == nil or index < 0 then return nil end
        local vtable = getVtableValidated(addr)
        if isNullOrNil(vtable) then return nil end
        local offsetToMethod = GDDEFS.PTRSIZE * index
        return readPointer(vtable + offsetToMethod)
      end

      local function loadScriptFromTable(fileName, arg)
        if isNullOrNil(fileName) then error('filename invalid') end
        local tableFile = findTableFile( fileName )
        if tableFile == nil then error('no script file found') end
        local fileStream = tableFile.getData()
        local scriptString = readStringLocal(fileStream.Memory, fileStream.Size)
        if scriptString == nil then error('script not loaded from file') end
        local doScript = loadstring(scriptString)
        if type(doScript) == 'function' then
          return doScript()
        else
          error('script not parsed')
        end
      end


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
          ([[local config = {majorVersion = 0X%X,minorVersion = 0X%X,GDCustomver = %s,GDDebugVer = %s,isMonoTarget = %s,useHardcoded = %s,offsetNodeChildren = 0X%X,offsetNodeStringName = 0X%X,offsetGDScriptInstance = 0X%X,offsetVariantVector = 0X%X,offsetVariantVectorSize = 0X%X,offsetGDScriptName = 0X%X,offsetFuncMap = 0X%X,offsetGDFunctionCode = 0X%X,offsetGDFunctionConst = 0X%X,offsetGDFunctionGlobals = 0X%X,offsetConstMap = 0X%X,offsetVariantMap = 0X%X}]]):format(
          (GDDEFS.MAJOR_VER or 0x0),
          (GDDEFS.MINOR_VER or 0x0),
          (tostring(GDDEFS.CUSTOMVER)),
          (tostring(GDDEFS.DEBUGVER)),
          (tostring(GDDEFS.MONO)),
          (tostring(false)),
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
          (GDDEFS.VARIANTMAP or 0x0)
          )
        )
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
          structElem.Name = gd_getNodeName(mainNodeTable[i + 1])
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

        local symbolToChildren = '[[pRoot]+' .. numtohexstr(GDDEFS.CHILDREN) .. ']' -- '[[pRoot]+CHILDREN]'
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

        if checkForGDScript(baseaddr) and isVtable( getVtable(baseaddr) ) then
          dumpedDissectorNodes = {} -- redundant?
          -- safe to assume, that's a starting point
          local nodeName = gd_getNodeName(baseaddr)
          if nodeName == 'N??' then nodeName = gd_getNodeNameFromScript(baseaddr) end
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

        elseif GDDEFS.bDisasmFunc and checkIfGDFunction(baseaddr) then
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
        if isInvalidPointer(addr) or not isVtable(getVtable(addr)) then
          return nil
        end

        local result = gd_getObjectName(addr)
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
        -- if isInvalidPointer(addr) or not isVtable( getVtable( addr ) ) then
        --     return nil
        -- end

        -- local result = gd_getObjectName(addr)
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
        -- local nodeAddr = gd_getDumpedNode(nodeName)
        -- local fields = gd_node_enumVariants(nodeAddr)
        -- if fields == nil or next(fields) == nil then return nil end

      end

      function GDAPI.godot_node_enumVariants(nodeAddr)
        return iterateVectorVariantsForFields(nodeAddr)
      end

      function GDAPI.gd_node_registerVariantsSelectively(nodeName, variantNameTable)
        local nodeAddr = gd_getDumpedNode( nodeName )
        if isNullOrNil(nodeAddr) then error('node addr not found') end
        if GDDEFS.MONO and checkScriptType(nodeAddr) == GDDEFS.SCRIPT_TYPES["CS"] then error('only GD targets') end
        -- namespace = (namespace and namespace ~= '' and namespace .. '.') or ''

        for _, fieldName in ipairs(variantNameTable) do
          local field = iterateVectorVariantsForNamedField(nodeAddr, fieldName)
          if field then registerSymbol( nodeName .. '.' .. field.Name , field.Offset , true ) end
        end
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
        mainMemrec.Script = "{$lua}\n[ENABLE]\nif syntaxcheck then return end\nlocal config = {\n---- e.g. Godot Engine v4.5.1.stable.custom_build ;;; godot.windows.template_debug.x86_64.exe\n---- If you specify all ENGINE VER values, set useHardcoded to true to let script use hardcoded offsets\n---- If you don't have the CERegEx plugin, the\n\n-- ENGINE VER START\nuseHardcoded =              true, -- set to true if you want the script to use hardcoded offsets to skip defining OFFSETS below, false if you do it yourself\nGDCustomver =               nil, -- (optional) if custom build ver, false otherwise;\nmajorVersion =              nil, -- (optional) major godot ver, e.g. 4\nminorVersion =              nil, -- (optional) minor godot ver, e.g. 5\nGDDebugVer =                nil, -- (optional) if it's template_debug ver, false otherwise\nisMonoTarget =              nil, -- (optional) set to true if it's using mono/C#, false otherwise\n-- ENGINE VER END\n\n-- replace nil with hex offsets according to the instruction\n-- OFFSETS START\noffsetNodeChildren =        nil, -- offset to Node->children, it's a classic array of Nodes: consecutive 8/4 byte ptrs on x64/x32 apps respectively\noffsetNodeStringName =      nil,  -- offset to Node->name, it's a pointer to StringName object which usually has a string at either 0x8 or 0x10 (x64)\noffsetGDScriptInstance =    nil, -- for Node types that have a GDScript, Node->GDScriptInstance, it points to an object with a vTable where the next pointer is the owner Node reference and the next offset being the GDScript\noffsetVariantVector =       nil, -- Node->GDScriptInstance->\noffsetVariantVectorSize =   nil, -- located 0x4 or 0x8 or 0x10 behind 1st elem of a vector\n\noffsetGDScriptName =        nil, -- Node->GDScriptInstance->GDScript->name, it points to a raw string data that starts with res://\noffsetFuncMap =             nil, -- if you need funcs: GDScript->member_functions - in 4.x - (4 consecutive pointers, capacity and size) use offset to the Head (second to the last ptr) || in 3.x (pointer to the RBT root and the sentinel after it) use offset to the root\noffsetGDFunctionCode =      nil, -- if you need funcs: GDScript->member_functions['abc']->code - it's an int array inside a function storing implemented GDFunction byetcode, very easy to spot\noffsetGDFunctionConst =     nil, -- if you need funcs: GDScript->member_functions['abc']->constants - it's a Vector<Variant> with script constants, relative to code\noffsetGDFunctionGlobals =   nil, -- if you need funcs: GDScript->member_functions['abc']->global_names - Vector of StringNames, relative to code and constants\noffsetConstMap =            nil, -- GDScript->constants - layout same as w/ offsetGDFunctionCode\noffsetVariantMap =          nil, -- GDScript->member_indices - layout same as w/ offsetGDFunctionCode\n\n--vtGetClassNameIndex =       nil, -- 0-based vtable index to the virtual method that returns class name for _this_ object\n-- OFFSETS END\n}\ngd_initDumper(config)\n[DISABLE]\n"
        -- useAssumption =             nil, -- set to true if you want the script to try to guess the offsets; unreliable
        local dumpMemrec = addrList.createMemoryRecord()
        dumpMemrec.Description = 'TEMPLATE: dump node'
        dumpMemrec.Type = vtAutoAssembler
        dumpMemrec.Async = true
        dumpMemrec.Options = '[moHideChildren,moDeactivateChildrenAsWell]'
        dumpMemrec.Script = '{$lua}\nif syntaxcheck then return end\n[ENABLE]\ngd_dumpNodeToAddr(memrec, gd_getDumpedNode( "Globals" ), false) -- change Globals to other node names\n[DISABLE]'
        dumpMemrec.appendToEntry(mainMemrec)

        local dumpMemrec = addrList.createMemoryRecord()
        dumpMemrec.Description = 'Dump Nodes (no children)'
        dumpMemrec.Type = vtAutoAssembler
        dumpMemrec.Options = '[moHideChildren,moDeactivateChildrenAsWell]'
        dumpMemrec.Async = true
        dumpMemrec.Script = '{$lua}\nif syntaxcheck then return end\n[ENABLE]\ngd_dumpAllNodesToAddr()\n[DISABLE]'
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
        local dumperPath = cedir .. [[autorun\GDumper.lua]]
        local offsetPath = cedir .. [[autorun\GDDumperModules\GDHardOffsets.lua]]
        local sigPath = cedir .. [[autorun\GDDumperModules\GDSignatures.lua]]
        local disasmPath = cedir .. [[autorun\GDDumperModules\GDFunctionStructDisassembler.lua]]
        local nodemonitor = cedir .. [[autorun\GDDumperModules\GDNodeMonitor.lua]]
        local types = cedir .. [[autorun\GDDumperModules\GDTypes.lua]]
        createTableFile("GDumper", dumperPath)
        createTableFile("GDOff", offsetPath)
        createTableFile("GDSig", sigPath)
        createTableFile("GDFDasm", disasmPath)
        createTableFile("GDT", types)
        createTableFile("GDNM", nodemonitor)
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
        local ok, result = pcall(loadScriptFromTable, "GDumper")
        if ok == false then error('Dumper load failed: '.. result or 'unknown error') end
        if sender then sender.Checked = true end
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
      function GDAPI.gd_buildGUI()
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
          addCustomMenuButtonTo(gdMenuItem, 'Root Struct', createVPStructForm)
          addCustomMenuButtonTo(gdMenuItem, 'GD Dissect', GDDissectorSwitch)
          addCustomMenuButtonTo(gdMenuItem, 'Add Template', addGDMemrecToTable)
          addCustomMenuButtonTo(gdMenuItem, 'Debug Mode', GDDebugSwitch)
          local menuItem = addCustomMenuButtonTo(gdMenuItem, 'Append Script', appendDumperScript)
          -- menuItem.OnEnter = function(sender) if sender.Enabled==false and findTableFile("GDumper")==nil then sender.Enabled=true end end
          
          -- addCustomMenuButtonTo(gdMenuItem, 'Append as memrec', appendDumperScriptAsMemrec)
          -- addCustomMenuButtonTo(gdMenuItem, 'Load Script', loadDumperScript)
          -- addCustomMenuButtonTo(gdMenuItem, 'Stuct name Lookup', GDStructNameLookupSwitch)
          -- addCustomMenuButtonTo( gdMenuItem, 'Addr Lookup', GDAddressLookupSwitch )
          addCustomMenuButtonTo(gdMenuItem, 'Use stored offsets', GDStoredOffsetsSwitch)
          addCustomMenuButtonTo(gdMenuItem, 'API doc' , function() shellExecute("https://github.com/palepine/GDDumper/blob/main/docs/GDUMPER_API.MD") end)
          addCustomMenuButtonTo(gdMenuItem, 'Support development', function() shellExecute("https://ko-fi.com/vesperpallens") end)
          -- addCustomMenuButtonTo( gdMenuItem, 'Reload from file', loadDumperScriptFromFile )
        end
      end

  -- ///---///--///---///--///---///--///--///---///--///---///--///---///--/// TYPES/SIZE

    local function isValidVariantType(typeId)
      local maxType = GDDEFS.VARIANT_TYPE_PROFILE.enums.VARIANT_MAX
      return type(typeId) == "number" and typeId >= 0 and typeId < maxType
    end

    local function validateVariantStride(vectorPtr, vectorSize, sizeOfVariant)
      if vectorSize <= 0 then return false end
      for index = 0, vectorSize - 1 do
        local typeId = readInteger(vectorPtr + index * sizeOfVariant)
        if not isValidVariantType(typeId) then return false end
      end

      return true
    end

    --- takes in a vector + its size. Returns an inferred variant size and successBool
    ---@param vectorPtr number
    ---@param vectorSize number
    local function redefineVariantSizeByVector(vectorPtr, vectorSize)
      if GDDEFS.SIZEOF_VARIANT then return GDDEFS.SIZEOF_VARIANT, true end

      local stdVectorSize = GDDEFS.USES_DOUBLE_REALT and 0x28 or 0x18

      if isNullOrNil(vectorPtr) or isNullOrNil(vectorSize) then return stdVectorSize, false; end

      -- whatever, let's try again later
      if vectorSize < 2 then return stdVectorSize, true end

      local matches = {}

      for _, sizeOfVariant in ipairs( { 0x18, 0x28 } ) do -- 0x18, 0x28, 0x30, 0x40
        -- we do runs with assumtions until one vector passes
        if validateVariantStride( vectorPtr, vectorSize, sizeOfVariant ) then
          matches[ #matches + 1 ] = sizeOfVariant -- { sizeOfVariant, count++ }
        end
      end

      if #matches == 1 then
        GDDEFS.SIZEOF_VARIANT = matches[1]
        return matches[1], true
      end

      sendDebugMessage("============SIZE OF VECTOR ISNT INFERRED============")
      return stdVectorSize, false

      -- // Variant takes 24 bytes when real_t is float, and 40 bytes if double.
      -- // It only allocates extra memory for AABB/Transform2D (24, 48 if double),
      -- // Basis/Transform3D (48, 96 if double), Projection (64, 128 if double),
      -- // and PackedArray/Array/Dictionary (platform-dependent).
    end

    --- returns an adjusted offset to a variant value
    ---@param gdType number
    local function getVariantValueOffset(gdType)
      if getGDTypeName(gdType) == 'OBJECT' then return 0x10 end -- objects have 0x10 offset for value, their ID before
      return 0x8
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
      if enum == nil then error("getGDTypeEnumFromName: invalid typename " .. typeName) end
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

      if GDDEFS.MAJOR_VER >= 4 then
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
      local method = getObjectVMethodByIndex( objAddr, GDDEFS.GET_TYPE_INDX )
      if isNullOrNil(method) then return nil end
      return executeMethod(0, nil, method, objAddr)
    end

    function GDAPI.getGDObjectName(objAddr)
      -- up until 4.6, the method was StringName* Object::_get_class_namev()
      -- in 4.6 it's GDType& Object::_get_typev(); GDType being a struct whose 2nd member is StringName with the object class name
      local metaAddr = getObjectMeta(objAddr)
      local className = ''

      if isNullOrNil(metaAddr) then return 'null' end

      if GDDEFS.MAJOR_VER <= 3 or (GDDEFS.MAJOR_VER >= 4 and GDDEFS.MINOR_VER < 6) then
        className = getStringNameStr(readPointer(metaAddr) or 0) or 'nstrn'

      elseif GDDEFS.MAJOR_VER == 4 and GDDEFS.MINOR_VER == 6 then
          -- const GDType *super_type;
          -- StringName name;
        metaAddr = getObjectMeta(objAddr)
        local stringNameAddr = readPointer(metaAddr + GDDEFS.PTRSIZE)
        className = getStringNameStr(stringNameAddr or 0) or 'nstrn'
      elseif GDDEFS.MAJOR_VER >= 4 and GDDEFS.MINOR_VER > 6 then
        -- const GDType *super_type;
        -- mutable InitState init_state = InitState::UNINITIALIZED;
        -- StringName name;
        local stringNameAddr = readPointer( metaAddr + GDDEFS.PTRSIZE * 2 ) -- TODO: use alignment
        className = getStringNameStr(stringNameAddr or 0) or 'nstrn'
      end

      return className
    end

  -- ///---///--///---///--///---///--///--///---///--///---///--///---///--/// HELPERS

    local function getNodeChildrenInfo(nodeAddr)
      if isNullOrNil(nodeAddr) then
        return nil, nil;
      end

      local childrenAddr = readPointer((nodeAddr or 0) + GDDEFS.CHILDREN) -- viewport has an array of all main ingame Nodes, those Nodes can contain further nodes
      if isNullOrNil(childrenAddr) then
        return nil, nil;
      end

      local childrenSize;
      if GDDEFS.MAJOR_VER >= 4 then
        childrenSize = readInteger( (nodeAddr or 0) + GDDEFS.CHILDREN - GDDEFS.CHILDREN_SIZE) -- size is 8 bytes behind
      else
        childrenSize = readInteger(childrenAddr - GDDEFS.CHILDREN_SIZE)
      end

      return childrenAddr, childrenSize
    end

    local function getNextMapElement(mapElement)
      if GDDEFS.MAJOR_VER >= 4 then
        return readPointer(mapElement) -- next is at 0x0
      else
        return readPointer(mapElement + GDDEFS.MAP_NEXTELEM)
      end
    end

    local function getDictElemPairNext(mapElement)
      if GDDEFS.MAJOR_VER >= 4 then
        return readPointer(mapElement) -- at 0x0
      else
        return readPointer( (mapElement or 0) + GDDEFS.DICTELEM_PAIR_NEXT)
      end
    end

    local function getDictionarySizeFromVariantPtr(variantPtr)
      return readInteger( (readPointer(variantPtr) or 0) + GDDEFS.DICT_SIZE)
    end

    local function isArrayEmptyFromVariantPtr(variantPtr)
      return readPointer( (readPointer(variantPtr) or 0) + GDDEFS.ARRAY_TOVECTOR) == 0
    end

    local function resolveScriptVariantType(mapElement, runtimeVariantType) -- TODO: remove?
      if GDDEFS.MAJOR_VER < 4 then return runtimeVariantType end
      -- local scriptType = readInteger(mapElement + GDDEFS.VAR_NAMEINDEX_VARTYPE)
      -- if scriptType > GDDEFS.MAXTYPE then scriptType = readInteger(mapElement + GDDEFS.VAR_NAMEINDEX_VARTYPE - 0x8) end
      -- if scriptType == runtimeVariantType then return scriptType end
      -- if (scriptType > runtimeVariantType) and (scriptType > 0 and scriptType < GDDEFS.MAXTYPE) then return scriptType end
      return runtimeVariantType
    end

    local function getVariantNameFromMapElement(mapElement)
      if GDDEFS.MAJOR_VER >= 4 then
        return getStringNameStr(readPointer(mapElement + GDDEFS.CONSTELEM_KEYVAL))
      end

      return getStringNameStr(readPointer(mapElement + GDDEFS.MAP_KEY))
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
          if GDDEFS.MAJOR_VER <= 3 then
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
      if isNullOrNil(mapElement) then return nil end

      if GDDEFS.MAJOR_VER >= 4 then
        return getGDFunctionName(mapElement)
      end
      return getStringNameStr(readPointer(mapElement + GDDEFS.MAP_KEY))
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
      if GDDEFS.MAJOR_VER >= 4 then
        local constType = readInteger(mapElement + GDDEFS.CONSTELEM_VALUE_VARIANT)
        local offsetToValue = getVariantValueOffset(constType)
        return getAddress(mapElement + GDDEFS.CONSTELEM_VALUE_VARIANT + offsetToValue), getCETypeFromGD(constType)
      else
        local constType = readInteger(mapElement + GDDEFS.CONSTELEM_VALUE_VARIANT)
        local offsetToValue = getVariantValueOffset(constType)
        return getAddress(mapElement + GDDEFS.CONSTELEM_VALUE_VARIANT + offsetToValue), getCETypeFromGD(constType)
      end
    end

    local function getFunctionMapLookupResult(mapElement)
      return readPointer(mapElement + GDDEFS.FUNC_MAPVAL)
    end

    local function createNextConstContainer(currentContainer, index)
      if GDDEFS.MAJOR_VER >= 4 then
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
      if GDDEFS.MAJOR_VER >= 4 then
        nextSymbol = wrapBrackets( currentSymbol .. "+0" )
      else --if GDDEFS.MAJOR_VER <= 3 then
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

      -- local variantArrSize, ok = redefineVariantSizeByVector(arrVectorAddr, arrVectorSize)
      -- if not ok then return nil end

      local variantArrSize = GDDEFS.SIZEOF_VARIANT
      
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

      if GDDEFS.MAJOR_VER <= 3 then
        local keyPtr = readPointer(mapElement) -- key is a ptr
        keyType = readInteger(keyPtr + GDDEFS.DICTELEM_KEY_VARIANT) -- variant's 0x0 is type
        local offsetToValue = getVariantValueOffset(keyType)
        keyValueAddr = getAddress(keyPtr + GDDEFS.DICTELEM_KEY_VARIANT + offsetToValue)
      else
        keyType = readInteger(mapElement + GDDEFS.DICTELEM_KEY_VARIANT)
        local offsetToValue = getVariantValueOffset(keyType)
        keyValueAddr = getAddress(mapElement + GDDEFS.DICTELEM_KEY_VARIANT + offsetToValue)
      end

      local keyTypeName = getGDTypeName(keyType)
      local keyName = "UNKNOWN"

      if keyTypeName == 'STRING' then -- TODO: handler + stringification implementation?
        -- immediate String
        keyName = readUTFString(readPointer(keyValueAddr)) or "_couldnt_read"
      elseif keyTypeName == 'STRING_NAME' then
        keyName = getStringNameStr(readPointer(keyValueAddr)) or "_couldnt_read"
      elseif keyTypeName == 'FLOAT' then
        keyName = tostring(readDouble(keyValueAddr) or "_couldnt_read") -- in godot 3.x real is 4 byte float or not?
      elseif keyTypeName == 'NODE_PATH' or keyTypeName == 'CALLABLE' then
        keyName = tostring(readPointer(keyValueAddr) or "_couldnt_read")
      elseif keyTypeName == 'INT' or keyTypeName == 'RID' then
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
      if GDDEFS.MAJOR_VER <= 3 then
        dictRoot = readPointer(dictAddr + GDDEFS.DICT_LIST)
        if isNullOrNil(dictRoot) then
          sendDebugMessage('dictRoot isnt valid')
          return nil
        end
      end

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
      if GDDEFS.MAJOR_VER >= 4 then
        return createChildStructElem(currentContainer, 'Next', 0x0, vtPointer, 'DictNext')
      end

      return createChildStructElem(currentContainer, 'Next', GDDEFS.DICTELEM_PAIR_NEXT, vtPointer, 'DictNext')
    end

    local function createNextSymbol(currentSymbol)
      if GDDEFS.MAJOR_VER >= 4 then
        return wrapBrackets( currentSymbol .. '+' .. numtohexstr(0x0) )
      else--if GDDEFS.MAJOR_VER <= 3 then
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
      if GDDEFS.MAJOR_VER >= 4 then
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
      local variantIndex = readInteger(mapElement + GDDEFS.VARIANTMAP_INDEX);
      local variantPtr, runtimeType, offsetToValue = getVariantByIndex(variantVector, variantIndex, variantSize)

      local name = getVariantNameFromMapElement(mapElement);
      -- local finalType = resolveScriptVariantType(mapElement, runtimeType);
      local finalType = runtimeType

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

      if bGDDebug then sendDebugMessage("name: " .. entry.name .. "\tIndex: " .. entry.index .. " type: " .. entry.typeName .. "\tPtr: " .. numtohexstr(entry.variantPtr) .. "\t Offset: " .. numtohexstr(entry.offsetToValue)) end

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

      if bGDDebug then sendDebugMessage("name: " .. entry.name .. "\tIndex: " .. entry.index .. "\ttype: " .. entry.typeName .. "\tPtr: " .. numtohexstr(entry.variantPtr) .. "\t Offset: " .. numtohexstr(entry.offsetToValue)) end

      return entry
    end

    local function readNodeConstEntry(mapElement)
      local constName = getNodeConstName(mapElement)
      local constType = readInteger(mapElement + GDDEFS.CONSTELEM_VALUE_VARIANT)
      local offsetToValue = GDDEFS.CONSTELEM_VALUE_VARIANT + getVariantValueOffset(constType)
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

      if bGDDebug then sendDebugMessage("name: " .. entry.name .. "\tIndex: " .. entry.index .. "\ttype: " .. entry.typeName .. "\tPtr: " .. numtohexstr(entry.variantPtr) .. "\t Offset: " .. numtohexstr(entry.offsetToValue)) end

      return entry
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

      if bGDDebug then sendDebugMessage("name: " .. entry.name .. "\tIndex: " .. entry.index .. "\ttype: " .. entry.typeName .. "\tPtr: " .. numtohexstr(entry.variantPtr) .. "\t Offset: " .. numtohexstr(entry.offsetToValue)) end

      return entry
    end

    local function readDictionaryContainerEntry(mapElement)

      local keyType, keyValueAddr, keyName = decodeDictionaryKeyName(mapElement)
      local valueType = readInteger(mapElement + GDDEFS.DICTELEM_VALUE_VARIANT)
      local offsetToValue = GDDEFS.DICTELEM_VALUE_VARIANT + getVariantValueOffset(valueType)
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

      if bGDDebug then sendDebugMessage("name: " .. entry.name .. "\tIndex: " .. entry.index .. "\ttype: " .. entry.typeName .. "\tPtr: " .. numtohexstr(entry.variantPtr) .. "\t Offset: " .. numtohexstr(entry.offsetToValue)) end

      return entry
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

        local function emitStringNameStruct(parent, label, offset, stringFieldLabel, isUTF, innerOffset)
          local outer = addStructureElem(parent, label, offset, vtPointer)
          outer.ChildStruct = createStructure("StringName")
          local stringType = vtUnicodeString and isUTF or vtString

          local inner = addStructureElem(outer, label, innerOffset, vtPointer)
          inner.ChildStruct = createStructure("stringy")
          local stringElem = addStructureElem(outer.ChildStruct and inner or inner, label .. " string", 0x0, stringType)

          if stringType == vtString then
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
          if not GDDEFS.bDisasmFunc then -- let's 
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
          if GDDEFS.MAJOR_VER >= 4 then
            return readPointer(mapElement)
          end
          return readPointer(mapElement + GDDEFS.MAP_NEXTELEM)
        end

        local function createNextFunctionContainer(currentContainer, index)
          if GDDEFS.MAJOR_VER >= 4 then
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
        local objectTypeName = gd_getObjectName(readPointer(realPtr))
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

        local stringNameAddr = readPointer(entry.variantPtr)
        local isUTF, offsetToString = checkStringNameType(stringNameAddr)
        local stringType = vtUnicodeString and isUTF or vtString

        if emitter == GDEmitters.StructEmitter then
          local outer = emitter.branch(contextTable, parent, "<STRING_NAME> " .. entry.name, rootOffset(entry, emitter), vtPointer, "StringName")
          local inner = emitter.branch(contextTable, outer, "StringName: " .. entry.name, offsetToString, vtPointer, "stringy")
          emitter.leaf(contextTable, inner, "String: " .. entry.name, 0x0, stringType)
        else
          if isNullOrNil(stringNameAddr) then
            emitter.leaf(contextTable, parent, "<STRING_NAME> " .. entry.name, rootOffset(entry, emitter), vtPointer)
            return
          end
          
          local stringContext =
          {
            nodeAddr = contextTable.nodeAddr,
            nodeName = contextTable.nodeName,
            baseAddress = stringNameAddr + offsetToString,
            symbol = contextTable.symbol and contextTable.symbol or ''
          }
          emitter.leaf(stringContext, parent, "<STRING_NAME> " .. entry.name, 0x0, stringType)
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
      -- the best I can do as of now for TOOLS_ENABLED
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
        if isNotNullOrNil(fallbackGDSemVerTable) and next(fallbackGDSemVerTable) then
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
                synchronize(gd_buildGUI())

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
      if isNullOrNil(GDDEFS) then GDDEFS = {} end

      local ver = getGodotVersionFromMagic()
      local magicFail = true
      if isNotNullOrNil(ver) and next(ver) then
        GDDEFS.VERSION_STRING = tostring(ver.major) .. '.' .. tostring(ver.minor)
        GDDEFS.MAJOR_VER = ver.major
        GDDEFS.MINOR_VER = ver.minor
        GDDEFS.PATCH_VER = ver.patch
        GDDEFS.FULL_GDVERSION_STRING = "Godot Engine ".. ver.major .. '.' .. ver.minor .. '.' .. ver.patch
        magicFail = false
      end

      if lregexScan and type(lregexScan) == "function" then
        GDDEFS.FULL_GDVERSION_STRING = getGodotVersionString()
      end

      if magicFail then -- <3 versions w/0 pck and encrypted packages
        sendDebugMessage("Failed to find Godot magic")
        major, minor, patch = (GDDEFS.FULL_GDVERSION_STRING or ''):match("v(%d+)%.(%d+)%.?(%d*)") -- m.m.p or m.m
        if isNullOrNil(major) or isNullOrNil(minor) then major, minor = (GDDEFS.FULL_GDVERSION_STRING):match("Godot Engine v?(%d+)%.(%d+)") end
        if isNullOrNil(major) or isNullOrNil(minor) then error('failed to find Godot Version') end
      end

      local exportTableStr = getExportTableName() or ""
      GDDEFS.DEBUGVER = exportTableStr:match("debug") and true or false
      GDDEFS.MONO = (exportTableStr):match("mono") and true or false
      GDDEFS.IS_STABLE_VER = (exportTableStr):match("stable") and true or false
      GDDEFS.CUSTOMVER = getIsCustomVer()
      GDDEFS.USES_DOUBLE_REALT = exportTableStr:match("%.double%.") ~= nil

      -- GDDEFS.CUSTOMVER = (GDDEFS.FULL_GDVERSION_STRING):match("custom") and true or false

      -- elseif (exportTableStr):match( "release" ) then -- or "opt" or "dev6"

      if isNotNullOrNil(major) and isNotNullOrNil(minor) then
        GDDEFS.MAJOR_VER = tonumber(major)
        GDDEFS.MINOR_VER = tonumber(minor)
        GDDEFS.PATCH_VER = tonumber(patch)
        GDDEFS.VERSION_STRING = major .. '.' .. minor
      end

      MainForm.setCaption( (GDDEFS.FULL_GDVERSION_STRING or "GD VERSION UNKNOWN") .. (GDDEFS.CUSTOMVER and " C" or '') .. (GDDEFS.DEBUGVER and " D" or '') .. (GDDEFS.MONO and " M" or '') )
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


      
      debugPrefix = 1;
      if targetIs64Bit() then
        GDDEFS.PTRSIZE = 0x8
        GDDEFS._x64 = true
      else
        GDDEFS.PTRSIZE = 0x4
        GDDEFS._x64 = false
      end -- for auto offsetdef and ptr arithmetics

      local scriptErrors = { [22] = "in use error", [43] = "parse error", [2] = "handler script error", [36] = "compilation error", [1] = "handler warning", }
      local callErrors = { [1] = "invalid method", [2] = "invalid argument", [3] = "too many args", [4] = "too few args", [5] = "instance is null", [6] = "method not const", }
      GDDEFS.SCRIPT_ERRORS = scriptErrors
      GDDEFS.CALL_ERRORS = callErrors
      GDDEFS.STRING = 0x4+0x4+GDDEFS.PTRSIZE
    end

    local function initGDVersion(config)
      if config == nil then config = {} end

      if isNotNullOrNil(config.majorVersion) and isNotNullOrNil(config.minorVersion) and
          isNotNullOrNil(config.GDCustomver) and isNotNullOrNil(config.GDDebugVer) then
        GDDEFS.VERSION_STRING = tostring(config.majorVersion) .. '.' .. tostring(config.minorVersion)
        GDDEFS.MAJOR_VER = config.majorVersion
        GDDEFS.MINOR_VER = config.minorVersion
        GDDEFS.PATCH_VER = config.releaseVersion
        GDDEFS.DEBUGVER = config.GDDebugVer
        GDDEFS.CUSTOMVER = config.GDCustomver
        GDDEFS.MONO = config.isMonoTarget and config.isMonoTarget or false
        GDDEFS.USES_DOUBLE_REALT = config.usesDoubleRealT
      else
        defineGDVersion()
        if isNotNullOrNil(config.GDCustomver) then GDDEFS.CUSTOMVER = config.GDCustomver end
      end
    end

    --- initializes and assigns offsets
    local function defineGDOffsets(config)
      if config == nil then config = {} end

      -- AUTOMATIC START
      if (bHardOffsets or config.useHardcoded) then
        local offsets = getStoredOffsetsFromVersion(GDDEFS.MAJOR_VER, GDDEFS.MINOR_VER, GDDEFS.PATCH_VER)
        GDDEFS.GET_TYPE_INDX = offsets.GET_TYPE_INDX or GDDEFS.GET_TYPE_INDX
        GDDEFS.CALLP_INDX = offsets.CALLP_INDX or GDDEFS.CALLP_INDX
        GDDEFS.GDSCRIPT_RELOAD_INDX = offsets.GDScriptRealoadIndex or GDDEFS.GDSCRIPT_RELOAD_INDX

        GDDEFS.CHILDREN = offsets.VPChildren
        GDDEFS.OBJ_STRING_NAME = offsets.VPObjStringName
        GDDEFS.GDSCRIPTINSTANCE = offsets.NodeGDScriptInstance
        GDDEFS.GDSCRIPTNAME = offsets.NodeGDScriptName
        GDDEFS.FUNC_MAP = offsets.GDScriptFunctionMap
        GDDEFS.CONST_MAP = offsets.GDScriptConstantMap
        GDDEFS.VARIANTMAP = offsets.GDScriptVariantNameHM
        GDDEFS.VAR_VECTOR = offsets.oVariantVector
        GDDEFS.SIZE_VECTOR = offsets.NodeVariantVectorSizeOffset
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
        GDDEFS.VARIANTMAP = config.offsetVariantMap or 0x0
        GDDEFS.GDSCRIPT_RELOAD_INDX = config.GDScriptRealoadIndex
        GDDEFS.FUNC_CODE = config.offsetGDFunctionCode or 0x0

        if GDDEFS.MAJOR_VER >= 4 then
          GDDEFS.VAR_VECTOR = config.offsetVariantVector or 0x28
          -- GDDEFS.VAR_NAMEINDEX_VARTYPE = config.offsetVariantMapVarType or 0x48
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
        elseif GDDEFS.MAJOR_VER <= 3 then
          GDDEFS.MAJOR_VER = 3
          GDDEFS.VAR_VECTOR = config.offsetVariantVector or 0x20
          GDDEFS.SIZE_VECTOR = config.offsetVariantVectorSize or 0x4
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
      GDDEFS.SIZEOF_VARIANT = GDDEFS.USES_DOUBLE_REALT and 0x28 or 0x18

      if GDDEFS.MAJOR_VER >= 4 then
        GDDEFS.GDSCRIPT_REF = alignOffset( alignOffset(GDDEFS.PTRSIZE, 0x8)+0x8 , GDDEFS.PTRSIZE ) + GDDEFS.PTRSIZE -- vtable*, uint64_t id, owner*, gdscript*
        GDDEFS.FUNC_MAPVAL = GDDEFS.PTRSIZE*3 -- next*, prev*, key*, value*
        GDDEFS.CHILDREN_SIZE = 0x4+0x4 -- int size int capacity
        GDDEFS.MAP_SIZE = GDDEFS.PTRSIZE*2 + 0x4 -- head*, tail*, int capacity, int size

        -- ARRAYS
          GDDEFS.ARRAY_TOVECTOR = alignOffset( alignOffset(4, GDDEFS.PTRSIZE) , GDDEFS.PTRSIZE ) + GDDEFS.PTRSIZE -- int refcount, byte VectorWriteProxy<T> write, vectorCoW*
          GDDEFS.P_ARRAY_TOARR = GDDEFS.PTRSIZE + alignOffset(4, GDDEFS.PTRSIZE) + GDDEFS.PTRSIZE -- 0x18

        -- DICTIONARY
          -- int refcount, ptr*, (ptr*), elements**, hashes*, head*, tail*, capacity, size
          GDDEFS.DICT_HEAD = GDDEFS.DICT_HEAD or alignOffset(4, GDDEFS.PTRSIZE) + GDDEFS.PTRSIZE*2 + GDDEFS.PTRSIZE*2 -- 0x28
          GDDEFS.DICT_TAIL = GDDEFS.DICT_TAIL or alignOffset(4, GDDEFS.PTRSIZE) + GDDEFS.PTRSIZE*2 + GDDEFS.PTRSIZE*3 -- 0x30
          GDDEFS.DICT_SIZE = GDDEFS.DICT_SIZE or alignOffset(4, GDDEFS.PTRSIZE) + GDDEFS.PTRSIZE*2 + GDDEFS.PTRSIZE*4 + 0x4 -- 0x3C
          if GDDEFS.MINOR_VER >= 6 then
            GDDEFS.DICT_HEAD = GDDEFS.DICT_HEAD - GDDEFS.PTRSIZE -- 0x20, GDDEFS.PTRSIZE*1 after refcount instead of 2
            GDDEFS.DICT_TAIL = GDDEFS.DICT_HEAD - GDDEFS.PTRSIZE -- 0x28
            GDDEFS.DICT_SIZE = GDDEFS.DICT_HEAD - GDDEFS.PTRSIZE -- 0x34
          end

          -- next*, prev*, key_variant, value_variant
          GDDEFS.DICTELEM_KEY_VARIANT = GDDEFS.PTRSIZE*2 -- 0x10, seems aligned well
          GDDEFS.DICTELEM_VALUE_VARIANT = GDDEFS.DICTELEM_KEY_VARIANT + GDDEFS.SIZEOF_VARIANT

        -- CONSTANTS
          -- next*, prev*, key_string_name*, value_variant
          GDDEFS.CONSTELEM_KEYVAL = GDDEFS.PTRSIZE*2
          GDDEFS.CONSTELEM_VALUE_VARIANT = GDDEFS.PTRSIZE*2 + alignOffset(GDDEFS.PTRSIZE, 8) -- 0x18 / 0x10
        -- VARIANT MAP
          GDDEFS.VARIANTELEM_KEY_VAL = GDDEFS.PTRSIZE*2
          GDDEFS.VARIANTMAP_INDEX = GDDEFS.PTRSIZE*3 -- 0x18

        GDDEFS.CLR_PTR = 0x20

      elseif GDDEFS.MAJOR_VER <= 3 then

        GDDEFS.GDSCRIPT_REF = GDDEFS.PTRSIZE*2 --0x10
        if GDDEFS.MONO then GDDEFS.GDSCRIPT_REF = GDDEFS.GDSCRIPT_REF + 0x8 end

        GDDEFS.CHILDREN_SIZE = 0x4

        -- MAP (RBT)
          -- map itself: root*, sentinel*, int size
          GDDEFS.MAP_SIZE = GDDEFS.PTRSIZE*2 -- 0x10
          
          -- map Node: int color, right*, left*, parent*, _next*, _prev*, Key(*), Value(*)
          GDDEFS.MAP_RELEM = alignOffset(0x4, GDDEFS.PTRSIZE) + GDDEFS.PTRSIZE*0
          GDDEFS.MAP_LELEM = alignOffset(0x4, GDDEFS.PTRSIZE) + GDDEFS.PTRSIZE*1 -- 0x10
          GDDEFS.MAP_PARELEM = alignOffset(0x4, GDDEFS.PTRSIZE) + GDDEFS.PTRSIZE*2
          GDDEFS.MAP_NEXTELEM = alignOffset(0x4, GDDEFS.PTRSIZE) + GDDEFS.PTRSIZE*3 -- 0x20
          GDDEFS.MAP_PREVELEM = alignOffset(0x4, GDDEFS.PTRSIZE) + GDDEFS.PTRSIZE*4
          GDDEFS.MAP_KEY = alignOffset(0x4, GDDEFS.PTRSIZE) + GDDEFS.PTRSIZE*5 -- 0x30
          GDDEFS.MAP_VAL = alignOffset(0x4, GDDEFS.PTRSIZE) + GDDEFS.PTRSIZE*6
          GDDEFS.FUNC_MAPVAL = GDDEFS.MAP_VAL
        
        -- DICTIONARY
          -- int refCount, ptr_List*, ptr_HashMap*, capacity, size;
          GDDEFS.DICT_LIST = alignOffset(0x4, GDDEFS.PTRSIZE)
          GDDEFS.DICT_HASHMAP = alignOffset(0x4, GDDEFS.PTRSIZE) + GDDEFS.PTRSIZE
          GDDEFS.DICT_SIZE =  GDDEFS.DICT_SIZE or alignOffset(0x4, GDDEFS.PTRSIZE) + GDDEFS.PTRSIZE*2 + 0x4 -- right?
          -- OrderedHashMap aka InternalList list, InternalMap map;
          GDDEFS.DICT_HEAD = GDDEFS.DICT_HEAD or GDDEFS.PTRSIZE*0 -- 0x0
          GDDEFS.DICT_TAIL = GDDEFS.DICT_TAIL or GDDEFS.PTRSIZE*1

          -- typedef List<Pair<const K *, V> > InternalList;
          GDDEFS.DICTELEM_KEY = GDDEFS.PTRSIZE*0
          GDDEFS.DICTELEM_KEY_VARIANT = 0x0
          GDDEFS.DICTELEM_VALUE_VARIANT = 0x8 -- GDDEFS.PTRSIZE*1 apparently 8byte aligned on x32
          GDDEFS.DICTELEM_PAIR_NEXT = GDDEFS.DICTELEM_VALUE_VARIANT + GDDEFS.SIZEOF_VARIANT -- 0x20

        -- ARRAY
          GDDEFS.ARRAY_TOVECTOR = alignOffset( alignOffset(4, GDDEFS.PTRSIZE) , GDDEFS.PTRSIZE ) + GDDEFS.PTRSIZE -- 0x10, same as 4.x
          GDDEFS.P_ARRAY_TOARR = alignOffset(4, GDDEFS.PTRSIZE) -- 0x8

        -- CONSTANTS
          GDDEFS.CONSTELEM_KEYVAL = GDDEFS.MAP_KEY -- 0x30
          GDDEFS.CONSTELEM_VALUE_VARIANT = GDDEFS.MAP_KEY + GDDEFS.PTRSIZE -- 0x38

        -- VARIANT
          GDDEFS.VARIANTMAP_INDEX = alignOffset( 0x4, GDDEFS.PTRSIZE ) + GDDEFS.PTRSIZE * 6

          -- just this for now
          if GDDEFS.MAJOR_VER == 2 then
            GDDEFS.ARRAY_TOVECTOR = 0x8 -- changed
          end

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

      if GDDEFS.MAJOR_VER >= 4 then
        if readInteger(strAddress) == 0 then
          return "??" -- "empt str"
        end
      elseif readSmallInteger(strAddress) == 0 then
        return "??" -- "empt str"
      end

      local charTable = {}
      local buff = 0

      if GDDEFS.MAJOR_VER <= 3 and (strSize and strSize > 0) then
        return readString(strAddress, strSize * 2, true) or "??" -- '???_INVALID_MEM_CAUGHT_WSIZE'

      elseif GDDEFS.MAJOR_VER <= 3 then
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
        return '�'
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
      if isNullOrNil(stringNameAddr) then return 'NaN_strname' end
      -- before 4.5: int refcount, int staticcount, cname*, name*; cnames are static ascii
      -- 4.5=<: int refcount, int staticcount, name*
      local nameAddr = readPointer( stringNameAddr + 0x8 ) -- 4+4
      if isNotNullOrNil(nameAddr) and isValidPointer(nameAddr) then
        if isInsideRDataStatic(nameAddr) then return readString(nameAddr, 150) end -- cstring
        return readUTFString(nameAddr)
      end
      nameAddr = readPointer( stringNameAddr + 0x8 + GDDEFS.PTRSIZE ) -- 4+4+ptr
      if isNullOrNil(nameAddr) or isInvalidPointer(nameAddr) then return '??' end
      return readUTFString(nameAddr)
    end

    --- reads a string from StringName
    ---@param stringNameAddr number
    ---@return bool @ nil on invalid, true on UTF, false on ASCII
    ---@return number @ offset to string
    function checkStringNameType(stringNameAddr)
      if isNullOrNil(stringNameAddr) then
        return nil, 0x8 + GDDEFS.PTRSIZE
      end
      
      local nameAddr = readPointer( stringNameAddr + 0x8 ) -- 4+4
      if isNotNullOrNil(nameAddr) and isValidPointer(nameAddr) then
        if isInsideRDataStatic(nameAddr) then
          return false, 0x8
        end
        return true, 0x8
      end
      nameAddr = readPointer( stringNameAddr + 0x8 + GDDEFS.PTRSIZE ) -- 4+4+ptr
      if isNullOrNil(nameAddr) or isInvalidPointer(nameAddr) then return nil, 0x8 + GDDEFS.PTRSIZE end
      return true, 0x8 + GDDEFS.PTRSIZE
    end


  -- ///---///--///---///--///---///--///--///---///--///---///--///---///--/// ROOT

    local function tryRegSceneTree()
      -- if isNotNullOrNil( readPointer('pSceneTree') ) then return true end

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
        if GDDEFS._x64 then
          resolvedAddr = nextAddr + relativeAddr
        else
          resolvedAddr = relativeAddr -- absolute on 32
        end
        sendDebugMessage("[SceneTree] calling a virtual method if I happen to crash:\tstatic ptr: " .. numtohexstr(resolvedAddr))
        local className = gd_getObjectName(readPointer(resolvedAddr))
        if className == "SceneTree" then
          sendDebugMessage("[SceneTree] via vtable - success!") --  .. numtohexstr(resolvedAddr) .. " sig: " .. aobSignature 
          registerSymbol('pSceneTree', resolvedAddr, false)
          return true
        else
          return false
        end
      end

      for i, sig in ipairs( GDAOB.SceneTree ) do
        if resolveRelAddr(sig.sig, sig.toRel) then
          return true
        end
      end
      sendDebugMessage("[SceneTree] lookup failed, you are on your own")
      return false
    end

    local function setSTtoRootOffset()
      -- if isNotNullOrNil( readPointer('pRoot') ) then return true end

      local sceneTree = readPointer('pSceneTree')
      local ptrsize, steps

      if targetIs64Bit() then
        ptrsize = 0x8
        steps = 0x350 / ptrsize
      else
        ptrsize = 0x4
        steps = 0x250 / ptrsize
      end

      for i = 13, steps do
        local candidateAddr = readPointer(sceneTree + i * ptrsize)
        if isNotNullOrNil(candidateAddr) and isVtable(getVtable(candidateAddr)) then

          for j=13, steps do
            if readPointer(candidateAddr + j*ptrsize) == sceneTree then
              sendDebugMessage('[ROOT] Nested loop hit: '..numtohexstr(i*ptrsize) .. ' VTable validation...')

              local className = gd_getObjectName(candidateAddr)
              if className ~= "Viewport" and className ~= "Window" then
                sendDebugMessage("[ROOT] Wrong hit (vtable double-check)")
                goto continue
              end

              sendDebugMessage('[ROOT] Vtable positive - success!')
              registerSymbol('oSTtoRoot', i*ptrsize, false)
              return true
            end
            ::continue::
          end

        end
      end

      -- isn't elegant either
      for i = 13, steps do
        local candidateAddr = readPointer(sceneTree + i * ptrsize)
        if isNotNullOrNil(candidateAddr) and isVtable(getVtable(candidateAddr)) then
          sendDebugMessage("[ROOT] calling a virtual method if I happen to crash: ofs\t" .. numtohexstr(i * ptrsize) .. "\taddr: " .. numtohexstr(candidateAddr))
          local className = gd_getObjectName(candidateAddr)
          if className == "Viewport" or className == "Window" then
            sendDebugMessage("[ROOT] via vtable - success!")
            registerSymbol('oSTtoRoot', i * ptrsize, false)
            return true
          end
        end
      end

      -- the approach based on signatures needs more complexity to be consistent
      local function setVPRVA(aobSignature)
        local addr = AOBScanModuleUnique(process, aobSignature, '+X-W-C')
        if addr == 0 or addr == nil then
          return false
        end
        local relativeAddr = readInteger(addr + 3)
        sendDebugMessage("[ROOT] via sigs - success!")
        registerSymbol('oSTtoRoot', relativeAddr, false)
        return true
      end
      
      for i, sig in ipairs( GDAOB.Root ) do
        if setVPRVA(sig) then
          sendDebugMessage('hit at: ' .. tostring(i) .. "\t" .. sig .. "\t value: " .. numtohexstr(getAddress('oSTtoRoot')))
          return true
        end
      end
      sendDebugMessage("[ROOT] lookup failed, you are on your own")
      return false
    end

    --- returns a valid Viewport pointer
    --- @return number
    function getViewport()
      local viewport = readPointer("pRoot")
      if isNullOrNil(viewport) then
        print("Viewport pointer is invalid; something's wrong");
        error('viewport pointer is invalid, couldn\'t read')
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

  -- ///---///--///---///--///---///--///--///---///--///---///--///---///--/// Object


    --- returns a node dictionary
    local function getMainNodeDict()
      local childrenAddr, childrenSize = getVPChildren()
      local nodeDict = {}

      if isNullOrNil(childrenAddr) then return end

      for i = 0, ( (childrenSize or 0) - 1) do

        local nodePtr = readPointer( (childrenAddr or 0) + i * GDDEFS.PTRSIZE)
        if isNullOrNil(nodePtr) then error('NO MAIN NODES') end

        local nodeNameStr = gd_getNodeName(nodePtr)
        local gdscriptName = gd_getNodeNameFromScript(nodePtr)
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
      if isNullOrNil(childrenAddr) or isNullOrNil(childrenSize) then error('VP Children not valid') end

      local nodeTable = {}

      for i = 0, (childrenSize - 1) do
        local nodeAddr = readPointer(childrenAddr + i * GDDEFS.PTRSIZE)
        if isNullOrNil(nodeAddr) then
          error('NO MAIN NODES')
        end
        local nodeNameStr = gd_getNodeNameFromScript(nodeAddr)
        if nodeNameStr == 'N??' then nodeNameStr = gd_getNodeName(nodeAddr) end
        registerSymbol(nodeNameStr, nodeAddr, true)
        table.insert(nodeTable, nodeAddr)
      end
      return nodeTable
    end

    --- gets a Node's GDScriptInstance addr
    ---@param nodeAddr number
    local function getNodeGDScriptInstance(nodeAddr)
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
      if isNullOrNil(nodeAddr) then return nil end

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
    function GDAPI.gd_getNodeName(nodeAddr)
      if isNullOrNil(nodeAddr) then return 'N??' end

      local nodeNamePtr = readPointer(nodeAddr + GDDEFS.OBJ_STRING_NAME)
      if isNullOrNil(nodeNamePtr) or isInvalidPointer(nodeNamePtr) then
        -- sendDebugMessage('nodeName invalid or not a pointer (?)')
        return 'N??'
      end

      return getStringNameStr(nodeNamePtr)
    end

    function GDAPI.gd_getNodeNameFromScript(nodeAddr, bWithAbsPath)
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

      if bWithAbsPath then
        local parsedPath = GDScriptName:gsub("^res://", ""):gsub("%.[^.]+$", ""):gsub("/", ".") -- catch only res://(.*).ext with dots instead of /
        return scriptMatch, parsedPath
      end

      return scriptMatch
    end

    --- Used to validate an object as a Node with GDScript, returns true if valid
    ---@param nodeAddr number
    ---@return boolean @ if GD/CSScript attached
    ---@return number @ script type enum
    function checkForGDScript(nodeAddr)

      if isNullOrNil(nodeAddr) then return false end

      local scriptInstance = readPointer(nodeAddr + GDDEFS.GDSCRIPTINSTANCE)
      if isNullOrNil(scriptInstance) then return false end

      local gdscript = readPointer(scriptInstance + GDDEFS.GDSCRIPT_REF)
      if isNullOrNil(gdscript) or not isVtable( getVtable(gdscript) ) then return false end

      local gdScriptName = readPointer(gdscript + GDDEFS.GDSCRIPTNAME)
      if isNullOrNil(gdScriptName) then sendDebugMessage(numtohexstr(nodeAddr) .. ' script name absent') return false end
      
      -- more expensive, but stronger assumption
      if ( readUTFString(gdScriptName) ):sub(1,4) == 'res:' then return true else sendDebugMessage(numtohexstr(nodeAddr) .. ' res:// not matched') return false end

      return true
    end

    function checkScriptType(nodeAddr)
      -- if GDDEFS.MONO == false then return 0 end; -- has to be checked already

      if isNullOrNil(nodeAddr) --[[or not isVtable( getVtable(nodeAddr) )]] then
        -- sendDebugMessage('nodeAddr/vtable invalid'.." address "..numtohexstr(nodeAddr))
        return 0
      end

      local scriptInstance = readPointer(nodeAddr + GDDEFS.GDSCRIPTINSTANCE)
      if isNullOrNil(scriptInstance) --[[or not isVtable( getVtable(scriptInstance) )]] then
        -- sendDebugMessage('ScriptInstance/vtable is 0/nil'.." address "..numtohexstr(nodeAddr))
        return 0
      end

      local gdscript = readPointer(scriptInstance + GDDEFS.GDSCRIPT_REF)
      if isNullOrNil(gdscript) or not isVtable( getVtable(gdscript) ) then
        -- sendDebugMessage('GDScript/vtable is 0/nil'.." address "..numtohexstr(nodeAddr))
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
      if isNullOrNil(objAddr) then return false end -- if object itself is valid
      local objectChildren, childrenSize = getNodeChildrenInfo(objAddr) -- check children & if it's a valid pointer
      if isNullOrNil(childrenSize) then return false end -- if no children, we don't need it
      local childAddr = readPointer(objectChildren)
      if isNullOrNil(childAddr) or not isVtable( getVtable(childAddr) ) then return false end  -- check the 0th object for vtable
      return true
    end

    --- builds a structure layout for a node's children array
    ---@param childrenArrStruct userdata
    ---@param nodeAddr number
    function iterateNodeChildrenToStruct(childrenArrStructElem, baseAddress)

      local childrenAddr, childrenSize = getNodeChildrenInfo(baseAddress)

      if isNullOrNil(childrenSize) then return; end

      for i = 0, (childrenSize - 1) do
        local nodeAddr = readPointer(childrenAddr + (i * GDDEFS.PTRSIZE))
        local nodeName = gd_getNodeName(nodeAddr)
        if nodeName == nil or nodeName == 'N??' then
          nodeName = gd_getNodeNameFromScript(nodeAddr)
        end
        local objectTypeName = gd_getObjectName(nodeAddr)
        objectTypeName = '<' .. objectTypeName .. '>'

        -- sendDebugMessage("Checking GDScript for "..nodeName)

        if checkForGDScript(nodeAddr) then
          addLayoutStructElem(childrenArrStructElem, objectTypeName .. ' cNode: ' .. nodeName, 0x6C3157, (i * GDDEFS.PTRSIZE), vtPointer)
        else
          addStructureElem(childrenArrStructElem, objectTypeName .. ' cObj: ' .. nodeName, (i * GDDEFS.PTRSIZE), vtPointer)
        end
      end
    end

    --- go over child nodes in the main nodes
    ---@param nodeAddr number
    ---@param parent userdata
    function iterateMNodeToAddr(nodeAddr, parent, contextTable)
      assert(type(nodeAddr) == 'number', "node addr has to be a number, instead got: " .. type(nodeAddr))
      assert(type(parent) == "userdata", "parent has to exist")


      local nodeName = gd_getNodeName(nodeAddr)
      local gdscriptName = gd_getNodeNameFromScript(nodeAddr)
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

      local nodeName = gd_getNodeName(nodeAddr) or 'NIL';
      local scriptName = gd_getNodeNameFromScript(nodeAddr)

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

      if not GDDEFS.MONO then return end
      if checkScriptType(nodeAddr) ~= GDDEFS.SCRIPT_TYPES["CS"] or GDDEFS.MAJOR_VER < 4 then return end

      sendDebugMessage("Node " .. nodeName .. " has csharp script type")
      local clrPtrElem = createChildStructElem(scriptInstStructElement, "CLRPtr", GDDEFS.CLR_PTR, vtPointer, "CLRPtr")
      -- addStructureElem(clrPtrElem, "CLRData", 0x0, vtPointer)
      local clrDataElem = createChildStructElem(clrPtrElem, "CLRData", 0x0, vtPointer, "CLRData")

      local clrDataAddr = readPointer( readPointer( gdScriptInstanceAddr + GDDEFS.CLR_PTR ) ) or 0x0
      if isNotNullOrNil(clrDataAddr) then
        clrDataElem.ChildStruct.fillFromDotNetAddress(clrDataAddr , true)
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
        if gdName == gd_getNodeNameFromScript(childAddr) then
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
        if nodeName == gd_getNodeName(childAddr) then
          return childAddr
        end
      end
      return nil
    end

    function GDAPI.gd_mono_getObjectFromNode(nodeAddr)
      assert(GDDEFS.MONO, 'Target has to be mono')
      assert(checkScriptType(nodeAddr) == GDDEFS.SCRIPT_TYPES["CS"], 'Node has to use C#')

      if GDDEFS.MAJOR_VER >= 4 then
        local GDSI = getNodeGDScriptInstance(nodeAddr) or 0x0
        local clrDataPtr = readPointer( GDSI + GDDEFS.CLR_PTR )
        return readPointer( clrDataPtr )
      end

      -- 3.x
      if isNullOrNil(GDDEFS.MONO_GETOBJ) then error('getmonoobject or gdchandle offset not defined') end
      return executeCodeEx(stdcall, timeout, GDDEFS.MONO_GETOBJ, nodeAddr)
    end

  -- ///---///--///---///--///---///--///--///---///--///---///--///---///--/// Script


    local function findGDExtensionInterfacePtr()
      local function findFuncPointer(aobSignature)
        local addr = AOBScanModuleUnique(process, aobSignature, '+X-W-C')
        if addr == 0 or addr == nil then return false end
        GDDEFS.GDXTENSION_GETPROC = addr
        return true
      end

      for i, sig in ipairs( GDAOB.GDExtension ) do
        if findFuncPointer(sig) then
          sendDebugMessage('[GDExtAPI] via sig - success!') --  .. "\t" .. sig
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

      -- first via rdata
      if findViaRDATA(structSignature) then
        sendDebugMessage('[NATIVE_API] via rdata success!')
        return true
      end

      -- fallback
      for i, sig in ipairs( GDAOB.GDNative ) do
        if findFuncPointer(sig) then
          sendDebugMessage('hit at: ' .. tostring(i) .. "\t" .. sig)
          return true
        end
      end
      return false
    end

    local function findMonoGetObject()
      local function findFuncPointer(aobSignature)
        local addr = AOBScanModuleUnique(process, aobSignature, '+X-W-C')
        if addr == 0 or addr == nil then return false end
        GDDEFS.MONO_GETOBJ = addr
        return true
      end

      for i, sig in ipairs( GDAOB.MonoGetObj ) do
        if findFuncPointer(sig) then
          sendDebugMessage('[MONO_GETOBJ] via sig - success!') --  .. "\t" .. sig
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

          function GDNativeInterface.godot_variant_destroy( ptr )
            assert(type(ptr) == 'number', 'ptr must be a number, instead got: ' .. type(ptr))

            local objDestor = GDNative:getFuncFromIndex(GDNative, 570)
            if isNullOrNil(objDestor) then error('godot_variant_destroy func ptr not found') end

            -- allocating target memory
            local objAlloc = allocateMemory(GDDEFS.PTRSIZE)
            if isNullOrNil(objAlloc) then error('mem_alloc failed to allocate') end
            writePointer(objAlloc, ptr)

            -- destroy
            executeCodeEx(stdcall, timeout, objDestor, objAlloc)
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

        function GDExtendedInterface.destroy_object_variant( ptr )
          assert(type(ptr) == 'number', 'string ptr must be a number, instead got: ' .. type(ptr))

          local variantDtor = GDExtendedInterface.getGDExtensionFunc('variant_destroy')
          if isNullOrNil(variantDtor) then error('variant dtor func ptr not found') end

          -- allocating target memory
          -- local objAlloc = allocateMemory(GDDEFS.PTRSIZE)
          -- if isNullOrNil(objAlloc) then error('mem_alloc failed to allocate') end
          -- writePointer(objAlloc, ptr)
          -- destroy SName
          executeCodeEx(stdcall, timeout, variantDtor, ptr)
          -- deAlloc(objAlloc)
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
        if GDDEFS.MAJOR_VER <= 3 then
          retObj = GDNativeInterface.godot_string_chars_to_utf8( str )
        else
          retObj = GDExtendedInterface.string_new_with_latin1_chars( str )
        end
        if retObj then GDI.constructed[retObj] = 'STRING' end
        return retObj
      end

      function GDI.construct_string_name( str )
        local retObj
        if GDDEFS.MAJOR_VER <= 3 then
          retObj = GDNativeInterface.godot_string_name_new_data( str )
        else
          retObj = GDExtendedInterface.string_name_new_with_latin1_chars( str )
        end
        if retObj then GDI.constructed[retObj] = 'STRING_NAME' end
        return retObj
      end

      function GDI.construct_string_name_variant( str )
        local objAlloc

        if GDDEFS.MAJOR_VER <= 3 then error('doesnt exist') end

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
        if objAlloc then GDI.constructed[objAlloc] = 'STRING_NAME' end
        return objAlloc
      end

      function GDI.construct_string_variant( str )
        local mallocPtr
        local varCtorPtr
        if GDDEFS.MAJOR_VER <= 3 then
          local varCtorPtr = GDNative:getFuncFromIndex(GDNative, 514)
          mallocPtr = GDNative:getFuncFromIndex(GDNative, 738)
          if isNullOrNil(mallocPtr) then error('mem_alloc func ptr not found') end
          if isNullOrNil(varCtorPtr) then error('variant ctor func ptr not found') end
        else
          varCtorPtr = GDExtendedInterface.get_variant_from_type_constructor('STRING')
          local mallocPtr = GDExtendedInterface.getGDExtensionFunc('mem_alloc')
          if isNullOrNil(mallocPtr) then error('mem_alloc func ptr not found') end
          if isNullOrNil(varCtorPtr) then error('get_variant_from_type_constructor func ptr not found') end
        end

        -- malloc
        local variantSpaceAlloc = 0x40 -- uninit dest store
        local objAlloc = executeCodeEx(stdcall, timeout, mallocPtr, variantSpaceAlloc)
        if isNullOrNil(objAlloc) then error('mem_alloc failed to allocate') end

        -- constructing variant string name
        local stringPtr = GDI.construct_string(str)

        -- storing in a pointer
        local ptrContainer = allocateMemory(GDDEFS.PTRSIZE)
        writePointer(ptrContainer, stringPtr)
        executeCodeEx(stdcall, timeout, varCtorPtr, objAlloc, ptrContainer)
        deAlloc(ptrContainer)
        
        if objAlloc then GDI.constructed[objAlloc] = 'STRING' end
        return objAlloc
      end

      function GDI.construct_object_variant( ptr )
        assert(isNotNullOrNil(ptr), 'ptr must be a valid number')
        local mallocPtr
        local varCtorPtr
        if GDDEFS.MAJOR_VER <= 3 then
          varCtorPtr = GDNative:getFuncFromIndex(GDNative, 527)
          mallocPtr = GDNative:getFuncFromIndex(GDNative, 738)
          if isNullOrNil(mallocPtr) then error('mem_alloc func ptr not found') end
          if isNullOrNil(varCtorPtr) then error('variant ctor func ptr not found') end
        else
          varCtorPtr = GDExtendedInterface.get_variant_from_type_constructor('OBJECT')
          mallocPtr = GDExtendedInterface.getGDExtensionFunc('mem_alloc')
          if isNullOrNil(mallocPtr) then error('mem_alloc func ptr not found') end
          if isNullOrNil(varCtorPtr) then error('get_variant_from_type_constructor func ptr not found') end
        end

        -- malloc
        local variantSpaceAlloc = 0x40 -- uninit dest store
        local objAlloc = executeCodeEx(stdcall, timeout, mallocPtr, variantSpaceAlloc)
        if isNullOrNil(objAlloc) then error('mem_alloc failed to allocate') end

        -- constructing variant string name
        local ptrContainer = allocateMemory(GDDEFS.PTRSIZE)
        writePointer(ptrContainer, ptr)
        executeCodeEx(stdcall, timeout, varCtorPtr, objAlloc, ptrContainer)
        deAlloc(ptrContainer)

        if objAlloc then GDI.constructed[objAlloc] = 'STRING' end
        return objAlloc
      end

      function GDI.get_variant_from_type_constructor( gdTypeName )
        local constructor

        if GDDEFS.MAJOR_VER <= 3 then
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
        if GDDEFS.MAJOR_VER <= 3 then
          GDNativeInterface.godot_string_name_destroy( ptr )
        else
          GDExtendedInterface.string_name_destroy( ptr )
        end
        if ptr then GDI.constructed[ptr] = nil end
      end

      function GDI.destroy_string_name( ptr )
        if GDDEFS.MAJOR_VER <= 3 then
          GDNativeInterface.godot_string_name_destroy( ptr )
        else
          GDExtendedInterface.string_destroy( ptr )
        end
        if ptr then GDI.constructed[ptr] = nil end
      end

      function GDI.destroy_object_variant( ptr )
        if GDDEFS.MAJOR_VER <= 3 then
          -- needs testing
          GDNativeInterface.godot_variant_destroy( ptr )
        else
          GDExtendedInterface.destroy_object_variant( ptr )
        end
        if ptr then GDI.constructed[ptr] = nil end
      end

      function GDI.destroy_variant( ptr )
        if GDDEFS.MAJOR_VER <= 3 then
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

    function GDAPI.gd_recompileScript(nodeAddr, fileName)
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
      -- success
      if eError == 0 then return eError end
      
      -- fail
      error('hotreloading GDScript failed, err: ' .. tostring(GDDEFS.SCRIPT_ERRORS[eError]) )
    end

    function GDAPI.gd_reloadScriptInstance(nodeAddr)
      assert(type(nodeAddr)=='number', 'Node addr has to be a number, instead got: '..type(nodeAddr))
      assert(checkForGDScript(nodeAddr), 'Node doesnt have gdscript')

      -- get Node's callp virtual
      local callpMethod = getObjectVMethodByIndex(nodeAddr, GDDEFS.CALLP_INDX )
      if isNullOrNil(callpMethod) then error('callp not found') end

      local gdScript = getNodeGDScript(nodeAddr)
      if isNullOrNil(gdScript) then error('gdscript invalid') end -- check it before any allocations

      -- construct bound method StringName and an object variant
      local methodSName = GDI.construct_string_name( 'set_script' )
      if isNullOrNil(methodSName) then error('string name not constructed') end
      local stringNamePtr = allocateMemory(GDDEFS.PTRSIZE)
      writePointer(stringNamePtr, methodSName) -- we need the stringName to be stored in a pointer passed to callp

      local int_t = 0
      local argTable = { { type = "NIL", value = nil } }
      setupCallArgs(VariantArena, GDVariant, argTable)

      local buffer = { type = int_t, value = VariantArena.base + VariantArena.returnBufOffset } -- rcx
      local args = { type = int_t, value = VariantArena.base + VariantArena.argListOffset } -- r9
      local argCount = 1
      local err = { type = int_t, value = VariantArena.base + VariantArena.callErrorOffset }
      writeInteger(err.value, -1)

      -- We cheat here with    node->set_script( Variant(TYPE::NIL) );     to avoid   if (get_script() == p_script) return;   but we lose the state
      executeCodeEx(stdcall, timeout, callpMethod,    buffer, nodeAddr, stringNamePtr, args, argCount, err)

      -- error checking, the object state should allegedly be fine
      local errVal = readPointer( err.value )
      if errVal ~= 0 then
        GDI.destroy_string_name( methodSName )
        deAlloc(stringNamePtr)
        error('resetting the script failed, err: ' .. tostring(GDDEFS.CALL_ERRORS[errVal]) )
      end

      -- Object::set_script(const Variant &p_script)
      local objectVariant = GDI.construct_object_variant(gdScript)

      -- setting up the arg
      local argTable = { { type = "OBJECT", value = nil, copy = objectVariant } } -- for we manage it
      setupCallArgs(VariantArena, GDVariant, argTable)

      writeInteger(err.value, -1)

      -- hotreload the SI of a node
      executeCodeEx(stdcall, timeout, callpMethod,    buffer, nodeAddr, stringNamePtr, args, argCount, err) -- node->callp("set_script", args, argc, err) // Object::set_script(const Variant &p_script)
      
      deAlloc(stringNamePtr)
      GDI.destroy_string_name(methodSName)
      GDI.destroy_object_variant(objectVariant)

      local errVal = readPointer( err.value )

      -- success
      if errVal == 0 then return readPointer( err.value ) end
      
      -- fail
      error('hotreloading GDSI failed, err: ' .. tostring(GDDEFS.CALL_ERRORS[errVal]) )
    end

    --- reloads from the binary tokens
    ---@param nodeAddr number
    function GDAPI.gd_revertScript(nodeAddr)
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
      if GDDEFS.MAJOR_VER >= 4 then
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
    function GDAPI.gd_getFunctionFromNode(nodeAddr, funcName)
      assert(type(nodeAddr) == 'number', "Node addr has to be a number, instead got: " .. type(nodeAddr))
      assert(type(funcName) == 'string', "Func name has to be a string, instead got: " .. type(funcName))
      assert(checkForGDScript(nodeAddr) == true, "Node addr doesn't have a GDScript" )

      local gdScriptName = gd_getNodeNameFromScript(nodeAddr) or "N??"
      local nodeMapContext = { addr = nodeAddr, name = '', gdname = '', memrec = nil, struct = nil, symbol = funcName or '' }
      local headElement, tailElement, mapSize, currentContainer = getNodeFuncMap(nodeMapContext)
      return findMapEntryByName(headElement, funcName, getFunctionMapName, getFunctionMapLookupResult, advanceFunctionMapElement)
    end

    --- patch a function's code with the bytes starting at an arbitrary pos
    ---@param funcObjAddr number
    ---@param patchToBytes table
    ---@param startPos number @0-based position to start patching from
    function GDAPI.gd_patchFunction( funcObjAddr, patchToBytes, startPos  )
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
    function GDAPI.gd_patchFunctionConst( funcObjAddr, constIndex, CEvalueType, value  )
      assert(type(funcObjAddr) == 'number', "Func addr has to be a number, instead got: " .. type(funcObjAddr))
      assert(type(constIndex) == 'number', "Const index must be a number, instead got: " .. type(constIndex))
      assert(type(value) == 'number', "value has to be a number, instead got: " .. type(value))
      assert(type(CEvalueType) == 'number', "ce value type has to be a number, instead got: " .. type(CEvalueType))

      local funcConstAddr = getFuncObjectConstAddr(funcObjAddr)
      if isNullOrNil(funcConstAddr) then error("function const addr is invalid") end

      local vectorSize = readInteger(funcConstAddr - GDDEFS.SIZE_VECTOR)

      -- local sizeOfVariant, ok = redefineVariantSizeByVector(funcConstAddr, vectorSize)
      -- if not ok then error("size refedinition failed") end
      local sizeOfVariant = GDDEFS.SIZEOF_VARIANT

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

      -- local variantSize, ok = redefineVariantSizeByVector(funcConstantVect, vectorSize)
      -- if not ok then sendDebugMessage("Variant resize failed") return end
      local variantSize = GDDEFS.SIZEOF_VARIANT
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

        local isUTF, stringOffset = checkStringNameType(stringNamePtr)

        -- sendDebugMessage('Looping: label: '..label.." funcVector: "..numtohexstr(funcGlobalVect))

        emitStringNameStruct(funcGlobalNameStructElem, label, entryOffset, stringFieldLabel, isUTF, stringOffset)
      end

      return;
    end

    function disassembleGDFunctionCodeToStruct(funcAddr, funcStruct)
      assert((type(funcAddr) == 'number') and (funcAddr ~= 0), 'funcAddr has to be a valid pointer, instead got: ' .. type(funcAddr))

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

        if currOpcode == GDFunc.CurrentDisassembler:getOPEnumFromInternalOPID(GDFunc.OP.OPCODE_END) then
          break
        end
        currIndx = currIndx + 1
      end
      sendDebugMessage('codeSize: ' .. tostring(codeSize))

      GDFunc.CurrentDisassembler:disassembleBytecode(codeInts, codeStructElement)

      return
    end

    function checkIfGDFunction(funcAddr)
      local funcStringNameAddr, funcResStringNameAddr, funcCodeAddr, funcCodeLastIdx, lastOpcode
      if GDDEFS.MAJOR_VER <= 3 or GDDEFS.VERSION_STRING == "4.1" then
        funcResStringNameAddr = readPointer(funcAddr) -- StringName source at 0x0;
        funcStringNameAddr = 0xBAAAAABE -- just a placeholder
      else
        funcStringNameAddr = readPointer(funcAddr) -- StringName funct name;
        funcResStringNameAddr = readPointer(funcAddr + GDDEFS.PTRSIZE) -- StringName source;
      end

      if isNullOrNil(funcResStringNameAddr) or isNullOrNil(funcStringNameAddr) then return false end

      if not (  getStringNameStr(funcResStringNameAddr)  ):match("res://") then return false end

      -- get code and its size to check the OPCODE_END
      funcCodeAddr = readPointer(funcAddr + GDDEFS.FUNC_CODE)
      if isNullOrNil(funcCodeAddr) then return false end
      funcCodeLastIdx = readInteger( funcCodeAddr - GDDEFS.SIZE_VECTOR ) - 1 -- Vector<int>
      lastOpcode = readInteger( funcCodeAddr + 4 * funcCodeLastIdx ) 

      if isNullOrNil(funcCodeAddr) or ( lastOpcode ~= GDFunc.CurrentDisassembler:getOPEnumFromInternalOPID(GDFunc.OP.OPCODE_END) ) then return false end
      -- already a strong assumption, discard the remaining checks
      return true
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

      for i, sign in ipairs( GDAOB.VMCall ) do
        if resolveVM_RELA(sign.sig, sign.sigsize) then
          sendDebugMessage('[VM_CALL] via sig - success!') --  .. "\t" .. sign.sig
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

    function GDAPI.gd_callFunctionFromNode(nodeAddr, funcName, argTable)
      assert(isNotNullOrNil(nodeAddr), "Node Addr must be valid")
      assert(type(funcName) == 'string', "function name must be a string, instead got: " .. type(funcName))

      local gdScriptInstance = getNodeGDScriptInstance(nodeAddr)
      if isNullOrNil(gdScriptInstance) then error("Nodes' script instance not found") end

      local functionAddr = gd_getFunctionFromNode( nodeAddr, funcName )
      if isNullOrNil(functionAddr) then error("Function address not found") end

      if isNotNullOrNil(GDDEFS.VM_CALL) then
        return GDAPI.executeGDFunction(functionAddr, gdScriptInstance, argTable)
      else
        -- calling methods via node->callp("functionStringName", args, argc, err)
        local callpMethod = getObjectVMethodByIndex(nodeAddr, GDDEFS.CALLP_INDX )
        if isNullOrNil(callpMethod) then error('callp not found') end

        local gdScript = getNodeGDScript(nodeAddr)
        if isNullOrNil(gdScript) then error('gdscript invalid') end -- wouldn't make sense

        -- construct bound method StringName
        local methodSName = GDI.construct_string_name( funcName )
        if isNullOrNil(methodSName) then error('string name not constructed') end
        local stringNamePtr = allocateMemory(GDDEFS.PTRSIZE)
        writePointer(stringNamePtr, methodSName) -- we need the stringName to be stored in a pointer passed to callp

        -- VariantArg setup
        if isNotNullOrNil(argTable) and type(argTable) == "table" and isNotNullOrNil(#argTable) then
          setupCallArgs(VariantArena, GDVariant, argTable)
        end

        local int_t = 0
        local buffer = { type = int_t, value = VariantArena.base + VariantArena.returnBufOffset } -- rcx
        local args = { type = int_t, value = VariantArena.base + VariantArena.argListOffset } -- r9
        local argCount = (argTable and #argTable) or 0
        local err = { type = int_t, value = VariantArena.base + VariantArena.callErrorOffset }
        writeInteger(err.value, -1)

        local returned = executeCodeEx(stdcall, timeout, callpMethod,    buffer, nodeAddr, stringNamePtr, args, argCount, err)
      
        deAlloc(stringNamePtr)
        GDI.destroy_string_name(methodSName)

        local errVal = readPointer( err.value )

        -- success
        if errVal == 0 then return VariantArena.base + VariantArena.returnBufOffset end
      
        -- fail
        error('Fail, err: ' .. tostring(GDDEFS.CALL_ERRORS[errVal]) )
      end
    end

    -- TODO: callp API

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

      if GDDEFS.MAJOR_VER >= 4 then
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
      local nodeName = gd_getNodeName(nodeMapContext.addr) or "UnknownNode"
      if nodeName == 'N??' then nodeName = gd_getNodeNameFromScript(nodeMapContext.addr) end

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
      
      if GDDEFS.MAJOR_VER <= 3 then
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

      if GDDEFS.MAJOR_VER <= 3 then
        currentRoot = createChildStructElem(currentRoot, 'dictList', GDDEFS.DICT_LIST, vtPointer, 'dictList')
        contextTable.symbol = wrapBrackets( contextTable.symbol .. '+DICT_LIST' )
      end

      local headContainer = createChildStructElem(currentRoot, 'dictHead', GDDEFS.DICT_HEAD, vtPointer, 'dictHead')
      contextTable.symbol = wrapBrackets( contextTable.symbol .. '+DICT_HEAD' )

      iterateDictionary(dictHead, headContainer, GDEmitters.StructEmitter, { bNeedStructOffset = true, nextContainerFactory = createNextDictContainer, nextSymbolFactory = createNextSymbol }, { nodeAddr = 0, nodeName = "Dictionary", symbol = contextTable.symbol })
      return
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
      -- local variantSize, ok = redefineVariantSizeByVector(variantVector, vectorSize)
      -- if not ok then sendDebugMessage("Variant resize strangely failed") return; end
      local variantSize = GDDEFS.SIZEOF_VARIANT

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
      local sizeOfVariant = GDDEFS.SIZEOF_VARIANT -- GDDEFS.USES_DOUBLE_REALT and 0x28 or 0x18

      local mapElement = headElement
      local fields = {}
      local index = 0

      repeat
        local entry = readNodeVariantEntry(mapElement, variantVector, sizeOfVariant)
        fields[index] = {}
        -- fields[index].Index = entry.Index
        fields[index].Name = entry.name
        fields[index].Offset = entry.offsetToValue
        fields[index].Sizeof = sizeOfVariant
        fields[index].Type = entry.typeId

        mapElement = getNextMapElement(mapElement)
        index = index+1
      until (mapElement == 0)

      return fields
    end

    function iterateVectorVariantsForNamedField(nodeAddr, variantName)
      if isNullOrNil(nodeAddr) then return nil end
      if nodeAddr == nil or variantName == '' then return nil end

      local headElement, tailElement, mapSize = getNodeVariantMap(nodeAddr)
      if isNullOrNil(headElement) or isNullOrNil(mapSize) then return nil end

      local variantVector, vectorSize = getNodeVariantVector(nodeAddr)
      local sizeOfVariant = GDDEFS.SIZEOF_VARIANT

      local mapElement = headElement
      local field = {}
      local index = 0

      repeat
        local entry = readNodeVariantEntry(mapElement, variantVector, sizeOfVariant)

        if entry.name == variantName then
          field.Name = entry.name
          field.Offset = entry.offsetToValue
          field.Sizeof = sizeOfVariant
          field.Type = entry.typeId
          return field
        end

        mapElement = getNextMapElement(mapElement)
        index = index+1
      until (mapElement == 0)
      return nil
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


    --- returns a vector pointer and its size via
    ---@param nodeAddr number
    function getNodeVariantVector(nodeAddr)
      -- if isNullOrNil(nodeAddr) then return; end

      local scriptInstance = readPointer( (nodeAddr or 0) + GDDEFS.GDSCRIPTINSTANCE)
      -- if isNullOrNil(scriptInstance) then return; end

      local vectorPtr = readPointer( ( scriptInstance or 0) + GDDEFS.VAR_VECTOR)
      local vectorSize = readInteger( (vectorPtr or 0) - GDDEFS.SIZE_VECTOR)

      -- if isNullOrNil(vectorSize) then return; end
      -- if isNullOrNil(vectorPtr) then return; end

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

      local mainElement = readPointer(gdScriptAddr + GDDEFS.VARIANTMAP) -- head / root
      local endElement = readPointer(gdScriptAddr + GDDEFS.VARIANTMAP + GDDEFS.PTRSIZE) -- tail / end
      local mapSize = readInteger(gdScriptAddr + GDDEFS.VARIANTMAP + GDDEFS.MAP_SIZE)

      if isNullOrNil(mainElement) or isNullOrNil(endElement) or isNullOrNil(mapSize) then
        sendDebugMessage('Variant: (hash)map is not found')
        return;
      end

      if GDDEFS.MAJOR_VER >= 4 then
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
    function getVariantByIndex(vectorAddr, index, varSize)
      if vectorAddr == nil then return end
      -- assert(type(vectorAddr) == 'number', "vector addr should be a number, instead got: " .. type(vectorAddr))
      -- assert((type(index) == 'number') and (index >= 0), "index should be a valid number, instead got: " .. type(index))

      -- if index > readInteger( ( (vectorAddr or 0) - GDDEFS.SIZE_VECTOR) ) or 0 - 1 then
      --   sendDebugMessage("index is out of vector size, pass index: " .. tostring(index) .. ' VecSize: ' .. tostring( (index > (readInteger( ( (vectorAddr or 0) - GDDEFS.SIZE_VECTOR) or 0 ) - 1)) ))
      -- end

      local variantType = readInteger(vectorAddr + varSize * index)
      local offsetToValue = getVariantValueOffset(variantType)

      local offset = varSize * index + offsetToValue
      local variantAddr = getAddress(vectorAddr + offset)

      -- if (variantType == nil) or (variantAddr == nil) then return 0,0,0 end
      return variantAddr, variantType, offset
    end

    VariantArena =
      {
        base = nil, -- alloc ptr
        size = 0x2000, -- allocated space
        cursor = 0, -- current offset
        variantSize = 0x40, -- for enough padding
        
        returnBufOffset = 0x0, -- 0x000..0x03F return Variant
        excptOffset = 0x40, -- exception, let it be of Variant
        callErrorOffset = 0x80, -- 12 bytes, it's mostly enum we are interested
        -- some padd
        argListOffset = 0x90, -- where const Variant **p_args
        -- 108 8byte for ptrs
        
        -- scratch
        scratchStart = 0x400,
        scratchEnd = 0x1F00,
        -- end padd
        
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
      function GDVariant.NIL(arena, value, copy)
        if isValidPointer(copy) then return copy end
        local v = arena:allocVariant()
        writeInteger(v + 0x0, getGDTypeEnumFromName('NIL') )
        writeQword(v + 0x8, 0x0)
        return v
      end

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
        -- if isNotNullOrNil(value) then error("object value invalid") end
        -- local v = arena:allocVariant()
        -- writeInteger(v + 0x0, getGDTypeEnumFromName('OBJECT') )
        -- writeInteger(v + 0x8, value.id)
        -- writePointer(v + 0x10, value.obj)
        return GDI.construct_object_variant( value )
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

    function GDAPI.gd_registerNodeOffsets(nodeName, namespace)
      local nodeAddr = gd_getDumpedNode( nodeName )
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
        classFields = gd_node_enumVariants( nodeAddr )
      end

      if not (classFields) or next(classFields)==nil then error('node isn\'t dumped or constructed yet, try again later') end

      for _ , field in pairs(classFields) do
        registerSymbol( namespace .. nodeName .. '.' .. field.Name , field.Offset , true )
      end
    end

    --- gets a dumped Node by name
    ---@param nodeName string
    function GDAPI.gd_getDumpedNode(nodeName)
      assert(type(nodeName) == "string", 'Node name should be a string, instead got: ' .. type(nodeName))
      if not (gdOffsetsDefined) then print('define the offsets first, silly') return; end

      if (not GD_DUMP_MONITOR_NODES_ABS) or next(GD_DUMP_MONITOR_NODES_ABS) == nil then return; end

      local longName = GD_DUMP_MONITOR_NODES_ABS[nodeName]
      if longName then return longName end

      return GD_DUMP_MONITOR_NODES[nodeName]
    end

    --- prints all gathered nodeNames
    function GDAPI.gd_printDumped()
      if not (gdOffsetsDefined) then print('define the offsets first, silly') return end

      if (not GD_DUMP_MONITOR_NODES_ABS) or next(GD_DUMP_MONITOR_NODES_ABS) == nil then return; end

      printf("%-90s%-90s%s", "[Script]", "[Abs]", "[Name]")
      for _, nodeAddr in pairs(GD_DUMP_MONITOR_NODES_ABS) do
        local gdScriptName, absPath = gd_getNodeNameFromScript(nodeAddr, true)
        local nodeNameStr = gd_getNodeName(nodeAddr)
        printf("%-90s%-90s%s", gdScriptName, absPath, nodeNameStr)
      end
    end

    --- dump for a specific node and append to the parent
    ---@param parentMemrec userdata
    ---@param nodeAddr number
    ---@param bDoConstants number
    function GDAPI.gd_dumpNodeToAddr(parentMemrec, nodeAddr, bDoConstants)
      assert(type(parentMemrec) == "userdata", 'Parent address has to be userdata, instead got: ' .. type(parentMemrec))
      assert(type(nodeAddr) == "number", 'Node address has to be a number, instead got: ' .. type(nodeAddr))
      if not (gdOffsetsDefined) then
        print('define the offsets first, silly')
        return
      end

      debugPrefix = 1; -- reset debug prefix, don't use that while running Node threads
      dumpedNodes = {}; -- let's start from scratch for single node dumps | there might be race conditions, not a big issue for most cases
      table.insert(dumpedNodes, nodeAddr)

      local nodeNameStr = gd_getNodeName(nodeAddr)
      local gdscriptName = gd_getNodeNameFromScript(nodeAddr)

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
    function GDAPI.gd_dumpAllNodesToAddr(thr)
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

      local symbolToChildren = '[[pRoot]+CHILDREN]' -- .. '+' .. numtohexstr(GDDEFS.CHILDREN)
      local newNodeSymStr, GDSIsym, variantVectorSym, GDScriptSym, GDScriptConstMapSym
      local nodeContext;

      for key, value in pairs(mainNodeDict) do
        newNodeSymStr = symbolToChildren .. '+' .. numtohexstr(value.index) .. "*" .. numtohexstr(GDDEFS.PTRSIZE) -- [[pRoot]+CHILDREN]+i*ptrsize
        GDSIsym = wrapBrackets( wrapBrackets(newNodeSymStr) .. '+GDSCRIPTINSTANCE' )                              -- [[[[pRoot]+CHILDREN]+i*ptrsize]+GDSCRIPTINSTANCE]
        variantVectorSym = wrapBrackets( GDSIsym .. '+VAR_VECTOR' )                                               -- [[[[[pRoot]+CHILDREN]+i*ptrsize]+GDSCRIPTINSTANCE]+VAR_VECTOR]
        GDScriptSym = wrapBrackets( GDSIsym .. '+GDSCRIPT_REF' )                                                  -- [[[[[pRoot]+CHILDREN]+i*ptrsize]+GDSCRIPTINSTANCE]+GDSCRIPT_REF]
        GDScriptConstMapSym = wrapBrackets( GDScriptSym .. '+CONST_MAP' )                                         -- [[[[[[[pRoot]+CHILDREN]+i*ptrsize]+GDSCRIPTINSTANCE]+GDSCRIPT_REF]+CONST_MAP]

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

    function GDAPI.gd_initDumper(config)
      -- init global
      initGDDefs()

      local ceDir = getCheatEngineDir() or ''

      -- retrieve the offset getted function
      local ok, result = pcall( dofile, ceDir .. [[autorun\GDDumperModules\GDHardOffsets.lua]] )
      if ok then
        getStoredOffsetsFromVersion = result.install( { sendDebugMessage = sendDebugMessage, } )
      else
        -- portable, we get a module object
        getStoredOffsetsFromVersion = loadScriptFromTable( "GDOff" ).install( { sendDebugMessage = sendDebugMessage, } )
      end

      -- retrieve the signatures
      local ok, result = pcall( dofile, ceDir .. [[autorun\GDDumperModules\GDSignatures.lua]] )
      if ok then
        GDAOB = result.install( {} )
      else
        GDAOB = loadScriptFromTable( "GDSig" ).install( {} )
      end

      -- essential version definition
      initGDVersion(config)

      -- define type conversion helpers via module
      local ok, result = pcall( dofile, ceDir .. [[autorun\GDDumperModules\GDTypes.lua]] )
      if ok then
        result.install( {GDDEFS=GDDEFS} )
      else
        loadScriptFromTable( "GDT" ).install( {GDDEFS=GDDEFS} )
      end

      -- build the correct disassembler profile inside the module
      local ok, result = pcall( dofile, ceDir .. [[autorun\GDDumperModules\GDFunctionStructDisassembler.lua]] )
      local GDFuncDisasm
      local dependencyContext = 
        {
          GDDEFS = GDDEFS,
          addStructureElem = addStructureElem,
          addLayoutStructElem = addLayoutStructElem,
          getGDTypeName = getGDTypeName,
          iterateFuncConstantsToStruct = iterateFuncConstantsToStruct,
          iterateFuncGlobalsToStruct = iterateFuncGlobalsToStruct,
          sendDebugMessage = sendDebugMessage,
        }
      if ok then
        result.install(dependencyContext)
      else
        loadScriptFromTable( "GDFDasm" ).install(dependencyContext)
      end

      -- initialize structure walker for non-standalone
      local ok, result = pcall( dofile, ceDir .. [[autorun\GDDumperModules\GDStructWalker.lua]] )
      local dependencyContext =
        {
          GDDEFS = GDDEFS,
          readUTFString = readUTFString,
          getStringNameStr = getStringNameStr,
          sendDebugMessage = sendDebugMessage,
          getSectionBounds = getSectionBounds,
          getMainModuleInfo = getMainModuleInfo,
          tryRegSceneTree = tryRegSceneTree,
          setSTtoRootOffset = setSTtoRootOffset,
        }
      if ok then
        result.install(dependencyContext)
      end

      -- define version and offsets
      defineGDOffsets(config)
      gdOffsetsDefined = true

      -- register symbols for pointer resolution
      registerGDSymbols()

      -- try finding SceneTree and Viewport/Window
      if tryRegSceneTree() and setSTtoRootOffset() then registerSymbol('pRoot', '[pSceneTree]+oSTtoRoot', false) end

      -- check if UTF32LE string type reged, otherwise define it
      checkGDStringType()

      -- disable show on print
      fuckoffPrint()

      -- exposing relevant API
      if GDDEFS.MAJOR_VER >= 4 and GDDEFS.MINOR_VER >= 1 then
        if findGDExtensionInterfacePtr() then GDI.Extension = GDExtendedInterface end
      end
      if GDDEFS.MAJOR_VER == 3 then -- doesn't exist in 2.x
        if findGDNativeAPIStruct() then GDI.GDNative = GDNativeInterface end
      end

      -- find GDScriptFunctions::call()
      if not findGDVMCallPtr() then sendDebugMessage('[VM_CALL] lookup failed.') end

      -- find mono get object
      if GDDEFS.MONO and GDDEFS.MAJOR_VER < 4 then 
        if not findMonoGetObject() then sendDebugMessage('[MONO_GETOBJ] lookup failed.') end
      end

      -- this guy will monitor threads and register them, isn't quite optimized non-intrusive solution
      local ok, result = pcall( dofile, ceDir .. [[autorun\GDDumperModules\GDNodeMonitor.lua]] )
      local dependencyContext =
        {
          GDDEFS = GDDEFS,
          readUTFString = readUTFString,
          getGDTypeEnumFromName = getGDTypeEnumFromName,
          getMainModuleInfo = getMainModuleInfo,
          getSectionBounds = getSectionBounds,
          gd_getNodeNameFromScript = GDAPI.gd_getNodeNameFromScript
        }

      if ok then
        result.install(dependencyContext)
      else
        loadScriptFromTable( "GDNM" ).install(dependencyContext)
      end

      -- it will spin from now on
      GDDEFS.Monitor:init()

    end
    godotRegisterPreinit()

    if (getCEVersion() < 7.7) then ShowMessage('Please update CE to 7.7 or newer') end

-- ///---///--///---///--///---///--///--///---///--///---///--///---///--///--///--/// API

  gd_dumpNodeToAddr = GDAPI.gd_dumpNodeToAddr
  gd_dumpAllNodesToAddr = GDAPI.gd_dumpAllNodesToAddr
  gd_initDumper = GDAPI.gd_initDumper

  -- objects
  gd_mono_getObjectFromNode = GDAPI.gd_mono_getObjectFromNode
  gd_getDumpedNode = GDAPI.gd_getDumpedNode
  gd_registerNodeOffsets = GDAPI.gd_registerNodeOffsets
  gd_getObjectName = GDAPI.getGDObjectName
  gd_getNodeNameFromScript = GDAPI.gd_getNodeNameFromScript
  gd_getNodeName = GDAPI.gd_getNodeName
  gd_node_enumVariants = GDAPI.godot_node_enumVariants
  gd_node_registerVariantsSelectively = GDAPI.gd_node_registerVariantsSelectively
  gd_AA_GETNODESTRUCT = GDAPI.godotAA_GETNODESTRUCT
  gd_getNodeChildByGDName = GDAPI.getNodeChildByGDName
  gd_getNodeChildByName = GDAPI.getNodeChildByName

  -- scripts
  gd_recompileScript = GDAPI.gd_recompileScript
  gd_revertScript = GDAPI.gd_revertScript
  gd_reloadScriptInstance = GDAPI.gd_reloadScriptInstance
  gd_executeFunction = GDAPI.executeGDFunction
  gd_callFunctionFromNode = GDAPI.gd_callFunctionFromNode
  gd_patchFunction = GDAPI.gd_patchFunction
  gd_getFunctionFromNode = GDAPI.gd_getFunctionFromNode
  gd_getNodeConstPtr = GDAPI.getNodeConstPtr
  gd_patchFunctionConst = GDAPI.gd_patchFunctionConst

  -- misc
  gd_buildGUI = GDAPI.gd_buildGUI  
  gd_printDumped = GDAPI.gd_printDumped
  gd_reportConfig = GDAPI.printGDConfig
  gd_getSemver = GDAPI.getGDSemver
  gd_assumeOffsets = nil
  gd_probeOffsets = nil