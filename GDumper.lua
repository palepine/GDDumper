-- This script was created by palepine. Support me: https://ko-fi.com/vesperpallens | https://www.patreon.com/c/palepine
-- I'd like to thank cfemen for some basic insights about the godot engine which saved me from reading much of the Godot Engine source code.
-- Github: https://github.com/palepine/GDDumper
-- tested on 50+ applications

-- to keep the code more organized in a single file, it's split into foldable sections
-- script can be documented better though

--///---///--///---///--///---///--///--///---///--///---///--///---///--/// Feat
    --#TODO add support for vectors and other complex structures
    --#TODO add more functionality for function overriding
    --#TODO create a plugin injecting routines to catch the root VP - this one is big
    --#TODO implement godot version detection
    --#TODO probably implement UTF-16 read string function to substitute CE's one
    --#TODO investigate packedArray size (at least 3.x)


--///---///--///---///--///---///--///--///---///--///---///--///---///--///--///--/// CHEAT ENGINE UTILITIES

        --///---///--///---///--///---/// MEMRECS
            --- adds a memrec to Owner
            ---@param memRecName string
            ---@param gdPtr number
            ---@param CEType number
            ---@param Owner userdata -- to append to
            ---@return userdata
            function addMemRecTo(memRecName, gdPtr, CEType, Owner)
                local newMemRec = getAddressList().createMemoryRecord()
                newMemRec.setDescription(memRecName)
                newMemRec.setType(CEType)

                if GDSOf.GD4_STRING_EXISTS then
                    if CEType == vtString then newMemRec.setType(vtCustom); newMemRec.CustomTypeName = "GD4 String" newMemRec.setAddress( readPointer( gdPtr) ) else newMemRec.setAddress( gdPtr ) end
                else
                    if CEType == vtString then newMemRec.String.Size = 100; newMemRec.String.Unicode = true; newMemRec.setAddress( readPointer( gdPtr) ) else newMemRec.setAddress( gdPtr ) end
                end

                if CEType == vtQword then newMemRec.ShowAsHex = true; end
                newMemRec.DontSave=true
                newMemRec.appendToEntry(Owner)
                return newMemRec
            end

        --///---///--///---///--///---/// POINTER HANDLERS

            --- checks if the value is a valid pointer
            ---@param addr number
            ---@return boolean
            function isValidPointer(addr)
                local success, result = pcall(readPointer, addr)
                return success and result ~= nil
            end

        --///---///--///---///--///---/// MISC

            --- turns off showOnPrint
            function fuckoffPrint()
                GetLuaEngine().cbShowOnPrint.Checked = false
            end

        --///---///--///---///--///---/// DEBUG

            --- multiplies a string by a number for more neat debug
            ---@param str string
            ---@param times number
            ---@return string
            function strMul(str, times)
                return string.rep(str, times)
            end

            function incDebugStep()
                debugPrefix = debugPrefix+1
                return string.rep('>', debugPrefix)
            end

            function decDebugStep()
                debugPrefix = debugPrefix-1
            end

        --///---///--///---///--///---/// STRUCTURES

            --- when called, creates a CE structure form window for the viewport and selects a newly-created GNODES structure
            function createVPStructForm()
                if not (gdOffsetsDefined) then print('define the offsets first, silly') return end
                -- let's ensure VP is found, it will throw an error otherwise
                getViewport()

                local symbolToChildren = '[[ptVP]+'..('%x'):format(GDSOf.CHILDREN)..']' -- '[[ptVP]+CHILDREN]'
                local viewportStructForm = createStructureForm( symbolToChildren, 'VP', 'Viewport' ) 
                local childrenStruct = createVPStructure()

                -- I couldn't find a better way to select a structure inside a StructDissect form
                for i = 0, viewportStructForm.Structures1.Count-1 do
                    local menuItem = viewportStructForm.Structures1.Item[i]
                    if menuItem.Caption == 'GDNODES' then menuItem.doClick() end
                end

            end

            --- called by createVPStructForm, deletes ALL structures, constructs a children structure of the viewport
            function createVPStructure()
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
                for i=0, #mainNodeTable-1 do
                    structElem = struct.addElement()
                    structElem.BackgroundColor = 0xFF8080
                    structElem.Offset = i * GDSOf.PTRSIZE -- GDSOf.PTRSIZE
                    structElem.VarType = vtPointer
                    structElem.Name = getNodeName( mainNodeTable[i+1] )
                end
                struct.endUpdate()
                struct.addToGlobalStructureList() -- so we can use it

                return struct
            end

            --- creates an element in a parent structure
            function addStructureElem(parentStructElement, elementName, offset, CEType)
                local element = parentStructElement.ChildStruct.addElement()
                element.Name = elementName
                element.Offset = offset
                element.Vartype = CEType

                if CEType == vtUnicodeString then
                    if GDSOf.GD4_STRING_EXISTS then
                        element.Vartype = vtCustom; element.CustomTypeName = "GD4 String"
                    else
                        element.Bytesize = 100;
                    end
                end

                return element
            end

            --- for node layout creation
            function addLayoutStructElem(parentStructElement, childName, backgroundColor, offset, CEType)
                parentStructElement.ChildStruct = parentStructElement.ChildStruct and parentStructElement.ChildStruct or createStructure( parentStructElement.Owner.Name or 'ChStructure' )
                local childStructElement = parentStructElement.ChildStruct.addElement()
                childStructElement.Name = childName
                if backgroundColor ~= nil then childStructElement.BackgroundColor = backgroundColor end
                childStructElement.Offset = offset or 0x0
                childStructElement.VarType = CEType
                return childStructElement
            end

            --- register our own structure dissector callback
            function enableGDDissect()
                if not (gdOffsetsDefined) then print('define the offsets first, silly') return end
                -- override CE's callback
                if structDissectID ~= nil then unregisterStructureDissectOverride( structDissectID ) end
                structDissectID = registerStructureDissectOverride( GDStructureDissect )
            end

            --- unregister our structure dissector callback
            function disableGDDissect()
                -- restore CE's callback
                unregisterStructureDissectOverride( structDissectID )
                structDissectID = nil;
            end

            --- overriden structure dissector function
            ---@param struct userdata @the newly created struct
            ---@param baseaddr number  @the address form the parent pointer
            function GDStructureDissect(struct, baseaddr)

                if baseaddr == nil or baseaddr == 0 then return false end
                struct = struct and struct or createStructure('') -- should not happen though?
                struct.beginUpdate()

                if checkForGDScript( baseaddr ) then
                    dumpedDissectorNodes = {}
                    -- safe to assume, that's a starting point
                    local nodeName = getNodeName( baseaddr )
                    nodeName = nodeName and nodeName or 'Anon Node'
                    struct.Name = ' Node: '..nodeName
                    local scriptInstStructElem = struct.addElement()
                    scriptInstStructElem.Name = 'GDScriptInstance'
                    scriptInstStructElem.BackgroundColor = 0xFF0080
                    scriptInstStructElem.Offset = GDSOf.GDSCRIPTINSTANCE
                    scriptInstStructElem.VarType = vtPointer
                    iterateNodeToStruct( baseaddr, scriptInstStructElem )
                else
                    -- otherwise just let CE decide, btw why the hell the base address should be a fucking hex string?
                    struct.autoGuess( ("%x"):format(baseaddr), 0x0, 0x200) -- 512 bytes
                end

                struct.endUpdate()
                return true
            end

        --///---///--///---///--///---/// GUI

        --- creates a menu button in the main menu
        function buildGDGUI()

            -- creates and adds button to parent with callback on click
            local function addCustomMenuButtonTo(ownerParent, captionName, customCallback)
                local newMenuItem = createMenuItem( ownerParent )
                newMenuItem.Caption = captionName
                ownerParent.add( newMenuItem )
                newMenuItem.OnClick = customCallback
                return newMenuItem
            end

            local menuItemCaption = 'GDDumper'
            local mainMenu = getMainForm().Menu
            local gdMenuItem = nil

            for i=0, mainMenu.Items.Count-1 do
                if mainMenu.Items.Item[i].Caption == menuItemCaption then
                    gdMenuItem = mainMenu.Items.Item[i]
                    break
                end
            end

            if not gdMenuItem then
                gdMenuItem = createMenuItem( mainMenu )
                gdMenuItem.Caption = menuItemCaption
                mainMenu.Items.add( gdMenuItem )
                addCustomMenuButtonTo( gdMenuItem, 'VP Struct', createVPStructForm )
                addCustomMenuButtonTo( gdMenuItem, 'GD Dissector', GDDissectorSwitch )
                addCustomMenuButtonTo( gdMenuItem, 'Create Script', addGDMemrecToTable )
            end

        end

        --- toggling dissector override
        function GDDissectorSwitch(sender)
            if not (gdOffsetsDefined) then print('define the offsets first, silly') return end
            sender.Checked = not sender.Checked
            if sender.Checked then
                enableGDDissect()
            else
                disableGDDissect()
            end
        end

        function addGDMemrecToTable(sender)
            local addrList = getAddressList()
            local mainMemrec = addrList.createMemoryRecord()
            mainMemrec.Description = "Dumper by palepine"
            mainMemrec.Type = vtAutoAssembler
            mainMemrec.Options = '[moHideChildren,moDeactivateChildrenAsWell]'
            mainMemrec.Script = '{$lua}\nif syntaxcheck then return end\n[ENABLE]\nbASSUMPTIONLOG=true\ninitDumper()\nnodeMonitor()\n[DISABLE]\nnodeMonitor()'
            
            local dumpMemrec = addrList.createMemoryRecord()
            dumpMemrec.Description = 'TEMPLATE: DumpOneNodeSymbol'
            dumpMemrec.Type = vtAutoAssembler
            dumpMemrec.Async = true
            dumpMemrec.Options = '[moHideChildren,moDeactivateChildrenAsWell]'
            dumpMemrec.Script = '{$lua}\nif syntaxcheck then return end\n[ENABLE]\nDumpNodeToAddr(memrec, getDumpedNode( "Globals" ), false) -- change Globals to other node names\n[DISABLE]'
            dumpMemrec.appendToEntry(mainMemrec)

            local dumpMemrec = addrList.createMemoryRecord()
            dumpMemrec.Description = 'Dump All Nodes'
            dumpMemrec.Type = vtAutoAssembler
            dumpMemrec.Options = '[moHideChildren,moDeactivateChildrenAsWell]'
            dumpMemrec.Async = true
            dumpMemrec.Script = '{$lua}\nif syntaxcheck then return end\n[ENABLE]\nDumpAllNodesToAddr()\n[DISABLE]'
            dumpMemrec.appendToEntry(mainMemrec)

            local supportPalique = addrList.createMemoryRecord()
            supportPalique.Description = 'Support the author'
            supportPalique.Type = vtAutoAssembler
            supportPalique.Color = 0x8F379F
            supportPalique.Script = '{$lua}\n[ENABLE]\nshellExecute("https://ko-fi.com/vesperpallens")\n[DISABLE]'
        end

--///---///--///---///--///---///--///--///---///--///---///--///---///--///--///--/// DUMPER CODE


    function initDumper(bOverrideAssumption, majorVersion, oChildren, oObjStringName, oGDScriptInstance, oGDScriptName, oFuncDict, oGDConst, oVariantNameHM, oVariantVector, oVariantNameHMVarType, oVarSize, oVariantHMIndex, oFuncDictVal, oGDFunctionString, oGDFunctionCode)
        --///---///--///---///--///---///--///--///---///--///---///--///---///--/// STRING

            --- reads GD strings (1-4 bytes)
            ---@param strAddress number
            ---@param strSize number
            function readUTFString(strAddress, strSize)
                assert(type(strAddress) == 'number',"string address should be a number, instead got: "..type(strAddress));

                local debugPrefixStr ='>';
                if bDEBUGMode then debugPrefixStr = incDebugStep() end; 
                local MAX_CHARS_TO_READ =  500 * 2

                if strSize and (strSize > MAX_CHARS_TO_READ) then if bDEBUGMode then print( debugPrefixStr..' readUTFString: chars to read is bigger than MAX_CHARS_TO_READ'); decDebugStep(); end; return "ain\'t reading this" end -- we aren't gonna read novels
                if GDSOf.MAJOR_VER >= 4 then if readInteger(strAddress) == 0 then if bDEBUGMode then print( debugPrefixStr..' readUTFString: empty string'); decDebugStep(); end; return "empt str" end else if readSmallInteger(strAddress) == 0 then if bDEBUGMode then print( debugPrefixStr..' readUTFString: empty string'); decDebugStep(); end; return "empt str" end end

                local charTable = {}
                local buff = 0
                
                if GDSOf.MAJOR_VER == 3 and (strSize and strSize > 0) then
                    if bDEBUGMode then decDebugStep(); end;
                    local retString = readString( strAddress, strSize , true ) or '???_INVALID_MEM_CAUGHT_WSIZE'
                    return retString
                elseif GDSOf.MAJOR_VER == 3 then
                    if bDEBUGMode then decDebugStep(); end;

                    local retString = readString( strAddress, MAX_CHARS_TO_READ , true )
                    
                    while MAX_CHARS_TO_READ > 0 and retString == nil do     -- https://github.com/cheat-engine/cheat-engine/issues/2602
                        MAX_CHARS_TO_READ = MAX_CHARS_TO_READ-100 -- quite a big stride
                        retString = readString( strAddress, MAX_CHARS_TO_READ , true )
                    end
                    return retString or '???_INVALID_MEM_CAUGHT'

                end

                if (strSize and strSize > 0) then

                    for i=0, strSize-1 do
                        buff = readInteger(strAddress + i * 0x4) or 0x0
                        if buff == 0 then break end;
                        charTable[#charTable+1] = codePointToUTF8( buff )
                    end

                else
                    --null terminator
                    for i=0, MAX_CHARS_TO_READ do
                        buff = readInteger(strAddress + i * 0x4) or 0x0
                        if buff == 0 then break end;
                        charTable[#charTable+1] = codePointToUTF8( buff )
                    end
                end

                if bDEBUGMode then decDebugStep(); end;
                return table.concat( charTable )
            end

            function codePointToUTF8(codePoint)
                if (codePoint < 0 or codePoint > 0x10FFFF) or (codePoint >= 0xD800 and codePoint <= 0xDFFF) then
                    return 'w-t-f'
                elseif codePoint <= 0x7F then
                    return string.char(codePoint)
                elseif codePoint <= 0x7FF then
                    return string.char(0xC0 | (codePoint >> 6),
                                        0x80 | (codePoint & 0x3F))
                elseif codePoint <= 0xFFFF then
                    return string.char(0xE0 | (codePoint >> 12),
                                        0x80 | ((codePoint >> 6) & 0x3F),
                                        0x80 | (codePoint & 0x3F))
                else
                    return string.char(0xF0 | (codePoint >> 18),
                                        0x80 | ((codePoint >> 12) & 0x3F),
                                        0x80 | ((codePoint >> 6) & 0x3F),
                                        0x80 | (codePoint & 0x3F))
                end
            end

            --- reads a string from StringName
            ---@param stringNamePtr number
            function getStringNameStr(stringNamePtr)
                assert((type(stringNamePtr) == 'number'),"string address should be a number, instead got: "..type(stringNamePtr));

                local debugPrefixStr ='>';
                if bDEBUGMode then debugPrefixStr = incDebugStep() end; 

                local retStringAddr = readPointer(stringNamePtr + GDSOf.STRING)
                if retStringAddr == 0 or retStringAddr == nil then
                    if bDEBUGMode then print( debugPrefixStr..' getStringNameStr: string address invalid, trying ASCII'); end;
                    retStringAddr = readPointer( stringNamePtr + 0x8 ) -- for cases when StringName holds a static ASCII string at 0x8
                    if retStringAddr == 0 or retStringAddr == nil then if bDEBUGMode then print( debugPrefixStr..' getStringNameStr: string address invalid, not ASCII either'); decDebugStep(); end; return '??' end  -- return an empty string if no string was found
                    if bDEBUGMode then decDebugStep(); end;

                    return readString( retStringAddr, 100 )
                end

                if bDEBUGMode then decDebugStep(); end;
                return readUTFString( retStringAddr )
            end

        --///---///--///---///--///---///--///--///---///--///---///--///---///--/// DEFINE

            --- initializes and assigns offsets
            function defineGDOffsets(bOverrideAssumption, majorVersion, oChildren, oObjStringName, oGDScriptInstance, oGDScriptName, oFuncDict, oGDConst, oVariantNameHM, oVariantVector, oVariantNameHMVarType, oVarSize, oVariantHMIndex,
                                        oFuncDictVal, oGDFunctionString, oGDFunctionCode)

                bMonitorNodes = false;
                bDEBUGMode = bDEBUGMode and true or nil
                bASSUMPTIONLOG = bASSUMPTIONLOG and true or nil
                dumpedMonitorNodes = {};
                debugPrefix = 1;

                majorVersion = majorVersion or 0
                
                if GDSOf == nil then GDSOf = {} end
                GDSOf.PTRSIZE = targetIs64Bit() and 0x8 or 0x4

                if bOverrideAssumption and majorVersion >= 4 then

                    GDSOf.MAJOR_VER = majorVersion

                    GDSOf.CHILDREN = oChildren or 0x1C0
                    GDSOf.OBJ_STRING_NAME = oObjStringName or 0x218
                    GDSOf.GDSCRIPTINSTANCE = oGDScriptInstance or 0x68
                    GDSOf.GDSCRIPTNAME = oGDScriptName or 0x168
                    GDSOf.FUNC_MAP = oFuncDict or 0x2C8
                    GDSOf.CONST_MAP = oGDConst or 0x298
                    GDSOf.VAR_NAMEINDEX_MAP = oVariantNameHM or 0x200


                    GDSOf.VAR_VECTOR = oVariantVector or 0x28
                    GDSOf.VAR_NAMEINDEX_VARTYPE = oVariantNameHMVarType or 0x48
                    GDSOf.SIZE_VECTOR = oVarSize or 0x8

                    GDSOf.GDSCRIPT_REF = 0x18
                    GDSOf.MAXTYPE = 39
                    GDSOf.SCRIPTFUNC_STRING = oGDFunctionString or 0x60
                    GDSOf.FUNC_MAPVAL = oFuncDictVal or 0x18
                    GDSOf.FUNC_CODE = oGDFunctionCode or 0x178


                    GDSOf.STRING = 0x10
                    GDSOf.CHILDREN_SIZE = 0x8

                    GDSOf.MAP_SIZE = 0x14

                    GDSOf.ARRAY_TOVECTOR = 0x10
                    GDSOf.P_ARRAY_TOARR = 0x18
                    GDSOf.P_ARRAY_SIZE = 0x8

                    GDSOf.DICT_HEAD = 0x28
                    GDSOf.DICT_TAIL = 0x30
                    GDSOf.DICT_SIZE = 0x3C

                    GDSOf.DICTELEM_KEYTYPE = 0x10
                    GDSOf.DICTELEM_KEYVAL = 0x18
                    GDSOf.DICTELEM_VALTYPE = 0x28

                    GDSOf.CONSTELEM_KEYVAL = 0x10
                    GDSOf.CONSTELEM_VALTYPE = 0x18

                    GDSOf.VAR_NAMEINDEX_I = 0x18

                elseif bOverrideAssumption and majorVersion == 3 then
                    GDSOf.MAJOR_VER = 3

                    GDSOf.CHILDREN = oChildren or 0x108
                    GDSOf.OBJ_STRING_NAME = oObjStringName or 0x130
                    GDSOf.GDSCRIPTINSTANCE = oGDScriptInstance or 0x58
                    GDSOf.GDSCRIPTNAME = oGDScriptName or 0x108
                    GDSOf.FUNC_MAP = oFuncDict or 0x1A8
                    GDSOf.CONST_MAP = oGDConst or 0x190
                    GDSOf.VAR_NAMEINDEX_MAP = oVariantNameHM or 0x1C0

                    GDSOf.VAR_VECTOR = oVariantVector or 0x20
                    GDSOf.SIZE_VECTOR = oVarSize or 0x4

                    GDSOf.VAR_NAMEINDEX_I = oVariantHMIndex or 0x38

                    GDSOf.MAXTYPE = 27
                    GDSOf.SCRIPTFUNC_STRING = oGDFunctionString or 0x80

                    GDSOf.GDSCRIPT_REF = 0x10

                    GDSOf.FUNC_MAPVAL = oFuncDictVal or 0x38
                    GDSOf.FUNC_CODE = oGDFunctionCode or 0x50

                    GDSOf.STRING = 0x10
                    GDSOf.CHILDREN_SIZE = 0x4

                    GDSOf.MAP_SIZE = 0x10
                    GDSOf.MAP_LELEM = 0x10
                    GDSOf.MAP_NEXTELEM = 0x20
                    GDSOf.MAP_KVALUE = 0x30

                    GDSOf.DICT_LIST = 0x8
                    GDSOf.DICT_HEAD = 0x0
                    GDSOf.DICT_TAIL = 0x8
                    GDSOf.DICT_SIZE = 0x10
                    GDSOf.DICTELEM_PAIR_NEXT = 0x20

                    GDSOf.DICTELEM_KEYTYPE = 0x0
                    GDSOf.DICTELEM_KEYVAL = 0x8
                    GDSOf.DICTELEM_VALTYPE = 0x8
                    GDSOf.DICTELEM_VALVAL = 0x10

                    GDSOf.ARRAY_TOVECTOR = 0x10
                    GDSOf.P_ARRAY_TOARR = 0x8
                    GDSOf.P_ARRAY_SIZE = 0x18

                    GDSOf.CONSTELEM_KEYVAL = 0x30
                    GDSOf.CONSTELEM_VALTYPE = 0x38

                elseif ( not bOverrideAssumption ) and majorVersion >= 4 then -- that semi-manual check might be avoided if assumption functions handle versions before 4.2
                        
                        GDSOf.DEBUGVER = false;
                        GDSOf.STRING = 0x10
                    local MAJOR_VER, CHILDREN, OBJ_STRING_NAME = assumeVPOffsets()
                        GDSOf.CHILDREN = CHILDREN
                        GDSOf.OBJ_STRING_NAME = OBJ_STRING_NAME
                        GDSOf.MAJOR_VER = majorVersion -- we know it better

                        GDSOf.GDSCRIPT_REF = 0x18
                        GDSOf.MAXTYPE = 39
                        GDSOf.STRING = 0x10 
                        GDSOf.CHILDREN_SIZE = 0x8 
                        GDSOf.MAP_SIZE = 0x14
                        GDSOf.ARRAY_TOVECTOR = 0x10 
                        GDSOf.P_ARRAY_TOARR = 0x18 
                        GDSOf.P_ARRAY_SIZE = 0x8 
                        GDSOf.DICT_HEAD = 0x28 
                        GDSOf.DICT_TAIL = 0x30 
                        GDSOf.DICT_SIZE = 0x3C 
                        GDSOf.DICTELEM_KEYTYPE = 0x10 
                        GDSOf.DICTELEM_KEYVAL = 0x18 
                        GDSOf.DICTELEM_VALTYPE = 0x28 
                        GDSOf.CONSTELEM_KEYVAL = 0x10 
                        GDSOf.CONSTELEM_VALTYPE = 0x18 
                        GDSOf.VAR_NAMEINDEX_I = 0x18 

                        local GDSCRIPTINSTANCE, GDSCRIPTNAME, FUNC_MAP, CONST_MAP, VAR_MAP, VAR_VECTOR, VAR_VECTOR_SIZE = assumeNodeOffsets()

                        GDSOf.GDSCRIPTINSTANCE = GDSCRIPTINSTANCE
                        GDSOf.GDSCRIPTNAME = GDSCRIPTNAME
                        GDSOf.FUNC_MAP = FUNC_MAP or 0x0
                        GDSOf.CONST_MAP = CONST_MAP or 0x400
                        GDSOf.VAR_NAMEINDEX_MAP = VAR_MAP
                        GDSOf.VAR_VECTOR = VAR_VECTOR
                        GDSOf.VAR_NAMEINDEX_VARTYPE = 0x48
                        GDSOf.SIZE_VECTOR = VAR_VECTOR_SIZE

                        GDSOf.SCRIPTFUNC_STRING = 0x60
                        GDSOf.FUNC_MAPVAL = 0x18 
                        GDSOf.FUNC_CODE = 0x178 

                        if bASSUMPTIONLOG then
                            print("Copy that: (mind that vector size can be 0x4)\n", "true,0x4,"..string.format('0x%x', GDSOf.CHILDREN)..","..string.format('0x%x', GDSOf.OBJ_STRING_NAME)..","..string.format('0x%x', GDSOf.GDSCRIPTINSTANCE)..","..string.format('0x%x', GDSOf.GDSCRIPTNAME)..","..string.format('0x%x',  GDSOf.FUNC_MAP)..","..string.format('0x%x',  GDSOf.CONST_MAP)..","..string.format('0x%x',  GDSOf.VAR_NAMEINDEX_MAP)..","..string.format('0x%x', GDSOf.VAR_VECTOR)..",0x48,"..string.format('0x%x', GDSOf.SIZE_VECTOR))
                        end

                else
                        GDSOf.DEBUGVER = false;
                        GDSOf.STRING = 0x10
                    local MAJOR_VER, CHILDREN, OBJ_STRING_NAME = assumeVPOffsets()
                        GDSOf.CHILDREN = CHILDREN
                        GDSOf.OBJ_STRING_NAME = OBJ_STRING_NAME
                        GDSOf.MAJOR_VER = MAJOR_VER

                    if GDSOf.MAJOR_VER >= 4 then
                        GDSOf.GDSCRIPT_REF = 0x18
                        GDSOf.MAXTYPE = 39
                        GDSOf.STRING = 0x10 
                        GDSOf.CHILDREN_SIZE = 0x8 
                        GDSOf.MAP_SIZE = 0x14
                        GDSOf.ARRAY_TOVECTOR = 0x10 
                        GDSOf.P_ARRAY_TOARR = 0x18 
                        GDSOf.P_ARRAY_SIZE = 0x8 
                        GDSOf.DICT_HEAD = 0x28 
                        GDSOf.DICT_TAIL = 0x30 
                        GDSOf.DICT_SIZE = 0x3C 
                        GDSOf.DICTELEM_KEYTYPE = 0x10 
                        GDSOf.DICTELEM_KEYVAL = 0x18 
                        GDSOf.DICTELEM_VALTYPE = 0x28 
                        GDSOf.CONSTELEM_KEYVAL = 0x10 
                        GDSOf.CONSTELEM_VALTYPE = 0x18 
                        GDSOf.VAR_NAMEINDEX_I = 0x18 

                        local GDSCRIPTINSTANCE, GDSCRIPTNAME, FUNC_MAP, CONST_MAP, VAR_MAP, VAR_VECTOR, VAR_VECTOR_SIZE = assumeNodeOffsets()

                        GDSOf.GDSCRIPTINSTANCE = GDSCRIPTINSTANCE
                        GDSOf.GDSCRIPTNAME = GDSCRIPTNAME
                        GDSOf.FUNC_MAP = FUNC_MAP or 0x0
                        GDSOf.CONST_MAP = CONST_MAP or 0x400
                        GDSOf.VAR_NAMEINDEX_MAP = VAR_MAP
                        GDSOf.VAR_VECTOR = VAR_VECTOR
                        GDSOf.VAR_NAMEINDEX_VARTYPE = 0x48
                        GDSOf.SIZE_VECTOR = VAR_VECTOR_SIZE

                        GDSOf.SCRIPTFUNC_STRING = 0x60
                        GDSOf.FUNC_MAPVAL = 0x18 
                        GDSOf.FUNC_CODE = 0x178 

                        if bASSUMPTIONLOG then
                            print("Copy that: (mind that vector size can be 0x4)\n", "true,0x4,"..string.format('0x%x', GDSOf.CHILDREN)..","..string.format('0x%x', GDSOf.OBJ_STRING_NAME)..","..string.format('0x%x', GDSOf.GDSCRIPTINSTANCE)..","..string.format('0x%x', GDSOf.GDSCRIPTNAME)..","..string.format('0x%x',  GDSOf.FUNC_MAP)..","..string.format('0x%x',  GDSOf.CONST_MAP)..","..string.format('0x%x',  GDSOf.VAR_NAMEINDEX_MAP)..","..string.format('0x%x', GDSOf.VAR_VECTOR)..",0x48,"..string.format('0x%x', GDSOf.SIZE_VECTOR))
                        end

                    else
                        GDSOf.VAR_NAMEINDEX_I = 0x38
                        GDSOf.MAXTYPE = 27
                        GDSOf.GDSCRIPT_REF = 0x10
                        GDSOf.STRING = 0x10
                        GDSOf.CHILDREN_SIZE = 0x4
                        GDSOf.MAP_SIZE = 0x10
                        GDSOf.MAP_LELEM = 0x10
                        GDSOf.MAP_NEXTELEM = 0x20
                        GDSOf.MAP_KVALUE = 0x30
                        GDSOf.DICT_LIST = 0x8
                        GDSOf.DICT_HEAD = 0x0
                        GDSOf.DICT_TAIL = 0x8
                        GDSOf.DICT_SIZE = 0x10
                        GDSOf.DICTELEM_PAIR_NEXT = 0x20
                        GDSOf.DICTELEM_KEYTYPE = 0x0
                        GDSOf.DICTELEM_KEYVAL = 0x8
                        GDSOf.DICTELEM_VALTYPE = 0x8
                        GDSOf.DICTELEM_VALVAL = 0x10
                        GDSOf.ARRAY_TOVECTOR = 0x10
                        GDSOf.P_ARRAY_TOARR = 0x8
                        GDSOf.P_ARRAY_SIZE = 0x18
                        GDSOf.CONSTELEM_KEYVAL = 0x30
                        GDSOf.CONSTELEM_VALTYPE = 0x38

                        local GDSCRIPTINSTANCE, GDSCRIPTNAME, FUNC_MAP, CONST_MAP, VAR_MAP, VAR_VECTOR, VAR_VECTOR_SIZE = assumeNodeOffsets()

                        GDSOf.GDSCRIPTINSTANCE = GDSCRIPTINSTANCE
                        GDSOf.GDSCRIPTNAME = GDSCRIPTNAME
                        GDSOf.FUNC_MAP = FUNC_MAP or 0x0
                        GDSOf.CONST_MAP = CONST_MAP or 0x400
                        GDSOf.VAR_NAMEINDEX_MAP = VAR_MAP
                        GDSOf.VAR_VECTOR = VAR_VECTOR
                        GDSOf.SIZE_VECTOR = VAR_VECTOR_SIZE

                        GDSOf.SCRIPTFUNC_STRING = 0x80
                        GDSOf.FUNC_MAPVAL = oFuncDictVal or 0x38
                        GDSOf.FUNC_CODE = oGDFunctionCode or 0x50

                        if bASSUMPTIONLOG then
                            print("Copy that:\n", "true,0x3,"..string.format('0x%x', GDSOf.CHILDREN)..","..string.format('0x%x', GDSOf.OBJ_STRING_NAME)..","..string.format('0x%x', GDSOf.GDSCRIPTINSTANCE)..","..string.format('0x%x', GDSOf.GDSCRIPTNAME)..","..string.format('0x%x',  GDSOf.FUNC_MAP)..","..string.format('0x%x',  GDSOf.CONST_MAP)..","..string.format('0x%x',  GDSOf.VAR_NAMEINDEX_MAP)..","..string.format('0x%x', GDSOf.VAR_VECTOR)..",nil,"..string.format('0x%x', GDSOf.SIZE_VECTOR)..",0x38")
                        end
                    end

                end

                gdOffsetsDefined = true
                checkGDStringType()
                fuckoffPrint()
            end

            --- not implemented
            function defineGDOpcodes()
                GDOP = {
                OPCODE_OPERATOR = 0,
                }
            end

            -- will use the VP pointer and try to assume the game version and the root offsets
            function assumeVPOffsets()

                function assumeChildrenOffset( viewport )

                    -- children array usually starts at 0x108, the furthest was 0x1C0
                    local CHILDREN;
                    local childrenSize, childrenAddr, nodeAddr;

                    for i=0, 50 do
                        CHILDREN = 0x100 + i * 8 -- 0x100 is the first offset for children, 0x1C0 is the last known offset

                        childrenAddr = readPointer( viewport + CHILDREN )

                        local bOK = true;

                        if childrenAddr ~= 0 and childrenAddr ~= nil then

                            -- let's try 4.x first
                            childrenSize = readInteger( viewport + CHILDREN - 0x8 ) -- size is 8 bytes behind for ~4.2+

                            if childrenSize ~= nil and ( childrenSize > 0 and childrenSize < 100 ) then -- let 100 be an arbitrary node num limit
                                if bASSUMPTIONLOG then print( "assumeVPOffsets: NODECNT: "..childrenSize ) end
                                for j=0, childrenSize-1 do
                                    nodeAddr = readPointer( childrenAddr + j * GDSOf.PTRSIZE )
                                    if nodeAddr == nil or nodeAddr == 0 or ( not isValidPointer( nodeAddr ) ) or ( not isValidPointer( readPointer( nodeAddr ) ) ) then bOK = false; break; end  -- check for ptr, it's vtable
                                end

                                if bOK then
                                    if bASSUMPTIONLOG then print("assumeOffsetsByVP: found a valid CHILDREN offset (4.x): "..string.format('0x%x', CHILDREN) ) end
                                    return true, 4, CHILDREN; -- return true, majorVersion, offset
                                end

                            else -- trying 3.x but also might be <4.2
                                childrenSize = readInteger( childrenAddr - 0x4 ) -- size is 4 bytes behind the 1st item in the array
                                if childrenSize ~= nil and childrenSize > 0 and childrenSize < 60 then
                                    if bASSUMPTIONLOG then print( "assumeVPOffsets: NODECNT: "..childrenSize ) end
                                    for i=0, childrenSize-1 do
                                        nodeAddr = readPointer(childrenAddr + i * 8)
                                        if nodeAddr == nil or nodeAddr == 0 or (not isValidPointer( nodeAddr) ) then bOK = false; break; end  -- if a node is invalid, that's a wrong offset
                                    end

                                    if bOK then
                                        if bASSUMPTIONLOG then print( "assumeOffsetsByVP: found a valid CHILDREN offset (3.x): "..string.format('0x%x', CHILDREN) ) end
                                        return true, 3, CHILDREN; -- return true, majorVersion, offset
                                    end
                                end
                            end


                        end
                    end

                    return;
                end

                function assumeObjNameOffset( CHILDREN, viewport )
                    -- object name is always after the children array
                    local OBJ_STRING_NAME, nodeNamePtr;

                    for i=0, 30 do
                        OBJ_STRING_NAME = CHILDREN + i * 8 -- 0x218 is the first offset for object name, 0x2A0 is the last known offset

                        nodeNamePtr = readPointer( viewport + OBJ_STRING_NAME )
                        if nodeNamePtr ~= 0 and nodeNamePtr ~= nil then
                            if getStringNameStr(nodeNamePtr) == 'root' then -- check for root
                                if bASSUMPTIONLOG then print( "assumeObjNameOffset: found a valid OBJ_STRING_NAME offset: "..string.format('0x%x', OBJ_STRING_NAME) ) end
                                return true, OBJ_STRING_NAME;
                            else
                                
                            end
                        end
                    end

                    return;
                end

                local viewport = getViewport()
                if viewport == 0 or viewport == nil then if bASSUMPTIONLOG then print( "assumeOffsetsByVP: viewport pointer is invalid" ); end error('viewport pointer is invalid') end

                local bSuccess, MAJOR_VER, CHILDREN = assumeChildrenOffset( viewport )
                if not bSuccess then
                    if bASSUMPTIONLOG then print( "<<< assumeOffsetsByVP: failed to assume CHILDREN offset, aborting" ) end
                    error("failed to assume CHILDREN offset")
                end

                GDSOf.MAJOR_VER = MAJOR_VER

                local bSuccess, OBJ_STRING_NAME = assumeObjNameOffset( CHILDREN, viewport )

                if not bSuccess then
                    if bASSUMPTIONLOG then print( "<<< assumeOffsetsByVP: failed to assume OBJ_STRING_NAME offset, aborting" ) end
                    error("failed to assume OBJ_STRING_NAME offset")
                end

                return MAJOR_VER, CHILDREN, OBJ_STRING_NAME
            end

            --- assumes the offsets for GDScriptInstance, GDScriptName, FuncMap, ConstMap, VarMap, VarVector
            function assumeNodeOffsets()

                local mainNodeDict = getMainNodeDict()
                local offsets =
                {
                    ['GDSCRIPTINSTANCE'] = {['offset'] = nil, ['checkedTimes'] = 0},
                    ['GDSCRIPTNAME'] = {['offset'] = nil, ['checkedTimes'] = 0},
                    ['FUNC_MAP'] = {['offset'] = nil, ['checkedTimes'] = 0},
                    ['CONST_MAP'] = {['offset'] = nil, ['checkedTimes'] = 0},
                    ['VAR_MAP'] = {['offset'] = nil, ['checkedTimes'] = 0},
                    ['VAR_VECTOR'] = {['offset'] = nil, ['checkedTimes'] = 0},
                    ['VAR_VECTOR_SIZE'] = {['offset'] = nil, ['checkedTimes'] = 0}
                }

                for key, value in pairs(mainNodeDict) do

                    local bSuccess, GDSCRIPTINSTANCE, gdScriptAddr, VAR_VECTOR, VAR_VECTOR_SIZE = assumeGDScriptOffset( value.PTR ) -- try to assume GDScriptInstance offset
                    if not bSuccess then goto continue end -- if we failed to assume GDScriptInstance, skip this node

                    if GDSCRIPTINSTANCE ~= nil and GDSCRIPTINSTANCE > 0 then
                        if offsets['GDSCRIPTINSTANCE']['offset'] ~= GDSCRIPTINSTANCE and offsets['GDSCRIPTINSTANCE']['checkedTimes'] == 0 then
                            offsets['GDSCRIPTINSTANCE']['offset'] = GDSCRIPTINSTANCE
                            offsets['GDSCRIPTINSTANCE']['checkedTimes'] = offsets['GDSCRIPTINSTANCE']['checkedTimes'] + 1
                        elseif offsets['GDSCRIPTINSTANCE']['offset'] ~= GDSCRIPTINSTANCE and offsets['GDSCRIPTINSTANCE']['checkedTimes'] > 0 then
                            if bASSUMPTIONLOG then print("//===============// assumeNodeOffsets: GDSCRIPTINSTANCE offset changed, this is unexpected: "..string.format('0x%x', GDSCRIPTINSTANCE).." vs. "..string.format('0x%x', offsets['GDSCRIPTINSTANCE']['offset'])) end
                        elseif offsets['GDSCRIPTINSTANCE']['offset'] == GDSCRIPTINSTANCE then 
                            offsets['GDSCRIPTINSTANCE']['checkedTimes'] = offsets['GDSCRIPTINSTANCE']['checkedTimes'] + 1
                        end
                    end

                    if VAR_VECTOR ~= nil and VAR_VECTOR > 0 then
                        if offsets['VAR_VECTOR']['offset'] ~= VAR_VECTOR and offsets['VAR_VECTOR']['checkedTimes'] == 0 then
                            offsets['VAR_VECTOR']['offset'] = VAR_VECTOR
                            offsets['VAR_VECTOR']['checkedTimes'] = offsets['VAR_VECTOR']['checkedTimes'] + 1
                        elseif offsets['VAR_VECTOR']['offset'] ~= VAR_VECTOR and offsets['VAR_VECTOR']['checkedTimes'] > 0 then
                            if bASSUMPTIONLOG then print("//===============// assumeNodeOffsets: VAR_VECTOR offset changed, this is unexpected: "..string.format('0x%x', VAR_VECTOR).." vs. "..string.format('0x%x', offsets['VAR_VECTOR']['offset'])) end
                        elseif offsets['VAR_VECTOR']['offset'] == VAR_VECTOR then 
                            offsets['VAR_VECTOR']['checkedTimes'] = offsets['VAR_VECTOR']['checkedTimes'] + 1
                        end
                    end

                    if VAR_VECTOR_SIZE ~= nil and VAR_VECTOR_SIZE > 0 then
                        if offsets['VAR_VECTOR_SIZE']['offset'] ~= VAR_VECTOR_SIZE and offsets['VAR_VECTOR_SIZE']['checkedTimes'] == 0 then
                            offsets['VAR_VECTOR_SIZE']['offset'] = VAR_VECTOR_SIZE
                            offsets['VAR_VECTOR_SIZE']['checkedTimes'] = offsets['VAR_VECTOR_SIZE']['checkedTimes'] + 1
                        elseif offsets['VAR_VECTOR_SIZE']['offset'] ~= VAR_VECTOR_SIZE and offsets['VAR_VECTOR_SIZE']['checkedTimes'] > 0 then
                            if bASSUMPTIONLOG then print("//===============// assumeNodeOffsets: VAR_VECTOR_SIZE offset changed, this is unexpected: "..string.format('0x%x', VAR_VECTOR_SIZE).." vs. "..string.format('0x%x', offsets['VAR_VECTOR_SIZE']['offset'])) end
                        elseif offsets['VAR_VECTOR_SIZE']['offset'] == VAR_VECTOR_SIZE then 
                            offsets['VAR_VECTOR_SIZE']['checkedTimes'] = offsets['VAR_VECTOR_SIZE']['checkedTimes'] + 1
                        end
                    end

                    local bSuccess, GDSCRIPTNAME, VAR_MAP, CONST_MAP, FUNC_MAP = assumeGDScriptMaps( gdScriptAddr )
                    if not bSuccess then goto continue end

                    if GDSCRIPTNAME ~= nil and GDSCRIPTNAME > 0 then
                        if offsets['GDSCRIPTNAME']['offset'] ~= GDSCRIPTNAME and offsets['GDSCRIPTNAME']['checkedTimes'] == 0 then
                            offsets['GDSCRIPTNAME']['offset'] = GDSCRIPTNAME
                            offsets['GDSCRIPTNAME']['checkedTimes'] = offsets['GDSCRIPTNAME']['checkedTimes'] + 1
                        elseif offsets['GDSCRIPTNAME']['offset'] ~= GDSCRIPTNAME and offsets['GDSCRIPTNAME']['checkedTimes'] > 0 then
                            if bASSUMPTIONLOG then print("//===============// assumeNodeOffsets: GDSCRIPTNAME offset changed, this is unexpected: "..string.format('0x%x', GDSCRIPTNAME).." vs. "..string.format('0x%x', offsets['GDSCRIPTNAME']['offset'])) end
                        elseif offsets['GDSCRIPTNAME']['offset'] == GDSCRIPTNAME then 
                            offsets['GDSCRIPTNAME']['checkedTimes'] = offsets['GDSCRIPTNAME']['checkedTimes'] + 1
                        end
                    end

                    if VAR_MAP ~= nil and VAR_MAP > 0 then
                        if offsets['VAR_MAP']['offset'] ~= VAR_MAP and offsets['VAR_MAP']['checkedTimes'] == 0 then
                            offsets['VAR_MAP']['offset'] = VAR_MAP
                            offsets['VAR_MAP']['checkedTimes'] = offsets['VAR_MAP']['checkedTimes'] + 1
                        elseif offsets['VAR_MAP']['offset'] ~= VAR_MAP and offsets['VAR_MAP']['checkedTimes'] > 0 then
                            if bASSUMPTIONLOG then print("//===============// assumeNodeOffsets: VAR_MAP offset changed, this is unexpected: "..string.format('0x%x', VAR_MAP).." vs. "..string.format('0x%x', offsets['VAR_MAP']['offset'])) end
                        elseif offsets['VAR_MAP']['offset'] == VAR_MAP then 
                            offsets['VAR_MAP']['checkedTimes'] = offsets['VAR_MAP']['checkedTimes'] + 1
                        end
                    end

                    if CONST_MAP ~= nil and CONST_MAP > 0 then
                        if offsets['CONST_MAP']['offset'] ~= CONST_MAP and offsets['CONST_MAP']['checkedTimes'] == 0 then
                            offsets['CONST_MAP']['offset'] = CONST_MAP
                            offsets['CONST_MAP']['checkedTimes'] = offsets['CONST_MAP']['checkedTimes'] + 1
                        elseif offsets['CONST_MAP']['offset'] ~= CONST_MAP and offsets['CONST_MAP']['checkedTimes'] > 0 then
                            if bASSUMPTIONLOG then print("//===============// assumeNodeOffsets: CONST_MAP offset changed, this is unexpected: "..string.format('0x%x', CONST_MAP).." vs. "..string.format('0x%x', offsets['CONST_MAP']['offset'])) end
                        elseif offsets['CONST_MAP']['offset'] == CONST_MAP then 
                            offsets['CONST_MAP']['checkedTimes'] = offsets['CONST_MAP']['checkedTimes'] + 1
                        end
                    end

                    if FUNC_MAP ~= nil and FUNC_MAP > 0 then
                        if offsets['FUNC_MAP']['offset'] ~= FUNC_MAP and offsets['FUNC_MAP']['checkedTimes'] == 0 then
                            offsets['FUNC_MAP']['offset'] = FUNC_MAP
                            offsets['FUNC_MAP']['checkedTimes'] = offsets['FUNC_MAP']['checkedTimes'] + 1
                        elseif offsets['FUNC_MAP']['offset'] ~= FUNC_MAP and offsets['FUNC_MAP']['checkedTimes'] > 0 then
                            if bASSUMPTIONLOG then print("//===============// assumeNodeOffsets: FUNC_MAP offset changed, this is unexpected: "..string.format('0x%x', FUNC_MAP).." vs. "..string.format('0x%x', offsets['FUNC_MAP']['offset'])) end
                        elseif offsets['FUNC_MAP']['offset'] == FUNC_MAP then 
                            offsets['FUNC_MAP']['checkedTimes'] = offsets['FUNC_MAP']['checkedTimes'] + 1
                        end
                    end

                    ::continue::
                end
                    
                if ( offsets['GDSCRIPTINSTANCE']['offset'] ~= nil and offsets['GDSCRIPTINSTANCE']['checkedTimes'] > 0 )
                and ( offsets['GDSCRIPTNAME']['offset'] ~= nil and offsets['GDSCRIPTNAME']['checkedTimes'] > 0 )
                -- and ( offsets['FUNC_MAP']['offset'] ~= nil and offsets['FUNC_MAP']['checkedTimes'] > 0 ) -- not a big deal actually
                and ( offsets['VAR_MAP']['offset'] ~= nil and offsets['VAR_MAP']['checkedTimes'] > 0 )
                and ( offsets['VAR_VECTOR']['offset'] ~= nil and offsets['VAR_VECTOR']['checkedTimes'] > 0 )
                and ( offsets['VAR_VECTOR_SIZE']['offset'] ~= nil and offsets['VAR_VECTOR_SIZE']['checkedTimes'] > 0 ) then
                    if bASSUMPTIONLOG then print("--//-- TIMES: GDSCRIPTINSTANCE: "..offsets['GDSCRIPTINSTANCE']['checkedTimes']..
                    ", GDSCRIPTNAME: "..offsets['GDSCRIPTNAME']['checkedTimes']..
                    ", FUNC_MAP: "..offsets['FUNC_MAP']['checkedTimes']..", VAR_MAP: "..offsets['VAR_MAP']['checkedTimes']..
                    ", VAR_VECTOR: "..offsets['VAR_VECTOR']['checkedTimes']..", VAR_VECTOR_SIZE: "..offsets['VAR_VECTOR_SIZE']['checkedTimes']..
                    ", CONST_MAP: "..offsets['CONST_MAP']['checkedTimes']) end
                    return offsets['GDSCRIPTINSTANCE']['offset'], offsets['GDSCRIPTNAME']['offset'], offsets['FUNC_MAP']['offset'], offsets['CONST_MAP']['offset'], offsets['VAR_MAP']['offset'], offsets['VAR_VECTOR']['offset'], offsets['VAR_VECTOR_SIZE']['offset']
                end

                error("<<< assumeNodeOffsets: failed to assume Node offsets after passing through all nodes, do it yourself pal")
            end

            function assumeGDScriptMaps(gdScriptAddr)
                local bOK = false;
                local bConstPresent = false;
                local GDSCRIPTNAME, VAR_MAP, CONST_MAP, FUNC_MAP, mapAddr, hashAddr, headAddr, tailAddr, mapSize, nextAddr, namePtr, endmapAddr, leftAddr, rightAddr, color, elementIndex;

                -- last resort for 3.x function map can be 8 bytes pointer after the StringName which contains an object which has a StringName at 0x0 that starts with 'res:'

                if GDSOf.MAJOR_VER >= 4 then
                    
                    bOK = false;
                    -- find script name
                    for i=0, 30 do
                        GDSCRIPTNAME = 0x120 + i * 8
                        local gdScriptNameAddr = readPointer( gdScriptAddr + GDSCRIPTNAME )
                        if gdScriptNameAddr ~= nil and gdScriptNameAddr ~= 0 then
                            if readUTFString( gdScriptNameAddr, 4*2 ) == 'res:' then
                                if bASSUMPTIONLOG then print( "assumeGDScriptMaps: found a valid GDSCRIPTNAME offset: "..string.format('0x%x', GDSCRIPTNAME) ) end
                                bOK = true
                                break;
                            end
                        end
                    end

                    if not bOK then if bASSUMPTIONLOG then print( "<<< assumeGDScriptMaps: failed to assume GDSCRIPTNAME offset, skipping" ); end GDSCRIPTNAME = nil end

                    bOK = false;
                    -- variant map
                    for i=0,40 do
                        VAR_MAP = GDSCRIPTNAME + i * 8
                        mapAddr = readPointer( gdScriptAddr + VAR_MAP )
                        if mapAddr ~= nil and mapAddr ~= 0 then
                            hashAddr = readPointer( gdScriptAddr + VAR_MAP+0x8 ) -- the whole hashmap
                            headAddr = readPointer( gdScriptAddr + VAR_MAP+0x10 )
                            tailAddr = readPointer( gdScriptAddr + VAR_MAP+0x18 )
                            mapSize = readInteger( gdScriptAddr + VAR_MAP+0x24 )

                            if ( hashAddr ~= nil and isValidPointer( hashAddr ) )
                            and ( headAddr ~= nil and isValidPointer( headAddr ) )
                            and ( tailAddr ~= nil and isValidPointer( tailAddr ) )
                            and mapSize > 0 and mapSize < 900 then

                                nextAddr = readPointer( headAddr )
                                namePtr = readPointer( headAddr + 0x10 )

                                if ( nextAddr ~= nil and isValidPointer( nextAddr ) ) and ( namePtr ~= nil and isValidPointer( namePtr ) ) then
                                    if readInteger( nextAddr + 0x18 ) == 1 then -- check the index
                                        VAR_MAP = VAR_MAP + 0x10
                                        if bASSUMPTIONLOG then print( "assumeGDScriptMaps: found a valid #3 VAR_MAP offset: "..string.format('0x%x', VAR_MAP) ) end
                                        bOK = true;
                                        break;
                                    end
                                end

                            end
                        end
                    end

                    if not bOK then if bASSUMPTIONLOG then print( "<<< assumeGDScriptMaps: failed to assume VAR_MAP offset, skipping" ); end  VAR_MAP = nil end

                    -- constant map (if it exists)
                    for i=0,40 do

                        CONST_MAP = 0x1F0 + i * 8 -- 4.x version are usually sequential, starts from 0x1F0
                        mapAddr = readPointer( gdScriptAddr + CONST_MAP )
                        if mapAddr ~= nil and mapAddr ~= 0 then
                            hashAddr = readPointer( gdScriptAddr + CONST_MAP+0x8 ) -- the whole hashmap
                            headAddr = readPointer( gdScriptAddr + CONST_MAP+0x10 )
                            tailAddr = readPointer( gdScriptAddr + CONST_MAP+0x18 )
                            mapSize = readInteger( gdScriptAddr + CONST_MAP+0x24 )

                            if ( hashAddr ~= nil and isValidPointer( hashAddr ) )
                            and ( headAddr ~= nil and isValidPointer( headAddr ) )
                            and ( tailAddr ~= nil and isValidPointer( tailAddr ))
                            and mapSize > 0 and mapSize < 900 then
                                local nextPtr = readPointer( headAddr )
                                local namePtr = readPointer( headAddr + 0x10 )
                                local elementType = readInteger( headAddr + 0x18 ) -- element type is at 0x18

                                if ( nextPtr ~= nil and isValidPointer( nextPtr ) ) and ( namePtr ~= nil and isValidPointer( namePtr ) ) and ( elementType > 0 and elementType < GDSOf.MAXTYPE ) then
                                    CONST_MAP = CONST_MAP + 0x10
                                    if bASSUMPTIONLOG then print( "assumeGDScriptMaps: found a valid #2 CONST_MAP offset: "..string.format('0x%x', CONST_MAP) ) end
                                    bConstPresent = true;
                                    break;
                                end

                            end
                        end
                    end

                    if not bConstPresent then if bASSUMPTIONLOG then print( "<<< assumeGDScriptMaps: failed to assume CONST_MAP offset, probably not used" ); end CONST_MAP = nil end

                    bOK = false;
                    -- function map
                    for i=0,35 do
                        if bConstPresent then
                            FUNC_MAP = CONST_MAP+0x18 + i * 8
                        else
                            FUNC_MAP = 0x260 + i * 8 -- not sure about this offset though
                        end

                        mapAddr = readPointer( gdScriptAddr + FUNC_MAP )
                        if mapAddr ~= nil and mapAddr ~= 0 then
                            hashAddr = readPointer( gdScriptAddr + FUNC_MAP+0x8 ) -- the whole hashmap
                            headAddr = readPointer( gdScriptAddr + FUNC_MAP+0x10 )
                            tailAddr = readPointer( gdScriptAddr + FUNC_MAP+0x18 )
                            mapSize = readInteger( gdScriptAddr + FUNC_MAP+0x24 )

                            if ( hashAddr ~= nil and isValidPointer( hashAddr ) )
                            and ( headAddr ~= nil and isValidPointer( headAddr ) ) 
                            and ( tailAddr ~= nil and isValidPointer( tailAddr ) )
                            and mapSize > 0 and mapSize < 900 then
                                local nextPtr = readPointer( headAddr )
                                local prevPtr = readInteger( headAddr + 0x8 )
                                local namePtr = readPointer( headAddr + 0x10 )
                                local funcPtr = readPointer( headAddr + 0x18 )

                                if ( nextPtr ~= nil and isValidPointer( nextPtr ) ) and ( namePtr ~= nil and isValidPointer( namePtr ) ) and ( funcPtr ~= nil and isValidPointer( funcPtr ) ) then
                                    FUNC_MAP = FUNC_MAP + 0x10
                                    if bASSUMPTIONLOG then print( "assumeGDScriptMaps: found a valid #1 FUNC_MAP offset: "..string.format('0x%x', FUNC_MAP) ) end
                                    bOK = true;
                                    break;
                                end
                            end
                        end
                    end

                    if not bOK then if bASSUMPTIONLOG then print( "<<< assumeGDScriptMaps: failed to assume FUNC_MAP offset, skipping" ); end FUNC_MAP = nil end


                else -------------------------------------------------------------------------- 3.x

                    -- find script name
                    for i=0, 20 do
                        GDSCRIPTNAME = 0x100 + i * 8 -- 0x100 is the earliest offset for GDScriptName I've seen
                        local gdScriptNameAddr = readPointer( gdScriptAddr + GDSCRIPTNAME )
                        if gdScriptNameAddr ~= nil and gdScriptNameAddr ~= 0 then
                            if readUTFString( gdScriptNameAddr, 4*2 ) == 'res:' then
                                if bASSUMPTIONLOG then print( "assumeGDScriptMaps: found a valid GDSCRIPTNAME offset: "..string.format('0x%x', GDSCRIPTNAME) ) end
                                bOK = true
                                break;
                            end
                        end
                    end

                    if not bOK then if bASSUMPTIONLOG then print( "<<< assumeGDScriptMaps: failed to assume GDSCRIPTNAME offset, skipping" ); end GDSCRIPTNAME = nil end

                    bOK = false;

                    -- constant map (if it exists) | First comes a variant map with no index, next constants, function and a variant map with indices
                    for i=0,8 do
                        CONST_MAP = 0x188 + i * 8 -- 0x188 is the earlies I know
                        mapAddr = readPointer( gdScriptAddr + CONST_MAP )
                        endmapAddr = readPointer( gdScriptAddr + CONST_MAP+0x8 )
                        mapSize = readInteger( gdScriptAddr + CONST_MAP+0x10 )

                        if ( mapAddr ~= nil and mapAddr ~= 0 ) and ( endmapAddr ~= nil and endmapAddr ~= 0 ) and mapSize > 0 and mapSize < 900  then
                            color = readInteger( mapAddr )
                            leftAddr = readPointer( mapAddr + 0x8 ) -- RedBlack-map
                            rightAddr = readPointer( mapAddr + 0x10 )
                            nextAddr = readPointer( mapAddr + 0x18 )

                            if ( color == 1 )
                            and ( leftAddr ~= nil and isValidPointer( leftAddr ) )
                            and ( rightAddr ~= nil and isValidPointer( rightAddr ) )
                            and ( nextAddr ~= nil and isValidPointer( nextAddr ) )
                            and ( nextAddr == leftAddr and rightAddr ~= endmapAddr ) then

                                namePtr = readPointer( rightAddr + 0x30 )
                                local elementType = readInteger( rightAddr + 0x38 ) -- element type is at 0x18
                                if ( namePtr ~= nil and isValidPointer( namePtr ) ) and ( elementType > 0 and elementType < GDSOf.MAXTYPE ) then
                                    if bASSUMPTIONLOG then print( "assumeGDScriptMaps: found a valid #2 CONST_MAP offset: "..string.format('0x%x', CONST_MAP) ) end
                                    bConstPresent = true;
                                    break;
                                end

                            end
                        end
                    end

                    if not bConstPresent then if bASSUMPTIONLOG then print( "<<< assumeGDScriptMaps: failed to assume CONST_MAP offset, probably not used" ); end CONST_MAP = nil end

                    bOK = false;
                    -- function map
                    for i=0,20 do
                        if bConstPresent then
                            FUNC_MAP = CONST_MAP+0x18 + i * 8
                        else
                            FUNC_MAP = 0x1A0 + 0x18*2 + i * 8 -- 0x1A0 start | GDSCRIPTNAME + (0x18+0x28)+ 0x18*2
                        end

                        mapAddr = readPointer( gdScriptAddr + FUNC_MAP )
                        endmapAddr = readPointer( gdScriptAddr + FUNC_MAP+0x8 )
                        mapSize = readInteger( gdScriptAddr + FUNC_MAP+0x10 )

                        if ( mapAddr ~= nil and mapAddr ~= 0 ) and ( endmapAddr ~= nil and endmapAddr ~= 0 ) and mapSize > 0 and mapSize < 900  then
                            color = readInteger( mapAddr )
                            leftAddr = readPointer( mapAddr + 0x8 ) -- RedBlack-map
                            rightAddr = readPointer( mapAddr + 0x10 )
                            nextAddr = readPointer( mapAddr + 0x18 )

                            if ( color == 1 )
                            and ( leftAddr ~= nil and isValidPointer( leftAddr ) )
                            and ( rightAddr ~= nil and isValidPointer( rightAddr ) )
                            and ( nextAddr ~= nil and isValidPointer( nextAddr ) )
                            and ( nextAddr == leftAddr and rightAddr ~= endmapAddr ) then

                                namePtr = readPointer( rightAddr + 0x30 )
                                local funcPtr = readPointer( rightAddr + 0x38 ) -- it's 0x0 offset is a gdscriptName ptr
                                local funcData = readPointer( rightAddr + 0x40 ) -- not sure what's that actually

                                if ( namePtr ~= nil and isValidPointer( namePtr ) ) and ( funcPtr ~= nil and isValidPointer( funcPtr ) ) and ( funcData ~= nil and isValidPointer( funcData ) ) then
                                    if bASSUMPTIONLOG then print( "assumeGDScriptMaps: found a valid #1 FUNC_MAP offset: "..string.format('0x%x', FUNC_MAP) ) end
                                    bOK = true;
                                    break;
                                end
                            end
                        end
                    end

                    if not bOK then if bASSUMPTIONLOG then print( "<<< assumeGDScriptMaps: failed to assume FUNC_MAP offset, skipping" ); end FUNC_MAP = nil end

                    bOK = false;
                    -- variant map (2nd map with indices)
                    for i=0,8 do
                        if FUNC_MAP ~= nil then
                            VAR_MAP = FUNC_MAP + 0x18 + i * 8 -- right after the func map
                        elseif CONST_MAP ~= nil then
                            VAR_MAP = CONST_MAP + 0x18*2 + i * 8 -- just 1 map after the const map
                        else
                            VAR_MAP = 0x1B8 + i * 8 -- usually starts at 0x1B8 | FUNC_MAP+0x18 | CONST_MAP + 0x18*2
                        end
                        
                        mapAddr = readPointer( gdScriptAddr + VAR_MAP )
                        endmapAddr = readPointer( gdScriptAddr + VAR_MAP+0x8 )
                        mapSize = readInteger( gdScriptAddr + VAR_MAP+0x10 )

                        if ( mapAddr ~= nil and mapAddr ~= 0 ) and ( endmapAddr ~= nil and endmapAddr ~= 0 ) and mapSize > 0 and mapSize < 900  then
                            color = readInteger( mapAddr )
                            leftAddr = readPointer( mapAddr + 0x8 ) -- RedBlack-map
                            rightAddr = readPointer( mapAddr + 0x10 )
                            nextAddr = readPointer( mapAddr + 0x18 )
                            elementIndex = readInteger( mapAddr + 0x38 )

                            if ( color == 1 )
                            and ( leftAddr ~= nil and isValidPointer( leftAddr ) )
                            and ( rightAddr ~= nil and isValidPointer( rightAddr ) )
                            and ( nextAddr ~= nil and isValidPointer( nextAddr ) )
                            and ( nextAddr == leftAddr and rightAddr ~= endmapAddr )
                            and elementIndex >= 0 and elementIndex < mapSize then

                                namePtr = readPointer( rightAddr + 0x30 )
                                if ( namePtr ~= nil and isValidPointer( namePtr ) ) then
                                    if bASSUMPTIONLOG then print( "assumeGDScriptMaps: found a valid #3 VAR_MAP offset: "..string.format('0x%x', VAR_MAP) ) end
                                    bOK = true;
                                    break;
                                end
                            end
                        end
                    end

                    if not bOK then if bASSUMPTIONLOG then print( "<<< assumeGDScriptMaps: failed to assume VAR_MAP offset, skipping" ); end VAR_MAP = nil end
                end

                return true, GDSCRIPTNAME, VAR_MAP, CONST_MAP, FUNC_MAP

            end

            function assumeGDScriptOffset(nodeAddr)    
                local GDSCRIPTINSTANCE, VAR_VECTOR, VAR_VECTOR_SIZE, scriptInstanceAddr, gdScriptAddr, nodeRefAddr;

                for i=0, 5 do
                    GDSCRIPTINSTANCE = 0x50 + i * 8 -- 0x50 is the first offset for GDScriptInstance, 0x70 is the last known offset
                    scriptInstanceAddr = readPointer( nodeAddr + GDSCRIPTINSTANCE )
                    if scriptInstanceAddr ~= nil and isValidPointer( scriptInstanceAddr ) then

                        if GDSOf.MAJOR_VER >= 4 then
                            gdScriptAddr = readPointer( scriptInstanceAddr + 0x18 ) -- gdscript ref is after the owner (node)
                            nodeRefAddr = readPointer( scriptInstanceAddr + 0x10 ) -- node reference

                            if ( gdScriptAddr ~= nil and gdScriptAddr ~= 0 ) and nodeRefAddr == nodeAddr then -- check for a valid script reference
                                if GDSCRIPTINSTANCE == 0x70 then
                                    VAR_VECTOR, VAR_VECTOR_SIZE = assumeVarVectorOffset( scriptInstanceAddr, true )
                                else
                                    VAR_VECTOR, VAR_VECTOR_SIZE = assumeVarVectorOffset( scriptInstanceAddr, false )
                                end

                                if bASSUMPTIONLOG then print( "assumeGDScriptOffset: found a valid GDSCRIPTINSTANCE offset: "..string.format('0x%x', GDSCRIPTINSTANCE) ) end
                                return true, GDSCRIPTINSTANCE, gdScriptAddr, VAR_VECTOR, VAR_VECTOR_SIZE;
                            end

                        else
                            gdScriptAddr = readPointer( scriptInstanceAddr + 0x10 ) -- gdscript ref is after the owner (node)
                            nodeRefAddr = readPointer( scriptInstanceAddr + 0x08 ) -- node reference

                            if ( gdScriptAddr ~= nil and gdScriptAddr ~= 0 ) and nodeRefAddr == nodeAddr then -- check for a valid script reference
                                if GDSCRIPTINSTANCE == 0x60 then
                                    VAR_VECTOR, VAR_VECTOR_SIZE = assumeVarVectorOffset( scriptInstanceAddr, true )
                                else
                                    VAR_VECTOR, VAR_VECTOR_SIZE = assumeVarVectorOffset( scriptInstanceAddr, false )
                                end

                                if bASSUMPTIONLOG then print( "assumeGDScriptOffset: found a valid GDSCRIPTINSTANCE offset: "..string.format('0x%x', GDSCRIPTINSTANCE) ) end
                                return true, GDSCRIPTINSTANCE, gdScriptAddr, VAR_VECTOR, VAR_VECTOR_SIZE;
                            end
                        end

                    end
                end

                return;
            end

            function assumeVarVectorOffset(gdScriptInstanceAddr, bDEBUG)
                -- so far the offsets were mostly consistent for both major versions
                local firstType, vectorAddr, VAR_VECTOR, VAR_VECTOR_SIZE;

                if GDSOf.MAJOR_VER >= 4 then
                    if bDEBUG then
                        vectorAddr = readPointer( gdScriptInstanceAddr + 0x58 )
                        if vectorAddr ~= nil and isValidPointer( vectorAddr ) then firstType = readInteger( vectorAddr ) else return end
                    else
                        vectorAddr = readPointer( gdScriptInstanceAddr + 0x28 )
                        if vectorAddr ~= nil and isValidPointer( vectorAddr ) then firstType = readInteger( vectorAddr ) else return end
                    end

                    if ( firstType >= 0 and firstType < GDSOf.MAXTYPE ) then
                        local vectorSize = readInteger( vectorAddr-0x4 )
                        local vectorSizeLong = readInteger( vectorAddr-0x8 )

                        if (vectorSize < 0 or vectorSize > 1500) and (vectorSizeLong < 0 or vectorSizeLong > 1500) then
                            if bASSUMPTIONLOG then print( "<<< assumeVarVectorOffset: failed to assume VAR_VECTOR/SIZE offset, size not in [0;1500)" ) end
                            error("failed to assume VAR_VECTOR offset")
                        elseif vectorSizeLong >= 0 and vectorSizeLong < 1500 then
                            VAR_VECTOR_SIZE = 0x8
                            if bASSUMPTIONLOG then print( "assumeVarVectorOffset: assuming VAR_VECTOR_SIZE (4.x) is 0x8" ) end
                        elseif vectorSize >= 0 and vectorSize < 1500 then
                            VAR_VECTOR_SIZE = 0x4
                            if bASSUMPTIONLOG then print( "assumeVarVectorOffset: assuming VAR_VECTOR_SIZE (4.x) is 0x4" ) end
                        else
                            if bASSUMPTIONLOG then print( "<<< assumeVarVectorOffset: failed to assume VAR_VECTOR_SIZE, aborting" ) end
                            error("failed to assume VAR_VECTOR size")
                        end

                        if bDEBUG then
                            GDSOf.DEBUGVER = true;
                            VAR_VECTOR = 0x58
                            if bASSUMPTIONLOG then print( "assumeVarVectorOffset: assuming VAR_VECTOR (4.x) is 0x58" ) end
                            return VAR_VECTOR, VAR_VECTOR_SIZE
                        else
                            GDSOf.DEBUGVER = false;
                            VAR_VECTOR = 0x28
                            if bASSUMPTIONLOG then print( "assumeVarVectorOffset: assuming VAR_VECTOR (4.x) is 0x28" ) end
                            return VAR_VECTOR, VAR_VECTOR_SIZE
                        end
                    else
                        if bASSUMPTIONLOG then print( "<<< assumeVarVectorOffset (4.x): failed to assume VAR_VECTOR offset, aborting" ) end
                        error("failed to assume VAR_VECTOR offset")
                    end

                else
                    if bDEBUG then
                        local vectorAddr = readPointer( gdScriptInstanceAddr + 0x38 )
                        if vectorAddr ~= nil and isValidPointer( vectorAddr ) then firstType = readInteger( vectorAddr ) else return end
                    else
                        local vectorAddr = readPointer( gdScriptInstanceAddr + 0x20 )
                        if vectorAddr ~= nil and isValidPointer( vectorAddr ) then firstType = readInteger( vectorAddr ) else return end
                    end

                    if ( firstType >= 0 and firstType < GDSOf.MAXTYPE ) then

                        if bDEBUG then
                            GDSOf.DEBUGVER = true;
                            VAR_VECTOR = 0x38
                            VAR_VECTOR_SIZE = 0x4
                            if bASSUMPTIONLOG then print( "assumeVarVectorOffset: assuming VAR_VECTOR_SIZE (3.x) is 0x4" ) end
                            if bASSUMPTIONLOG then print( "assumeVarVectorOffset: assuming VAR_VECTOR (3.x) is 0x38" ) end
                            return VAR_VECTOR, VAR_VECTOR_SIZE
                        else
                            GDSOf.DEBUGVER = false;
                            if bASSUMPTIONLOG then print( "assumeVarVectorOffset: assuming VAR_VECTOR_SIZE (3.x) is 0x4" ) end
                            if bASSUMPTIONLOG then print( "assumeVarVectorOffset: assuming VAR_VECTOR (3.x) is 0x20" ) end
                            VAR_VECTOR = 0x20
                            VAR_VECTOR_SIZE = 0x4
                            return VAR_VECTOR, VAR_VECTOR_SIZE
                        end 
                    else
                        if bASSUMPTIONLOG then print( "<<< assumeVarVectorOffset: failed to assume VAR_VECTOR offset, aborting" ) end
                        error("failed to assume VAR_VECTOR offset")
                    end

                end

            end

        --///---///--///---///--///---///--///--///---///--///---///--///---///--/// Viewport

            --- returns a valid Viewport pointer
            --- @return number
            function getViewport()

                local viewport = readPointer("ptVP")
                if viewport == 0 or viewport == nil then print("Viewport pointer is invalid; something's wrong"); error('viewport pointer is invalid, couldn\'t read') end
                return viewport
            end

            --- returns a childrenArrayPtr and its size
            ---@return number
            function getVPChildren()
                local viewport = getViewport()

                local debugPrefixStr ='>';
                if bDEBUGMode then debugPrefixStr = incDebugStep() end;

                local childrenPtr = readPointer( viewport + GDSOf.CHILDREN ) -- viewport has an array of all main ingame Nodes, those Nodes can contain further nodes
                if childrenPtr == 0 or childrenPtr == nil then if bDEBUGMode then print( debugPrefixStr..' getVPChildren: failed to get VP children'); decDebugStep(); end; return; end

                local childrenSize;
                if GDSOf.MAJOR_VER == 4 then
                    childrenSize = readInteger( viewport + GDSOf.CHILDREN - GDSOf.CHILDREN_SIZE ) -- size is 8 bytes behind
                elseif GDSOf.MAJOR_VER > 4 then
                    childrenSize = readInteger( childrenPtr - GDSOf.CHILDREN_SIZE ) -- versions before ~4.2 have size inside the array 4 bytes behind
                else
                    childrenSize = readInteger( childrenPtr - GDSOf.CHILDREN_SIZE )
                end

                if childrenSize == 0 or childrenSize == nil then if bDEBUGMode then print( debugPrefixStr..' getVPChildren: ChildSize is invalid'); decDebugStep(); end; return; end

                if bDEBUGMode then decDebugStep(); end;
                return childrenPtr, childrenSize
            end

        --///---///--///---///--///---///--///--///---///--///---///--///---///--/// Node

            --- returns a code with a ScriptInstance initialized
            ---@param nodeName string
            function getNodeWithGDScriptInstance(nodeName)
                assert(type(nodeName) == "string",'Node name should be a string, instead got: '..type(nodeName))

                local childrenPtr, childrenSize = getVPChildren()
                if childrenPtr == nil or childrenSize == nil then return end

                local debugPrefixStr ='>';
                if bDEBUGMode then debugPrefixStr = incDebugStep() end; 

                for i=0,( childrenSize-1 ) do

                    local nodeAddr = readPointer( childrenPtr + i* GDSOf.PTRSIZE )
                    if nodeAddr == 0 or nodeAddr == nil then if bDEBUGMode then print( debugPrefixStr..' getNodeWithGDScriptInstance: nodeAddr invalid'); decDebugStep(); end; return end

                    local nodeNameStr = getNodeName(nodeAddr)
                    local gdScriptInsance = readQword( nodeAddr + GDSOf.GDSCRIPTINSTANCE )
                    if gdScriptInsance == nil or gdScriptInsance == 0 then if bDEBUGMode then print( debugPrefixStr..' getNodeWithGDScriptInstance: ScriptInstance is 0/nil'); decDebugStep(); end; return end

                    if nodeNameStr == nodeName then
                        if bDEBUGMode then decDebugStep(); end;

                        return nodeAddr
                    end
                end
                if bDEBUGMode then decDebugStep(); end;

                return
            end

            --- get a Node name by addr
            ---@param nodeAddr number
            function getNodeName( nodeAddr )
                assert(type(nodeAddr) == 'number',"getNodeName: Node Addr has to be a number, instead got: "..type(nodeAddr))

                local debugPrefixStr ='>';
                if bDEBUGMode then debugPrefixStr = incDebugStep() end;

                local nodeNamePtr = readPointer( nodeAddr + GDSOf.OBJ_STRING_NAME )
                if nodeNamePtr == nil or nodeNamePtr == 0 or ( not isValidPointer( nodeNamePtr ) ) then if bDEBUGMode then print( debugPrefixStr..' getNodeName: nodeName invalid or not a pointer (?)'); decDebugStep(); end; return end

                nodeNamePtr = readPointer( nodeNamePtr + GDSOf.STRING )
                if nodeNamePtr == 0 or nodeNamePtr == nil then
                    if bDEBUGMode then print( debugPrefixStr..' getNodeName: string address invalid, trying ASCII'); end;

                    nodeNamePtr = readPointer( nodeAddr + GDSOf.OBJ_STRING_NAME )
                    nodeNamePtr = readPointer( nodeNamePtr + 0x8 ) -- for cases when StringName holds a static ASCII string at 0x8
                    if nodeNamePtr == 0 or nodeNamePtr == nil then if bDEBUGMode then print( debugPrefixStr..' getNodeName: string address invalid, not ASCII either'); decDebugStep(); end; return 'N??' end  -- return empty string if no string was found
                    if bDEBUGMode then decDebugStep(); end;

                    return readString( nodeNamePtr, 100 )

                end
                if bDEBUGMode then decDebugStep(); end;

                return readUTFString( nodeNamePtr )
            end

            --- Used to validate an object as a Node, returns true if valid
            ---@param nodeAddr number
            function checkForGDScript(nodeAddr)

                local debugPrefixStr ='>';
                if bDEBUGMode and inMainThread() then debugPrefixStr = incDebugStep() end; 

                if nodeAddr == 0 or nodeAddr == nil then if bDEBUGMode and inMainThread() then print( debugPrefixStr..' checkForGDScript: nodeAddr invalid'); decDebugStep(); end; return false end

                if (not isValidPointer( readPointer( nodeAddr ) ) ) then if bDEBUGMode and inMainThread() then print( debugPrefixStr..' checkForGDScript: Node vTable invalid'); decDebugStep(); end; return false end

                local scriptInstance = readPointer( nodeAddr + GDSOf.GDSCRIPTINSTANCE )
                if scriptInstance == nil or scriptInstance == 0 then if bDEBUGMode and inMainThread() then print( debugPrefixStr..' checkForGDScript: ScriptInstance is 0/nil'); decDebugStep(); end; return false end
                
                local gdscript = readPointer( scriptInstance + GDSOf.GDSCRIPT_REF )
                if ( (gdscript == nil) or (gdscript == 0) ) then if bDEBUGMode and inMainThread() then print( debugPrefixStr..' checkForGDScript: GDScript is 0/nil'); decDebugStep(); end; return false end;

                if isValidPointer( gdscript ) and isValidPointer( scriptInstance ) then

                    if getGDResName( nodeAddr, 4*2 ) == 'res:'  then

                        if bDEBUGMode and inMainThread() then decDebugStep(); end;
                        return true;

                    else

                        if bDEBUGMode and inMainThread() then print( debugPrefixStr..' checkForGDScript: getGDResName returned false for res://'); decDebugStep(); end
                        return false;

                    end

                else
                    if bDEBUGMode and inMainThread() then print( debugPrefixStr..' checkForGDScript: Script/Instance probably not a pointer: '..string.format('gdScript %x ', gdscript)..string.format('ScriptInstance %x ', scriptInstance)); decDebugStep(); end

                    return false;

                end
            end

            --- go over child nodes in the main nodes
            ---@param nodeAddr number
            ---@param Owner userdata
            function iterateMNodeToAddr(nodeAddr, Owner)
                assert( type(nodeAddr) == 'number',"iterateMNodeToAddr: node addr has to be a number, instead got: "..type(nodeAddr))
                assert( type(Owner) == "userdata" ,"iterateMNodeToAddr: Owner has to exist")

                local debugPrefixStr ='>';
                if bDEBUGMode then debugPrefixStr = incDebugStep() end; 

                local nodeName = getNodeName( nodeAddr )
                if bDEBUGMode then print( debugPrefixStr..' iterateMNodeToAddr: MemberNode: '..tostring(nodeName) ) end
                for i, storedNode in ipairs(dumpedNodes) do -- check if a node was already dumped
                    if storedNode == nodeAddr then
                        if bDEBUGMode then print( debugPrefixStr..' iterateMNodeToAddr: NODE '..tostring(nodeName)..' ALREADY DUMPED' ); decDebugStep(); end;

                        synchronize(function(Owner)
                                Owner.setDescription( Owner.Description .. ' /D/' ) -- let's note what nodes are copies
                                Owner.Options = '[moHideChildren]'
                            end, Owner
                        )

                        return
                    end
                end
                table.insert( dumpedNodes , nodeAddr )

                synchronize(function( nodeName , Owner )
                        Owner.setDescription( Owner.Description .. ' : '..tostring( nodeName ) ) -- append node name
                    end, nodeName, Owner
                )

                if bDEBUGMode then print( debugPrefixStr..' iterateMNodeToAddr: STEP: Constants for: '..tostring(nodeName) ) end

                local newConstRec = synchronize(function(Owner)
                            local addrList = getAddressList()
                            local newConstRec = addrList.createMemoryRecord()
                            newConstRec.setDescription( "Consts:" )
                            newConstRec.setAddress( 0xBABE )
                            newConstRec.setType( vtPointer )
                            newConstRec.Options = '[moHideChildren, moAllowManualCollapseAndExpand, moManualExpandCollapse]'
                            newConstRec.DontSave = true
                            newConstRec.appendToEntry( Owner )
                            return newConstRec
                        end, Owner
                    )

                iterateNodeConstToAddr( nodeAddr , newConstRec )

                if bDEBUGMode then print( debugPrefixStr..' iterateMNodeToAddr: STEP: VARIANTS for: '..tostring(nodeName) ) end
                iterateVecVarToAddr( nodeAddr , Owner)

                if bDEBUGMode then decDebugStep(); end;
                return
            end

            --- builds the structure layout for a Node when guessed
            ---@param nodeAddr number
            ---@param scriptInstStructElement userdata
            function iterateNodeToStruct(nodeAddr, scriptInstStructElement)

                local debugPrefixStr ='>';
                local nodeName;
                if bDEBUGMode then debugPrefixStr = incDebugStep() end;         
                if bDEBUGMode then nodeName = getNodeName( nodeAddr ); print( debugPrefixStr..' iterateNodeToStruct: Node: '..tostring(nodeName) ) end

                for i, storedNode in ipairs(dumpedDissectorNodes) do -- check if a node was already dumped
                    if storedNode == nodeAddr then
                        if bDEBUGMode then print( debugPrefixStr..' iterateNodeToStruct: NODE '..tostring(nodeName)..' ALREADY DUMPED' ); decDebugStep(); end;
                        Owner.Name = Owner.Name..' /D/'
                        return
                    end
                end
                table.insert( dumpedDissectorNodes , nodeAddr )

                local varVectorStructElem = addLayoutStructElem( scriptInstStructElement, 'Variants', 0x000080, GDSOf.VAR_VECTOR, vtPointer )
                local scriptStructElem = addLayoutStructElem( scriptInstStructElement, 'GDScript', 0x008080, GDSOf.GDSCRIPT_REF, vtPointer )
                local constMapStructElem = addLayoutStructElem( scriptStructElem, 'Consts', 0x400000, GDSOf.CONST_MAP, vtPointer )

                if bDEBUGMode then print( debugPrefixStr..' iterateNodeToStruct: STEP: VARIANTS for: '..tostring(nodeName) ) end
                varVectorStructElem.ChildStruct = createStructure( 'Vars' )
                iterateVecVarToStruct( nodeAddr , varVectorStructElem )        

                if bDEBUGMode then print( debugPrefixStr..' iterateNodeToStruct: STEP: Constants for: '..tostring(nodeName) ) end
                constMapStructElem.ChildStruct = createStructure( 'Consts' )
                iterateNodeConstToStruct( nodeAddr , constMapStructElem )

                if bDEBUGMode then decDebugStep(); end;
                return
            end

            --- go over child nodes in the main nodes
            ---@param nodeAddr number
            function iterateMNode(nodeAddr)
                if type(nodeAddr) ~= 'number' then return end

                for i, storedNode in ipairs(dumpedMonitorNodes) do -- check if a node was already dumped
                    if storedNode == nodeAddr then return end
                end
                table.insert( dumpedMonitorNodes , nodeAddr )
                iterateVecVarForNodes( nodeAddr )
            end

            --- gets a GDScript name, best use to return 1st 3 chars for 'res'
            ---@param nodeAddr number
            ---@param strSize number
            function getGDResName(nodeAddr, strSize)
                assert(type(nodeAddr) == 'number',"getGDResName: nodeAddr should be a number, instead got: "..type(nodeAddr))

                local debugPrefixStr ='>';
                if bDEBUGMode and inMainThread() then debugPrefixStr = incDebugStep() end; 

                local gdScriptInstance = readPointer( nodeAddr + GDSOf.GDSCRIPTINSTANCE )
                if gdScriptInstance == 0 or gdScriptInstance == nil then if bDEBUGMode and inMainThread() then print( debugPrefixStr..' getGDResName: gdScriptInstance invalid'); decDebugStep(); end; return end

                local gdScript = readPointer( gdScriptInstance + GDSOf.GDSCRIPT_REF )
                if gdScript == 0 or gdScript == nil then if bDEBUGMode and inMainThread() then print( debugPrefixStr..' getGDResName: gdScript invalid'); decDebugStep(); end; return end

                local gdScriptName = readPointer( gdScript + GDSOf.GDSCRIPTNAME )
                if gdScriptName == 0 or gdScriptName == nil then if bDEBUGMode and inMainThread() then print( debugPrefixStr..' getGDResName: gdScriptName invalid'); decDebugStep(); end; return end

                if bDEBUGMode and inMainThread() then decDebugStep(); end;

                return readUTFString( gdScriptName, strSize )
            end

            -- this monstrosity is used to check for a valid poitner and its vtable
            ---@param objectPtr number -- a ptr to an object or nullptr
            ---@return number -- returns a more valid pointer to an object
            ---@return boolean -- true if the returned pointer was shifted back to get a valid ptr
            function checkForVT( objectPtr )
                local objectAddr = readPointer( objectPtr ) -- it's either an obj ptr or zero

                if (not isValidPointer( objectAddr ) ) and ( not isValidPointer(  readPointer( objectAddr ) ) ) then -- check for vtable and 1st vmethod
                    local debugPrefixStr ='>';
                    if bDEBUGMode and inMainThread() then debugPrefixStr = incDebugStep() end; 

                    if bDEBUGMode and inMainThread() then print( debugPrefixStr..' checkForVT: OBJ addr likely not a ptr, shifting back 0x8: ptr: '..string.format( '%x', tonumber(objectPtr) ) ); end;
                    local adjustedObjectPtr = objectPtr - GDSOf.PTRSIZE; -- shift back to get a ptr
                    local wrapperAddr = readPointer( adjustedObjectPtr ) -- this will be a wrapped obj ptr
                    objectAddr = readPointer( wrapperAddr )

                    if ( wrapperAddr == 0 ) or ( not isValidPointer( wrapperAddr ) )  then -- check the wrapper, obj and its vtable
                        if bDEBUGMode and inMainThread() then print( debugPrefixStr..' checkForVT: OBJ addr still not an obj  ptr, leave it be'); decDebugStep(); end;
                        return objectPtr, false; -- revert the value, whatever
                    end

                    if isValidPointer( objectAddr ) then -- check for vtable to be safe
                        if bDEBUGMode and inMainThread() then print( debugPrefixStr..' checkForVT: shifted OBJ addr is a ptr, returning it'); decDebugStep(); end;
                        return readPointer( adjustedObjectPtr ), true -- objects at 0x8 offsetToValue are wrapped ptrs, so we return the ptr

                    else
                        if bDEBUGMode and inMainThread() then print( debugPrefixStr..' checkForVT: OBJ addr still not a ptr, leave it be'); decDebugStep() end;
                        return objectPtr, false; -- revert the value, whatever
                    end
                else
                    return objectPtr, false
                end
            end

            --- gets a Node by name
            ---@param nodeName string
            function getNode(nodeName)
                assert(type(nodeName) == "string",'Node name should be a string, instead got: '..type(nodeName))
                if not (gdOffsetsDefined) then print('define the offsets first, silly') return end

                local childrenPtr, childrenSize = getVPChildren()
                if childrenPtr == nil or childrenSize == nil then return end

                for i=0,( childrenSize-1 ) do

                    local nodeAddr = readPointer( childrenPtr + i * GDSOf.PTRSIZE )
                    if nodeAddr == 0 then if bDEBUGMode then print( 'getNode: nodeAddr invalid' ); end; return end

                    local nodeNameStr = getNodeName(nodeAddr)
                    if nodeNameStr == nodeName then
                        return nodeAddr
                    end
                end
                return
            end

            --- returns a const ptr and its type
            ---@param nodeName string
            ---@param constName string
            function getNodeConstPtr(nodeName, constName)
                assert(type(nodeName) == 'string',"Node name has to be a string, instead got: "..type(nodeName))
                assert(type(constName) == 'string',"Constant name has to be a string, instead got: "..type(constName))

                local nodePtr = getNodeWithGDScriptInstance(nodeName)
                if nodePtr == nil then if bDEBUGMode then print( " getNodeConstPtr: Node + GDSI: "..tostring(nodeName).." wasn't found") end; return; end

                local mapElement = getNodeConstantMap(nodePtr)
                repeat
                    if getNodeConstName( mapElement ) == constName then
                        if GDSOf.MAJOR_VER >= 4 then
                            local constType = readInteger( mapElement + GDSOf.CONSTELEM_VALTYPE ) 
                            local offsetToValue = getVariantValueOffset( constType )
                            return getAddress( mapElement + GDSOf.CONSTELEM_VALTYPE + offsetToValue ), getCETypeFromGD( readInteger( mapElement + GDSOf.CONSTELEM_VALTYPE ) )
                        else
                            return getAddress( mapElement + GDSOf.CONSTELEM_VALVAL ), getCETypeFromGD( readInteger( mapElement + GDSOf.CONSTELEM_VALTYPE ) )
                        end
                    end

                    if GDSOf.MAJOR_VER >= 4 then
                        mapElement = readPointer( mapElement )
                    else
                        mapElement = readPointer( mapElement + GDSOf.MAP_NEXTELEM )
                    end
                until (mapElement == 0)
            end



        --///---///--///---///--///---///--///--///---///--///---///--///---///--/// Func

            --- returns a head element, tail element and (hash)map size
            ---@param nodePtr number
            function getNodeFunctionMap(nodeAddr)
                assert(type(nodeAddr) == 'number',"nodeAddr should be a number, instead got: "..type(nodeAddr))

                local debugPrefixStr ='>';
                if bDEBUGMode then debugPrefixStr = incDebugStep() end;

                local gdScriptInstance = readPointer( nodeAddr + GDSOf.GDSCRIPTINSTANCE )
                if gdScriptInstance == 0 or gdScriptInstance == nil then if bDEBUGMode then print( debugPrefixStr..' getNodeFunctionMap: gdScriptInstance is invalid'); decDebugStep(); end; return; end

                local scriptPtr = readPointer( gdScriptInstance + GDSOf.GDSCRIPT_REF )
                if scriptPtr == 0 or scriptPtr == nil then if bDEBUGMode then print( debugPrefixStr..' getNodeFunctionMap: scriptPtr is invalid'); decDebugStep(); end; return; end

                local mainElement = readPointer( scriptPtr + GDSOf.FUNC_MAP )
                local lastElement = readPointer( scriptPtr + GDSOf.FUNC_MAP + GDSOf.PTRSIZE )
                local mapSize = readInteger( scriptPtr + GDSOf.FUNC_MAP + GDSOf.MAP_SIZE )

                if (mainElement == 0 or mainElement == nil) or
                    (lastElement == 0 or lastElement == nil) or
                    (mapSize == 0 or mapSize == nil) then
                    if bDEBUGMode then print(  debugPrefixStr..'getNodeFunctionMap: (hash)map is not found'); decDebugStep(); end;
                    return;
                end

                if bDEBUGMode then decDebugStep(); end;
                if GDSOf.MAJOR_VER >= 4 then
                    return mainElement, lastElement, mapSize
                else
                    return getLeftmostMapElem( mainElement, lastElement, mapSize )
                end
            end

            --- returns a lua string for function name
            ---@param mapElement number
            function getGDFunctionName(mapElement)
                local mapElementValue = readPointer( mapElement + GDSOf.GDSCRIPT_REF ) -- #TODO wtf the offset isn't correct I guess
                local functionNameAddr = readPointer( mapElementValue + GDSOf.SCRIPTFUNC_STRING )
                if functionNameAddr == 0 or functionNameAddr == nil then if bDEBUGMode then print('getGDFunctionName: functionname invalid') end return 'F??' end
                return readUTFString( functionNameAddr )
            end

            --- gets a functionPtr by nodename and funcname
            ---@param nodeName string
            ---@param funcName string
            function getGDFunctionPtr(nodeName, funcName)
                assert(type(nodeName) == 'string',"Node name has to be a string, instead got: "..type(nodeName))

                local nodePtr = getNodeWithGDScriptInstance(nodeName)
                if nodePtr == nil then print( "getGDFunctionPtr: Node: "..tostring(nodeName).." wasn't found" ); return; end
                local mapFuncName;
                local mapElement = getNodeFunctionMap(nodePtr)

                repeat
                    if GDSOf.MAJOR_VER >= 4 then
                        mapFuncName = getGDFunctionName( mapElement ) -- #TODO IS it correct? Didn't care about functions much
                    else
                        mapFuncName = getStringNameStr( readPointer( mapElement + GDSOf.MAP_KVALUE ) )
                    end
                    if mapFuncName == funcName then
                        return readPointer( mapElement + GDSOf.FUNC_MAPVAL )
                    end

                    if GDSOf.MAJOR_VER >= 4 then
                        mapElement = readPointer( mapElement )
                    else
                        mapElement = readPointer( mapElement + GDSOf.MAP_NEXTELEM )
                    end
                until (mapElement == 0)
            end

        --///---///--///---///--///---///--///--///---///--///---///--///---///--/// Const

            --- returns a head element, tail element and (hash)Map size
            ---@param nodeAddr number
            function getNodeConstMap(nodeAddr, constStructElement)
                assert(type(nodeAddr) == 'number',"getNodeConstMap: NodePtr should be a number, instead got: "..type(nodeAddr))
                local debugPrefixStr ='>';
                if bDEBUGMode then debugPrefixStr = incDebugStep() end; 

                local scriptInstanceAddr = readPointer( nodeAddr + GDSOf.GDSCRIPTINSTANCE )
                if scriptInstanceAddr == 0 or scriptInstanceAddr == nil then if bDEBUGMode then print( debugPrefixStr..' getNodeConstMap: scriptInstance is invalid'); decDebugStep(); end; return; end

                local gdScriptAddr = readPointer( scriptInstanceAddr + GDSOf.GDSCRIPT_REF )
                if gdScriptAddr == 0 or gdScriptAddr == nil then if bDEBUGMode then print( debugPrefixStr..' getNodeConstMap: GDScript is invalid'); decDebugStep(); end; return; end

                local mainElement = readPointer( gdScriptAddr + GDSOf.CONST_MAP ) -- head or root depending on the version
                local lastElement = readPointer( gdScriptAddr + GDSOf.CONST_MAP + GDSOf.PTRSIZE ) -- tail or end
                local mapSize = readInteger( gdScriptAddr + GDSOf.CONST_MAP + GDSOf.MAP_SIZE ) -- hashmap or map
                if (mainElement == 0 or mainElement == nil) or
                    (lastElement == 0 or lastElement == nil) or
                    (mapSize == 0 or mapSize == nil) then
                        if bDEBUGMode then print( debugPrefixStr..' getNodeConstMap: Const: (hash)map is not found'); decDebugStep(); end
                        return;-- return to skip if the const map is absent
                end
                if bDEBUGMode then decDebugStep(); end;
                
                if GDSOf.MAJOR_VER >= 4 then
                    return mainElement, lastElement, mapSize, constStructElement
                else
                    if constStructElement then constStructElement.ChildStruct = createStructure('ConstMapRes') end
                    return getLeftmostMapElem( mainElement, lastElement, mapSize, constStructElement )
                end
            end

            --- returns a lua string for const name
            ---@param mapElement number
            function getNodeConstName(mapElement)
                local debugPrefixStr ='>';
                if bDEBUGMode then debugPrefixStr = incDebugStep() end; 

                local mapElementKey = readPointer( mapElement + GDSOf.CONSTELEM_KEYVAL )
                if mapElementKey == 0 or mapElementKey == nil then
                if bDEBUGMode then print( debugPrefixStr..' getNodeConstName: (hash)mapElementKey invalid'); decDebugStep(); end; return 'C??' end

                local constNameStr = readPointer( mapElementKey + GDSOf.STRING )

                if constNameStr == 0 or constNameStr == nil then
                    if bDEBUGMode then print( debugPrefixStr..' getNodeConstName: string address invalid, trying ASCII'); end;
                    constNameStr = readPointer( mapElementKey + 0x8 ) -- for cases when StringName holds a static ASCII string at 0x8
                    if constNameStr == 0 or constNameStr == nil then if bDEBUGMode then print( debugPrefixStr..' getNodeName: string address invalid, not ASCII either'); decDebugStep(); end; return 'C??' end  -- return empty string if no string was found
                    if bDEBUGMode then decDebugStep(); end;

                    return readString( constNameStr, 100 )
                end

                if bDEBUGMode then decDebugStep(); end;

                return readUTFString( constNameStr )
            end

            -- iterates over const (hash)map of a node and creates addresses for it
            ---@param nodeAddr number
            ---@param Owner userdata
            function iterateNodeConstToAddr(nodeAddr, Owner)
                assert(type(nodeAddr) == 'number',"iterateNodeConstToAddr Node addr has to be a number, instead got: "..type(nodeAddr))

                local debugPrefixStr ='>';
                if bDEBUGMode then debugPrefixStr = incDebugStep() end; 

                local nodeName = getNodeName( nodeAddr )
                if not checkForGDScript( nodeAddr ) then if bDEBUGMode then print( debugPrefixStr.." iterateNodeConstToAddr: Node "..tostring(nodeName).." with NO GDScript"); decDebugStep(); end;

                    synchronize(function(Owner)
                                Owner.Destroy()
                            end, Owner
                        )
                    return;

                end;

                local headElement, tailElement, mapSize = getNodeConstMap(nodeAddr)
                if (headElement==0 or headElement==nil) or (mapSize==0 or mapSize==nil) then
                    if bDEBUGMode then print( debugPrefixStr..' iterateNodeConstToAddr (hash)map empty?: '..string.format( 'Address: %x ', tonumber(nodeAddr) ) ); decDebugStep(); end

                    synchronize(function(Owner)
                            Owner.Destroy()
                        end, Owner
                    )

                    return; -- just return on fail
                end

                if bDEBUGMode then print( debugPrefixStr.." iterateNodeConstToAddr BEFORE loop (Node: "..tostring(nodeName)..": "..string.format('%x',nodeAddr).."):\t\t"..string.format('head: %x | ', headElement)..string.format('tailEnd: %x | ', tailElement)..'(Hash)M size: '..tostring(mapSize) ) end
                local mapElement = headElement -- hashmap or map
                local prefixStr = 'CONST: '
                local suffixStr = 'array: '

                repeat
                    local constName = getNodeConstName( mapElement )
                    local constType = readInteger( mapElement + GDSOf.CONSTELEM_VALTYPE )
                    local offsetToValue = GDSOf.CONSTELEM_VALTYPE + getVariantValueOffset( constType )
                    local constPtr = getAddress( mapElement + offsetToValue ) -- to be safe

                    if bDEBUGMode then print( debugPrefixStr.." iterateNodeConstToAddr loop (Node: "..tostring(nodeName)..": "..string.format('%x',nodeAddr).."):\t\t"..string.format('(hash)M elem: %x | ', mapElement)..' constName: '..tostring(constName)..'\t constType: '..tostring(constType)..string.format('\t constValue: %x', readPointer(constPtr) ) ) end
                    local constTypeName = getGDTypeName( constType )

                    if constTypeName == 'ARRAY' then
                        if bDEBUGMode then print( debugPrefixStr.." iterateNodeConstToAddr loop: ARRAY case for name: "..tostring(constName)) end

                        if readPointer( readPointer( constPtr ) + GDSOf.ARRAY_TOVECTOR ) == 0 then

                            synchronize(function( prefixStr, suffixStr, constName, constPtr, constType, Owner)
                                    addMemRecTo( prefixStr..'array: (empty): '..constName , constPtr , getCETypeFromGD( constType ) , Owner )
                                end, prefixStr, suffixStr, constName, constPtr, constType, Owner
                            )

                        else
                            suffixStr = 'array: '

                            local newParentMemrec = synchronize(function( prefixStr, suffixStr, constName, constPtr, constType, Owner)
                                        local newParentMemrec = addMemRecTo( prefixStr..suffixStr..constName , constPtr , getCETypeFromGD( constType ) , Owner ) 
                                        newParentMemrec.Options = '[moHideChildren, moAllowManualCollapseAndExpand, moManualExpandCollapse]'
                                        return newParentMemrec
                                    end, prefixStr, suffixStr, constName, constPtr, constType, Owner
                                )

                            iterateArrayToAddr( readPointer( constPtr ) , newParentMemrec )
                        end

                    elseif constTypeName == 'DICTIONARY' then
                        if bDEBUGMode then print( debugPrefixStr.." iterateNodeConstToAddr loop: DICT case for name: "..tostring(constName) ) end
                        
                        local dictSize
                        if GDSOf.MAJOR_VER >= 4 then
                            dictSize = readInteger( readPointer( constPtr ) + GDSOf.DICT_SIZE )
                        else
                            dictSize = readInteger( readPointer( readPointer( constPtr ) + GDSOf.DICT_LIST ) + GDSOf.DICT_SIZE )
                        end

                        if dictSize == nil or dictSize == 0 then
                            suffixStr = 'dict (empty): '

                            synchronize(function( prefixStr, suffixStr, constName, constPtr, constType, Owner)
                                    addMemRecTo( prefixStr..suffixStr..constName , constPtr , getCETypeFromGD( constType ) , Owner ) -- when the dicitonary is empty, just add the addr
                                end, prefixStr, suffixStr, constName, constPtr, constType, Owner
                            )

                        else
                            suffixStr = 'dict: '

                            local newParentMemrec = synchronize(function( prefixStr, suffixStr, constName, constPtr, constType, Owner)
                                            local newParentMemrec = addMemRecTo( prefixStr..suffixStr..constName , constPtr , getCETypeFromGD( constType ) , Owner )
                                            newParentMemrec.Options = '[moHideChildren, moAllowManualCollapseAndExpand, moManualExpandCollapse]'
                                        return newParentMemrec
                                    end, prefixStr, suffixStr, constName, constPtr, constType, Owner
                                )

                            iterateDictionaryToAddr( readPointer( constPtr ) , newParentMemrec )
                        end

                    elseif ( constTypeName == 'OBJECT' ) then
                        if bDEBUGMode then print( debugPrefixStr.." iterateNodeConstToAddr loop: OBJ case for name: "..tostring(constName) ) end
                        constPtr = checkForVT( constPtr )

                        if checkForGDScript( readPointer( constPtr ) ) then  -- is it even possible to have const nodes?
                            suffixStr = 'mNode: '

                            local newParentMemrec = synchronize(function( prefixStr, suffixStr, constName, constPtr, constType, Owner)
                                            local newParentMemrec = addMemRecTo( prefixStr..suffixStr..constName , constPtr , getCETypeFromGD( constType ) , Owner )
                                            newParentMemrec.Options = '[moHideChildren, moAllowManualCollapseAndExpand, moManualExpandCollapse]'
                                        return newParentMemrec
                                    end, prefixStr, suffixStr, constName, constPtr, constType, Owner
                                )

                            iterateMNodeToAddr( readPointer( constPtr ) , newParentMemrec )
                        else
                            if bDEBUGMode then print( debugPrefixStr..' iterateNodeConstToAddr: OBJ doesn\'t have GDScript/Inst'); end;

                            suffixStr = 'obj: '

                            synchronize(function( prefixStr, suffixStr, constTypeName, constName, constPtr, constType, Owner)
                                    addMemRecTo( prefixStr..suffixStr..' '..tostring(constTypeName)..' '..constName , constPtr , getCETypeFromGD( constType )  , Owner )
                                end, prefixStr, suffixStr, constTypeName, constName, constPtr, constType, Owner
                            )

                        end
                    elseif ( constTypeName == 'PACKED_STRING_ARRAY' ) or ( constTypeName == 'PACKED_BYTE_ARRAY' )
                        or ( constTypeName == 'PACKED_INT32_ARRAY' ) or ( constTypeName == 'PACKED_INT64_ARRAY' )
                        or ( constTypeName == 'PACKED_FLOAT32_ARRAY' ) or ( constTypeName == 'PACKED_FLOAT64_ARRAY' )
                        or ( constTypeName == 'PACKED_VECTOR2_ARRAY' ) or ( constTypeName == 'PACKED_VECTOR3_ARRAY' )
                        or ( constTypeName == 'PACKED_COLOR_ARRAY' ) or ( constTypeName == 'PACKED_VECTOR4_ARRAY' ) then

                        if bDEBUGMode then print( debugPrefixStr.." iterateNodeConstToAddr loop: "..tostring(constTypeName).." case: "..tostring(constName)) end
                        
                        local arrayAddr = readPointer( constPtr )
                        if readPointer( arrayAddr + GDSOf.P_ARRAY_TOARR ) == 0 then -- when there are no elements in an array, its pointer shuld be 0 ?
                            prefixStr = 'pck_arr (empty): '

                            synchronize(function( prefixStr, constName, constTypeName, arrayAddr, constType, Owner)
                                    addMemRecTo( prefixStr..constName.. ' T: '..tostring(constTypeName) , arrayAddr , getCETypeFromGD( constType ) , Owner )
                                end, prefixStr, constName, constTypeName, arrayAddr, constType, Owner
                            )

                        else
                            prefixStr = 'pck_arr: '

                            local newParentMemrec = synchronize(function( prefixStr, constName, constTypeName, arrayAddr, constType, Owner)
                                        local newParentMemrec = addMemRecTo( prefixStr..constName.. ' T: '..tostring(constTypeName) , arrayAddr , getCETypeFromGD( constType ) , Owner )
                                        newParentMemrec.Options = '[moHideChildren, moAllowManualCollapseAndExpand, moManualExpandCollapse]'
                                        return newParentMemrec
                                    end, prefixStr, constName, constTypeName, arrayAddr, constType, Owner
                                )

                            iteratePackedArrayToAddr(  arrayAddr , constTypeName, newParentMemrec )
                        end

                    else

                        synchronize(function( prefixStr, constName, constPtr, constType, Owner)
                                    addMemRecTo( prefixStr..constName , constPtr , getCETypeFromGD( constType ) , Owner ) 
                                end, prefixStr, constName, constPtr, constType, Owner
                            )

                    end
                    if GDSOf.MAJOR_VER >= 4 then
                        mapElement = readPointer(mapElement)
                    else
                        mapElement = readPointer( mapElement + GDSOf.MAP_NEXTELEM )
                    end
                until (mapElement == 0)
                if bDEBUGMode then decDebugStep(); end;
                return
            end

            -- iterates over const (hash)map of a node and builds the structure for it
            ---@param nodeAddr number
            ---@param constStructElement userdata
            function iterateNodeConstToStruct(nodeAddr, constStructElement)
                assert(type(nodeAddr) == 'number',"iterateNodeConstToStruct Node addr has to be a number, instead got: "..type(nodeAddr))

                local nodeName;
                local index = 0;

                local debugPrefixStr ='>';
                if bDEBUGMode then debugPrefixStr = incDebugStep(); nodeName  = getNodeName( nodeAddr ) end;

                local headElement, tailElement, mapSize, constStructElement = getNodeConstMap( nodeAddr, constStructElement)
                if (headElement==0 or headElement==nil) or (mapSize==0 or mapSize==nil) then
                    if bDEBUGMode then print( debugPrefixStr..' iterateNodeConstToStruct (hash)map empty?: '..string.format( 'Address: %x ', tonumber(nodeAddr) ) ); decDebugStep(); end
                    return; -- just return on fail
                end

                if bDEBUGMode then print( debugPrefixStr.." iterateNodeConstToStruct BEFORE loop (Node: "..tostring(nodeName)..": "..string.format('%x',nodeAddr).."):\t\t"..string.format('head: %x | ', headElement)..string.format('tailEnd: %x | ', tailElement)..'(Hash)M size: '..tostring(mapSize) ) end
                local mapElement = headElement -- hashmap or map
                local prefixStr = 'CONST: '
                local suffixStr = 'UNKNOWN: '

                repeat
                    local constName = getNodeConstName( mapElement )
                    local constType = readInteger( mapElement + GDSOf.CONSTELEM_VALTYPE )
                    local offsetToValue = GDSOf.CONSTELEM_VALTYPE + getVariantValueOffset( constType )
                    local constPtr = getAddress( mapElement + offsetToValue ) -- to be safe

                    if bDEBUGMode then print( debugPrefixStr.." iterateNodeConstToStruct loop (Node: "..tostring(nodeName)..": "..string.format('%x',nodeAddr).."):\t\t"..string.format('(hash)M elem: %x | ', mapElement)..' constName: '..tostring(constName)..'\t constType: '..tostring(constType)..string.format('\t constValue: %x', readPointer(constPtr) ) ) end
                    local constTypeName = getGDTypeName( constType )

                    if constTypeName == 'ARRAY' then
                        if bDEBUGMode then print( debugPrefixStr.." iterateNodeConstToStruct loop: ARRAY case for name: "..tostring(constName)) end

                        if readPointer( readPointer( constPtr ) + GDSOf.ARRAY_TOVECTOR ) == 0 then
                            addStructureElem( constStructElement, prefixStr..'array: (empty): '..constName, offsetToValue, getCETypeFromGD( constType ) )
                        else
                            suffixStr = 'array: '
                            local newParentStructElem = addStructureElem( constStructElement, prefixStr..suffixStr..constName, offsetToValue, getCETypeFromGD( constType ) )
                            newParentStructElem.ChildStruct = createStructure('Array')
                            iterateArrayToStruct( readPointer( constPtr ) , newParentStructElem )
                        end

                    elseif constTypeName == 'DICTIONARY' then
                        if bDEBUGMode then print( debugPrefixStr.." iterateNodeConstToStruct loop: DICT case for name: "..tostring(constName) ) end
                        local dictSize
                        if GDSOf.MAJOR_VER >= 4 then
                            dictSize = readInteger( readPointer( constPtr ) + GDSOf.DICT_SIZE )
                        else
                            dictSize = readInteger( readPointer( readPointer( constPtr ) + GDSOf.DICT_LIST ) + GDSOf.DICT_SIZE )
                        end

                        if dictSize == nil or dictSize == 0 then
                            suffixStr = 'dict (empty): '
                            addStructureElem( constStructElement, prefixStr..suffixStr..constName, offsetToValue, getCETypeFromGD( constType ) )
                        else
                            suffixStr = 'dict: '
                            local newParentStructElem = addStructureElem( constStructElement, prefixStr..suffixStr..constName, offsetToValue, getCETypeFromGD( constType ) )
                            newParentStructElem.ChildStruct = createStructure('Dict')
                            iterateDictionaryToStruct( readPointer( constPtr ) , newParentStructElem )
                        end

                    elseif ( constTypeName == 'OBJECT' ) then
                        if bDEBUGMode then print( debugPrefixStr.." iterateNodeConstToStruct loop: OBJ case for name: "..tostring(constName) ) end
                        local bShifted, newParentStructElem;
                        constPtr, bShifted = checkForVT( constPtr ) -- check if the pointer is valid, if not, shift it back 0x8 bytes
                        if bShifted then
                            offsetToValue = offsetToValue - GDSOf.PTRSIZE
                            newParentStructElem = addStructureElem( constStructElement, prefixStr..'Wrapper: '..constName, offsetToValue, vtPointer )
                            newParentStructElem.ChildStruct = createStructure('Wrapper')
                            offsetToValue = 0x0 -- the object lies at 0x0 now
                        else
                            newParentStructElem = constStructElement
                        end

                        if checkForGDScript( readPointer( constPtr ) ) then  -- is it even possible to have const nodes?
                            suffixStr = 'mNode: '
                            addStructureElem( newParentStructElem, prefixStr..suffixStr..constName, offsetToValue, getCETypeFromGD( constType ) )
                        else
                            if bDEBUGMode then print( debugPrefixStr..' iterateNodeConstToStruct: OBJ doesn\'t have GDScript/Inst'); end;
                            suffixStr = 'obj: '
                            addStructureElem( newParentStructElem, prefixStr..suffixStr..constName, offsetToValue, getCETypeFromGD( constType ) )
                        end

                    elseif ( constTypeName == 'PACKED_STRING_ARRAY' ) or ( constTypeName == 'PACKED_BYTE_ARRAY' )
                        or ( constTypeName == 'PACKED_INT32_ARRAY' ) or ( constTypeName == 'PACKED_INT64_ARRAY' )
                        or ( constTypeName == 'PACKED_FLOAT32_ARRAY' ) or ( constTypeName == 'PACKED_FLOAT64_ARRAY' )
                        or ( constTypeName == 'PACKED_VECTOR2_ARRAY' ) or ( constTypeName == 'PACKED_VECTOR3_ARRAY' )
                        or ( constTypeName == 'PACKED_COLOR_ARRAY' ) or ( constTypeName == 'PACKED_VECTOR4_ARRAY' ) then

                        if bDEBUGMode then print( debugPrefixStr.." iterateNodeConstToStruct loop: "..tostring(constTypeName).." case: "..tostring(constName)) end

                        local arrayAddr = readPointer( constPtr )
                        if readPointer( arrayAddr + GDSOf.P_ARRAY_TOARR ) == 0 then -- when there are no elements in an array, its pointer shuld be 0 ?
                            prefixStr = 'pck_arr (empty): '
                            addStructureElem( constStructElement, prefixStr..constName.. ' T: '..tostring(constTypeName), offsetToValue, getCETypeFromGD( constType ) )
                        else
                            prefixStr = 'pck_arr: '
                            local newParentStructElem = addStructureElem( constStructElement, prefixStr..constName.. ' T: '..tostring(constTypeName), offsetToValue, getCETypeFromGD( constType ) )
                            newParentStructElem.ChildStruct = createStructure('P_Array')
                            iteratePackedArrayToStruct(  arrayAddr , constTypeName, newParentStructElem )
                        end

                    elseif ( constTypeName == 'STRING' ) then
                            prefixStr = 'String: '
                            local newParentStructElem = addStructureElem( constStructElement, prefixStr..suffixStr..constName, offsetToValue, vtPointer )
                            newParentStructElem.ChildStruct = createStructure('String')
                            local stringElement = addStructureElem(newParentStructElem, prefixStr..suffixStr..constName, 0x0, vtUnicodeString )
                            --stringElement.Bytesize = 100*4

                    else
                        addStructureElem( constStructElement, prefixStr..constName, offsetToValue, getCETypeFromGD( constType ) )
                    end

                    index = index+1
                    if GDSOf.MAJOR_VER >= 4 then
                        mapElement = readPointer(mapElement)
                        constStructElement = addStructureElem( constStructElement, 'Next['..index..']', 0x0, vtPointer )
                        constStructElement.ChildStruct = createStructure('ConstNext')
                    else
                        mapElement = readPointer( mapElement + GDSOf.MAP_NEXTELEM )
                        constStructElement = addStructureElem( constStructElement, 'Next', GDSOf.MAP_NEXTELEM, vtPointer )
                        constStructElement.ChildStruct = createStructure('ConstNext')
                    end
                until (mapElement == 0)

                if bDEBUGMode then decDebugStep(); end;
                return
            end

        --///---///--///---///--///---///--///--///---///--///---///--///---///--/// Dictionary

            --- iterates a dictionary and adds it to a class
            ---@param dictAddr number
            ---@param Owner userdata
            function iterateDictionaryToAddr(dictAddr, Owner)
                assert( type(dictAddr) == 'number', 'iterateDictionaryToAddr: dictAddr has to be a number, instead got: '..type(dictAddr))

                local debugPrefixStr ='>';
                if bDEBUGMode then debugPrefixStr = incDebugStep() end; 
                if (not (dictAddr > 0)) then if bDEBUGMode then print( debugPrefixStr..' iterateDictionaryToAddr: dictAddr was 0'); decDebugStep(); end; return; end
                if bDEBUGMode then print( debugPrefixStr..' iterateDictionaryToAddr: dictAddr'..string.format(' at %x', dictAddr)) end
                
                if GDSOf.MAJOR_VER == 3 then
                    dictAddr = readPointer( dictAddr + GDSOf.DICT_LIST ) -- for 3.x it's dictList actually
                end
                local dictSize = readInteger( dictAddr + GDSOf.DICT_SIZE )
                if (dictSize == 0 or dictSize == nil) then if bDEBUGMode then print( debugPrefixStr..' iterateDictionaryToAddr Dict: dictSize was 0'); decDebugStep(); end return; end

                local dictHead = readPointer( dictAddr + GDSOf.DICT_HEAD ) -- each key is likely to be a StringName, sometimes enum
                local dictTail = readPointer( dictAddr + GDSOf.DICT_TAIL )
                if bDEBUGMode then print( debugPrefixStr..' iterateDictionaryToAddr: (hash)Map\t'..string.format(' head %x | last %x | size %d', dictHead, dictTail, dictSize)) end
                local mapElement = dictHead
                repeat
                    if bDEBUGMode then print( debugPrefixStr..' iterateDictionaryToAddr: Loop Map start'..string.format(' (hash)ElemAddr: %x', mapElement)) end
                    
                    local keyType, keyValueAddr
                    if GDSOf.MAJOR_VER == 3 then
                        local keyPtr = readPointer( mapElement ) -- key is a ptr
                        keyType = readInteger( keyPtr + GDSOf.DICTELEM_KEYTYPE )
                        keyValueAddr = getAddress( keyPtr + GDSOf.DICTELEM_KEYVAL )
                    else
                        keyType = readInteger( mapElement + GDSOf.DICTELEM_KEYTYPE ) -- those can be a key , NodePath, Callable, StringName, etc
                        keyValueAddr = getAddress( mapElement + GDSOf.DICTELEM_KEYVAL )                
                    end

                    local keyName = "UNKNOWN"
                    local valueValue;
                    local prefixStr = '';
                    local keyTypeName = getGDTypeName( keyType )
                    if ( keyTypeName == 'STRING' ) then -- 4
                        keyName = readUTFString( readPointer( keyValueAddr ) )
                    elseif ( keyTypeName == 'STRING_NAME') then -- 21
                        keyName = getStringNameStr( readPointer( keyValueAddr ) )
                    elseif ( keyTypeName == 'FLOAT' ) then -- 3
                        keyName = tostring( readDouble( keyValueAddr ) ) -- in godot 3.x real is 4 byte float or not?
                    elseif ( keyTypeName == 'NODE_PATH' or keyTypeName == 'RID' or keyTypeName == 'CALLABLE' ) then
                        keyName = tostring( readPointer( keyValueAddr ) )
                    else -- bool, int | might need separate for Vector2, Vector3, Color, etc
                        keyName = readInteger( keyValueAddr )
                    end

                    local valueType = readInteger( mapElement + GDSOf.DICTELEM_VALTYPE )
                    local offsetToValue = GDSOf.DICTELEM_VALTYPE + getVariantValueOffset( valueType )
                    valueValue = readPointer( mapElement + offsetToValue )
                    local valueValuePtr = getAddress( mapElement + offsetToValue ) -- let's have both for now

                    local valueTypeName = getGDTypeName( valueType )
                    if ( valueTypeName == 'DICTIONARY' ) then -- dictionary
                        if bDEBUGMode then print( debugPrefixStr..' iterateDictionaryToAddr: DICT CASE for name: '..tostring(keyName)) end
                        local dictSizeCheck
                        if GDSOf.MAJOR_VER >= 4 then
                            dictSizeCheck = readInteger( valueValue + GDSOf.DICT_SIZE )
                        else
                            dictSizeCheck = readInteger( readPointer( valueValue + GDSOf.DICT_LIST ) + GDSOf.DICT_SIZE )
                        end

                        if dictSizeCheck == nil or dictSizeCheck == 0 then
                            prefixStr = 'dict (empty): '

                            synchronize(function( prefixStr, keyName, valueValue, valueType, Owner)
                                        addMemRecTo( prefixStr..keyName , valueValue , getCETypeFromGD( valueType ) , Owner ) -- when the dicitonary is empty, just add the addr
                                    end, prefixStr, keyName, valueValue, valueType, Owner
                                )

                        else
                            prefixStr = 'mdict: '

                            local newParentMemrec = synchronize(function( prefixStr, keyName, valueValue, valueType, Owner)
                                            local newParentMemrec = addMemRecTo( prefixStr..keyName , valueValue , getCETypeFromGD( valueType ) , Owner )
                                            newParentMemrec.Options = '[moHideChildren, moAllowManualCollapseAndExpand, moManualExpandCollapse]'
                                        return newParentMemrec
                                    end, prefixStr, keyName, valueValue, valueType, Owner
                                )

                            iterateDictionaryToAddr( valueValue , newParentMemrec ) -- recursive
                        end 

                    elseif ( valueTypeName == 'ARRAY') then
                        if bDEBUGMode then print( debugPrefixStr.." iterateDictionaryToAddr: DICT ARRAY case for name: "..tostring(keyName)) end
                        
                        prefixStr = 'array: '
                        if readPointer( valueValue + GDSOf.ARRAY_TOVECTOR ) == 0 then -- when there are no elements in an array, it's vector ptr is 0

                            synchronize(function( prefixStr, keyName, valueValue, valueType, Owner)
                                        addMemRecTo( prefixStr..'empty: '..keyName , valueValue , getCETypeFromGD( valueType ) , Owner )
                                    end, prefixStr, keyName, valueValue, valueType, Owner
                                )

                        else
                            prefixStr = 'array: '

                            local newParentMemrec = synchronize(function( prefixStr, keyName, valueValue, valueType, Owner)
                                            local newParentMemrec = addMemRecTo( prefixStr..keyName , valueValue , getCETypeFromGD( valueType ) , Owner )
                                            newParentMemrec.Options = '[moHideChildren, moAllowManualCollapseAndExpand, moManualExpandCollapse]'
                                        return newParentMemrec
                                    end, prefixStr, keyName, valueValue, valueType, Owner
                                )

                            iterateArrayToAddr(  valueValue , newParentMemrec )
                        end

                    elseif ( valueTypeName == 'OBJECT' ) then
                        if bDEBUGMode then print( debugPrefixStr.." iterateDictionaryToAddr loop: OBJ case for name: "..tostring(keyName)..string.format(' and addr %x ', valueValue)) end
                        valueValuePtr = checkForVT( valueValuePtr )
                        valueValue = readPointer( valueValuePtr ) -- checkForVT returns a pointer

                        if checkForGDScript( valueValue ) then
                            if bDEBUGMode then print( debugPrefixStr.." iterateDictionaryToAddr loop: NODE case: "..string.format('%x ', valueValue)..tostring(keyName)) end
                            prefixStr = 'mNode: '

                            local newParentMemrec = synchronize(function( prefixStr, keyName, valueValue, valueType, Owner)
                                            local newParentMemrec = addMemRecTo( prefixStr..keyName , valueValue , getCETypeFromGD( valueType ) , Owner )
                                            newParentMemrec.Options = '[moHideChildren, moAllowManualCollapseAndExpand, moManualExpandCollapse]'
                                        return newParentMemrec
                                    end, prefixStr, keyName, valueValue, valueType, Owner
                                )

                            iterateMNodeToAddr( valueValue , newParentMemrec )
                        else
                            if bDEBUGMode then print( debugPrefixStr..' iterateDictionaryToAddr: OBJ doesn\'t have GDScript/Inst'); end
                            prefixStr = 'obj: '

                            synchronize(function( prefixStr, keyName, valueValue, valueType, Owner)
                                        addMemRecTo( prefixStr..keyName , valueValue , getCETypeFromGD( valueType )  , Owner )
                                    end, prefixStr, keyName, valueValue, valueType, Owner
                                )

                        end
                    elseif ( valueTypeName == 'PACKED_STRING_ARRAY' ) or ( valueTypeName == 'PACKED_BYTE_ARRAY' )
                        or ( valueTypeName == 'PACKED_INT32_ARRAY' ) or ( valueTypeName == 'PACKED_INT64_ARRAY' )
                        or ( valueTypeName == 'PACKED_FLOAT32_ARRAY' ) or ( valueTypeName == 'PACKED_FLOAT64_ARRAY' )
                        or ( valueTypeName == 'PACKED_VECTOR2_ARRAY' ) or ( valueTypeName == 'PACKED_VECTOR3_ARRAY' )
                        or ( valueTypeName == 'PACKED_COLOR_ARRAY' ) or ( valueTypeName == 'PACKED_VECTOR4_ARRAY' ) then

                            if bDEBUGMode then print( debugPrefixStr.." iterateDictionaryToAddr loop: "..tostring(valueTypeName).." case: "..tostring(keyName)) end


                            if readPointer( valueValue + GDSOf.P_ARRAY_TOARR ) == 0 then -- when there are no elements in an array, its pointer shuld be 0 ?
                                prefixStr = 'pck_arr (empty): '

                                synchronize(function( prefixStr, keyName, valueTypeName, valueValue, valueType, Owner)
                                            addMemRecTo( prefixStr..keyName..' of '..valueTypeName , valueValue , getCETypeFromGD( valueType ) , Owner )
                                        end, prefixStr, keyName, valueTypeName, valueValue, valueType, Owner
                                    )

                            else

                                local newParentMemrec = synchronize(function( prefixStr, keyName, valueTypeName, valueValue, valueType, Owner)
                                                local newParentMemrec = addMemRecTo( prefixStr..keyName.. ' T: '..tostring(valueTypeName) , valueValue , getCETypeFromGD( valueType ) , Owner )
                                                newParentMemrec.Options = '[moHideChildren, moAllowManualCollapseAndExpand, moManualExpandCollapse]'
                                            return newParentMemrec
                                        end, prefixStr, keyName, valueTypeName, valueValue, valueType, Owner
                                    )

                                iteratePackedArrayToAddr(  valueValue , valueTypeName, newParentMemrec )
                            end

                    else
                        valueValue = valueValuePtr -- getAddress( mapElement + GDSOf.DICTELEM_VALTYPE + offsetToValue )
                        if valueValue == 0 then if bDEBUGMode then print( debugPrefixStr.." iterateDictionaryToAddr: ValueValue is 0: uninitialized?") end end

                        synchronize(function( prefixStr, keyName, valueValue, valueType, Owner)
                                        addMemRecTo( prefixStr..keyName , valueValue , getCETypeFromGD( valueType )  , Owner )
                                    end, prefixStr, keyName, valueValue, valueType, Owner
                                )

                    end

                    if bDEBUGMode then print( debugPrefixStr..' iterateDictionaryToAddr nextloop, result: \t'..string.format(' name %s || elem 0x%x || keyT %d | keyV 0x%x || valT %d | valV addr 0x%x', tostring(keyName), (mapElement or 0), (keyType or 0), (keyValueAddr or 0), (valueType or 0), (valueValue or 0))) end
                    if GDSOf.MAJOR_VER >= 4 then
                        mapElement = readPointer( mapElement )
                    else
                        mapElement = readPointer( mapElement + GDSOf.DICTELEM_PAIR_NEXT )
                    end
                until (mapElement == 0)

                if bDEBUGMode then decDebugStep(); end;
                return
            end

            --- iterates a dictionary and adds it to a struct
            ---@param dictAddr number
            ---@param dictStructElement userdata
            function iterateDictionaryToStruct(dictAddr, dictStructElement)
                assert( type(dictAddr) == 'number', 'iterateDictionaryToStruct: dictAddr has to be a number, instead got: '..type(dictAddr))

                local debugPrefixStr ='>';
                if bDEBUGMode then debugPrefixStr = incDebugStep() end; 
                if (not (dictAddr > 0)) then if bDEBUGMode then print( debugPrefixStr..' iterateDictionaryToStruct: dictAddr was 0'); decDebugStep(); end; return; end
                if bDEBUGMode then print( debugPrefixStr..' iterateDictionaryToStruct: dictAddr'..string.format(' at %x', dictAddr)) end

                if GDSOf.MAJOR_VER == 3 then
                    dictAddr = readPointer( dictAddr + GDSOf.DICT_LIST ) -- for 3.x it's dictList actually
                end
                local dictSize = readInteger( dictAddr + GDSOf.DICT_SIZE )
                if (dictSize == 0 or dictSize == nil) then if bDEBUGMode then print( debugPrefixStr..' iterateDictionaryToStruct Dict: dictSize was 0'); decDebugStep(); end return; end
                if GDSOf.MAJOR_VER == 3 then -- dot it when the size is correct
                    dictStructElement = addStructureElem( dictStructElement, 'dictList', GDSOf.DICT_LIST, vtPointer )
                    dictStructElement.ChildStruct = createStructure('dictList')
                end

                local dictHead = readPointer( dictAddr + GDSOf.DICT_HEAD )
                local dictTail = readPointer( dictAddr + GDSOf.DICT_TAIL )
                local dictStructElement = addStructureElem( dictStructElement, 'dictHead', GDSOf.DICT_HEAD, vtPointer )
                dictStructElement.ChildStruct = createStructure('dictHead')
                if bDEBUGMode then print( debugPrefixStr..' iterateDictionaryToStruct: (hash)Map\t'..string.format(' head %x | last %x | size %d', dictHead, dictTail, dictSize)) end
                local mapElement = dictHead
                repeat
                    if bDEBUGMode then print( debugPrefixStr..' iterateDictionaryToStruct: Loop Map start'..string.format(' hashElemAddr: %x', mapElement)) end

                    local keyType, keyValueAddr
                    if GDSOf.MAJOR_VER == 3 then
                        local keyPtr = readPointer( mapElement ) -- key is a ptr
                        keyType = readInteger( keyPtr + GDSOf.DICTELEM_KEYTYPE )
                        keyValueAddr = getAddress( keyPtr + GDSOf.DICTELEM_KEYVAL )
                    else
                        keyType = readInteger( mapElement + GDSOf.DICTELEM_KEYTYPE ) -- those can be a key , NodePath, Callable, StringName, etc
                        keyValueAddr = getAddress( mapElement + GDSOf.DICTELEM_KEYVAL )                
                    end

                    local keyName = "UNKNOWN"
                    local valueValue;
                    local prefixStr = '';
                    local keyTypeName = getGDTypeName( keyType )
                    if ( keyTypeName == 'STRING' ) then -- 4
                        keyName = readUTFString( readPointer( keyValueAddr ) )
                    elseif ( keyTypeName == 'STRING_NAME') then -- 21
                        keyName = getStringNameStr( readPointer( keyValueAddr ) )
                    elseif ( keyTypeName == 'FLOAT' ) then -- 3
                        keyName = tostring( readDouble( keyValueAddr ) ) -- in godot 3.x real is 4 byte float or not?
                    elseif ( keyTypeName == 'NODE_PATH' or keyTypeName == 'RID' or keyTypeName == 'CALLABLE' ) then
                        keyName = tostring( readPointer( keyValueAddr ) )
                    else -- bool, int | might need separate for Vector2, Vector3, Color, etc
                        keyName = readInteger( keyValueAddr )
                    end

                    local valueType = readInteger( mapElement + GDSOf.DICTELEM_VALTYPE )
                    local offsetToValue = GDSOf.DICTELEM_VALTYPE + getVariantValueOffset( valueType )
                    valueValue = readPointer( mapElement + offsetToValue ) -- I'm kinda inconsistent here, should I rewrite it to be a ptr only?

                    local valueValuePtr = getAddress( mapElement + offsetToValue )

                    local valueTypeName = getGDTypeName( valueType )
                    if ( valueTypeName == 'DICTIONARY' ) then -- dictionary
                        if bDEBUGMode then print( debugPrefixStr..' iterateDictionaryToStruct: DICT CASE for name: '..tostring(keyName)) end
                        local dictSizeCheck
                        if GDSOf.MAJOR_VER >= 4 then
                            dictSizeCheck = readInteger( valueValue + GDSOf.DICT_SIZE )
                        else
                            dictSizeCheck = readInteger( readPointer( valueValue + GDSOf.DICT_LIST ) + GDSOf.DICT_SIZE )
                        end

                        if dictSizeCheck == nil or dictSizeCheck == 0 then
                            prefixStr = 'dict (empty): '
                            addStructureElem( dictStructElement, prefixStr..keyName, offsetToValue, getCETypeFromGD( valueType ) )
                        else
                            prefixStr = 'mdict: '
                            local newParentStructElem = addStructureElem( dictStructElement, prefixStr..keyName, offsetToValue, getCETypeFromGD( valueType ) )
                            newParentStructElem.ChildStruct = createStructure('Dict')
                            iterateDictionaryToStruct( valueValue , newParentStructElem )
                        end 

                    elseif ( valueTypeName == 'ARRAY') then
                        if bDEBUGMode then print( debugPrefixStr.." iterateDictionaryToStruct: DICT ARRAY case for name: "..tostring(keyName)) end
                        prefixStr = 'array: '

                        if readPointer( valueValue + GDSOf.ARRAY_TOVECTOR ) == 0 then -- when there are no elements in an array, it's vector ptr is 0
                            addStructureElem( dictStructElement, prefixStr..'empty: '..keyName, offsetToValue, getCETypeFromGD( valueType ) )
                        else
                            prefixStr = 'array: '
                            local newParentStructElem = addStructureElem( dictStructElement, prefixStr..keyName, offsetToValue, getCETypeFromGD( valueType ) )
                            newParentStructElem.ChildStruct = createStructure('Array')
                            iterateArrayToStruct( valueValue , newParentStructElem )
                        end

                    elseif ( valueTypeName == 'OBJECT' ) then
                        if bDEBUGMode then print( debugPrefixStr.." iterateDictionaryToStruct loop: OBJ case for name: "..tostring(keyName)..string.format(' and addr %x ', valueValue)) end
                        local bShifted, newParentStructElem;
                        valueValuePtr, bShifted = checkForVT( valueValuePtr ) -- check if the pointer is valid, if not, shift it back 0x8 bytes
                        valueValue = readPointer( valueValuePtr ) -- checkForVT returns a pointer
                        if bShifted then
                            offsetToValue = offsetToValue - GDSOf.PTRSIZE
                            newParentStructElem = addStructureElem( dictStructElement, 'Wrapper: '..keyName, offsetToValue, vtPointer )
                            newParentStructElem.ChildStruct = createStructure('Wrapper')
                            offsetToValue = 0x0 -- the object lies at 0x0 now
                        else
                            newParentStructElem = dictStructElement
                        end

                        if checkForGDScript( valueValue ) then
                            if bDEBUGMode then print( debugPrefixStr.." iterateDictionaryToStruct loop: NODE case: "..string.format('%x ', valueValue)..tostring(keyName)) end
                            prefixStr = 'mNode: '
                            addStructureElem( newParentStructElem, prefixStr..keyName, offsetToValue, getCETypeFromGD( valueType ) )
                        else
                            if bDEBUGMode then print( debugPrefixStr..' iterateDictionaryToStruct: OBJ doesn\'t have GDScript/Inst'); end
                            prefixStr = 'obj: '
                            addStructureElem( newParentStructElem, prefixStr..keyName, offsetToValue, getCETypeFromGD( valueType ) )
                        end

                    elseif ( valueTypeName == 'PACKED_STRING_ARRAY' ) or ( valueTypeName == 'PACKED_BYTE_ARRAY' )
                        or ( valueTypeName == 'PACKED_INT32_ARRAY' ) or ( valueTypeName == 'PACKED_INT64_ARRAY' )
                        or ( valueTypeName == 'PACKED_FLOAT32_ARRAY' ) or ( valueTypeName == 'PACKED_FLOAT64_ARRAY' )
                        or ( valueTypeName == 'PACKED_VECTOR2_ARRAY' ) or ( valueTypeName == 'PACKED_VECTOR3_ARRAY' )
                        or ( valueTypeName == 'PACKED_COLOR_ARRAY' ) or ( valueTypeName == 'PACKED_VECTOR4_ARRAY' ) then

                            if bDEBUGMode then print( debugPrefixStr.." iterateDictionaryToStruct loop: "..tostring(valueTypeName).." case: "..tostring(keyName)) end

                            if readPointer( valueValue + GDSOf.P_ARRAY_TOARR ) == 0 then -- when there are no elements in an array, its pointer shuld be 0 ?
                                prefixStr = 'pck_arr (empty): '
                                addStructureElem( dictStructElement, prefixStr..keyName..' of '..valueTypeName, offsetToValue, getCETypeFromGD( valueType ) )
                            else
                                prefixStr = 'pck_arr: '
                                local newParentStructElem = addStructureElem( dictStructElement, prefixStr..keyName.. ' T: '..tostring(valueTypeName), offsetToValue, getCETypeFromGD( valueType ) )
                                newParentStructElem.ChildStruct = createStructure('P_Array')
                                iteratePackedArrayToStruct(  valueValue , valueTypeName, newParentStructElem )
                            end

                    elseif ( valueTypeName == 'STRING' ) then
                            prefixStr = 'String: '
                            local newParentStructElem = addStructureElem( dictStructElement, prefixStr..keyName, offsetToValue, vtPointer )
                            newParentStructElem.ChildStruct = createStructure('String')
                            local stringElement = addStructureElem(newParentStructElem, prefixStr..keyName, 0x0, vtUnicodeString )
                            --stringElement.Bytesize = 100*4

                    else
                        valueValue = valueValuePtr -- getAddress( mapElement + GDSOf.DICTELEM_VALTYPE + offsetToValue )
                        if valueValue == 0 then if bDEBUGMode then print( debugPrefixStr.." iterateDictionaryToStruct: ValueValue is 0: uninitialized?") end end
                        addStructureElem( dictStructElement, prefixStr..keyName, offsetToValue, getCETypeFromGD( valueType ) )
                    end

                    if bDEBUGMode then print( debugPrefixStr..' iterateDictionaryToStruct nextloop, result: \t'..string.format(' name %s || elem 0x%x || keyT %d | keyV 0x%x || valT %d | valV addr 0x%x', tostring(keyName), (mapElement or 0), (keyType or 0), (keyValueAddr or 0), (valueType or 0), (valueValue or 0))) end
                    if GDSOf.MAJOR_VER >= 4 then
                        mapElement = readPointer( mapElement )
                        dictStructElement = addStructureElem( dictStructElement, 'Next', 0x0, vtPointer )
                        dictStructElement.ChildStruct = createStructure('DictNext')
                    else
                        dictStructElement = addStructureElem( dictStructElement, 'Next',  GDSOf.DICTELEM_PAIR_NEXT, vtPointer )
                        dictStructElement.ChildStruct = createStructure('DictNext')
                        mapElement = readPointer(mapElement + GDSOf.DICTELEM_PAIR_NEXT)
                    end

                until (mapElement == 0)

                if bDEBUGMode then decDebugStep(); end;
                return
            end

            --- iterates a dictionary for nodes
            ---@param dictAddr number
            function iterateDictionaryForNodes(dictAddr)
                assert( type(dictAddr) == 'number', 'iterateDictionaryForNodes: dictAddr has to be a number, instead got: '..type(dictAddr))
                if (not (dictAddr > 0)) then return; end

                if GDSOf.MAJOR_VER == 3 then
                    dictAddr = readPointer( dictAddr + GDSOf.DICT_LIST ) -- for 3.x it's dictList actually
                end
                local dictSize = readInteger( dictAddr + GDSOf.DICT_SIZE )
                if (dictSize == 0 or dictSize == nil) then return; end

                local mapElement = readPointer( dictAddr + GDSOf.DICT_HEAD )
                repeat
                    local valueValue;
                    local valueType = readInteger( mapElement + GDSOf.DICTELEM_VALTYPE )
                    local offsetToValue = GDSOf.DICTELEM_VALTYPE + getVariantValueOffset( valueType )
                    valueValue = readPointer( mapElement +  offsetToValue ) -- to avoid doing it several times
                    local valueValuePtr = getAddress( mapElement + offsetToValue )

                    local valueTypeName = getGDTypeName( valueType )
                    if ( valueTypeName == 'DICTIONARY' ) then -- dictionary
                        local dictSizeCheck
                        if GDSOf.MAJOR_VER >= 4 then
                            dictSizeCheck = readInteger( valueValue + GDSOf.DICT_SIZE )
                        else
                            dictSizeCheck = readInteger( readPointer( valueValue + GDSOf.DICT_LIST ) + GDSOf.DICT_SIZE )
                        end
                        if dictSizeCheck ~= nil and dictSizeCheck ~= 0 then
                            iterateDictionaryForNodes( valueValue ) -- recursive
                        end

                    elseif ( valueTypeName == 'ARRAY') then

                        if readPointer( valueValue + GDSOf.ARRAY_TOVECTOR ) ~= 0 then
                            iterateArrayForNodes( valueValue )
                        end

                    elseif ( valueTypeName == 'OBJECT' ) then
                        valueValuePtr = checkForVT( valueValuePtr )
                        valueValue = readPointer( valueValuePtr ) -- checkForVT returns a ptr
                        if checkForGDScript( valueValue ) then
                            iterateMNode( valueValue )
                        end

                    else
                    end
                    if GDSOf.MAJOR_VER >= 4 then
                        mapElement = readPointer( mapElement )
                    else
                        mapElement = readPointer( mapElement + GDSOf.DICTELEM_PAIR_NEXT )
                    end

                until (mapElement == 0)
            end

        --///---///--///---///--///---///--///--///---///--///---///--///---///--/// Array

            --- takes in an array address and address owner to append to
            ---@param arrayAddr number
            ---@param Owner userdata
            function iterateArrayToAddr(arrayAddr, Owner)
                assert(type(arrayAddr) == 'number',"Array "..tostring(arrayAddr).." has to be a number, instead got: "..type(arrayAddr))

                local debugPrefixStr ='>';
                if bDEBUGMode then debugPrefixStr = incDebugStep() end; 

                local arrVectorAddr = readPointer( arrayAddr + GDSOf.ARRAY_TOVECTOR )
                if arrVectorAddr == nil or arrVectorAddr == 0 then if bDEBUGMode then print( debugPrefixStr.." iterateArrayToAddr: vector ptr ("..tostring(arrVectorAddr)..") wasn't found."); decDebugStep(); end; return; end        
                local arrVectorSize = readInteger(arrVectorAddr - GDSOf.SIZE_VECTOR )
                if arrVectorSize == nil or arrVectorSize == 0 then if bDEBUGMode then print( debugPrefixStr.." iterateArrayToAddr: vector ptr's ("..tostring(arrVectorAddr)..") size was: "..tostring(arrVectorSize)); decDebugStep(); end; return; end

                if bDEBUGMode then print( debugPrefixStr..' iterateArrayToAddr start array vector:'..string.format(' at %x ', arrVectorAddr)..'with size: '..tostring(arrVectorSize)) end

                local variantArrSize, bSuccess = redefineVariantSizeByVector( arrVectorAddr , arrVectorSize )

                if not bSuccess then if bDEBUGMode then print( debugPrefixStr.." iterateVecVarToAddr: Variant resize failed") end; decDebugStep(); return; end
                local prefixStr = 'array['

                for varIndex=0, arrVectorSize-1 do

                    local variantPtr, variantType = getVariantByIndex( arrVectorAddr, varIndex, variantArrSize )
                    if variantPtr == 0 then if bDEBUGMode then print( debugPrefixStr.." iterateArrayToAddr: vector ptr ("..tostring(arrVectorAddr)..") wasn't found.") end; goto continue; end;

                    if bDEBUGMode then print( debugPrefixStr.." iterateArrayToAddr loop (Array: "..string.format('%x',arrayAddr).."): iterating index: "..tostring(varIndex)..' of '..tostring(arrVectorSize-1)..' | GDype: '..tostring(variantType)..' | VarAddr: '..string.format('%x',variantPtr)) end

                    local variantTypeName = getGDTypeName( variantType )
                    if ( variantTypeName == 'ARRAY' ) then
                        if bDEBUGMode then print( debugPrefixStr.." iterateArrayToAddr: NESTED ARRAY case") end

                        if readPointer( readPointer(variantPtr) + GDSOf.ARRAY_TOVECTOR ) == 0 then -- when there are no elements in an array, it's vector ptr is 0
                            prefixStr = 'array['

                            synchronize(function( prefixStr, varIndex, variantPtr, variantType, Owner)
                                            addMemRecTo( prefixStr..varIndex..'] (empty)' , variantPtr , getCETypeFromGD( variantType ) , Owner )
                                    end, prefixStr, varIndex, variantPtr, variantType, Owner
                                )

                        else
                            prefixStr = 'array['

                            local newParentMemrec = synchronize(function( prefixStr, varIndex, variantPtr, variantType, Owner)
                                            local newParentMemrec = addMemRecTo( prefixStr..varIndex..']' , variantPtr , getCETypeFromGD( variantType ) , Owner )
                                            newParentMemrec.Options = '[moHideChildren, moAllowManualCollapseAndExpand, moManualExpandCollapse]'
                                        return newParentMemrec
                                    end, prefixStr, varIndex, variantPtr, variantType, Owner
                                )

                            iterateArrayToAddr( readPointer( variantPtr ) , newParentMemrec )
                        end

                    elseif ( variantTypeName == 'DICTIONARY' ) then
                        if bDEBUGMode then print( debugPrefixStr.." iterateArrayToAddr loop: DICT case") end
                        local dictSize
                        if GDSOf.MAJOR_VER >= 4 then
                            dictSize = readInteger( readPointer( variantPtr ) + GDSOf.DICT_SIZE )
                        else
                            dictSize = readInteger( readPointer( readPointer( variantPtr ) + GDSOf.DICT_LIST ) + GDSOf.DICT_SIZE )
                        end

                        if dictSize == nil or dictSize == 0 then
                            prefixStr = 'dict (empty): '

                            synchronize(function( prefixStr, variantPtr, variantType, Owner)
                                        addMemRecTo( prefixStr , variantPtr , getCETypeFromGD( variantType ) , Owner ) -- when the dicitonary is empty, just add the addr
                                    end, prefixStr, variantPtr, variantType, Owner
                                )

                        else
                            prefixStr = 'mdict: '

                            local newParentMemrec = synchronize(function( prefixStr, variantPtr, variantType, Owner)
                                            local newParentMemrec = addMemRecTo( prefixStr , variantPtr , getCETypeFromGD( variantType ) , Owner )
                                            newParentMemrec.Options = '[moHideChildren, moAllowManualCollapseAndExpand, moManualExpandCollapse]'
                                        return newParentMemrec
                                    end, prefixStr, variantPtr, variantType, Owner
                                )

                            iterateDictionaryToAddr( readPointer( variantPtr ) , newParentMemrec )
                        end

                    elseif ( variantTypeName == 'OBJECT' ) then
                        if bDEBUGMode then print( debugPrefixStr.." iterateArrayToAddr loop: OBJ case") end
                        variantPtr = checkForVT( variantPtr )

                        if checkForGDScript( readPointer( variantPtr ) ) then
                            prefixStr = 'mNode: '
                            local nodeName = getNodeName( readPointer( variantPtr ) )

                            local newParentMemrec = synchronize(function( prefixStr, nodeName, variantPtr, variantType, Owner)
                                            local newParentMemrec = addMemRecTo( prefixStr..tostring(nodeName) , variantPtr , getCETypeFromGD( variantType ) , Owner )
                                            newParentMemrec.Options = '[moHideChildren, moAllowManualCollapseAndExpand, moManualExpandCollapse]'
                                        return newParentMemrec
                                    end, prefixStr, nodeName, variantPtr, variantType, Owner
                                )

                            iterateMNodeToAddr( readPointer( variantPtr ) , newParentMemrec )

                        else
                            if bDEBUGMode then print( debugPrefixStr..' iterateArrayToAddr: OBJ doesn\'t have GDScript/Inst'); end
                            prefixStr = 'obj: '
                            local nodeName = getNodeName( readPointer( variantPtr ) )

                            synchronize(function( prefixStr, nodeName, variantPtr, variantType, Owner)
                                        addMemRecTo( prefixStr..tostring(nodeName) , variantPtr , getCETypeFromGD( variantType )  , Owner )
                                    end, prefixStr, nodeName, variantPtr, variantType, Owner
                                )

                        end

                    elseif ( variantTypeName == 'PACKED_STRING_ARRAY' ) or ( variantTypeName == 'PACKED_BYTE_ARRAY' )
                        or ( variantTypeName == 'PACKED_INT32_ARRAY' ) or ( variantTypeName == 'PACKED_INT64_ARRAY' )
                        or ( variantTypeName == 'PACKED_FLOAT32_ARRAY' ) or ( variantTypeName == 'PACKED_FLOAT64_ARRAY' )
                        or ( variantTypeName == 'PACKED_VECTOR2_ARRAY' ) or ( variantTypeName == 'PACKED_VECTOR3_ARRAY' )
                        or ( variantTypeName == 'PACKED_COLOR_ARRAY' ) or ( variantTypeName == 'PACKED_VECTOR4_ARRAY' ) then

                            if bDEBUGMode then print( debugPrefixStr.." iterateArrayToAddr loop: "..tostring(variantTypeName).." case") end

                            local arrayAddr = readPointer( variantPtr )

                            if readPointer( arrayAddr + GDSOf.P_ARRAY_TOARR ) == 0 then -- when there are no elements in an array, its vector ptr is 0 ?
                                prefixStr = 'mpck_arr (empty): '

                                synchronize(function( prefixStr, variantTypeName, variantPtr, variantType, Owner)
                                            addMemRecTo( prefixStr..' of '..tostring(variantTypeName) , variantPtr , getCETypeFromGD( variantType ) , Owner )
                                        end, prefixStr, variantTypeName, variantPtr, variantType, Owner
                                    )

                            else
                                prefixStr = 'mpck_arr: '

                                local newParentMemrec = synchronize(function( prefixStr, variantTypeName, variantPtr, variantType, Owner)
                                            local newParentMemrec = addMemRecTo( prefixStr..' of '..tostring(variantTypeName) , variantPtr , getCETypeFromGD( variantType ) , Owner )
                                            newParentMemrec.Options = '[moHideChildren, moAllowManualCollapseAndExpand, moManualExpandCollapse]'
                                            return newParentMemrec
                                        end, prefixStr, variantTypeName, variantPtr, variantType, Owner
                                    )

                                iteratePackedArrayToAddr(  arrayAddr , variantTypeName, newParentMemrec )
                            end

                    else
                        prefixStr = 'array['

                        synchronize(function( prefixStr, varIndex, variantTypeName, variantPtr, variantType, Owner)
                                        addMemRecTo( prefixStr..varIndex..']: '..tostring(variantTypeName) , variantPtr , getCETypeFromGD( variantType )  , Owner )
                                    end, prefixStr, varIndex, variantTypeName, variantPtr, variantType, Owner
                                )

                    end
                    ::continue:: -- just to feel safe when variantPtr is 0
                end

                if bDEBUGMode then decDebugStep(); end;
                return
            end

            --- takes in an array address and struct owner to append to
            ---@param arrayAddr number
            ---@param Owner userdata
            function iterateArrayToStruct(arrayAddr, arrayStructElement)
                assert(type(arrayAddr) == 'number',"iterateArrayToStruct: Array "..tostring(arrayAddr).." has to be a number, instead got: "..type(arrayAddr))

                local debugPrefixStr ='>';
                if bDEBUGMode then debugPrefixStr = incDebugStep() end; 

                local arrVectorAddr = readPointer( arrayAddr + GDSOf.ARRAY_TOVECTOR )
                if arrVectorAddr == nil or arrVectorAddr == 0 then if bDEBUGMode then print( debugPrefixStr.." iterateArrayToStruct: vector ptr ("..tostring(arrVectorAddr)..") wasn't found."); decDebugStep(); end; return; end        
                local arrVectorSize = readInteger(arrVectorAddr - GDSOf.SIZE_VECTOR )
                if arrVectorSize == nil or arrVectorSize == 0 then if bDEBUGMode then print( debugPrefixStr.." iterateArrayToStruct: vector ptr's ("..tostring(arrVectorAddr)..") size was: "..tostring(arrVectorSize)); decDebugStep(); end; return; end
                arrayStructElement = addStructureElem( arrayStructElement, 'VectorArray', GDSOf.ARRAY_TOVECTOR, vtPointer )
                arrayStructElement.ChildStruct = createStructure('ArrayData')

                if bDEBUGMode then print( debugPrefixStr..' iterateArrayToStruct start array vector:'..string.format(' at %x ', arrVectorAddr)..'with size: '..tostring(arrVectorSize)) end
                local variantArrSize, bSuccess = redefineVariantSizeByVector( arrVectorAddr , arrVectorSize )
                if not bSuccess then if bDEBUGMode then print( debugPrefixStr.." iterateVecVarToAddr: Variant resize failed") end; decDebugStep(); return; end
                local prefixStr = 'array['

                for varIndex=0, arrVectorSize-1 do

                    local variantPtr, variantType, offsetToValue = getVariantByIndex( arrVectorAddr, varIndex, variantArrSize, true )
                    if variantPtr == 0 then if bDEBUGMode then print( debugPrefixStr.." iterateArrayToStruct: vector ptr ("..tostring(arrVectorAddr)..") wasn't found.") end; goto continue; end;

                    if bDEBUGMode then print( debugPrefixStr.." iterateArrayToStruct loop (Array: "..string.format('%x',arrayAddr).."): iterating index: "..tostring(varIndex)..' of '..tostring(arrVectorSize-1)..' | GDype: '..tostring(variantType)..' | VarAddr: '..string.format('%x',variantPtr)) end
                    local variantTypeName = getGDTypeName( variantType )

                    if ( variantTypeName == 'ARRAY' ) then
                        if bDEBUGMode then print( debugPrefixStr.." iterateArrayToStruct: NESTED ARRAY case") end

                        if readPointer( readPointer(variantPtr) + GDSOf.ARRAY_TOVECTOR ) == 0 then -- when there are no elements in an array, it's vector ptr is 0
                            prefixStr = 'array['
                            addStructureElem( arrayStructElement, prefixStr..varIndex..'] (empty)', offsetToValue, getCETypeFromGD( variantType ) )
                        else
                            prefixStr = 'array['
                            local newParentStructElem = addStructureElem( arrayStructElement, prefixStr..varIndex..']', offsetToValue, getCETypeFromGD( variantType ) )
                            newParentStructElem.ChildStruct = createStructure('Array')
                            iterateArrayToStruct( readPointer( variantPtr ) , newParentStructElem )
                        end

                    elseif ( variantTypeName == 'DICTIONARY' ) then
                        if bDEBUGMode then print( debugPrefixStr.." iterateArrayToStruct loop: DICT case") end
                        local dictSize
                        if GDSOf.MAJOR_VER >= 4 then
                            dictSize = readInteger( readPointer( variantPtr ) + GDSOf.DICT_SIZE )
                        else
                            dictSize = readInteger( readPointer( readPointer( variantPtr ) + GDSOf.DICT_LIST ) + GDSOf.DICT_SIZE )
                        end

                        if dictSize == nil or dictSize == 0 then
                            prefixStr = 'dict (empty): '
                            addStructureElem( arrayStructElement, prefixStr, offsetToValue, getCETypeFromGD( variantType ) )
                        else
                            prefixStr = 'mdict: '
                            local newParentStructElem = addStructureElem( arrayStructElement, prefixStr, offsetToValue, getCETypeFromGD( variantType ) )
                            newParentStructElem.ChildStruct = createStructure('Dict')
                            iterateDictionaryToStruct( readPointer( variantPtr ) , newParentStructElem )
                        end

                    elseif ( variantTypeName == 'OBJECT' ) then
                        if bDEBUGMode then print( debugPrefixStr.." iterateArrayToStruct loop: OBJ case") end
                        local bShifted, newParentStructElem;
                        variantPtr, bShifted = checkForVT( variantPtr ) -- check if the pointer is valid, if not, shift it back 0x8 bytes
                        if bShifted then
                            offsetToValue = offsetToValue - GDSOf.PTRSIZE
                            newParentStructElem = addStructureElem( arrayStructElement, 'Wrapper', offsetToValue, vtPointer )
                            newParentStructElem.ChildStruct = createStructure('Wrapper')
                            offsetToValue = 0x0 -- the object lies at 0x0 now
                        else
                            newParentStructElem = arrayStructElement
                        end

                        local valueAddr = readPointer( variantPtr )
                        local nodeName = getNodeName( valueAddr )

                        if checkForGDScript( valueAddr ) then
                            prefixStr = 'mNode: '
                            addStructureElem( newParentStructElem, prefixStr..tostring(nodeName), offsetToValue, getCETypeFromGD( variantType ) )
                        else
                            if bDEBUGMode then print( debugPrefixStr..' iterateArrayToStruct: OBJ doesn\'t have GDScript/Inst'); end
                            prefixStr = 'obj: '
                            addStructureElem( newParentStructElem, prefixStr..tostring(nodeName), offsetToValue, getCETypeFromGD( variantType ) )
                        end

                    elseif ( variantTypeName == 'PACKED_STRING_ARRAY' ) or ( variantTypeName == 'PACKED_BYTE_ARRAY' )
                        or ( variantTypeName == 'PACKED_INT32_ARRAY' ) or ( variantTypeName == 'PACKED_INT64_ARRAY' )
                        or ( variantTypeName == 'PACKED_FLOAT32_ARRAY' ) or ( variantTypeName == 'PACKED_FLOAT64_ARRAY' )
                        or ( variantTypeName == 'PACKED_VECTOR2_ARRAY' ) or ( variantTypeName == 'PACKED_VECTOR3_ARRAY' )
                        or ( variantTypeName == 'PACKED_COLOR_ARRAY' ) or ( variantTypeName == 'PACKED_VECTOR4_ARRAY' ) then

                        if bDEBUGMode then print( debugPrefixStr.." iterateArrayToStruct loop: "..tostring(variantTypeName).." case") end
                        
                        local arrayAddr = readPointer( variantPtr )
                        if readPointer( arrayAddr + GDSOf.P_ARRAY_TOARR ) == 0 then -- when there are no elements in an array, its vector ptr is 0 ?
                            prefixStr = 'mpck_arr (empty): '
                            addStructureElem( arrayStructElement, prefixStr..' of '..tostring(variantTypeName), offsetToValue, getCETypeFromGD( variantType ) )
                        else
                            prefixStr = 'mpck_arr: '
                            local newParentStructElem = addStructureElem(arrayStructElement, prefixStr..' of '..tostring(variantTypeName), offsetToValue, getCETypeFromGD( variantType ) )
                            newParentStructElem.ChildStruct = createStructure('P_Array')
                            iteratePackedArrayToStruct(  arrayAddr, variantTypeName, newParentStructElem )
                        end

                    elseif ( variantTypeName == 'STRING' ) then
                            prefixStr = 'string['
                            local newParentStructElem = addStructureElem( arrayStructElement, prefixStr..varIndex..']', offsetToValue, vtPointer )
                            newParentStructElem.ChildStruct = createStructure('String')
                            local stringElement = addStructureElem(newParentStructElem, prefixStr..varIndex..']', 0x0, vtUnicodeString )
                            --stringElement.Bytesize = 100*4

                    else
                        prefixStr = 'array['
                        addStructureElem( arrayStructElement, prefixStr..varIndex..']', offsetToValue, getCETypeFromGD( variantType ) )
                    end
                    ::continue:: -- just to feel safe when variantPtr is 0
                end

                if bDEBUGMode then decDebugStep(); end;
                return
            end

            --- iterates an array for nodes
            ---@param arrayAddr number
            function iterateArrayForNodes(arrayAddr)
                assert(type(arrayAddr) == 'number',"iterateArrayForNodes: array "..tostring(arrayAddr).." has to be a number, instead got: "..type(arrayAddr))

                local arrVectorAddr = readPointer( arrayAddr + GDSOf.ARRAY_TOVECTOR )
                if arrVectorAddr == nil or arrVectorAddr == 0 then return; end        
                local arrVectorSize = readInteger(arrVectorAddr - GDSOf.SIZE_VECTOR )
                if arrVectorSize == nil or arrVectorSize == 0 then return; end

                local variantArrSize, bSuccess = redefineVariantSizeByVector( arrVectorAddr , arrVectorSize )
                if not bSuccess then return; end

                for varIndex=0, arrVectorSize-1 do

                    local variantPtr, variantType = getVariantByIndex( arrVectorAddr, varIndex, variantArrSize )
                    if variantPtr == 0 then goto continue; end;

                    local variantTypeName = getGDTypeName( variantType )

                    if ( variantTypeName == 'ARRAY' ) then
                        if readPointer( readPointer(variantPtr) + GDSOf.ARRAY_TOVECTOR ) ~= 0 then
                            iterateArrayForNodes( readPointer( variantPtr ) )
                        end

                    elseif ( variantTypeName == 'DICTIONARY' ) then
                        local dictSize
                        if GDSOf.MAJOR_VER >= 4 then
                            dictSize = readInteger( readPointer( variantPtr ) + GDSOf.DICT_SIZE )
                        else -- 3.x
                            dictSize = readInteger( readPointer( readPointer( variantPtr ) + GDSOf.DICT_LIST ) + GDSOf.DICT_SIZE )
                        end

                        if dictSize ~= nil and dictSize ~= 0 then
                            iterateDictionaryForNodes( readPointer( variantPtr ) )
                        end

                    elseif ( variantTypeName == 'OBJECT' ) then
                        variantPtr = checkForVT( variantPtr )

                        if checkForGDScript( readPointer( variantPtr ) ) then
                            iterateMNode( readPointer( variantPtr )  )
                        end

                    else
                    end
                    ::continue:: -- just to feel safe when variantPtr is 0
                end
            end

            --- iterates a packed array and adds it to a class
            ---@param packedArrayAddr number
            ---@param packedTypeName string
            ---@param Owner userdata
            function iteratePackedArrayToAddr(packedArrayAddr, packedTypeName, Owner)
                assert(type(packedArrayAddr) == 'number',"Packed Array "..tostring(packedArrayAddr).." has to be a number, instead got: "..type(packedArrayAddr))
                assert(type(packedTypeName) == 'string',"TypeName "..tostring(packedTypeName).." has to be a string, instead got: "..type(packedTypeName))

                local debugPrefixStr ='>';
                if bDEBUGMode then debugPrefixStr = incDebugStep() end; 

                local packedDataArrAddr = readPointer( packedArrayAddr + GDSOf.P_ARRAY_TOARR )
                if packedDataArrAddr == nil or packedDataArrAddr == 0 then if bDEBUGMode then print( debugPrefixStr.." iteratePackedArrayToAddr: vector ptr ("..tostring(packedDataArrAddr)..") wasn't found. Packed Arr type: "..tostring(packedTypeName)); decDebugStep(); end; return; end        
                local packedVectorSize = readInteger( packedDataArrAddr - GDSOf.SIZE_VECTOR )
                if packedVectorSize == nil or packedVectorSize == 0 then if bDEBUGMode then print( debugPrefixStr.." iteratePackedArrayToAddr: vector ptr's ("..tostring(packedDataArrAddr)..") size: "..tostring(packedVectorSize)..' Packed Arr type: '..tostring(packedTypeName)); decDebugStep(); end; return; end

                if bDEBUGMode then print( debugPrefixStr..' iteratePackedArrayToAddr start array vector:'..string.format(' at %x ', packedDataArrAddr)..'with size: '..tostring(packedVectorSize)..' and type: '..tostring(packedTypeName)) end

                local prefixStr = 'pck_arr['

                if packedVectorSize > 150 then
                    if bDEBUGMode then print( debugPrefixStr.." iteratePackedArrayToAddr: Packed Array is quite big ("..tostring(packedVectorSize).."), truncating...") end

                    synchronize(function(packedDataArrAddr, packedVectorSize, Owner)
                                addMemRecTo( 'This array\'s size is '..tostring(packedVectorSize)..': dumping 150', packedDataArrAddr , vtPointer , Owner )
                                addMemRecTo( 'Calculate next indices: base of this addr + sizeof(type)*index', packedDataArrAddr , vtPointer , Owner )
                            end, packedDataArrAddr, packedVectorSize, Owner
                        )

                    packedVectorSize = 150 -- truncate to 150 elements
                end

                if ( packedTypeName == 'PACKED_STRING_ARRAY') then
                    for elemIndex=0, packedVectorSize-1 do
                        local arrElement = getAddress( packedDataArrAddr + elemIndex * GDSOf.PTRSIZE ) -- each element is a pointer to a StringName
                        if readPointer( arrElement ) == 0 then if bDEBUGMode then print( debugPrefixStr.." iteratePackedArrayToAddr: Packed Array String element ("..tostring(arrElement)..") is zero.") end; goto continue; end;

                        synchronize(function(prefixStr, elemIndex, arrElement, Owner)
                                    addMemRecTo( prefixStr..elemIndex..']' , arrElement , vtString , Owner )
                                end, prefixStr, elemIndex, arrElement, Owner
                            )

                        ::continue:: -- just to feel safe
                    end

                elseif ( packedTypeName == 'PACKED_INT32_ARRAY' ) or ( packedTypeName == 'PACKED_FLOAT32_ARRAY' ) then -- 4 bytes
                    if bDEBUGMode then print( debugPrefixStr.." iteratePackedArrayToAddr before loop (Packed Array: "..string.format('%x',packedArrayAddr).."): 32 int or float ") end
                    for elemIndex=0, packedVectorSize-1 do
                        local arrElement = getAddress( packedDataArrAddr + elemIndex * 0x4 )

                        if packedTypeName == 'PACKED_FLOAT32_ARRAY' then
                            synchronize(function(prefixStr, elemIndex, arrElement, Owner)
                                        addMemRecTo( prefixStr..elemIndex..']' , arrElement , vtSingle , Owner )
                                    end, prefixStr, elemIndex, arrElement, Owner
                                )
                        else
                            synchronize(function(prefixStr, elemIndex, arrElement, Owner)
                                        addMemRecTo( prefixStr..elemIndex..']' , arrElement , vtDword , Owner )
                                    end, prefixStr, elemIndex, arrElement, Owner
                                )
                        end
                    end
                elseif ( packedTypeName == 'PACKED_INT64_ARRAY' ) or ( packedTypeName == 'PACKED_FLOAT64_ARRAY' ) then -- 8 bytes
                    if bDEBUGMode then print( debugPrefixStr.." iteratePackedArrayToAddr before loop (Packed Array: "..string.format('%x',packedArrayAddr).."): 64 int or double" ) end
                    for elemIndex=0, packedVectorSize-1 do
                        local arrElement = getAddress( packedDataArrAddr + elemIndex * GDSOf.PTRSIZE )

                        if packedTypeName == 'PACKED_FLOAT64_ARRAY' then
                            synchronize(function(prefixStr, elemIndex, arrElement, Owner)
                                        addMemRecTo( prefixStr..elemIndex..']' , arrElement , vtDouble , Owner )
                                    end, prefixStr, elemIndex, arrElement, Owner
                                )
                        else
                            synchronize(function(prefixStr, elemIndex, arrElement, Owner)
                                        addMemRecTo( prefixStr..elemIndex..']' , arrElement , vtQword , Owner )
                                    end, prefixStr, elemIndex, arrElement, Owner
                                )
                        end
                    end

                elseif ( packedTypeName == 'PACKED_BYTE_ARRAY' ) then -- 1 byte
                    if bDEBUGMode then print( debugPrefixStr.." iteratePackedArrayToStruct before loop (Packed Array: "..string.format('%x',packedArrayAddr).."): byte" ) end
                    for elemIndex=0, packedVectorSize-1 do
                        local arrElement = getAddress( packedDataArrAddr + elemIndex * 0x1 )

                        synchronize(function(prefixStr, elemIndex, arrElement, Owner)
                                    addMemRecTo( prefixStr..elemIndex..']' , arrElement , vtByte , Owner )
                                end, prefixStr, elemIndex, arrElement, Owner
                            )
                    end
                -- PACKED_VECTOR2_ARRAY PACKED_VECTOR3_ARRAY PACKED_COLOR_ARRAY PACKED_VECTOR4_ARRAY are not handled
                else
                    if bDEBUGMode then print( debugPrefixStr.." iteratePackedArrayToAddr: Unhandled Packed Array type: "..tostring(packedTypeName) ) end
                    for elemIndex=0, packedVectorSize-1 do
                        local arrElement = getAddress( packedDataArrAddr + elemIndex * GDSOf.PTRSIZE )

                        synchronize(function(prefixStr, elemIndex, arrElement, Owner)
                                    addMemRecTo( prefixStr..elemIndex..']' , arrElement , vtPointer , Owner )
                                end, prefixStr, elemIndex, arrElement, Owner
                            )
                    end
                end

                if bDEBUGMode then decDebugStep(); end;
                return
            end

            --- iterates a packed array and adds it to a struct
            ---@param packedArrayAddr number
            ---@param packedTypeName string
            ---@param pArrayStructElement userdata
            function iteratePackedArrayToStruct(packedArrayAddr, packedTypeName, pArrayStructElement)
                assert(type(packedArrayAddr) == 'number',"Packed Array "..tostring(packedArrayAddr).." has to be a number, instead got: "..type(packedArrayAddr))
                assert(type(packedTypeName) == 'string',"TypeName "..tostring(packedTypeName).." has to be a string, instead got: "..type(packedTypeName))

                local debugPrefixStr ='>';
                if bDEBUGMode then debugPrefixStr = incDebugStep() end; 

                local packedDataArrAddr = readPointer( packedArrayAddr + GDSOf.P_ARRAY_TOARR )
                if packedDataArrAddr == nil or packedDataArrAddr == 0 then if bDEBUGMode then print( debugPrefixStr.." iteratePackedArrayToStruct: vector ptr ("..tostring(packedDataArrAddr)..") wasn't found. Packed Arr type: "..tostring(packedTypeName)); decDebugStep(); end; return; end        
                local packedVectorSize = readInteger( packedDataArrAddr - GDSOf.SIZE_VECTOR ) -- cannot confirm I'm right and if packed, those can be easily null terminated
                if packedVectorSize == nil or packedVectorSize == 0 then if bDEBUGMode then print( debugPrefixStr.." iteratePackedArrayToStruct: vector ptr's ("..tostring(packedDataArrAddr)..") size: "..tostring(packedVectorSize)..' Packed Arr type: '..tostring(packedTypeName)); decDebugStep(); end; return; end
                pArrayStructElement = addStructureElem( pArrayStructElement, 'PckArray', GDSOf.P_ARRAY_TOARR, vtPointer )
                pArrayStructElement.ChildStruct = createStructure('PArrayData')
                
                if bDEBUGMode then print( debugPrefixStr..' iteratePackedArrayToStruct start array vector:'..string.format(' at %x ', packedDataArrAddr)..'with size: '..tostring(packedVectorSize)..' and type: '..tostring(packedTypeName)) end
                local prefixStr = 'pck_arr['

                if packedVectorSize > 256 then
                    packedVectorSize = 256
                end
                local offsetToValue

                if ( packedTypeName == 'PACKED_STRING_ARRAY') then
                    for elemIndex=0, packedVectorSize-1 do
                        offsetToValue = elemIndex * GDSOf.PTRSIZE
                        local arrElement = getAddress( packedDataArrAddr + offsetToValue ) -- each element is a pointer to a String
                        if readPointer( arrElement ) == 0 then if bDEBUGMode then print( debugPrefixStr.." iteratePackedArrayToStruct: Packed Array String element ("..tostring(arrElement)..") is zero.") end; goto continue; end;

                        local stringPtrElement = addStructureElem( pArrayStructElement, ('strElem[%d]'):format(elemIndex), offsetToValue, vtPointer )
                        stringPtrElement.ChildStruct = createStructure('StringItem')
                        local stringElement = addStructureElem( stringPtrElement, 'String', 0x0, vtUnicodeString )
                        --stringElement.Bytesize = 100*4

                        ::continue:: -- just to feel safe
                    end

                elseif ( packedTypeName == 'PACKED_INT32_ARRAY' ) or ( packedTypeName == 'PACKED_FLOAT32_ARRAY' ) then -- 4 bytes
                    if bDEBUGMode then print( debugPrefixStr.." iteratePackedArrayToStruct before loop (Packed Array: "..string.format('%x',packedArrayAddr).."): 32 int or float ") end
                    for elemIndex=0, packedVectorSize-1 do
                        offsetToValue = elemIndex * 0x4
                        if packedTypeName == 'PACKED_FLOAT32_ARRAY' then
                            addStructureElem( pArrayStructElement, prefixStr..elemIndex..']', offsetToValue, vtSingle)
                        else
                            addStructureElem( pArrayStructElement, prefixStr..elemIndex..']', offsetToValue, vtDword)
                        end
                    end

                elseif ( packedTypeName == 'PACKED_INT64_ARRAY' ) or ( packedTypeName == 'PACKED_FLOAT64_ARRAY' ) then -- 8 bytes
                    if bDEBUGMode then print( debugPrefixStr.." iteratePackedArrayToStruct before loop (Packed Array: "..string.format('%x',packedArrayAddr).."): 64 int or double" ) end
                    for elemIndex=0, packedVectorSize-1 do
                        offsetToValue = elemIndex * GDSOf.PTRSIZE
                        if packedTypeName == 'PACKED_FLOAT64_ARRAY' then
                            addStructureElem( pArrayStructElement, prefixStr..elemIndex..']', offsetToValue, vtDouble)
                        else
                            addStructureElem( pArrayStructElement, prefixStr..elemIndex..']', offsetToValue, vtQword)
                        end
                    end

                elseif ( packedTypeName == 'PACKED_BYTE_ARRAY' ) then -- 1 byte
                    if bDEBUGMode then print( debugPrefixStr.." iteratePackedArrayToStruct before loop (Packed Array: "..string.format('%x',packedArrayAddr).."): byte" ) end
                    for elemIndex=0, packedVectorSize-1 do
                        offsetToValue = elemIndex * 0x1
                        addStructureElem( pArrayStructElement, prefixStr..elemIndex..']', offsetToValue, vtByte)
                    end

                else
                    if bDEBUGMode then print( debugPrefixStr.." iteratePackedArrayToStruct: Unhandled Packed Array type: "..tostring(packedTypeName) ) end
                    for elemIndex=0, packedVectorSize-1 do
                        offsetToValue = elemIndex * GDSOf.PTRSIZE
                        addStructureElem( pArrayStructElement, prefixStr..elemIndex..'] /U/', offsetToValue, vtPointer)
                    end
                end

                if bDEBUGMode then decDebugStep(); end;
                return
            end

        --///---///--///---///--///---///--///--///---///--///---///--///---///--/// Variant

            --- nodeName and owner to append to
            ---@param nodeAddr number
            ---@param Owner userdata
            function iterateVecVarToAddr(nodeAddr, Owner)
                assert(type(nodeAddr) == 'number',"iterateVecVarToAddr: Node addr has to be a number, instead got: "..type(nodeAddr))

                local debugPrefixStr ='>';
                if bDEBUGMode then debugPrefixStr = incDebugStep() end; 

                local nodeName = getNodeName( nodeAddr )

                if not checkForGDScript( nodeAddr ) then if bDEBUGMode then print( debugPrefixStr.." iterateVecVarToAddr: Node "..tostring(nodeName).." with NO GDScript"); decDebugStep(); end; return; end;

                if bDEBUGMode then print( debugPrefixStr..' iterateVecVarToAddr start (hash)map for node: '..tostring(nodeName)..string.format(' at %x', nodeAddr)) end
                local headElement, tailElement, mapSize = getNodeVariantMap(nodeAddr)
                if ( headElement==0 or headElement==nil ) or ( mapSize==0 or mapSize==nil ) then
                    if bDEBUGMode then print( debugPrefixStr..' iterateVecVarToAddr (hash)Map empty?: '..tostring(nodeName)); decDebugStep(); end
                    return; --just return on fail
                end 
                local mapElement = headElement
                local prefixStr = 'var: '
                local variantVector, vectorSize = getNodeVariantVector(nodeAddr)
                local variantSize, bSuccess = redefineVariantSizeByVector( variantVector, vectorSize )
                if not bSuccess then if bDEBUGMode then print( debugPrefixStr.." iterateVecVarToAddr: Variant resize failed"); decDebugStep(); end return; end

                repeat
                    -- the vector is stored inside a GDScirptInstance and memberIndices inside the GDScript (as a BP)
                    local variantName, variantTypeScr, testedVarT
                    local variantIndex = readInteger( mapElement + GDSOf.VAR_NAMEINDEX_I )
                    local variantPtr, variantType = getVariantByIndex( variantVector, variantIndex, variantSize ) -- let's do that first to avoid several ver blocks
                    
                    if GDSOf.MAJOR_VER >= 4 then -- 4.x versions have type in the memberinfo which 3.x does not (or i'm not aware of)
                        variantName = getStringNameStr( readPointer( mapElement + GDSOf.STRING ) )
                        local variantTypeScr = readInteger( mapElement + GDSOf.VAR_NAMEINDEX_VARTYPE )
                        if variantTypeScr > GDSOf.MAXTYPE then variantTypeScr = readInteger( mapElement + GDSOf.VAR_NAMEINDEX_VARTYPE - 0x8 ) end; -- 4.2.2 had the issue with type offset being different for different memberinfos

                        if variantTypeScr == variantType then -- silly, but the types are sometimes inconsistent, cross-checking resolves for most tested cases
                        testedVarT = variantTypeScr
                        elseif ( variantTypeScr > variantType ) and ( variantTypeScr > 0 and variantTypeScr <= GDSOf.MAXTYPE ) then
                        testedVarT = variantTypeScr
                        elseif ( variantType > variantTypeScr ) and ( variantType > 0 and variantType <= GDSOf.MAXTYPE ) then
                        testedVarT = variantType
                        elseif variantTypeScr > GDSOf.MAXTYPE then
                            testedVarT = variantType; if bDEBUGMode then print( debugPrefixStr..' iterateVecVarToAddr: fallback1, cached type is used'); end; -- if the source is incorrect
                        else
                        testedVarT = variantTypeScr; if bDEBUGMode then print( debugPrefixStr..' iterateVecVarToAddr: fallback2, cached type is used'); end; -- let's have cached if everything is wrong
                        end
                    else
                        variantName = getStringNameStr( readPointer( mapElement + GDSOf.MAP_KVALUE ) )
                        testedVarT = variantType -- actually not tested, just to be compatible
                        variantTypeScr = variantType
                    end

                    if bDEBUGMode then print( debugPrefixStr.." iterateVecVarToAddr loop (Node: "..tostring(nodeName)..": "..string.format('%x',nodeAddr).."): iterating at:\t\t"..variantName..' index: '..tostring(variantIndex)..' of '..tostring(mapSize-1)..' | GDype (src/act/test): '..tostring(variantTypeScr)..'/'..tostring(variantType)..'/'..tostring(testedVarT)..' | VarAddr: '..string.format('%x',variantPtr)) end
                    local testedVarName = getGDTypeName( testedVarT ) 

                    if ( testedVarName == 'DICTIONARY' ) then
                        if bDEBUGMode then print( debugPrefixStr.." iterateVecVarToAddr loop: DICT case for name: "..tostring(variantName) ) end
                        prefixStr = 'dict: '
                        local dictSize
                        if GDSOf.MAJOR_VER >= 4 then
                            dictSize = readInteger( readPointer( variantPtr ) + GDSOf.DICT_SIZE )
                        else
                            dictSize = readInteger( readPointer( readPointer( variantPtr ) + GDSOf.DICT_LIST ) + GDSOf.DICT_SIZE )
                        end

                        if dictSize == nil or dictSize == 0 then
                            prefixStr = 'dict (empty): '

                            synchronize(function( prefixStr, variantName, variantPtr, testedVarT, Owner)
                                        addMemRecTo( prefixStr..variantName , variantPtr , getCETypeFromGD( testedVarT ) , Owner ) -- when the dicitonary is empty, just add the addr
                                    end, prefixStr, variantName, variantPtr, testedVarT, Owner
                                )

                        else

                            local newParentMemrec = synchronize(function( prefixStr, variantName, variantPtr, testedVarT, Owner)
                                            local newParentMemrec = addMemRecTo( prefixStr..variantName , variantPtr , getCETypeFromGD( testedVarT ) , Owner )
                                            newParentMemrec.Options = '[moHideChildren, moAllowManualCollapseAndExpand, moManualExpandCollapse]'
                                        return newParentMemrec
                                    end, prefixStr, variantName, variantPtr, testedVarT, Owner
                                )

                            iterateDictionaryToAddr( readPointer( variantPtr ) , newParentMemrec )
                        end

                    elseif testedVarName == 'ARRAY' then
                        if bDEBUGMode then print( debugPrefixStr.." iterateVecVarToAddr: ARRAY case for name: "..tostring(variantName) ) end
                        
                        if readPointer( readPointer(variantPtr) + GDSOf.ARRAY_TOVECTOR ) == 0 then

                            synchronize(function( variantName, variantPtr, testedVarT, Owner)
                                        addMemRecTo( 'array: (empty): '..variantName , variantPtr , getCETypeFromGD( testedVarT ) , Owner )
                                    end, variantName, variantPtr, testedVarT, Owner
                                )

                        else
                            prefixStr = 'array: '

                            local newParentMemrec = synchronize(function( prefixStr, variantName, variantPtr, testedVarT, Owner)
                                            local newParentMemrec = addMemRecTo( prefixStr..variantName , variantPtr , getCETypeFromGD( testedVarT ) , Owner )
                                            newParentMemrec.Options = '[moHideChildren, moAllowManualCollapseAndExpand, moManualExpandCollapse]'
                                        return newParentMemrec
                                    end, prefixStr, variantName, variantPtr, testedVarT, Owner
                                )

                            iterateArrayToAddr( readPointer( variantPtr ) , newParentMemrec )
                        end

                    elseif ( testedVarName == 'OBJECT' ) then
                        if bDEBUGMode then print( debugPrefixStr.." iterateVecVarToAddr loop: OBJ case: name: "..tostring(variantName)..string.format(' addr: %x ', variantPtr)) end
                        variantPtr = checkForVT( variantPtr )

                        if checkForGDScript( readPointer( variantPtr ) ) then
                            if bDEBUGMode then print( debugPrefixStr.." iterateVecVarToAddr loop: NODE case: "..string.format('%x ', variantPtr)..tostring(variantName)) end
                            prefixStr = 'mNode: '

                            local newParentMemrec = synchronize(function( prefixStr, variantName, variantPtr, testedVarT, Owner)
                                            local newParentMemrec = addMemRecTo( prefixStr..variantName , variantPtr , getCETypeFromGD( testedVarT ) , Owner )
                                            newParentMemrec.Options = '[moHideChildren, moAllowManualCollapseAndExpand, moManualExpandCollapse]'
                                        return newParentMemrec
                                    end, prefixStr, variantName, variantPtr, testedVarT, Owner
                                )

                            iterateMNodeToAddr( readPointer( variantPtr ) , newParentMemrec )
                        else
                            if bDEBUGMode then print( debugPrefixStr..' iterateVecVarToAddr: OBJ doesn\'t have GDScript/Inst'); end
                            prefixStr = 'obj: '

                            synchronize(function( prefixStr, variantName, variantPtr, testedVarT, Owner)
                                        addMemRecTo( prefixStr..variantName , variantPtr , getCETypeFromGD( testedVarT )  , Owner )
                                    end, prefixStr, variantName, variantPtr, testedVarT, Owner
                                )

                        end

                    elseif ( testedVarName == 'PACKED_STRING_ARRAY' ) or ( testedVarName == 'PACKED_BYTE_ARRAY' )
                        or ( testedVarName == 'PACKED_INT32_ARRAY' ) or ( testedVarName == 'PACKED_INT64_ARRAY' )
                        or ( testedVarName == 'PACKED_FLOAT32_ARRAY' ) or ( testedVarName == 'PACKED_FLOAT64_ARRAY' )
                        or ( testedVarName == 'PACKED_VECTOR2_ARRAY' ) or ( testedVarName == 'PACKED_VECTOR3_ARRAY' )
                        or ( testedVarName == 'PACKED_COLOR_ARRAY' ) or ( testedVarName == 'PACKED_VECTOR4_ARRAY' ) then -- packed arrays are a simple arrays of ptr

                            if bDEBUGMode then print( debugPrefixStr.." iterateVecVarToAddr loop: "..tostring(testedVarName).." case for name: "..tostring(variantName) ) end

                            local arrayAddr = readPointer( variantPtr )
                            if readPointer( arrayAddr + GDSOf.P_ARRAY_TOARR ) == 0 then
                                prefixStr = 'pck_arr (empty): '

                                synchronize(function( prefixStr, variantName, testedVarName, variantPtr, testedVarT, Owner)
                                            addMemRecTo( prefixStr..variantName..' of '..testedVarName , variantPtr , getCETypeFromGD( testedVarT ) , Owner ) -- when the packed array is empty, just add the addr
                                        end, prefixStr, variantName, testedVarName, variantPtr, testedVarT, Owner
                                    )

                            else
                                prefixStr = 'pck_arr: '
                                local newParentMemrec = synchronize(function( prefixStr, variantName, testedVarName, variantPtr, testedVarT, Owner)
                                            local newParentMemrec = addMemRecTo( prefixStr..variantName..' of '..testedVarName , variantPtr , getCETypeFromGD( testedVarT ) , Owner )
                                            newParentMemrec.Options = '[moHideChildren, moAllowManualCollapseAndExpand, moManualExpandCollapse]'
                                        return newParentMemrec
                                    end, prefixStr, variantName, testedVarName, variantPtr, testedVarT, Owner
                                )

                                iteratePackedArrayToAddr(  arrayAddr , testedVarName, newParentMemrec )
                            end

                    else
                        prefixStr = 'var: '

                        synchronize(function( prefixStr, variantName, variantPtr, testedVarT, Owner)
                                        addMemRecTo( prefixStr..variantName , variantPtr , getCETypeFromGD( testedVarT ) , Owner )
                                    end, prefixStr, variantName, variantPtr, testedVarT, Owner
                                )

                    end

                    if GDSOf.MAJOR_VER >= 4 then
                        mapElement = readPointer( mapElement )
                    else
                        mapElement = readPointer( mapElement + GDSOf.MAP_NEXTELEM )
                    end
                until (mapElement == 0)

                if bDEBUGMode then decDebugStep(); end;
                return
            end

            --- nodeName and ownerStruct to append to
            ---@param nodeAddr number
            ---@param varStructElement userdata
            function iterateVecVarToStruct(nodeAddr, varStructElement)
                assert(type(nodeAddr) == 'number',"iterateVecVarToStruct: Node addr has to be a number, instead got: "..type(nodeAddr))
                
                local nodeName;
                local debugPrefixStr ='>';
                if bDEBUGMode then debugPrefixStr = incDebugStep(); nodeName = getNodeName( nodeAddr ) end; 

                if bDEBUGMode then print( debugPrefixStr..' iterateVecVarToAddr start (hash)map for node: '..tostring(nodeName)..string.format(' at %x', nodeAddr)) end

                local headElement, tailElement, mapSize = getNodeVariantMap(nodeAddr)
                if ( headElement==0 or headElement==nil ) or ( mapSize==0 or mapSize==nil ) then
                    if bDEBUGMode then print( debugPrefixStr..' iterateVecVarToAddr (hash)Map empty?: '..tostring(nodeName)); decDebugStep(); end
                    return; --just return on fail
                end 
                local mapElement = headElement
                local prefixStr = 'var: '
                local variantVector, vectorSize = getNodeVariantVector(nodeAddr)
                local variantSize, bSuccess = redefineVariantSizeByVector( variantVector, vectorSize )
                if not bSuccess then if bDEBUGMode then print( debugPrefixStr.." iterateVecVarToStruct: Variant resize failed"); decDebugStep(); end return; end

                repeat
                    -- the vector is stored inside a GDScirptInstance and memberIndices inside the GDScript (as a BP)
                    local variantName, variantTypeScr, testedVarT
                    local variantIndex = readInteger( mapElement + GDSOf.VAR_NAMEINDEX_I )
                    local variantPtr, variantType, offsetToValue = getVariantByIndex( variantVector, variantIndex, variantSize, true )

                    if GDSOf.MAJOR_VER >= 4 then -- 4.x versions have type in the memberinfo which 3.x does not (or i'm not aware of)
                        variantName = getStringNameStr( readPointer( mapElement + GDSOf.STRING ) )
                        local variantTypeScr = readInteger( mapElement + GDSOf.VAR_NAMEINDEX_VARTYPE )
                        if variantTypeScr > GDSOf.MAXTYPE then variantTypeScr = readInteger( mapElement + GDSOf.VAR_NAMEINDEX_VARTYPE - 0x8 ) end; -- 4.2.2 had the issue with type offset being different for different memberinfos

                        if variantTypeScr == variantType then -- silly, but the types are sometimes inconsistent, cross-checking resolves for most tested cases
                        testedVarT = variantTypeScr
                        elseif ( variantTypeScr > variantType ) and ( variantTypeScr > 0 and variantTypeScr <= GDSOf.MAXTYPE ) then
                        testedVarT = variantTypeScr
                        elseif ( variantType > variantTypeScr ) and ( variantType > 0 and variantType <= GDSOf.MAXTYPE ) then
                        testedVarT = variantType
                        elseif variantTypeScr > GDSOf.MAXTYPE then
                            testedVarT = variantType; if bDEBUGMode then print( debugPrefixStr..' iterateVecVarToAddr: fallback1, cached type is used'); end; -- if the source is incorrect
                        else
                        testedVarT = variantTypeScr; if bDEBUGMode then print( debugPrefixStr..' iterateVecVarToAddr: fallback2, cached type is used'); end; -- let's have cached if everything is wrong
                        end
                    else
                        variantName = getStringNameStr( readPointer( mapElement + GDSOf.MAP_KVALUE ) )
                        testedVarT = variantType -- actually not tested, just to be compatible
                        variantTypeScr = variantType
                    end

                    if bDEBUGMode then print( debugPrefixStr.." iterateVecVarToAddr loop (Node: "..tostring(nodeName)..": "..string.format('%x',nodeAddr).."): iterating at:\t\t"..variantName..' index: '..tostring(variantIndex)..' of '..tostring(mapSize-1)..' | GDype (src/act/test): '..tostring(variantTypeScr)..'/'..tostring(variantType)..'/'..tostring(testedVarT)..' | VarAddr: '..string.format('%x',variantPtr)) end
                    local testedVarName = getGDTypeName( testedVarT ) 

                    if ( testedVarName == 'DICTIONARY' ) then
                        if bDEBUGMode then print( debugPrefixStr.." iterateVecVarToAddr loop: DICT case for name: "..tostring(variantName) ) end
                        prefixStr = 'dict: '
                        local dictSize
                        if GDSOf.MAJOR_VER >= 4 then
                            dictSize = readInteger( readPointer( variantPtr ) + GDSOf.DICT_SIZE )
                        else
                            dictSize = readInteger( readPointer( readPointer( variantPtr ) + GDSOf.DICT_LIST ) + GDSOf.DICT_SIZE )
                        end

                        if dictSize == nil or dictSize == 0 then
                            prefixStr = 'dict (empty): '
                            addStructureElem( varStructElement, prefixStr..variantName, offsetToValue, getCETypeFromGD( testedVarT ) )
                        else
                            local newParentStructElem = addStructureElem( varStructElement, prefixStr..variantName, offsetToValue, getCETypeFromGD( testedVarT ) )
                            newParentStructElem.ChildStruct = createStructure('Dict')
                            iterateDictionaryToStruct( readPointer( variantPtr ) , newParentStructElem )
                        end

                    elseif testedVarName == 'ARRAY' then
                        if bDEBUGMode then print( debugPrefixStr.." iterateVecVarToStruct: ARRAY case for name: "..tostring(variantName) ) end
                        prefixStr = 'array: '

                        if readPointer( readPointer(variantPtr) + GDSOf.ARRAY_TOVECTOR ) == 0 then
                            addStructureElem( varStructElement, 'array: (empty): '..variantName, offsetToValue, getCETypeFromGD( testedVarT ) )
                        else
                            local newParentStructElem = addStructureElem( varStructElement, prefixStr..variantName, offsetToValue, getCETypeFromGD( testedVarT ) )
                            newParentStructElem.ChildStruct = createStructure('Array')
                            iterateArrayToStruct( readPointer( variantPtr ) , newParentStructElem )
                        end

                    elseif ( testedVarName == 'OBJECT' ) then
                        if bDEBUGMode then print( debugPrefixStr.." iterateVecVarToAddr loop: OBJ case: name: "..tostring(variantName)..string.format(' addr: %x ', variantPtr)) end
                        local bShifted, newParentStructElem;
                        variantPtr, bShifted = checkForVT( variantPtr ) -- check if the pointer is valid, if not, shift it back 0x8 bytes
                        if bShifted then
                            offsetToValue = offsetToValue - GDSOf.PTRSIZE
                            newParentStructElem = addStructureElem( varStructElement, 'Wrapper: '..variantName, offsetToValue, vtPointer )
                            newParentStructElem.ChildStruct = createStructure('Wrapper')
                            offsetToValue = 0x0 -- the object lies at 0x0 now
                        else
                            newParentStructElem = varStructElement
                        end
                        prefixStr = 'mNode: '

                        if checkForGDScript( readPointer( variantPtr ) ) then
                            if bDEBUGMode then print( debugPrefixStr.." iterateVecVarToStruct loop: NODE DETECTED, SKIP: "..string.format('%x ', variantPtr)..tostring(variantName)) end 
                            addStructureElem( newParentStructElem, prefixStr..variantName, offsetToValue, getCETypeFromGD( testedVarT ) )
                        else
                            if bDEBUGMode then print( debugPrefixStr..' iterateVecVarToStruct: OBJ doesn\'t have GDScript/Inst'); end
                            prefixStr = 'obj: '
                            addStructureElem( newParentStructElem, prefixStr..variantName, offsetToValue, getCETypeFromGD( testedVarT ) )
                        end

                    elseif ( testedVarName == 'PACKED_STRING_ARRAY' ) or ( testedVarName == 'PACKED_BYTE_ARRAY' )
                        or ( testedVarName == 'PACKED_INT32_ARRAY' ) or ( testedVarName == 'PACKED_INT64_ARRAY' )
                        or ( testedVarName == 'PACKED_FLOAT32_ARRAY' ) or ( testedVarName == 'PACKED_FLOAT64_ARRAY' )
                        or ( testedVarName == 'PACKED_VECTOR2_ARRAY' ) or ( testedVarName == 'PACKED_VECTOR3_ARRAY' )
                        or ( testedVarName == 'PACKED_COLOR_ARRAY' ) or ( testedVarName == 'PACKED_VECTOR4_ARRAY' ) then -- packed arrays are a simple arrays of ptr

                            if bDEBUGMode then print( debugPrefixStr.." iterateVecVarToStruct loop: "..tostring(testedVarT).." case for name: "..tostring(variantName) ) end
                            local arrayAddr = readPointer( variantPtr )

                            if readPointer( arrayAddr + GDSOf.P_ARRAY_TOARR ) == 0 then
                                prefixStr = 'pck_arr (empty): '
                                addStructureElem( varStructElement, prefixStr..variantName..' of '..testedVarName, offsetToValue, getCETypeFromGD( testedVarT ) )
                            else
                                prefixStr = 'pck_arr: '
                                local newParentStructElem = addStructureElem(varStructElement, prefixStr..variantName..' of '..testedVarName, offsetToValue, getCETypeFromGD( testedVarT ) )
                                newParentStructElem.ChildStruct = createStructure('P_Array')
                                iteratePackedArrayToStruct(  arrayAddr, testedVarName, newParentStructElem )
                            end

                    elseif ( testedVarName == 'STRING' ) then
                            prefixStr = 'String: '
                            local newParentStructElem = addStructureElem( varStructElement, prefixStr..variantName, offsetToValue, vtPointer )
                            newParentStructElem.ChildStruct = createStructure('String')
                            local stringElement = addStructureElem(newParentStructElem, prefixStr..variantName, 0x0, vtUnicodeString )
                            stringElement.Bytesize = 100*4

                    else
                        prefixStr = 'var: '
                        addStructureElem( varStructElement, prefixStr..variantName, offsetToValue, getCETypeFromGD( testedVarT ) )
                    end

                    if GDSOf.MAJOR_VER >= 4 then
                        mapElement = readPointer( mapElement )
                    else
                        mapElement = readPointer( mapElement + GDSOf.MAP_NEXTELEM )
                    end
                until (mapElement == 0)

                if bDEBUGMode then decDebugStep(); end;
                return
            end

            --- iterate nodes only and owner to append to
            ---@param nodeAddr number
            function iterateVecVarForNodes(nodeAddr)
                assert(type(nodeAddr) == 'number',"iterateVecVarToAddr: Node addr has to be a number, instead got: "..type(nodeAddr))

                if not checkForGDScript( nodeAddr ) then return; end;
                local variantVector, vectorSize = getNodeVariantVector(nodeAddr)
                if vectorSize == nil or vectorSize == 0 then return; end

                local variantSize, bSuccess = redefineVariantSizeByVector( variantVector, vectorSize )
                if not bSuccess then return; end

                for variantIndex=0, vectorSize-1 do

                    local variantPtr, variantType = getVariantByIndex( variantVector, variantIndex, variantSize )
                    local variantTypeName = getGDTypeName( variantType ) 
                    if ( variantTypeName == 'DICTIONARY' ) then
                        local dictSize

                        if GDSOf.MAJOR_VER >= 4 then
                            dictSize = readInteger( readPointer( variantPtr ) + GDSOf.DICT_SIZE )
                        else -- 3.x
                            dictSize = readInteger( readPointer( readPointer( variantPtr ) + GDSOf.DICT_LIST ) + GDSOf.DICT_SIZE )
                        end

                        if dictSize ~= nil and dictSize ~= 0 then
                            iterateDictionaryForNodes( readPointer( variantPtr ) )
                        end

                    elseif variantTypeName == 'ARRAY' then
                        if readPointer( readPointer(variantPtr) + GDSOf.ARRAY_TOVECTOR ) ~= 0 then
                            iterateArrayForNodes( readPointer( variantPtr ) )
                        end

                    elseif ( variantTypeName == 'OBJECT' ) then
                        variantPtr = checkForVT( variantPtr )
                        if checkForGDScript( readPointer( variantPtr ) ) then
                            iterateMNode( readPointer( variantPtr ) )
                        end

                    else
                    end
                end
            end

            --- returns a vector pointer and its size via
            ---@param nodeAddr number
            function getNodeVariantVector(nodeAddr)
                assert(type(nodeAddr) == 'number',"nodeAddr should be a number, instead got: "..type(nodeAddr))

                local debugPrefixStr ='>';
                if bDEBUGMode and inMainThread() then debugPrefixStr = incDebugStep() end; 

                local scriptInstance = readPointer( nodeAddr + GDSOf.GDSCRIPTINSTANCE )
                if scriptInstance == nil or scriptInstance == 0 then if bDEBUGMode and inMainThread() then print( debugPrefixStr..' getNodeVariantVector: scriptInstance is absent for '..string.format(' %x', nodeAddr)); decDebugStep(); end return; end

                local vectorPtr = readPointer( scriptInstance + GDSOf.VAR_VECTOR )
                local vectorSize = readInteger( vectorPtr - GDSOf.SIZE_VECTOR )

                if (vectorPtr == 0 or vectorPtr == nil) or
                    (vectorSize == 0 or vectorSize == nil)
                    then
                        if bDEBUGMode and inMainThread() then print( debugPrefixStr..' getNodeVariantVector: vector is absent for '..string.format(' %x', nodeAddr)); decDebugStep(); end

                        return;
                end

                if bDEBUGMode and inMainThread() then decDebugStep(); end;

                return vectorPtr, vectorSize
            end

            --- returns a VariantData's (hash) map head, tail and size via a nodeAddr
            ---@param nodeAddr number
            function getNodeVariantMap(nodeAddr)
                assert(type(nodeAddr) == 'number',"nodeAddr should be a number, instead got: "..type(nodeAddr))

                local debugPrefixStr ='>';
                if bDEBUGMode then debugPrefixStr = incDebugStep() end; 

                local scriptInstanceAddr = readPointer( nodeAddr + GDSOf.GDSCRIPTINSTANCE )
                if scriptInstanceAddr == nil or scriptInstanceAddr == 0 then if bDEBUGMode then print( debugPrefixStr..' getNodeVariantMap: scriptInstance is absent for '..string.format(' %x', nodeAddr)); decDebugStep(); end return; end

                local gdScriptAddr = readPointer( scriptInstanceAddr + GDSOf.GDSCRIPT_REF )
                if gdScriptAddr == nil or gdScriptAddr == 0 then if bDEBUGMode then print( debugPrefixStr..' getNodeVariantMap: GDScript is absent for '..string.format(' %x', nodeAddr)); decDebugStep(); end return; end

                local mainElement = readPointer( gdScriptAddr + GDSOf.VAR_NAMEINDEX_MAP ) -- head / root
                local endElement = readPointer( gdScriptAddr + GDSOf.VAR_NAMEINDEX_MAP + GDSOf.PTRSIZE ) -- tail / end
                local mapSize = readInteger( gdScriptAddr + GDSOf.VAR_NAMEINDEX_MAP + GDSOf.MAP_SIZE )

                if (mainElement == 0 or mainElement == nil) or
                    (endElement == 0 or endElement == nil) or
                    (mapSize == 0 or mapSize == nil) then
                        
                        if bDEBUGMode then print( debugPrefixStr..' getNodeVariantMap: Variant: (hash)map is not found'); decDebugStep(); end
                        return;
                end

                if bDEBUGMode then decDebugStep(); end;
                if GDSOf.MAJOR_VER >= 4 then
                    return mainElement, endElement, mapSize
                else
                    return getLeftmostMapElem( mainElement, endElement, mapSize )
                end
            end

            --- returns a pointer to the variant's value and its type for a sanity check
            ---@param vectorAddr number
            ---@param index number
            ---@param varSize number
            ---@param bOffsetret boolean
            function getVariantByIndex(vectorAddr, index, varSize, bPushOffset)
                assert(type(vectorAddr) == 'number',">>getVariantByIndex: vector addr should be a number, instead got: "..type(vectorAddr))
                assert((type(index) == 'number') and (index >= 0), ">>getVariantByIndex: index should be a valid number, instead got: "..type(nodePtr))
                assert((type(varSize) == 'number') and (varSize >= 0x18), ">>getVariantByIndex: variant size should be at least 0x18, instead got: "..tostring(varSize))

                local debugPrefixStr ='>';
                if bDEBUGMode then debugPrefixStr = incDebugStep() end; 

                if bDEBUGMode and ( index > ( readInteger( vectorAddr - GDSOf.SIZE_VECTOR) - 1 ) ) then print( debugPrefixStr.." getVariantByIndex: index is beyond vector size, pass index: "..tostring(index)..' VecSize: '..tostring(( readInteger( vectorAddr - GDSOf.SIZE_VECTOR) - 1 )) ) end

                local variantType = readInteger( vectorAddr + varSize * index )
                local offsetToValue = getVariantValueOffset( variantType )

                local offset = varSize * index + offsetToValue
                local variantAddr = getAddress( vectorAddr + offset ) -- 0x8 or 0x10 is value

                if ( variantType == nil) -- variantType == 0 -- zero is nil which happens for uninitialized
                    or (variantAddr == nil) -- zero is possible for uninitialized variantPtr == 0 or 
                    then print('getVariantByIndex: variant ptr or type invalid'); error('getVariantByIndex: variant ptr or type invalid') end

                if bDEBUGMode then decDebugStep(); end;

                if bPushOffset then
                    return variantAddr, variantType, offset
                else
                    return variantAddr, variantType
                end
            end

        --///---///--///---///--///---///--///--///---///--///---///--///---///--/// (Hash)Map

            --- will return the leftmost map element @3.x
            ---@param rootElement number
            ---@param endElement number
            ---@param mapSize number
            function getLeftmostMapElem(rootElement, endElement, mapSize, struct)

                local debugPrefixStr ='>';
                if bDEBUGMode then debugPrefixStr = incDebugStep() end; 

                local mapElement = readPointer( rootElement + GDSOf.MAP_LELEM )
                if ( mapElement == nil ) or ( mapElement == 0 ) then if bDEBUGMode then print( debugPrefixStr..' getLeftmostMapElem: mapElement is likely non-existent: root : '..string.format( '%x', tonumber(rootElement) )..string.format(' last %x', tonumber(endElement) )..string.format(' size %x', tonumber(mapSize) )  ); decDebugStep(); end return 0, endElement, mapSize end -- return 0 as a head element 
                    local leftStructElem
                    if struct then
                        leftStructElem = addStructureElem( struct, 'rootElem', GDSOf.MAP_LELEM, vtPointer )
                        leftStructElem.ChildStruct = createStructure('rootElem')
                    end

                if ( mapElement == endElement ) then
                    if bDEBUGMode then decDebugStep(); end
                    return mapElement, endElement, mapSize -- not sure that's possible
                else
                    while readPointer( mapElement + GDSOf.MAP_LELEM ) ~= endElement do
                        mapElement = readPointer( mapElement + GDSOf.MAP_LELEM )
                        if struct then
                            leftStructElem = addStructureElem( leftStructElem, 'goLeft', GDSOf.MAP_LELEM, vtPointer )
                            leftStructElem.ChildStruct = createStructure('goLeft')
                        end
                    end
                    if mapElement == 0 or mapElement == nil then if bDEBUGMode then print( debugPrefixStr..' getLeftmostMapElem: mapElement is likely non-existent: root : '..string.format( '%x', tonumber(rootElement) )..string.format(' last %x', tonumber(endElement) )..string.format(' size %x', tonumber(mapSize) )  ); decDebugStep(); end return 0, endElement, mapSize end -- return 0 as a head element
                    if bDEBUGMode then decDebugStep(); end
                    if struct then
                        return mapElement, endElement, mapSize, leftStructElem
                    else
                        return mapElement, endElement, mapSize
                    end
                end
            end


        --///---///--///---///--///---///--///--///---///--///---///--///---///--/// Type & Size

            --- @unreliable takes in a vector + its size. Returns an inferred variant size and successBool
            ---@param vectorPtr number
            ---@param vectorSize number
            function redefineVariantSizeByVector(vectorPtr, vectorSize)
                assert((type(vectorPtr) == 'number'),"vectorPtr has to be a number, instead got: "..type(vectorPtr))
                assert((type(vectorSize) == 'number') and (vectorSize > 0),"VectorSize is empty or not a number, type: "..type(vectorSize))

                local debugPrefixStr = '>';
                if bDEBUGMode and inMainThread() then debugPrefixStr = incDebugStep() end; 

                if (vectorSize == 0 or vectorSize == nil) then if bDEBUGMode and inMainThread() then print( debugPrefixStr..' redefineVariantSizeByVector: Bad vector size for '..string.format('%x',vectorPtr)); decDebugStep(); end; return 0x18, true; end

                if GDSOf.MAJOR_VER >= 4 then

                    if (vectorSize == 1) and ( readInteger(vectorPtr) == 27 ) then
                        if bDEBUGMode and inMainThread() then print( debugPrefixStr.." 1-sized Vector: Variant was resized to 0x30 (vector: "..string.format('%x )',vectorPtr)); decDebugStep(); end;

                        return 0x30, true;

                    elseif (vectorSize == 1) then
                        if bDEBUGMode and inMainThread() then print( debugPrefixStr.." 1-sized Vector: Variant was left 0x18 long (vector: "..string.format('%x )',vectorPtr)); decDebugStep(); end;

                        return 0x18, true;

                    end

                    if (vectorSize == 2) and getGDTypeName( readInteger( vectorPtr ) ) and getGDTypeName( readInteger( vectorPtr + 0x18 ) ) then -- is it a valid variant Type?
                        if bDEBUGMode then decDebugStep(); end;

                        return 0x18, true;

                    elseif (vectorSize == 2) and getGDTypeName( readInteger( vectorPtr ) ) and getGDTypeName( readInteger( vectorPtr + 0x30 ) ) then  -- if it's 0x30
                        if bDEBUGMode and inMainThread() then print( debugPrefixStr.." Variant was resized to 0x30 (vector: "..string.format('%x',vectorPtr)..")"); decDebugStep(); end;

                        return 0x30, true;

                    elseif (vectorSize == 2) and getGDTypeName( readInteger( vectorPtr ) ) and getGDTypeName( readInteger( vectorPtr + 0x40 ) ) then -- if it's 0x40
                        if bDEBUGMode and inMainThread() then print( debugPrefixStr.." Variant was resized to 0x40 (vector: "..string.format('%x',vectorPtr)..")"); decDebugStep(); end;

                        return 0x40, true;

                    end

                    if getGDTypeName( readInteger( vectorPtr ) ) and getGDTypeName( readInteger( vectorPtr + 0x18 ) ) and getGDTypeName( readInteger( vectorPtr + 0x18*2 ) ) then -- is it a valid variant Type?
                        if bDEBUGMode then decDebugStep(); end;

                        return 0x18, true;

                    elseif getGDTypeName( readInteger( vectorPtr ) ) and getGDTypeName( readInteger( vectorPtr + 0x30 ) ) and getGDTypeName( readInteger( vectorPtr + 0x30*2 ) ) then
                        if bDEBUGMode and inMainThread() then print(  debugPrefixStr.." Variant was resized to 0x30 (vector: "..string.format('%x',vectorPtr)..")"); decDebugStep(); end;

                        return 0x30, true;

                    elseif getGDTypeName( readInteger( vectorPtr ) ) and getGDTypeName( readInteger( vectorPtr + 0x40 ) ) and getGDTypeName( readInteger( vectorPtr + 0x40*2 ) ) then
                        if bDEBUGMode and inMainThread() then print(  debugPrefixStr.." Variant was resized to 0x40 (vector: "..string.format('%x',vectorPtr)..")"); decDebugStep(); end;

                        return 0x40, true;

                    end

                else

                    if (vectorSize == 1) and ( getGDTypeName( vectorPtr ) == 'DICTIONARY' ) then -- for some reasons single-sized vectors with dict were 0x30
                        if bDEBUGMode and inMainThread() then print( debugPrefixStr.." redefineVariantSizeByVector: 1-sized Vector: Variant was resized to 0x30 (vector: "..string.format('%x )',vectorPtr)); decDebugStep(); end;

                        return 0x20, true;

                    elseif (vectorSize == 1) then
                        if bDEBUGMode and inMainThread() then print( debugPrefixStr.." redefineVariantSizeByVector: 1-sized Vector: Variant was left 0x18 long (vector: "..string.format('%x )',vectorPtr)); decDebugStep(); end;

                        return 0x18, true; -- Usual size is 0x18 in 3.x

                    end

                    if (vectorSize == 2) and getGDTypeName( readInteger( vectorPtr ) ) and getGDTypeName( readInteger( vectorPtr + 0x18 ) ) then -- is it a valid variant Type?
                        if bDEBUGMode and inMainThread() then decDebugStep(); end;

                        return 0x18, true; -- Usual size is 0x18 in 3.x

                    elseif (vectorSize == 2) and getGDTypeName( readInteger( vectorPtr ) ) and getGDTypeName( readInteger( vectorPtr + 0x20 ) ) then 
                        if bDEBUGMode and inMainThread() then print( debugPrefixStr.." redefineVariantSizeByVector: 2s Variant was resized to 0x20 (vector: "..string.format('%x',vectorPtr)..")"); decDebugStep(); end;

                        return 0x20, true;

                    elseif (vectorSize == 2) and getGDTypeName( readInteger( vectorPtr ) ) and getGDTypeName( readInteger( vectorPtr + 0x30 ) ) then
                        if bDEBUGMode and inMainThread() then print( debugPrefixStr.." redefineVariantSizeByVector: 2s Variant was resized to 0x30 (vector: "..string.format('%x',vectorPtr)..")"); decDebugStep(); end;

                        return 0x30, true; -- what's the longest for 3.x?
                    end

                    if getGDTypeName( readInteger( vectorPtr ) ) and getGDTypeName( readInteger( vectorPtr + 0x18 ) ) and getGDTypeName( readInteger( vectorPtr + 0x18*2 ) ) then -- is it a valid variant Type?
                        if bDEBUGMode and inMainThread() then decDebugStep(); end;

                        return 0x18, true; -- Usual size is 0x18 in 3.x

                    elseif getGDTypeName( readInteger( vectorPtr ) ) and getGDTypeName( readInteger( vectorPtr + 0x20 ) ) and getGDTypeName( readInteger( vectorPtr + 0x20*2 ) ) then
                        if bDEBUGMode and inMainThread() then print( debugPrefixStr.." redefineVariantSizeByVector: Variant was resized to 0x20 (vector: "..string.format('%x',vectorPtr)..")"); decDebugStep(); end;

                        return 0x20, true;

                    elseif getGDTypeName( readInteger( vectorPtr ) ) and getGDTypeName( readInteger( vectorPtr + 0x30 ) ) and getGDTypeName( readInteger( vectorPtr + 0x30*2 ) ) then
                        if bDEBUGMode and inMainThread() then print( debugPrefixStr.." redefineVariantSizeByVector: Variant was resized to 0x30 (vector: "..string.format('%x',vectorPtr)..")"); decDebugStep(); end;

                        return 0x30, true; -- what's the longest for 3.x?
                    end

                end

                if bDEBUGMode and inMainThread() then print( debugPrefixStr.." redefineVariantSizeByVector: Variant resize failed past 4 cases (vector: "..string.format('%x',vectorPtr)..")"); decDebugStep(); end;
                -- // Variant takes 24 bytes when real_t is float, and 40 bytes if double.
                -- // It only allocates extra memory for AABB/Transform2D (24, 48 if double),
                -- // Basis/Transform3D (48, 96 if double), Projection (64, 128 if double),
                -- // and PackedArray/Array/Dictionary (platform-dependent).
                return false;        
            end

            --- returns an adjusted offset to a variant value
            ---@param gdType number
            function getVariantValueOffset(gdType)
                assert(type(gdType) == "number",'getVariantValueOffset: Type from enum should be a number, instead got: '..type(gdType))
                if ( getGDTypeName( gdType ) == 'OBJECT' ) then return 0x10 end -- objects have 0x10 offset for value
                -- not sure about the rest
                return 0x8 -- the rest have this offset
            end

            --- takes a godot type. Returns CEType
            ---@param gdType number
            function getCETypeFromGD(gdType)
                assert(type(gdType) == "number",'getCETypeFromGD Type from enum should be a number, instead got: '..type(gdType))

                if GDSOf.MAJOR_VER >= 4 then
                    if (gdType == 2) then return vtDword end
                    if (gdType == 1) then return vtByte end
                    if (gdType == 3) then return vtDouble end
                    if (gdType == 4) then return vtString end -- not sure though, need to test that, GD string is 4byte per char
                    if (gdType == 27) then return vtPointer end
                    if (gdType == 28) then return vtPointer end
                    if (gdType == 21) then return vtPointer end
                    if (gdType == 24) then return vtPointer end -- object
                    if (gdType == 0) then return vtPointer end

                    if (gdType == 5) then return vtSingle end -- vector is 2 floats (x,y)
                    if (gdType == 6) then return vtSingle end
                    if (gdType == 7) then return vtSingle end
                    if (gdType == 8) then return vtSingle end
                    if (gdType == 9) then return vtSingle end
                    if (gdType == 10) then return vtSingle end
                    if (gdType == 11) then return vtSingle end
                    if (gdType == 12) then return vtPointer end
                    if (gdType == 13) then return vtPointer end
                    if (gdType == 14) then return vtPointer end
                    if (gdType == 15) then return vtPointer end
                    if (gdType == 16) then return vtPointer end
                    if (gdType == 17) then return vtPointer end
                    if (gdType == 18) then return vtPointer end
                    if (gdType == 19) then return vtPointer end
                    if (gdType == 20) then return vtDword end 
                    if (gdType == 22) then return vtPointer end
                    if (gdType == 23) then return vtPointer end
                    if (gdType == 25) then return vtPointer end
                    if (gdType == 26) then return vtPointer end
                    if (gdType == 29) then return vtPointer end
                    if (gdType == 30) then return vtPointer end
                    if (gdType == 31) then return vtPointer end
                    if (gdType == 32) then return vtPointer end
                    if (gdType == 33) then return vtPointer end
                    if (gdType == 34) then return vtPointer end
                    if (gdType == 35) then return vtPointer end
                    if (gdType == 36) then return vtPointer end
                    if (gdType == 37) then return vtPointer end
                    if (gdType == 38) then return vtPointer end
                    if (gdType == 39) then return vtDword end
                else
                    if (gdType == 2) then return vtDword end
                    if (gdType == 1) then return vtByte end
                    if (gdType == 3) then return vtDouble end
                    if (gdType == 18) then return vtPointer end
                    if (gdType == 19) then return vtPointer end
                    if (gdType == 17) then return vtPointer end -- object
                    if (gdType == 4) then return vtString end -- not sure though, need to test that, GD string is 4byte per char
                    if (gdType == 0) then return vtPointer end

                    if (gdType == 5) then return vtSingle end -- vector is 2 floats (x,y)
                    if (gdType == 6) then return vtSingle end
                    if (gdType == 7) then return vtSingle end
                    if (gdType == 8) then return vtSingle end
                    if (gdType == 9) then return vtCustom end
                    if (gdType == 10) then return vtCustom end
                    if (gdType == 11) then return vtCustom end
                    if (gdType == 12) then return vtCustom end
                    if (gdType == 13) then return vtCustom end
                    if (gdType == 14) then return vtDword end
                    if (gdType == 15) then return vtUnicodeString end
                    if (gdType == 16) then return vtPointer end
                    if (gdType == 20) then return vtPointer end 
                    if (gdType == 21) then return vtPointer end
                    if (gdType == 22) then return vtPointer end
                    if (gdType == 23) then return vtPointer end
                    if (gdType == 24) then return vtPointer end
                    if (gdType == 25) then return vtPointer end
                    if (gdType == 26) then return vtPointer end
                    if (gdType == 27) then return vtPointer end
                end
                --[[
                vtByte=0
                vtWord=1
                vtDword=2
                vtQword=3
                vtSingle=4
                vtDouble=5
                vtString=6
                vtUnicodeString=7 --Only used by autoguess
                vtByteArray=8
                vtBinary=9
                vtAutoAssembler=11
                vtPointer=12 --Only used by autoguess and structures
                vtCustom=13
                vtGrouped=14
                --]]
                return
            end

            --- takes in a godot type, returns a godot type name
            ---@param typeInt number
            function getGDTypeName(typeInt)
                if type(typeInt) ~= "number" then if bDEBUGMode then print("getGDTypeName: input not a number, instead: "..tostring(typeInt)) end; return false; end

                if GDSOf.MAJOR_VER >= 4 then
                    if (typeInt == 2) then return "INT" end -- these go first
                    if (typeInt == 1) then return "BOOL" end
                    if (typeInt == 3) then return "FLOAT" end
                    if (typeInt == 4) then return "STRING" end
                    if (typeInt == 27) then return "DICTIONARY" end
                    if (typeInt == 28) then return "ARRAY" end
                    if (typeInt == 24) then return "OBJECT" end
                    if (typeInt == 21) then return "STRING_NAME" end
                    if (typeInt == 0) then return "NIL" end

                    if (typeInt == 5) then return "VECTOR2" end
                    if (typeInt == 6) then return "VECTOR2I" end
                    if (typeInt == 7) then return "RECT2" end
                    if (typeInt == 8) then return "RECT2I" end
                    if (typeInt == 9) then return "VECTOR3" end
                    if (typeInt == 10) then return "VECTOR3I" end
                    if (typeInt == 11) then return "TRANSFORM2D" end
                    if (typeInt == 12) then return "VECTOR4" end
                    if (typeInt == 13) then return "VECTOR4I" end
                    if (typeInt == 14) then return "PLANE" end
                    if (typeInt == 15) then return "QUATERNION" end
                    if (typeInt == 16) then return "AABB" end
                    if (typeInt == 17) then return "BASIS" end
                    if (typeInt == 18) then return "TRANSFORM3D" end
                    if (typeInt == 19) then return "PROJECTION" end
                    if (typeInt == 20) then return "COLOR" end
                    if (typeInt == 22) then return "NODE_PATH" end
                    if (typeInt == 23) then return "RID" end
                    if (typeInt == 25) then return "CALLABLE" end
                    if (typeInt == 26) then return "SIGNAL" end
                    if (typeInt == 29) then return "PACKED_BYTE_ARRAY" end
                    if (typeInt == 30) then return "PACKED_INT32_ARRAY" end
                    if (typeInt == 31) then return "PACKED_INT64_ARRAY" end
                    if (typeInt == 32) then return "PACKED_FLOAT32_ARRAY" end
                    if (typeInt == 33) then return "PACKED_FLOAT64_ARRAY" end
                    if (typeInt == 34) then return "PACKED_STRING_ARRAY" end
                    if (typeInt == 35) then return "PACKED_VECTOR2_ARRAY" end
                    if (typeInt == 36) then return "PACKED_VECTOR3_ARRAY" end
                    if (typeInt == 37) then return "PACKED_COLOR_ARRAY" end
                    if (typeInt == 38) then return "PACKED_VECTOR4_ARRAY" end
                    if (typeInt == 39) then return "VARIANT_MAX" end
                else -- 3.x
                    if (typeInt == 2) then return "INT" end -- these go first
                    if (typeInt == 1) then return "BOOL" end
                    if (typeInt == 3) then return "FLOAT" end
                    if (typeInt == 18) then return "DICTIONARY" end
                    if (typeInt == 19) then return "ARRAY" end
                    if (typeInt == 17) then return "OBJECT" end
                    if (typeInt == 4) then return "STRING" end
                    if (typeInt == 0) then return "NIL" end

                    if (typeInt == 5) then return "VECTOR2" end
                    if (typeInt == 6) then return "RECT2" end
                    if (typeInt == 7) then return "VECTOR3" end
                    if (typeInt == 8) then return "TRANSFORM2D" end
                    if (typeInt == 9) then return "PLANE" end
                    if (typeInt == 10) then return "QUATERNION" end
                    if (typeInt == 11) then return "AABB" end
                    if (typeInt == 12) then return "BASIS" end
                    if (typeInt == 13) then return "TRANSFORM3D" end
                    if (typeInt == 14) then return "COLOR" end
                    if (typeInt == 15) then return "NODE_PATH" end
                    if (typeInt == 16) then return "RID" end
                    if (typeInt == 20) then return "PACKED_BYTE_ARRAY" end
                    if (typeInt == 21) then return "PACKED_INT64_ARRAY" end
                    if (typeInt == 22) then return "PACKED_FLOAT32_ARRAY" end
                    if (typeInt == 23) then return "PACKED_STRING_ARRAY" end
                    if (typeInt == 24) then return "PACKED_VECTOR2_ARRAY" end
                    if (typeInt == 25) then return "PACKED_VECTOR3_ARRAY" end
                    if (typeInt == 26) then return "PACKED_COLOR_ARRAY" end
                    if (typeInt == 27) then return "VARIANT_MAX" end
                end

                return false; -- nil
            end

            --- I'm gonna add a 4byte string type
            function checkGDStringType()

                function codePointToUTF8(codePoint)
                    if (codePoint < 0 or codePoint > 0x10FFFF) or (codePoint >= 0xD800 and codePoint <= 0xDFFF) then
                        return '?'
                    elseif codePoint <= 0x7F then
                        return string.char(codePoint)
                    elseif codePoint <= 0x7FF then
                        return string.char(0xC0 | (codePoint >> 6),
                                            0x80 | (codePoint & 0x3F))
                    elseif codePoint <= 0xFFFF then
                        return string.char(0xE0 | (codePoint >> 12),
                                            0x80 | ((codePoint >> 6) & 0x3F),
                                            0x80 | (codePoint & 0x3F))
                    else
                        return string.char(0xF0 | (codePoint >> 18),
                                            0x80 | ((codePoint >> 12) & 0x3F),
                                            0x80 | ((codePoint >> 6) & 0x3F),
                                            0x80 | (codePoint & 0x3F))
                    end
                end

                function UTF8Codepoints(str)
                    local i, strSize = 1, #str

                    -- closure
                    return function()
                        if i > strSize then return nil end
                        local byte1 = str:byte( i )

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
                            if i + 1 > n then i = n + 1; return 0xFFFD end

                            local byte2 = str:byte( i + 1 )
                            if ( byte2 & 0xC0 ) ~= 0x80 then i = i + 1; return 0xFFFD end -- lead

                            local codePoint = ( (byte1 & 0x1F) << 6 ) | ( byte2 & 0x3F ) -- payload bits
                            i = i + 2
                            return codePoint

                        -- 3-byte | 0xE0–0xEF
                        elseif byte1 < 0xF0 then
                            if i + 2 > n then i = n + 1; return 0xFFFD end

                            local byte2, byte3 = str:byte( i + 1 ), str:byte( i + 2 )
                            if ( byte2 & 0xC0 ) ~= 0x80 or ( byte3 & 0xC0 ) ~= 0x80 then i = i + 1; return 0xFFFD end -- lead

                            local codePoint = ( ( byte1 & 0x0F ) << 12 ) | ( ( byte2 & 0x3F ) << 6 ) | ( byte3 & 0x3F )  -- payload bits
                            -- reject surrogates
                            if codePoint >= 0xD800 and codePoint <= 0xDFFF then codePoint = 0xFFFD end
                            i = i + 3
                            return codePoint

                        -- 4-byte | 0xF0–0xF7
                        elseif byte1 < 0xF5 then
                            if i + 3 > n then i = n + 1; return 0xFFFD end

                            local byte2, byte3, byte4 = str:byte(i+1), str:byte(i+2), str:byte(i+3)
                            if ( byte2 & 0xC0 ) ~= 0x80 or ( byte3 & 0xC0 ) ~= 0x80 or ( byte4 & 0xC0 ) ~= 0x80 then i = i + 1; return 0xFFFD end
                    
                            local codePoint = ( ( byte1 & 0x07 ) << 18 ) | ( ( byte2 & 0x3F ) << 12 ) | ( ( byte3 & 0x3F ) << 6 ) | ( byte4 & 0x3F )
                            if codePoint > 0x10FFFF then codePoint = 0xFFFD end
                            i = i + 4
                            return codePoint
                        end

                        -- anything else is invalid lead
                        i = i + 1
                        return 0xFFFD
                    end
                end


                function gd4string_bytestovalue(b1,address)
                    local MAX_CHARS_TO_READ = 32768
                    local charTable = {}
                    local buff = 0;

                    for i=0,MAX_CHARS_TO_READ do
                        buff = readInteger(address + i * 0x4) or 0x0
                        if buff == 0 then break end
                        charTable[#charTable+1] = codePointToUTF8( buff )
                    end

                    return table.concat( charTable )
                end

                function gd4string_valuetobytes(str,address)
                    error('Writing not implemented until I figure out how to do it properly')
                    local idx = 0
                    for codePoint in UTF8Codepoints( str ) do
                        -- clamping invalid/surrogate range
                        if ( codePoint < 0 or codePoint > 0x10FFFF ) or ( codePoint >= 0xD800 and codePoint <= 0xDFFF ) then codePoint = 0xFFFD end

                        writeInteger( address + idx * 0x4, codePoint )
                        idx = idx + 1
                    end

                    -- null terminator
                    writeInteger(address + idx * 4, 0x0)

                    return string.byte( str, 1 ) -- bullshit, from what I suggest, CE stores the last 8bytes (?) of the orig memory in advance and after the callback it writes
                                                    --those 8 bytes replacing the first byte with a null terminator (if returned nothing here)
                end

                if GDSOf.MAJOR_VER >= 4 then
                    if getCustomType("GD4 String") then
                        GDSOf.GD4_STRING_EXISTS = true
                    else
                        registerCustomTypeLua('GD4 String', 1, gd4string_bytestovalue, gd4string_valuetobytes, false, true)
                        GDSOf.GD4_STRING_EXISTS = true
                    end
                else
                    GDSOf.GD4_STRING_EXISTS = false
                end
            end

        --///---///--///---///--///---///--///--///---///--///---///--///---///--/// Dumper

            --- returns a node dictionary
            function getMainNodeDict()
                local childrenAddr, childrenSize = getVPChildren()
                if childrenAddr == nil or childrenSize == nil then return end

                local nodeDict = {}

                for i=0,(childrenSize-1) do

                    local nodePtr = readPointer( childrenAddr + i * GDSOf.PTRSIZE )
                    if nodePtr == nil or nodePtr == 0 then error('getMainNodeDict: NO MAIN NODES') end

                    local nodeNameStr = getNodeName(nodePtr)
                    nodeNameStr = tostring(nodeNameStr)
                    registerSymbol( nodeNameStr , nodePtr) -- let's have them registered

                    if GDSOf.MAJOR_VER >= 4 then

                        nodeDict[ nodeNameStr ] = {
                                                    NAME = nodeNameStr,
                                                    PTR = nodePtr,
                                                    TYPE = 24, -- node
                                                    MEMREC = 0
                                                }
                    else
                        nodeDict[ nodeNameStr ] = {
                                                NAME = nodeNameStr,
                                                PTR = nodePtr,
                                                TYPE = 17, -- node
                                                MEMREC = 0
                                            }
                    end

                end
                return nodeDict
            end

            --- returns a node table
            function getMainNodeTable()
                local childrenAddr, childrenSize = getVPChildren()
                if childrenAddr == nil or childrenSize == nil then return end

                local nodeTable = {}

                for i=0,(childrenSize-1) do

                    local nodeAddr = readPointer( childrenAddr + i * GDSOf.PTRSIZE )
                    if nodeAddr == nil or nodeAddr == 0 then error('getMainNodeDict: NO MAIN NODES') end

                    local nodeNameStr = getNodeName( nodeAddr )
                    nodeNameStr = tostring( nodeNameStr )
                    registerSymbol( nodeNameStr , nodeAddr) -- let's have them registered when we do structs
                    table.insert( nodeTable, nodeAddr)
                end
                return nodeTable
            end

            --- prints all functions for a given nodeName
            ---@param nodeName string
            function DumpNodeFunctions(nodeName)
                assert(type(nodeName) == 'string',"Node name has to be a string, instead got: "..type(nodeName))

                local nodeaddr = getNodeWithGDScriptInstance( nodeName )
                if nodeaddr == nil then print(" DumpNodeFunctions: Node: "..tostring(nodeName).." wasn't found"); return; end
                
                local headElementPtr, tailElementPtr, mapSize = getNodeFunctionMap( nodeaddr )
                local mapElement = headElementPtr

                repeat
                    local funcName = getGDFunctionName(mapElement)
                    printf("Func: %s - %x : of node: %s", funcName , readPointer( mapElement + 0x18 ) , nodeName ) -- mysterious number, it should be a constant I guess
                    if GDSOf.MAJOR_VER >= 4 then
                        mapElement = readPointer( mapElement )
                    else
                        mapElement = readPointer( mapElement + GDSOf.MAP_NEXTELEM )
                    end

                until (mapElement == 0)
            end

            --- gets a dumped Node by name
            ---@param nodeName string
            function getDumpedNode(nodeName)
                assert(type(nodeName) == "string",'Node name should be a string, instead got: '..type(nodeName))
                if not (gdOffsetsDefined) then print('define the offsets first, silly') return end

                if (not dumpedMonitorNodes) or #dumpedMonitorNodes == 0 then if bDEBUGMode then print('getDumpedNode: dumped nodes table is nil, dump the game first') end return; end
                for _,nodeAddr in ipairs(dumpedMonitorNodes) do
                    local nodeNameStr = getNodeName(nodeAddr)
                    if nodeNameStr == nodeName then
                        return nodeAddr
                    end
                end
                return
            end

            --- prints all gathered nodeNames
            function printDumpedNodes()
                if (not dumpedMonitorNodes) or #dumpedMonitorNodes == 0 then if bDEBUGMode then print('printDumpedNodes: dumped nodes table is nil, dump the game first') end return; end
                if not (gdOffsetsDefined) then print('define the offsets first, silly') return end

                for _,nodeAddr in ipairs(dumpedMonitorNodes) do
                    local nodeNameStr = getNodeName( nodeAddr )
                    printf(">Node name: %s \t Node addr: %x", tostring(nodeNameStr), tonumber(nodeAddr))
                end
            end

            --- prints all functions for dumped Nodes
            function printDumpedNodeFunctions()
                if (not dumpedMonitorNodes) or #dumpedMonitorNodes == 0 then if bDEBUGMode then print('printDumpedNodeFunctions: dumped nodes table is nil, dump the game first') end return; end
                if not (gdOffsetsDefined) then print('define the offsets first, silly') return end

                for _, nodeAddr in ipairs(dumpedMonitorNodes) do

                    local nodeNameStr = getNodeName( nodeAddr )
                    if not checkForGDScript( nodeAddr ) then if bDEBUGMode then print('printDumpedNodeFunctions: node '..tostring(nodeNameStr)..' doesnt have GDScript/Inst') end goto continue end

                    local headElement, tailElement, mapSize = getNodeFunctionMap( nodeAddr )
                    if mapSize == 0 or mapSize == nil then if bDEBUGMode then print('printDumpedNodeFunctions: node '..tostring(nodeNameStr)..' doesnt have functions') end goto continue end
                    printf(">Node: %s \t Address %x :: functions (%d): ", tostring(nodeNameStr), tonumber(nodeAddr), tonumber(mapSize))
                    local mapElement = headElement
                    repeat
                        local funcName = getGDFunctionName( mapElement )
                        printf( "Func: %s ", tostring( funcName ) )
                        if GDSOf.MAJOR_VER >= 4 then
                            mapElement = readPointer( mapElement )
                        else
                            mapElement = readPointer( mapElement + GDSOf.MAP_NEXTELEM )
                        end
                    until (mapElement == 0)

                    ::continue:: 
                end
            end

            function nodeMonitorThread(thr)

                while(bMonitorNodes) do
                    local mainNodeDict = getMainNodeDict()
                    dumpedMonitorNodes = {};
                    for key, value in pairs(mainNodeDict) do    

                        table.insert( dumpedMonitorNodes , value.PTR )
                        iterateVecVarForNodes( value.PTR )
                    end
                    sleep(3000)
                end
                thr.terminate()
            end

            -- switches node monitoring (in a thread)
            function nodeMonitor()
                if not (gdOffsetsDefined) then print('define the offsets first, silly') return end
                bMonitorNodes = not bMonitorNodes
                if bMonitorNodes then createThread(nodeMonitorThread) end
            end

            --- dump for a specific node and append to the parent
            ---@param parentMemrec userdata
            ---@param nodeAddr number
            ---@param bDoConstants number
            function DumpNodeToAddr(parentMemrec, nodeAddr, bDoConstants)
                assert(type(parentMemrec) == "userdata",'Parent address has to be userdata, instead got: '..type(parentMemrec))
                assert(type(nodeAddr) == "number",'Node address has to be a number, instead got: '..type(nodeAddr))
                if not (gdOffsetsDefined) then print('define the offsets first, silly') return end

                debugPrefix = 1; -- reset debug prefix, don't use that while running Node threads
                dumpedNodes = {}; -- let's start from scratch for single node dumps | there might be race conditions, not a big issue for most cases
                table.insert( dumpedNodes , nodeAddr )

                local nodeNameStr = getNodeName( nodeAddr )
                if not checkForGDScript( nodeAddr ) then if bDEBUGMode then print( debugPrefixStr..' DumpNodeToAddr: node '..nodeNameStr..' doesnt have GDScript/Inst') end return end
                if bDEBUGMode then print( debugPrefixStr..' DumpNodeToAddr: node '..tostring(nodeNameStr)..string.format( 'addr: %x' , nodeAddr ) ) end

                synchronize(function(parentMemrec)
                        if parentMemrec.Count ~= 0 then -- let's clear all children
                            while parentMemrec.Child[0] ~= nil do
                                parentMemrec.Child[0].Destroy()
                            end
                        end
                    end, parentMemrec
                )

                if bDoConstants then
                    if bDEBUGMode then print( debugPrefixStr..' DumpNodeToAddr: constants for node: '..tostring(nodeNameStr) ) end

                    local newConstRec = synchronize(function(parentMemrec)
                                local newConstRec = getAddressList().createMemoryRecord()
                                newConstRec.setDescription( "Consts:" )
                                newConstRec.setAddress( 0xBABE )
                                newConstRec.setType( vtPointer )
                                newConstRec.Options = '[moHideChildren, moAllowManualCollapseAndExpand, moManualExpandCollapse]'
                                newConstRec.DontSave = true
                                newConstRec.appendToEntry( parentMemrec )
                                return newConstRec
                            end, parentMemrec
                        )

                    iterateNodeConstToAddr( nodeAddr , newConstRec )
                end
                    if bDEBUGMode then print( debugPrefixStr..' DumpNodeToAddr: variants for node: '..tostring(nodeNameStr) ) end
                    iterateVecVarToAddr( nodeAddr , parentMemrec )
                    debugPrefix = 1; -- reset debug prefix
            end

            --- dumps all the active objects to the Address List
            function DumpAllNodesToAddr(thr)
                if not (gdOffsetsDefined) then print('define the offsets first, silly') return end

                print('MAIN: DUMP PROCESS STARTED')
                debugPrefix = 1; -- reset debug prefix
                dumpedNodes = {}; -- mutually linked nodes may end up in endless recursion + we use it for API | an obvious race condition if a user calls that on different nodes at the same time, don't care much
                local parentRec

                parentRec = synchronize(function()
                            local addrList = getAddressList()
                            local mainAddr = addrList.getMemoryRecordByDescription("DUMPED:")
                            if mainAddr then mainAddr.Destroy() end

                            local parentRec = addrList.createMemoryRecord()
                            parentRec.setDescription("DUMPED:")
                            parentRec.setAddress( 0xBABE )
                            parentRec.setType(vtPointer)
                            parentRec.Options = '[moHideChildren, moAllowManualCollapseAndExpand, moManualExpandCollapse]'
                            parentRec.DontSave=true
                            return parentRec
                        end
                    )

                local mainNodeDict = getMainNodeDict()

                for key, value in pairs(mainNodeDict) do   

                    value.MEMREC = synchronize(function(value, key, parentRec)
                                local newNodeMemRec = addMemRecTo( key, value.PTR, getCETypeFromGD(value.TYPE), parentRec )
                                newNodeMemRec.Options = '[moHideChildren, moAllowManualCollapseAndExpand, moManualExpandCollapse]'
                                return newNodeMemRec
                            end, value, key, parentRec
                        )

                    table.insert( dumpedNodes , value.PTR )
                    if bDEBUGMode then print('MAIN: loop. STEP: Constants for: '..key) end

                    local newConstRec = synchronize(function(value)
                                local newConstRec = getAddressList().createMemoryRecord()
                                newConstRec.setDescription( "Consts:" )
                                newConstRec.setAddress( 0xBABE )
                                newConstRec.setType( vtPointer )
                                newConstRec.Options = '[moHideChildren, moAllowManualCollapseAndExpand, moManualExpandCollapse]'
                                newConstRec.DontSave = true
                                newConstRec.appendToEntry( value.MEMREC )
                                return newConstRec
                            end, value
                        )

                    iterateNodeConstToAddr( value.PTR , newConstRec )

                    if bDEBUGMode then print(' MAIN: loop. STEP: VARIANTS for: '..key) end
                    iterateVecVarToAddr( value.PTR , value.MEMREC )
                end

                debugPrefix = 1;
                print('MAIN: DUMP PROCESS FINISHED')

            end

        --///---///--///---///--///---///--///--///---///--///---///--///---///--/// Setter

            --- never implemented or tested; accepts a pointer to the GDScriptFunction and an array of ints to replace. Each opcode is 4 bytes, Godot opcodes can vary in arguments; didn't explore GD VM
            ---@param gdFunctionPtr number
            ---@param opsToReplace table
            ---@param opsToStore table
            function OverrideFunctionOps(gdFunctionPtr, opsToReplace, opsToStore)
                assert( (type(gdFunctionPtr) == 'number') and (gdFunctionPtr ~= 0),'OverrideFunctionOps: GD function has to be a valid pointer, instead got: '..type(gdFunctionPtr)..' '..tostring(gdFunctionPtr) )
                assert( #opsToReplace > 0, 'opcode arr should have elements')

                if opsToStore == nil then local opsToStore = {}; end

                local codePtr = readPointer( gdFunctionPtr + GDSOf.FUNC_CODE )
                for i=0, #opsToReplace do
                    --implement switch table via function below, but you have to learn what arguments each opcode has and consider polymorphic implementation if possible
                    opsToStore[i] = readInteger(codePtr + i*0x4)
                    writeInteger(codePtr + i*0x4,opsToReplace[i])
                end
                return opsToStore
            end



        defineGDOffsets(bOverrideAssumption, majorVersion, oChildren, oObjStringName, oGDScriptInstance, oGDScriptName, oFuncDict, oGDConst, oVariantNameHM, oVariantVector, oVariantNameHMVarType, oVarSize, oVariantHMIndex, oFuncDictVal, oGDFunctionString, oGDFunctionCode)
    end





    buildGDGUI()

