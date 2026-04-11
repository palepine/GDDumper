-- This script was created by palepine. Support me: https://ko-fi.com/vesperpallens
-- I'd like to thank cfemen for some basic insights about the godot engine which saved me from reading much of the Godot Engine source code initially.
-- Source code on github: https://github.com/palepine/GDDumper

--///---///--///---///--///---///--///--///---///--///---///--///---///--/// Feat
    --TODO a plugin injecting routines?
    --TODO investigate packedArray size (at least 3.x)
    --TODO dump nodes schema with the addresslist?
    --TODO add more functionality for function overriding ==>
    --TODO bytecode patching function that assembles a function for return;end. or return true;end It should store the original function (address association?)
    --TODO always check UTF32>UTF8>ASCII for all strings and both 8/10 offsets

--///---///--///---///--///---///--///--///---///--///---///--///---///--///--///--/// CHEAT ENGINE UTILITIES

        --///---///--///---///--///---/// MEMRECS
            --- adds a memrec to parent
            ---@param memRecName string
            ---@param gdPtr number
            ---@param CEType number
            ---@param parent userdata -- to append to
            ---@return userdata
            function addMemRecTo(memRecName, gdPtr, CEType, parent)
                local newMemRec = getAddressList().createMemoryRecord()
                newMemRec.setDescription(memRecName)
                newMemRec.setType(CEType)

                if GDSOf.GD4_STRING_EXISTS then
                    if CEType == vtString then newMemRec.setType(vtCustom); newMemRec.CustomTypeName = "GD4 String" newMemRec.setAddress( readPointer( gdPtr) ) else newMemRec.setAddress( gdPtr ) end
                else
                    if CEType == vtString then newMemRec.String.Size = 100; newMemRec.String.Unicode = true; newMemRec.setAddress( readPointer( gdPtr) ) else newMemRec.setAddress( gdPtr ) end
                end

                if CEType == vtQword then newMemRec.ShowAsHex = true; end
                if CEType == vtDword then newMemRec.ShowAsSigned = true; end -- color and int

                newMemRec.DontSave=true
                newMemRec.appendToEntry(parent)
                return newMemRec
            end

        --///---///--///---///--///---/// GD preinit

            function getExportTableName()
                local base = getAddress(process)

                -- cases when getAddress fails
                if isNullOrNil(base) then base = enumModules()[1].Address end

                -- first check via PE -- https://wiki.osdev.org/PE
                if isNotNullOrNil(base) then
                    local PE = base + readInteger( base + 0x3C ) -- MZ.e_lfanew has an offset to PE
                    local optPE = PE + 0x18 -- just skip to optional header
                    local magic = readSmallInteger(optPE) -- Pe32OptionalHeader.mMagic
                    local dataDirOffset = (magic == 0x10B) and 0x60 or 0x70 -- 32/64 bit
                    local exportRVA = readInteger( optPE + dataDirOffset ) -- skip directly to DataDirectory
                    if (exportRVA) and exportRVA ~= 0 then 
                        local exportVA  = base + exportRVA -- jump to exportRVA (.edata)
                        local nameRVA = readInteger(exportVA + 0xC) -- 12 is PEExportsTableHeader.mNameRVA, offset to name's virtual address
                        
                        return readString( (base + nameRVA), 60 ) or "ExportTableNotFound"
                    end
                end
            end

            function getGodotVersionString()
                local reStr = [[Godot\sEngine\s(\(With\sGodot\sSecure\)\s)?[vV]?(0|[1-9]\d*)(?:\.(0|[1-9]\d*))?(?:\.(0|[1-9]\d*))?(?:[\.-]((?:dev|alpha|beta|rc|stable)\d*))?(?:[\.+-]((?:[\w\-+\.]*)))?]]
                local godotVersionStringTable = lregexScan({   pattern = reStr,
                                                                protection = "WR-E-C",
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
                    print("Version string not found")
                    return "SEMVER_NOT_FOUND"
                end
            end

            --- heuristic to identify whether the process is godot
            function godotOnProcessOpened(processid, processhandle, caption)
                -- similar to monoscript.lua in implementation
                if GD_OldOnProcessOpened~=nil then
                    GD_OldOnProcessOpened(processid, processhandle, caption)
                end

                if godot_ProcessMonitorThread == nil then
                    godot_ProcessMonitorThread = createThread(function(thr)
                        thr.Name = 'GDDumper_ProcessMonitorThread'
                        targetIsGodot = false
                        -- first check via PE -- https://wiki.osdev.org/PE
                        local exportTablename = getExportTableName() or ""
                        if ( exportTablename ):match("([gG][oO][Dd][Oo][Tt])") then
                            -- if GDSOf == nil then GDSOf = {} end
                            -- GDSOf.GDEXPORT_TABLE = exportTablename
                            targetIsGodot = true;
                        end
                        
                        -- secondly, check if there's a package file, many apps do
                        if not targetIsGodot then
                            local pathToExe = enumModules()[1].PathToFile
                            local gameDir , exeName = extractFilePath(pathToExe) , string.match(extractFileName(pathToExe) , "([^/]+)%.exe$")
                            local pathList = getFileList(gameDir)
                            local pckName = exeName..'.pck'

                            for _, path in ipairs(pathList) do
                                if (extractFileName(path) == pckName) then targetIsGodot = true; end
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

                        if targetIsGodot then synchronize(buildGDGUI())
                        
                        elseif targetIsGodot == false and GDGUIInit == true then
                                synchronize(function()
                                    disableGDDissect()
                                    local mainMenu = getMainForm().Menu
                                    for i=0, mainMenu.Items.Count-1 do
                                        if mainMenu.Items.Item[i].Caption == 'GDDumper' then
                                            mainMenu.Items.Item[i].Destroy()
                                            break
                                        end
                                    end
                                    GDGUIInit = false
                                end)
                        end

                    end
                    )
                    godot_ProcessMonitorThread = nil
                end

                return nil
            end

            function godotRegisterPreinit()
                GD_OldOnProcessOpened = MainForm.OnProcessOpened
                MainForm.OnProcessOpened = godotOnProcessOpened
            end

            function defineGDVersion()
                local godotVersionString = getGodotVersionString()

                if isNullOrNil(GDSOf) then GDSOf = {} end

                GDSOf.FULL_GDVERSION_STRING = godotVersionString
                local major, minor, patch, tag = (godotVersionString):match( "v?(%d+)%.(%d+)%.?(%d*)%-?(%a*)" )
                
                if isNullOrNil(major) or isNullOrNil(minor) then
                    major, minor, patch = (godotVersionString):match( "Godot Engine v?(%d+)%.(%d+)%.?(%a*)" )
                end
                
                local exportTableStr = getExportTableName() or ""
                
                if (exportTableStr):match( "debug" ) then
                    GDSOf.DEBUGVER = true
                --elseif (exportTableStr):match( "release" ) then -- or "opt" or "dev6"
                else
                    GDSOf.DEBUGVER = false
                end

                if (godotVersionString):match( "custom" ) then -- TODO: for now let it be liek this until custom debug versions
                    GDSOf.CUSTOMVER = true
                end
                
                if isNotNullOrNil(major) and isNotNullOrNil(minor) then
                    GDSOf.MAJOR_VER = tonumber(major)
                    GDSOf.MINOR_VER = tonumber(minor)
                    GDSOf.VERSION_STRING = major..'.'..minor
                end
            end

            function getStoredOffsetsFromVersion( majminVersionStr )

                majminVersionStr = majminVersionStr or GDSOf.VERSION_STRING
                -- TODO: GDSOf.MAXTYPE
                -- offsets in Node/Objects in debug versions are shifted by 0x8 in most cases; function code/constants/globals are shifted less often
                -- TODO: custom debug versions
                -- TODO: refactor the branching

                -- VPChildren, VPObjStringName, NodeGDScriptInstance, NodeGDScriptName, GDScriptFunctionMap, GDScriptConstantMap, GDScriptVariantNameHM, oVariantVector, _4x_MoreStableGDScriptVariantNameType, NodeVariantVectorSizeOffset, _3x_GDScriptVariantNamesIndex, GDScriptFunctionCode, GDScriptFunctionCodeConsts, GDScriptFunctionCodeGlobals
                if majminVersionStr == "4.6" then
                        GDSOf.DICT_HEAD = 0x20
                        GDSOf.DICT_TAIL = 0x28
                        GDSOf.DICT_SIZE = 0x3C
                    if GDSOf.DEBUGVER then
                        GDSOf.STRING = 0x8
                        return 0x140+0x8, 0x190+0x8, 0x60+0x8, 0xF0+0x8, 0x230+0x8, 0x208+0x8, 0x180+0x8, 0x28+0x28, 0x44, 0x10, nil, 0x178, 0x198, 0x1A8
                    elseif GDSOf.CUSTOMVER then
                        GDSOf.STRING = 0x8
                        return 0x140+0x48, 0x190+0x48, 0x60, 0xF0+0x48, 0x230+0x48, 0x208+0x48, 0x180+0x48, 0x28, 0x44, 0x8--[[0x10 too]], nil, 0x178--[[+0x8]], 0x198--[[+0x8]], 0x1A8--[[+0x8]]
                    else
                        -- godot.windows.template_release.x86_64.exe
                        -- Godot Engine v4.6.stable.official.89cea1439
                        -- 49 8B 06 4C 89 F2 48 89 7C 24
                        GDSOf.STRING = 0x8
                        return 0x140, 0x190, 0x60, 0xF0, 0x230, 0x208, 0x180, 0x28, 0x44, 0x10, nil, 0x178, 0x198, 0x1A8
                    end
                elseif majminVersionStr == "4.5" then
                        GDSOf.DICT_HEAD = 0x20
                        GDSOf.DICT_TAIL = 0x28
                        GDSOf.DICT_SIZE = 0x3C
                    if GDSOf.DEBUGVER then
                        -- godot.windows.template_debug.x86_64.exe 
                        -- Godot Engine v4.5.1.stable.official 
                        -- 48 8B 06 8B 8C 24
                        GDSOf.STRING = 0x8
                        return 0x170+0x8, 0x1C0+0x8, 0x68+0x8, 0x120+0x8, 0x268+0x8, 0x208+0x8, 0x1B8+0x8, 0x28+0x28, 0x48, 0x8, nil, 0x178+0x8, 0x198+0x8, 0x1A8+0x8
                    elseif GDSOf.CUSTOMVER then
                        -- godot.windows.template_release.x86_64.exe 
                        -- Godot Engine v4.5.1.stable.custom_build 
                        GDSOf.STRING = 0x8
                        return 0x170+0x48, 0x1C0+0x48, 0x68, 0x120+0x48, 0x268+0x48, 0x208+0x48, 0x1B8+0x48, 0x28, 0x48, 0x8, nil, 0x178+0x8, 0x198+0x8, 0x1A8+0x8
                    else
                        -- godot.windows.template_release.x86_64.exe 
                        -- Godot Engine v4.5.1.stable.official.f62fdbde1 
                        GDSOf.STRING = 0x8

                        return 0x170, 0x1C0, 0x68, 0x120, 0x268, 0x208, 0x1B8, 0x28, 0x48, 0x8, nil, 0x180, 0x1A0, 0x1B0 --0x178, 0x198, 0x1A8
                    end
                elseif majminVersionStr == "4.4" then
                    if GDSOf.DEBUGVER then
                        -- godot.windows.template_debug.x86_64.exe 
                        -- Godot Engine v4.4.1.stable.official
                        -- godot.windows.template_debug.x86_64.mono.exe 
                        -- Godot Engine v4.4.stable.mono.official 
                        -- 48 8B 03 48 89 D9 FF 90 ? ? ? ? 84 C0 0F 84 ? ? ? ? 48 89 D9 E8 ? ? ? ? 84 C0
                        -- 48 8B 03 48 8D B4 24 ? ? ? ? 48 89 DA 4C 8D AC 24
                        GDSOf.STRING = 0x8
                        return 0x188+0x8, 0x1E0+0x8, 0x68+0x8, 0x130+0x8, 0x2D8+0x8, 0x2A8+0x8, 0x210+0x8, 0x28+0x30, 0x48, 0x8, nil, 0x178, 0x198, 0x1A8
                    elseif GDSOf.CUSTOMVER then
                        GDSOf.STRING = 0x10
                        -- godot.windows.template_release.x86_64.exe
                        -- Godot Engine v4.4.1.stable.custom_build.49a5bc7b6
                        return 0x188+0x48, 0x1E0+0x48, 0x68, 0x130+0x48, 0x2D8+0x48, 0x2A8+0x48, 0x210+0x48, 0x28, 0x48, 0x8, nil, 0x178, 0x198, 0x1A8
                    else
                        -- godot.windows.template_release.x86_64.exe 
                        -- Godot Engine v4.4.stable.official.4c311cbee 
                        -- 49 8B 45 ? 4C 89 EA 48 89 7C 24
                        return 0x188, 0x1E0, 0x68, 0x130, 0x2D8, 0x2A8, 0x210, 0x28, 0x48, 0x8, nil, 0x178, 0x198, 0x1A8
                    end
                elseif majminVersionStr == "4.3" then
                    if GDSOf.DEBUGVER then
                        -- godot.windows.template_debug.x86_64.exe (0x8 string, static names that are ascii)
                        -- Godot Engine v4.3.stable.official 
                        GDSOf.STRING = 0x8
                        return 0x178+0x8, 0x1D0+0x8, 0x68+0x8, 0x120+0x8, 0x280+0x8, 0x250+0x8, 0x1B8+0x8, 0x28+0x30, 0x48, 0x8, nil, 0x178, 0x198, 0x1A8
                    elseif GDSOf.CUSTOMVER then
                        -- godot.windows.template_release.x86_64.exe 
                        -- Godot Engine v4.3.stable.custom_build
                        -- GDSOf.STRING = 0x8
                        return 0x178+0x48, 0x1D0+0x48, 0x68, 0x120+0x48, 0x280+0x48, 0x250+0x48, 0x1B8+0x48, 0x28, 0x48, 0x8, nil, 0x178--[[+0x8]], 0x198--[[+0x8]], 0x1A8--[[+0x8]]
                    else
                        -- godot.windows.template_release.x86_64.exe 
                        -- Godot Engine v4.3.stable.official 
                        -- 48 8B 03 C7 84 24 ? ? ? ? ? ? ? ? 48 89 DA
                        return 0x178, 0x1D0, 0x68, 0x120, 0x280, 0x250, 0x1B8, 0x28, 0x40, 0x8, nil, 0x178, 0x198, 0x1A8
                    end
                elseif majminVersionStr == "4.2" then
                    if GDSOf.DEBUGVER then
                        -- godot.windows.template_debug.x86_64.exe 
                        --  Godot Engine v4.2.2.stable.official
                        GDSOf.STRING = 0x8
                        return 0x178+0x8, 0x1D0+0x8, 0x68+0x8, 0x120+0x8, 0x280+0x8, 0x250+0x8, 0x1B8+0x8, 0x28+0x30, 0x48, 0x4, nil, 0x170, 0x190, 0x1A0
                    elseif GDSOf.CUSTOMVER then
                        error("Not defined yet")
                        GDSOf.STRING = 0x8
                        return 0x178+0x48, 0x1D0+0x48, 0x68, 0x120+0x48, 0x280+0x48, 0x250+0x48, 0x1B8+0x48, 0x28, 0x48, 0x4, nil, 0x170--[[+0x8]], 0x190--[[+0x8]], 0x1A0--[[+0x8]]
                    else
                        -- godot.windows.template_release.x86_64.exe 
                        -- Godot Engine v4.2.1.stable.official.b09f793f5 
                        return 0x178, 0x1D0, 0x68, 0x120, 0x280, 0x250, 0x1B8, 0x28, 0x40, 0x4, nil, 0x170, 0x190, 0x1A0
                    end
                elseif majminVersionStr == "4.1" then
                    -- 4.1.2 has some wild offsets however
                    if GDSOf.DEBUGVER then
                        -- godot.windows.template_debug.x86_64.exe 
                        --  Godot Engine v4.1.1.stable.official
                        GDSOf.STRING = 0x8
                        return 0x178+0x8, 0x1D0+0x8, 0x68+0x8, 0x148+0x8, 0x260+0x8, 0x1F0+0x8, 0x290+0x8, 0x28+0x30, 0x40, 0x4, nil, 0x118, 0x100, 0xF0
                    elseif GDSOf.CUSTOMVER then
                        -- Godot Engine v4.1.2.rc.custom_build
                        GDSOf.STRING = 0x10
                        return 0x178+0x48, 0x1D0+0x48, 0x68, 0x148+0x48, 0x260+0x48, 0x1F0+0x48, 0x290+0x48, 0x28, 0x40, 0x4, nil, 0x118, 0x100, 0xF0
                    else
                        -- godot.windows.template_release.x86_64.exe 
                        -- Godot Engine v4.2.1.stable.official.b09f793f5 
                        return 0x178, 0x1D0, 0x68, 0x148, 0x260, 0x1F0, 0x290, 0x28, 0x40, 0x4, nil, 0x118 --[[?]], 0xF0, 0x100 -- 0x100, 0xF0
                    end
                elseif majminVersionStr == "4.0" then
                    if GDSOf.DEBUGVER then
                        -- error("Not defined yet")
                        GDSOf.STRING = 0x8
                        return 0x168+0x8, 0x1C0+0x8, 0x68+0x8, 0x178+0x8, 0x270+0x8, 0x238+0x8, 0x2A8+0x8, 0x28+0x30, 0x40, 0x8, nil, 0x118 --[[?]], 0x100, 0xF0
                    elseif GDSOf.CUSTOMVER then
                        error("Not defined yet")
                        return 0x168+0x48, 0x1C0+0x48, 0x68, 0x178+0x48, 0x270+0x48, 0x238+0x48, 0x2A8+0x48, 0x28, 0x40, 0x8, nil, 0x118 --[[?]], 0x100, 0xF0
                    else
                        return 0x168, 0x1C0, 0x68, 0x178, 0x270, 0x238, 0x2A8, 0x28, 0x40, 0x8, nil, 0x118 --[[?]], 0x100, 0xF0
                    end
                elseif majminVersionStr == "3.6" then
                    if GDSOf.DEBUGVER then
                        -- godot.windows.opt.debug.64.exe 
                        GDSOf.STRING = 0x8
                        return 0x108+0x8, 0x130+0x8, 0x58+0x8, 0x108+0x8, 0x1A8+0x8, 0x190+0x8, 0x1C0+0x8, 0x20+0x18, nil, 0x4, 0x38, 0x50, 0x20, 0x30
                    elseif GDSOf.CUSTOMVER then
                        -- error("Not defined yet")
                        GDSOf.STRING = 0x10
                        return 0x108--[[+0x48]], 0x130--[[+0x48]], 0x58, 0x108--[[+0x48]], 0x1A8--[[+0x48]], 0x190--[[+0x48]], 0x1C0--[[+0x48]], 0x20--[[+0x18]], nil, 0x4, 0x38, 0x50, 0x20, 0x30
                    else
                        -- godot.windows.opt.64.exe 
                        --  Godot Engine v3.6.stable.custom_build.de2f0f147 
                        return 0x108, 0x130, 0x58, 0x108, 0x1A8, 0x190, 0x1C0, 0x20, nil, 0x4, 0x38, 0x50, 0x20, 0x30
                    end
                elseif majminVersionStr == "3.5" then
                    
                    if GDSOf._x64bit then
                        if GDSOf.DEBUGVER then
                            -- godot.windows.opt.debug.64.exe
                            -- Godot Engine 3.5.2.stable 
                            GDSOf.STRING = 0x8
                            return 0x108+0x8, 0x130+0x8, 0x58+0x8, 0x108+0x8, 0x1A8+0x8, 0x190+0x8, 0x1C0+0x8, 0x20+0x18, nil, 0x4, 0x38, 0x50, 0x20, 0x30
                        elseif GDSOf.CUSTOMVER then
                            error("Not defined yet")
                            return 0x108+0x48, 0x130+0x48, 0x58, 0x108+0x48, 0x1A8+0x48, 0x190+0x48, 0x1C0+0x48, 0x20+0x18, nil, 0x4, 0x38, 0x50, 0x20, 0x30
                        else
                            -- godot.windows.opt.64.exe 
                            -- Godot Engine v3.5.1.stable.official
                            -- 48 8B 01 48 89 CB 41 89 D4 FF
                            return 0x108, 0x130, 0x58, 0x108, 0x1A8, 0x190, 0x1C0, 0x20, nil, 0x4, 0x38, 0x50, 0x20, 0x30
                        end
                    else
                        if GDSOf.DEBUGVER then
                            error("Not defined yet")
                        elseif GDSOf.CUSTOMVER then
                            error("Not defined yet")
                        else
                            -- godot.windows.opt.32.exe
                            -- Godot Engine v3.5.3.stable.official
                            -- 48 8B 01 48 89 CB 41 89 D4 FF
                            GDSOf.STRING = 0x8 -- ascii
                            GDSOf.GDSCRIPT_REF = 0x8
                            GDSOf.MAP_SIZE = 0x10
                            GDSOf.MAP_LELEM = 0x8
                            GDSOf.MAP_NEXTELEM = 0x10
                            GDSOf.MAP_KVALUE = 0x18
                            GDSOf.FUNC_MAPVAL = 0x1C
                            GDSOf.DICT_LIST = 0x4
                            GDSOf.DICT_HEAD = 0x0
                            GDSOf.DICT_TAIL = 0x4
                            GDSOf.DICT_SIZE = 0x10
                            GDSOf.DICTELEM_PAIR_NEXT = 0x20
                            GDSOf.DICTELEM_KEYTYPE = 0x0
                            GDSOf.DICTELEM_KEYVAL = 0x8
                            GDSOf.DICTELEM_VALTYPE = 0x8
                            GDSOf.DICTELEM_VALVAL = 0x10
                            GDSOf.ARRAY_TOVECTOR = 0x8
                            GDSOf.P_ARRAY_TOARR = GDSOf.P_ARRAY_TOARR or 0x4
                            GDSOf.P_ARRAY_SIZE = GDSOf.P_ARRAY_SIZE or 0xC
                            GDSOf.CONSTELEM_KEYVAL = 0x18
                            GDSOf.CONSTELEM_VALTYPE = 0x20
                            return 0x90, 0xB0, 0x38, 0x94, 0xE8, 0xDC, 0xF4, 0x10, 0x34, 0x4, 0x1C, 0x38, 0x20, 0x28
                        end
                    end

                elseif majminVersionStr == "3.4" then
                    if GDSOf.DEBUGVER then
                        -- error("Not defined yet")
                        GDSOf.STRING = 0x8
                        return 0x108+0x8, 0x120+0x8, 0x58+0x8, 0x108+0x8, 0x1A8+0x8, 0x190+0x8, 0x1C0+0x8, 0x20+0x18, nil, 0x4, 0x38, 0x50, 0x20, 0x30
                    elseif GDSOf.CUSTOMVER then
                        error("Not defined yet")
                        GDSOf.STRING = 0x8
                        return 0x108+0x48, 0x120+0x48, 0x58, 0x108+0x48, 0x1A8+0x48, 0x190+0x48, 0x1C0+0x48, 0x20+0x18, nil, 0x4, 0x38, 0x50, 0x20, 0x30
                    else
                        --godot.windows.opt.64.exe 
                        --Godot Engine v3.4.4.stable.official.419e713a2
                        return 0x108, 0x120, 0x58, 0x108, 0x1A8, 0x190, 0x1C0, 0x20, nil, 0x4, 0x38, 0x50, 0x20, 0x30
                    end
                elseif majminVersionStr == "3.3" then
                    if GDSOf.DEBUGVER then
                        -- error("Not defined yet")
                        GDSOf.STRING = 0x8
                        return 0x100+0x8, 0x118+0x8, 0x50+0x8, 0x100+0x8, 0x1A0+0x8, 0x188+0x8, 0x1B8+0x8, 0x20+0x18, nil, 0x4, 0x38, 0x50, 0x20, 0x30
                    elseif GDSOf.CUSTOMVER then
                        error("Not defined yet")
                        GDSOf.STRING = 0x8
                        return 0x100+0x48, 0x118+0x48, 0x50, 0x100+0x48, 0x1A0+0x48, 0x188+0x48, 0x1B8+0x48, 0x20+0x18, nil, 0x4, 0x38, 0x50, 0x20, 0x30
                    else
                        -- godot.windows.opt.64.exe 
                        -- Godot Engine v3.3.2.stable.official 
                        return 0x100, 0x118, 0x50, 0x100, 0x1A0, 0x188, 0x1B8, 0x20, nil, 0x4, 0x38, 0x50, 0x20, 0x30
                    end
                elseif majminVersionStr == "3.2" then
                    if GDSOf.DEBUGVER then
                        error("Not defined yet")
                        GDSOf.STRING = 0x8
                        return 0x118+0x8, 0x130+0x8, 0x50+0x8, 0x108+0x8, 0x1C0+0x8, 0x1A8+0x8, 0x1D8+0x8, 0x20+0x18, nil, 0x4, 0x38, 0x50, 0x20, 0x30
                    elseif GDSOf.CUSTOMVER then
                        -- godot.windows.opt.64.exe
                        -- Godot Engine v3.2.stable.custom_build 
                        return 0x110, 0x128, 0x50, 0x100, 0x1B8, 0x1A0, 0x1D0, 0x20, nil, 0x4, 0x38, 0x50, 0x20, 0x30
                    else
                        error("Not defined yet")
                        return 0x118, 0x130, 0x50, 0x108, 0x1C0, 0x1A8, 0x1D8, 0x20, nil, 0x4, 0x38, 0x50, 0x20, 0x30
                    end
                else
                    print("No recorded version found")
                    error("Not defined yet")
                    return
                end
            end

        --///---///--///---///--///---/// POINTER HANDLERS

            --- checks if the value is a valid pointer
            ---@param addr number
            ---@return boolean
            function isValidPointer(addr)
                local success, result = pcall(readPointer, addr)
                return success and result ~= nil
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
            function getSectionBounds(sectionName)
                local base = getAddress(process)
                if base == 0 or base == nil then base = enumModules()[1].Address end -- for cases when getAddress fails
                if not base then return nil end -- if it's still failing, quit

                -- DOS header -> e_lfanew
                local peOffset = readInteger(base + 0x3C)
                if not peOffset then return nil end

                local PE = base + peOffset

                local signature = readInteger(PE)
                if signature ~= 0x00004550 then return nil end

                -- IMAGE_FILE_HEADER
                local numberOfSections   = readSmallInteger(PE + 0x6)
                local sizeOfOptionalHdr  = readSmallInteger(PE + 0x14)

                if not numberOfSections or not sizeOfOptionalHdr then return nil end

                -- Section table starts after:
                -- 4 bytes PE signature + 20 bytes IMAGE_FILE_HEADER + optional header
                local sectionTable = PE + 0x18 + sizeOfOptionalHdr

                for i = 0, numberOfSections - 1 do
                    local sec = sectionTable + (i * 0x28) -- IMAGE_SECTION_HEADER = 40 bytes

                    local name = readString(sec, 8) or ""
                    name = name:gsub("%z.*", "") -- strip trailing nulls

                    if name == sectionName then
                        local virtualSize    = readInteger(sec + 0x8)
                        local virtualAddress = readInteger(sec + 0xC)

                        if not virtualSize or not virtualAddress then return nil end

                        return {
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

            -- check VTable validity for main module (MM)
            ---@param VTAddr number
            ---@return boolean
            function isMMVTable( VTAddr )
                if VTAddr == 0 or VTAddr == nil then return false end
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
                
                if moduleStart < VTAddr and VTAddr < moduleEnd then
                    -- iterate a few pointers and confirm if they are executable
                    local ptrsize = targetIs64Bit() and 0x8 or 0x4
                    local sectionInfo = getSectionBounds(".text")
                    if sectionInfo == nil then return false end

                    for i=0, 5 do -- 5 pointers
                        local pmethod = readPointer( VTAddr + ptrsize*i )
                        if not isInsideMMTextSection( pmethod, sectionInfo ) then
                            return false
                        end
                    end
                else -- outside the main module
                    return false
                end

                return true
            end

            function isInsideMMTextSection(addr, sectionInfo)
                if addr == nil or addr == 0 then return false end
                -- in .text range
                if addr > sectionInfo.startAddress and sectionInfo.endAddress > addr then
                    return true
                end
            end

        --///---///--///---///--///---/// MISC

            --- turns off showOnPrint
            function fuckoffPrint()
                GetLuaEngine().cbShowOnPrint.Checked = false
            end

            function isNullOrNil(toCheck)
                return toCheck == nil or toCheck == 0
            end

            function isNotNullOrNil(toCheck)
                return not isNullOrNil(toCheck)
            end

        --///---///--///---///--///---/// DEBUG

            --- multiplies a string by a number for more neat debug
            ---@param str string
            ---@param times number
            ---@return string
            function strMul(str, times)
                return string.rep(str, times)
            end

            function debugStepIn()
                if bDEBUGMode and inMainThread() then debugPrefix = debugPrefix+1 end
            end

            function debugStepOut()
                if bDEBUGMode and inMainThread() then debugPrefix = debugPrefix-1 end
            end

            function getDebugPrefix()
                return strMul('>', debugPrefix)
            end

            function sendDebugMessage(msg)
                if bDEBUGMode and isNotNullOrNil( msg ) and inMainThread()  then
                    print( getDebugPrefix().. " " .. tostring( msg ) )
                end
            end

            function sendDebugMessageAndStepOut(msg)
                if bDEBUGMode and isNotNullOrNil( msg ) and inMainThread()  then
                    print( getDebugPrefix().. " " .. tostring( msg ) )
                    debugStepOut()
                end
            end

            function getGDSemver()
                print(getExportTableName()..'\n'..getGodotVersionString())
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
                elseif CEType == vtDword then
                    element.DisplayMethod = 'dtSignedInteger'
                end

                return element
            end

            --- for node layout creation
            function addLayoutStructElem(parentStructElement, childName, backgroundColor, offset, CEType)
                parentStructElement.ChildStruct = parentStructElement.ChildStruct and parentStructElement.ChildStruct or createStructure( parentStructElement.parent.Name or 'ChStructure' )
                local childStructElement = parentStructElement.ChildStruct.addElement()
                childStructElement.Name = childName
                if backgroundColor ~= nil then childStructElement.BackgroundColor = backgroundColor end
                childStructElement.Offset = offset or 0x0
                childStructElement.VarType = CEType
                return childStructElement
            end

            local function createChildStructElem(parent, label, offset, ceType, structName)
                local elem = addStructureElem(parent, label, offset, ceType)
                elem.ChildStruct = createStructure(structName)
                return elem
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
                if structDissectID ~= nil then
                    unregisterStructureDissectOverride( structDissectID )
                end
                structDissectID = nil;
            end

            --- overriden structure dissector function
            ---@param struct userdata @the newly created struct
            ---@param baseaddr number  @the address form the parent pointer
            function GDStructureDissect(struct, baseaddr)

                if isNullOrNil(baseaddr) then return false end
                struct = struct and struct or createStructure('') -- should not happen though?
                struct.beginUpdate()

                if checkForGDScript( baseaddr ) and isMMVTable( readPointer(baseaddr) ) then
                    dumpedDissectorNodes = {} -- redundant?
                    -- safe to assume, that's a starting point
                    local nodeName = getNodeName( baseaddr )
                    nodeName = nodeName and nodeName or 'Anon Node'
                    struct.Name = ' Node: '..nodeName
                    local scriptInstStructElem = struct.addElement()
                    scriptInstStructElem.Name = 'GDScriptInstance'
                    scriptInstStructElem.BackgroundColor = 0xFF0080
                    scriptInstStructElem.Offset = GDSOf.GDSCRIPTINSTANCE
                    scriptInstStructElem.VarType = vtPointer

                    if isPointerNotNull( baseaddr + GDSOf.CHILDREN ) then
                        local childrenStructElem = struct.addElement()
                        childrenStructElem.Name = 'Children'
                        childrenStructElem.BackgroundColor = 0xFF0080
                        childrenStructElem.Offset = GDSOf.CHILDREN
                        childrenStructElem.VarType = vtPointer
                        childrenStructElem.ChildStruct = createStructure( 'Children' )
                        iterateNodeChildrenToStruct( childrenStructElem, baseaddr )
                    end

                    iterateNodeToStruct( baseaddr, scriptInstStructElem )

                elseif bDISASSEMBLEFUNCTIONS and checkIfGDFunction(baseaddr) then -- not implemented for 3.x as of now
                    disassembleGDFunctionCodeToStruct( baseaddr, struct )

                elseif checkIfGDObjectWithChildren(baseaddr) then -- experimental, creating structs for nonGDScript objects
                    local childrenStructElem = struct.addElement()
                    childrenStructElem.Name = 'Children'
                    childrenStructElem.BackgroundColor = 0xFF0080
                    childrenStructElem.Offset = GDSOf.CHILDREN
                    childrenStructElem.VarType = vtPointer
                    childrenStructElem.ChildStruct = createStructure( 'Children' )
                    iterateNodeChildrenToStruct( childrenStructElem, baseaddr )
                else
                    -- otherwise just let CE decide, btw why the hell the base address should be a fucking hex string?
                    struct.autoGuess( ("%x"):format(baseaddr), 0x0, 0x500 --[[0x200]]) -- 0x500 for researching
                end

                struct.endUpdate()
                return true
            end

        --///---///--///---///--///---/// GUI

            --- creates a menu button in the main menu
            function buildGDGUI()
                if GDGUIInit then return end
                GDGUIInit = true

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
                    addCustomMenuButtonTo( gdMenuItem, 'Disasm Funcs', GDDisasmFuncSwitch )
                    addCustomMenuButtonTo( gdMenuItem, 'Use stored offsets', GDStoredOffsetsSwitch )
                    addCustomMenuButtonTo( gdMenuItem, 'Guess log', GDGuessLogSwitch )
                    addCustomMenuButtonTo( gdMenuItem, 'Debug Mode', GDDebugSwitch )
                    addCustomMenuButtonTo( gdMenuItem, 'Add Template', addGDMemrecToTable )
                    local menuItem = addCustomMenuButtonTo( gdMenuItem, 'Append Script', appendDumperScript )
                    -- menuItem.OnEnter = function(sender) if sender.Enabled==false and findTableFile("GDumper")==nil then sender.Enabled=true end end
                    addCustomMenuButtonTo( gdMenuItem, 'Load Script', loadDumperScript )
                    
                    addCustomMenuButtonTo( gdMenuItem, 'Reload from file', loadDumperScriptFromFile )
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

            function GDDebugSwitch(sender)
                sender.Checked = not sender.Checked
                if sender.Checked then
                    bDEBUGMode = true
                else
                    bDEBUGMode = false
                end
            end

            function GDGuessLogSwitch(sender)
                sender.Checked = not sender.Checked
                if sender.Checked then
                    bASSUMPTIONLOG = true
                else
                    bASSUMPTIONLOG = false
                end
            end

            function GDDisasmFuncSwitch(sender)
                sender.Checked = not sender.Checked
                if sender.Checked then
                    bDISASSEMBLEFUNCTIONS = true
                else
                    bDISASSEMBLEFUNCTIONS = false
                end
            end

            function GDStoredOffsetsSwitch(sender)
                sender.Checked = not sender.Checked
                if sender.Checked then
                    bHARDCODEDOFFSETS = true
                else
                    bHARDCODEDOFFSETS = false
                end
            end

            function addGDMemrecToTable(sender)
                local addrList = getAddressList()
                local mainMemrec = addrList.createMemoryRecord()
                mainMemrec.Description = "Dumper"
                mainMemrec.Type = vtAutoAssembler
                mainMemrec.Options = '[moHideChildren,moDeactivateChildrenAsWell]'
                mainMemrec.Script = "{$lua}\nif syntaxcheck then return end\n[ENABLE]\nlocal config = {\n-- replace nil with hex offsets according to the instruction\nmajorVersion =              nil, -- major godot version\n\noffsetNodeChildren =        nil, -- offset to Node->children, it's a classic array of Nodes: consecutive 8/4 byte ptrs on x64/x32 apps respectively\noffsetNodeStringName =      nil,  -- offset to Node->name, it's a pointer to StringName object which usually has a string at either 0x8 or 0x10 (x64)\noffsetGDScriptInstance =    nil, -- for Node types that have a GDScript, Node->GDScriptInstance, it points to an object with a vTable where the next pointer is the owner Node reference and the next offset being the GDScript\noffsetVariantVector =       nil, -- Node->GDScriptInstance->\noffsetVariantVectorSize =   nil,\n\noffsetGDScriptName =        nil, -- Node->GDScriptInstance->GDScript->name, it points to a raw string data that starts with res://\noffsetFuncMap =             nil, -- if you need funcs: GDScript->member_functions - in 4.x - (4 consecutive pointers, capacity and size) use offset to the Head (second to the last ptr) || in 3.x (pointer to the RBT root and the sentinel after it) use offset to the root\noffsetGDFunctionCode =      nil, -- if you need funcs: GDScript->member_functions['abc']->code - it's an int array inside a function storing implemented GDFunction byetcode, very easy to spot\noffsetGDFunctionConst =     nil, -- if you need funcs: GDScript->member_functions['abc']->constants - it's a Vector<Variant> with script constants, relative to code\noffsetGDFunctionGlobals =   nil, -- if you need funcs: GDScript->member_functions['abc']->global_names - Vector of StringNames, relative to code and constants\noffsetConstMap =            nil, -- GDScript->constants - layout same as w/ offsetGDFunctionCode\noffsetVariantMap =          nil, -- GDScript->member_indices - layout same as w/ offsetGDFunctionCode\noffsetVariantMapVarType =   nil, -- essential for 4.x: MemberInfo inside GDScript->member_indices, we need pointer to the Variant type for crosschecking \noffsetVariantMapIndex =     nil, -- essential for 3.x: MemberInfo inside GDScript->member_indices, we need pointer to the Variant index for correctly mapping Variants in Nodes\n\nstartMonitoringNodes =      false, -- if start a Node visitor thread\nenableDebugMode =           false, -- if print debug logs\nenableGuessLog =            false, -- if print heuristic-explored offsets (experimental)\nenableFunDisasm =           false, -- if disassemble function into opcodes (experimental)\nuseHardcodedOffsets =       false, -- if use version-hardcoded offsets, requires a regex plugin (experimental)\n}\ninitDumper(config)\nnodeMonitor()\n[DISABLE]\nnodeMonitor()"
                
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

            -- attaches the script to the table
            function appendDumperScript(sender)
                local cedir = getCheatEngineDir()
                local scriptPath = cedir..[[autorun\GDumper.lua]]
                createTableFile("GDumper",scriptPath)
                sender.Enabled=false
            end

            -- load from attached script
            function loadDumperScript(sender)
                local tableFile = findTableFile("GDumper")
                if tableFile == nil then return end
                local fileStream = tableFile.getData()
                local scriptString = readStringLocal(fileStream.Memory, fileStream.Size)
                if scriptString ~= nil then
                    local doScript = loadstring(scriptString)
                    if type(doScript) == 'function' then
                        doScript()
                        sender.Checked = true
                    end
                    
                end
            end

            function loadDumperScriptFromFile(sender)
                local cedir = getCheatEngineDir()
                local scriptPath = cedir..[[autorun\GDumper.lua]]
                local scriptFile, err = io.open(scriptPath, "r")
                if not scriptFile then error("Could not open file: " .. scriptPath .. "\n" .. tostring(err)) end
                local scriptCode = scriptFile:read("*a")
                scriptFile:close()
                if scriptCode and scriptCode ~= "" then
                    local doScript, loadErr = loadstring(scriptCode)
                    if not doScript then error("Compile error in " .. scriptPath .. ":\n" .. tostring(loadErr)) end
                    local ok, runErr = pcall(doScript)
                    if not ok then error("Runtime error in " .. scriptPath .. ":\n" .. tostring(runErr)) end
                else
                    error("File is empty: " .. scriptPath)
                end
            end

--///---///--///---///--///---///--///--///---///--///---///--///---///--///--///--/// DUMPER CODE


    function initDumper(config)
        --///---///--///---///--///---///--///--///---///--///---///--///---///--/// STRING

            --- reads GD strings (1-4 bytes)
            ---@param strAddress number
            ---@param strSize number
            function readUTFString(strAddress, strSize)
                assert(type(strAddress) == 'number',"string address should be a number, instead got: "..type(strAddress));

                --debugStepIn()
                local MAX_CHARS_TO_READ =  1500 * 2

                if strSize and (strSize > MAX_CHARS_TO_READ) then
                    --sendDebugMessageAndStepOut('readUTFString: chars to read is bigger than MAX_CHARS_TO_READ')
                    return "??" --"ain\'t reading this"  -- we aren't gonna read novels
                end
                
                if GDSOf.MAJOR_VER == 4 then
                    if readInteger(strAddress) == 0 then
                        --sendDebugMessageAndStepOut('readUTFString: empty string');
                        return "??" --"empt str"
                    end
                elseif readSmallInteger(strAddress) == 0 then
                    --sendDebugMessageAndStepOut(' readUTFString: empty string')
                    return "??" --"empt str"
                end

                local charTable = {}
                local buff = 0

                if GDSOf.MAJOR_VER == 3 and (strSize and strSize > 0) then
                    --debugStepOut()
                    return readString( strAddress, strSize * 2 , true ) or "??" -- '???_INVALID_MEM_CAUGHT_WSIZE'

                elseif GDSOf.MAJOR_VER == 3 then
                    --debugStepOut()
                    local retString = readString( strAddress, MAX_CHARS_TO_READ , true )

                    while MAX_CHARS_TO_READ > 0 and retString == nil do     -- https://github.com/cheat-engine/cheat-engine/issues/2602
                        MAX_CHARS_TO_READ = MAX_CHARS_TO_READ-100 -- quite a stride
                        retString = readString( strAddress, MAX_CHARS_TO_READ , true )
                    end
                    --debugStepOut()
                    return retString or "??" -- '???_INVALID_MEM_CAUGHT'

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

                --debugStepOut()
                return table.concat( charTable ) or "??" --'???_UNKNSTR'
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

                -- debugStepIn()

                local retStringAddr = readPointer(stringNamePtr + GDSOf.STRING)
                if isNullOrNil(retStringAddr) then
                    -- sendDebugMessage('getStringNameStr: string address invalid, trying ASCII')
                    retStringAddr = readPointer( stringNamePtr + 0x8 ) -- for cases when StringName holds a static ASCII string at 0x8
                    if isNullOrNil(retStringAddr) then
                        -- sendDebugMessageAndStepOut('getStringNameStr: string address invalid, not ASCII either')
                        return '??'
                    end  -- return an empty string if no string was found

                    -- debugStepOut()
                    return readString( retStringAddr, 100 )
                end

                -- debugStepOut()
                return readUTFString( retStringAddr )
            end

        --///---///--///---///--///---///--///--///---///--///---///--///---///--/// DEFINE

            --- initializes and assigns offsets
            function defineGDOffsets( config )
                if config == nil then config = {} end

                bMonitorNodes = false;
                bMonitorNodes = config.startMonitoringNodes or bMonitorNodes
                bDEBUGMode = bDEBUGMode and true or nil
                bDEBUGMode = config.enableDebugMode or bDEBUGMode                
                bDISASSEMBLEFUNCTIONS = bDISASSEMBLEFUNCTIONS and true or false
                bDISASSEMBLEFUNCTIONS = config.enableFunDisasm or bDISASSEMBLEFUNCTIONS
                bHARDCODEDOFFSETS = bHARDCODEDOFFSETS and true or false
                bHARDCODEDOFFSETS = config.useHardcodedOffsets or bHARDCODEDOFFSETS

                dumpedMonitorNodes = {};
                debugPrefix = 1;

                if GDSOf == nil then GDSOf = {} end

                if targetIs64Bit() then
                    GDSOf.PTRSIZE = 0x8
                    GDSOf._x64bit = true
                else  -- TODO: theres a lot more to do with 32bit in the script
                    GDSOf.PTRSIZE = 0x4
                    GDSOf._x64bit = false
                end

                GDSOf.VERSION_STRING = config.majMinVerStr or nil

                if lregexScan and type(lregexScan) == "function" then -- a regex plugin must be initialized for that
                    defineGDVersion()
                end

                if bHARDCODEDOFFSETS or not( config.majMinVerStr == nil or config.majMinVerStr == "") then
                    GDSOf.CHILDREN,
                    GDSOf.OBJ_STRING_NAME,
                    GDSOf.GDSCRIPTINSTANCE,
                    GDSOf.GDSCRIPTNAME,
                    GDSOf.FUNC_MAP,
                    GDSOf.CONST_MAP,
                    GDSOf.VAR_NAMEINDEX_MAP,
                    GDSOf.VAR_VECTOR,
                    GDSOf.VAR_NAMEINDEX_VARTYPE,
                    GDSOf.SIZE_VECTOR,
                    GDSOf.VAR_NAMEINDEX_I,
                    GDSOf.FUNC_CODE,
                    GDSOf.FUNC_CONST,
                    GDSOf.FUNC_GLOBNAMEPTR
                      = getStoredOffsetsFromVersion( GDSOf.VERSION_STRING )

                    if GDSOf.MAJOR_VER == 4 then
                        GDSOf.GDSCRIPT_REF = 0x18
                        GDSOf.MAXTYPE = 39
                        GDSOf.FUNC_MAPVAL = 0x18
                        GDSOf.STRING = GDSOf.STRING or 0x10
                        GDSOf.CHILDREN_SIZE = 0x8
                        GDSOf.MAP_SIZE = 0x14
                        GDSOf.ARRAY_TOVECTOR = 0x10
                        GDSOf.P_ARRAY_TOARR = 0x18
                        GDSOf.P_ARRAY_SIZE = 0x8
                        GDSOf.DICT_HEAD = GDSOf.DICT_HEAD or 0x28
                        GDSOf.DICT_TAIL = GDSOf.DICT_TAIL or 0x30
                        GDSOf.DICT_SIZE = GDSOf.DICT_TAIL or 0x3C
                        GDSOf.DICTELEM_KEYTYPE = 0x10
                        GDSOf.DICTELEM_KEYVAL = 0x18
                        GDSOf.DICTELEM_VALTYPE = 0x28
                        GDSOf.CONSTELEM_KEYVAL = 0x10
                        GDSOf.CONSTELEM_VALTYPE = 0x18
                        GDSOf.VAR_NAMEINDEX_I = 0x18
                    else
                        GDSOf.MAXTYPE = 27
                        GDSOf.GDSCRIPT_REF = GDSOf.GDSCRIPT_REF or 0x10
                        GDSOf.FUNC_MAPVAL = GDSOf.FUNC_MAPVAL or 0x38
                        GDSOf.STRING = GDSOf.STRING or 0x10
                        GDSOf.CHILDREN_SIZE = 0x4
                        GDSOf.MAP_SIZE = GDSOf.MAP_SIZE or 0x10
                        GDSOf.MAP_LELEM = GDSOf.MAP_LELEM or 0x10
                        GDSOf.MAP_NEXTELEM = GDSOf.MAP_NEXTELEM or 0x20
                        GDSOf.MAP_KVALUE = GDSOf.MAP_KVALUE or 0x30
                        GDSOf.DICT_LIST = GDSOf.DICT_LIST or 0x8
                        GDSOf.DICT_HEAD = GDSOf.DICT_HEAD or 0x0
                        GDSOf.DICT_TAIL = GDSOf.DICT_TAIL or 0x8
                        GDSOf.DICT_SIZE = GDSOf.DICT_SIZE or 0x1C -- GDSOf.DICT_SIZE = GDSOf.DICT_SIZE or 0x10
                        GDSOf.DICTELEM_PAIR_NEXT = GDSOf.DICTELEM_PAIR_NEXT or 0x20
                        GDSOf.DICTELEM_KEYTYPE = GDSOf.DICTELEM_KEYTYPE or 0x0
                        GDSOf.DICTELEM_KEYVAL = GDSOf.DICTELEM_KEYVAL or 0x8
                        GDSOf.DICTELEM_VALTYPE = GDSOf.DICTELEM_VALTYPE or 0x8
                        GDSOf.DICTELEM_VALVAL = GDSOf.DICTELEM_VALVAL or 0x10
                        GDSOf.ARRAY_TOVECTOR = GDSOf.ARRAY_TOVECTOR or 0x10
                        GDSOf.P_ARRAY_TOARR = GDSOf.P_ARRAY_TOARR or 0x8
                        GDSOf.P_ARRAY_SIZE = GDSOf.P_ARRAY_SIZE or 0x18
                        GDSOf.CONSTELEM_KEYVAL = GDSOf.CONSTELEM_KEYVAL or 0x30
                        GDSOf.CONSTELEM_VALTYPE = GDSOf.CONSTELEM_VALTYPE or 0x38
                    end

                    gdOffsetsDefined = true
                    checkGDStringType()
                    defineGDFunctionEnums()
                    fuckoffPrint()
                    return
                end

                local majorVersion = GDSOf.MAJOR_VER or config.majorVersion or 0

                if majorVersion == 4 then

                    GDSOf.MAJOR_VER = majorVersion

                    GDSOf.CHILDREN = config.offsetNodeChildren or 0x0
                    GDSOf.OBJ_STRING_NAME = config.offsetNodeStringName or 0x0
                    GDSOf.GDSCRIPTINSTANCE = config.offsetGDScriptInstance or 0x0
                    GDSOf.GDSCRIPTNAME = config.offsetGDScriptName or 0x0
                    GDSOf.FUNC_MAP = config.offsetFuncMap or 0x0
                    GDSOf.CONST_MAP = config.offsetConstMap or 0x0
                    GDSOf.VAR_NAMEINDEX_MAP = config.offsetVariantMap or 0x0

                    GDSOf.VAR_VECTOR = config.offsetVariantVector or 0x28
                    GDSOf.VAR_NAMEINDEX_VARTYPE = config.offsetVariantMapVarType or 0x48
                    GDSOf.SIZE_VECTOR = config.offsetVariantVectorSize or 0x8

                    GDSOf.GDSCRIPT_REF = 0x18
                    GDSOf.MAXTYPE = 39
                    --GDSOf.SCRIPTFUNC_STRING = GDFunctionString or 0x60
                    GDSOf.FUNC_MAPVAL = 0x18
                    GDSOf.FUNC_CODE = config.offsetGDFunctionCode or 0x0
                    GDSOf.FUNC_CONST = config.offsetGDFunctionConst or (GDSOf.FUNC_CODE+0x20)
                    GDSOf.FUNC_GLOBNAMEPTR = config.offsetGDFunctionGlobals or (GDSOf.FUNC_CONST+0x10) -- there's a Vector of globalnames 0x10 after FUNC_CONST, i.e. 0x1A8, alternatively _globalnames_ptr at 0x2E0 which is the actual referenced array by the VM?

                    GDSOf.STRING = GDSOf.STRING or 0x10
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

                else
                    GDSOf.MAJOR_VER = 3

                    GDSOf.CHILDREN = config.offsetNodeChildren or 0x0
                    GDSOf.OBJ_STRING_NAME = config.offsetNodeStringName or 0x0
                    GDSOf.GDSCRIPTINSTANCE = config.offsetGDScriptInstance or 0x0
                    GDSOf.GDSCRIPTNAME = config.offsetGDScriptName or 0x0
                    GDSOf.FUNC_MAP = config.offsetFuncMap or 0x0
                    GDSOf.CONST_MAP = config.offsetConstMap or 0x0
                    GDSOf.VAR_NAMEINDEX_MAP = config.offsetVariantMap or 0x0

                    GDSOf.VAR_VECTOR = config.offsetVariantVector or 0x20
                    GDSOf.SIZE_VECTOR = config.offsetVariantVectorSize or 0x4

                    GDSOf.VAR_NAMEINDEX_I = config.offsetVariantMapIndex or 0x38

                    GDSOf.MAXTYPE = 27
                    --GDSOf.SCRIPTFUNC_STRING = oGDFunctionString or 0x80

                    GDSOf.GDSCRIPT_REF = 0x10

                    GDSOf.FUNC_MAPVAL = 0x38
                    GDSOf.FUNC_CODE = config.offsetGDFunctionCode or 0x0
                    GDSOf.FUNC_GLOBNAMEPTR = config.offsetGDFunctionGlobals or (GDSOf.FUNC_CODE-0x20)
                    GDSOf.FUNC_CONST = config.offsetGDFunctionConst or (GDSOf.FUNC_GLOBNAMEPTR-0x10)
                    GDSOf.STRING = GDSOf.STRING or 0x10
                    GDSOf.CHILDREN_SIZE = 0x4

                    GDSOf.MAP_SIZE = 0x10
                    GDSOf.MAP_LELEM = 0x10
                    GDSOf.MAP_NEXTELEM = 0x20
                    GDSOf.MAP_KVALUE = 0x30

                    GDSOf.DICT_LIST = 0x8
                    GDSOf.DICT_HEAD = 0x0
                    GDSOf.DICT_TAIL = 0x8
                    GDSOf.DICT_SIZE = 0x1C -- GDSOf.DICT_SIZE = 0x10
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

                end

                gdOffsetsDefined = true
                checkGDStringType()
                defineGDFunctionEnums()
                fuckoffPrint()
            end

        --///---///--///---///--///---///--///--///---///--///---///--///---///--/// Viewport

            --- returns a valid Viewport pointer
            --- @return number
            function getViewport()

                local viewport = readPointer("ptVP")
                if isNullOrNil(viewport) then print("Viewport pointer is invalid; something's wrong"); error('viewport pointer is invalid, couldn\'t read') end
                return viewport
            end

            --- returns a childrenArrayPtr and its size
            ---@return number
            function getVPChildren()
                local viewport = getViewport()

                debugStepIn()

                local childrenPtr = readPointer( viewport + GDSOf.CHILDREN ) -- viewport has an array of all main ingame Nodes, those Nodes can contain further nodes
                if isNullOrNil(childrenPtr) then
                    sendDebugMessageAndStepOut('getVPChildren: failed to get VP children')
                    return;
                end

                local childrenSize;
                if GDSOf.MAJOR_VER == 4 then
                    childrenSize = readInteger( viewport + GDSOf.CHILDREN - GDSOf.CHILDREN_SIZE ) -- size is 8 bytes behind
                elseif GDSOf.MAJOR_VER > 4 then
                    childrenSize = readInteger( childrenPtr - GDSOf.CHILDREN_SIZE ) -- versions before ~4.2 have size inside the array 4 bytes behind
                else
                    childrenSize = readInteger( childrenPtr - GDSOf.CHILDREN_SIZE )
                end

                if isNullOrNil(childrenSize) then
                    sendDebugMessageAndStepOut('getVPChildren: ChildSize is invalid')
                    return;
                end

                debugStepOut();
                return childrenPtr, childrenSize
            end

        --///---///--///---///--///---///--///--///---///--///---///--///---///--/// VISITORS
            
            local NodeVisitor = {}

            function NodeVisitor.recurseDictionary(dictPtr)
                iterateDictionaryForNodes(dictPtr)
            end

            function NodeVisitor.recurseArray(arrPtr)
                iterateArrayForNodes(arrPtr)
            end

            function NodeVisitor.visitObject(objPtr)
                local realPtr, bShifted = checkForVT( objPtr )
                local nodePtr = readPointer(realPtr)
                if checkForGDScript( nodePtr ) then iterateMNode( nodePtr ) end
            end

        --///---///--///---///--///---///--///--///---///--///---///--///---///--/// EMITTERS

            -- leaves just add entries
            -- layouts are basically leaves with colors (where it makes sense)
            -- branches are developing tree structures/recursion
            
            GDEmitters ={}
            ---------------------------------------------------------------------------------
            GDEmitters.StructEmitter = {}

                local function rootOffset(entry, emitter)
                    if emitter == GDEmitters.StructEmitter then
                        return entry.offsetToValue
                    end
                    return 0x0
                end

                local function fieldOffset(entry, emitter, rel)
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
                    iterateDictionaryToStruct(dictPtr, parent)
                end

                function GDEmitters.StructEmitter.recurseArray(contextTable, parent, arrPtr)
                    iterateArrayToStruct(arrPtr, parent)
                end

                function GDEmitters.StructEmitter.recurseNode(contextTable, parent, nodePtr)
                    -- DISABLED
                end

                function GDEmitters.StructEmitter.recursePackedArray(contextTable, parent, arrayAddr, typeName)
                    iteratePackedArrayToStruct(arrayAddr, typeName, parent)
                end
            ---------------------------------------------------------------------------------
            GDEmitters.AddrEmitter = {}

                local function makeAddr(base, offset)
                    return (base or 0) + (offset or 0)
                end

                function GDEmitters.AddrEmitter.leaf(contextTable, parent, label, offset, ceType)
                    local created
                    synchronize(function(label, addr, ceType, parent)
                                    created = addMemRecTo(label, addr, ceType, parent)
                                end, label, makeAddr(contextTable.baseAddress, offset), ceType, parent
                            )
                    return created
                end

                function GDEmitters.AddrEmitter.layout(contextTable, parent, label, color, offset, ceType)
                    local created
                    synchronize(function(label, addr, ceType, parent)
                                    created = addMemRecTo(label, addr, ceType, parent)
                                end, label, makeAddr(contextTable.baseAddress, offset), ceType, parent
                            )
                    return created
                end

                function GDEmitters.AddrEmitter.branch(contextTable, parent, label, offset, ceType, childStructName)
                    local created
                    synchronize(function(label, addr, ceType, parent)
                                    created = addMemRecTo(label, addr, ceType, parent)
                                    created.Options = '[moHideChildren, moAllowManualCollapseAndExpand, moManualExpandCollapse]'
                                end, label, makeAddr(contextTable.baseAddress, offset), ceType, parent
                            )
                    return created
                end

                function GDEmitters.AddrEmitter.recurseDictionary(contextTable, parent, dictPtr)
                    iterateDictionaryToAddr(dictPtr, parent)
                end

                function GDEmitters.AddrEmitter.recurseArray(contextTable, parent, arrPtr)
                    iterateArrayToAddr(arrPtr, parent)
                end

                function GDEmitters.AddrEmitter.recurseNode(contextTable, parent, nodePtr)
                    iterateMNodeToAddr(nodePtr, parent)
                end

                function GDEmitters.AddrEmitter.recursePackedArray(contextTable, parent, arrayAddr, typeName)
                    iteratePackedArrayToAddr(arrayAddr, typeName, parent)
                end

            ---------------------------------------------------------------------------------

            local function emitStringNameStruct(parent, label, offset, stringFieldLabel, bUniShift)
                local outer = addStructureElem(parent, label, offset, vtPointer)
                outer.ChildStruct = createStructure("StringName")

                local innerOffset = bUniShift and GDSOf.STRING or (GDSOf.STRING - GDSOf.PTRSIZE)
                local inner = addStructureElem(outer, label, innerOffset, vtPointer)
                inner.ChildStruct = createStructure("stringy")
                local stringElem = addStructureElem(outer.ChildStruct and inner or inner, label .. " string", 0x0, bUniShift and vtUnicodeString or vtString)

                if not bUniShift then
                    stringElem.Bytesize = 100
                end

                return outer, inner, stringElem
            end

            local function emitFunctionCodeStruct(funcParent, funcName)
                return addStructureElem(funcParent, 'Code: ' .. funcName, GDSOf.FUNC_CODE, vtPointer)
            end

            local function emitFunctionConstantsStruct(funcParent, funcName, funcValueAddr)

                local constantsElem = createChildStructElem( funcParent, "Constants: " .. funcName, GDSOf.FUNC_CONST, vtPointer, "GDFConst")
                local funcConstAddr = readPointer(funcValueAddr + GDSOf.FUNC_CONST)
                iterateFuncConstantsToStruct(funcConstAddr, constantsElem)
                return constantsElem
            end

            local function emitFunctionGlobalsStruct(funcParent, funcName, funcValueAddr)

                local globalsElem = createChildStructElem( funcParent, "Globals: "..funcName, GDSOf.FUNC_GLOBNAMEPTR, vtPointer, "GDFGlobals" )
                local funcGlobalAddr = readPointer(funcValueAddr + GDSOf.FUNC_GLOBNAMEPTR)
                iterateFuncGlobalsToStruct(funcGlobalAddr, globalsElem)
                return globalsElem
            end

            local function emitFunctionStructEntry(funcStructElement, mapElement, funcName)
                local funcRoot
                if not bDISASSEMBLEFUNCTIONS then
                    funcRoot = createChildStructElem( funcStructElement, "func: " .. funcName, GDSOf.FUNC_MAPVAL, vtPointer, "GDFunction" )
                    local funcValueAddr = readPointer(mapElement + GDSOf.FUNC_MAPVAL)
                    emitFunctionCodeStruct(funcRoot, funcName)
                    emitFunctionConstantsStruct(funcRoot, funcName, funcValueAddr)
                    emitFunctionGlobalsStruct(funcRoot, funcName, funcValueAddr)
                else
                    funcRoot = addStructureElem( funcStructElement, "func: " .. funcName, GDSOf.FUNC_MAPVAL, vtPointer )
                end
                
                return funcRoot
            end

            local function advanceFunctionMapElement(mapElement)
                if GDSOf.MAJOR_VER == 4 then
                    return readPointer(mapElement)
                end
                return readPointer(mapElement + GDSOf.MAP_NEXTELEM)
            end

            local function createNextFunctionContainer(currentContainer, index)
                if GDSOf.MAJOR_VER == 4 then
                    local nextElem = addStructureElem(currentContainer, "Next[" .. index .. "]", 0x0, vtPointer)
                    nextElem.ChildStruct = createStructure("FuncNext")
                    return nextElem
                end

                local nextElem = addStructureElem(currentContainer, "Next", GDSOf.MAP_NEXTELEM, vtPointer)
                nextElem.ChildStruct = createStructure('FuncNext')
                return nextElem
            end

            ---------------------------------------------------------------------------------


            GDEmitters.PackedStructEmitter = {}

                function GDEmitters.PackedStructEmitter.emitPackedString(parent, elemIndex, offsetToValue, arrElement)
                    local stringPtrElement = addStructureElem(parent, ('strElem[%d]'):format(elemIndex), offsetToValue, vtPointer)
                    stringPtrElement.ChildStruct = createStructure('StringItem')
                    addStructureElem(stringPtrElement, 'String', 0x0, vtUnicodeString)
                end

                function GDEmitters.PackedStructEmitter.emitPackedScalar(parent, prefixStr, elemIndex, offsetToValue, arrElement, ceType)
                    addStructureElem(parent, prefixStr .. elemIndex .. ']', offsetToValue, ceType)
                end

                function GDEmitters.PackedStructEmitter.emitPackedVec2(parent, prefixStr, elemIndex, offsetToValue, arrElement)
                    addStructureElem(parent, prefixStr .. elemIndex .. ']: x', offsetToValue, vtSingle)
                    addStructureElem(parent, prefixStr .. elemIndex .. ']: y', offsetToValue + 0x4, vtSingle)
                end

                function GDEmitters.PackedStructEmitter.emitPackedVec3(parent, prefixStr, elemIndex, offsetToValue, arrElement)
                    addStructureElem(parent, prefixStr .. elemIndex .. ']: x', offsetToValue, vtSingle)
                    addStructureElem(parent, prefixStr .. elemIndex .. ']: y', offsetToValue + 0x4, vtSingle)
                    addStructureElem(parent, prefixStr .. elemIndex .. ']: z', offsetToValue + 0x8, vtSingle)
                end

                function GDEmitters.PackedStructEmitter.emitPackedColor(parent, prefixStr, elemIndex, offsetToValue, arrElement)
                    addStructureElem(parent, prefixStr .. elemIndex .. ']: R', offsetToValue, vtSingle)
                    addStructureElem(parent, prefixStr .. elemIndex .. ']: G', offsetToValue + 0x4, vtSingle)
                    addStructureElem(parent, prefixStr .. elemIndex .. ']: B', offsetToValue + 0x8, vtSingle)
                    addStructureElem(parent, prefixStr .. elemIndex .. ']: A', offsetToValue + 0xC, vtSingle)
                end

            GDEmitters.PackedAddrEmitter = {}

                function GDEmitters.PackedAddrEmitter.emitPackedString(parent, elemIndex, offsetToValue, arrElement)
                    synchronize(function(elemIndex, arrElement, parent)
                        addMemRecTo('pck_arr[' .. elemIndex .. ']', arrElement, vtString, parent)
                    end, elemIndex, arrElement, parent)
                end

                function GDEmitters.PackedAddrEmitter.emitPackedScalar(parent, prefixStr, elemIndex, offsetToValue, arrElement, ceType)
                    synchronize(function(prefixStr, elemIndex, arrElement, ceType, parent)
                        addMemRecTo(prefixStr .. elemIndex .. ']', arrElement, ceType, parent)
                    end, prefixStr, elemIndex, arrElement, ceType, parent)
                end

                function GDEmitters.PackedAddrEmitter.emitPackedVec2(parent, prefixStr, elemIndex, offsetToValue, arrElement)
                    synchronize(function(prefixStr, elemIndex, arrElement, parent)
                        addMemRecTo(prefixStr .. elemIndex .. ']: x', arrElement, vtSingle, parent)
                        addMemRecTo(prefixStr .. elemIndex .. ']: y', arrElement + 0x4, vtSingle, parent)
                    end, prefixStr, elemIndex, arrElement, parent)
                end

                function GDEmitters.PackedAddrEmitter.emitPackedVec3(parent, prefixStr, elemIndex, offsetToValue, arrElement)
                    synchronize(function(prefixStr, elemIndex, arrElement, parent)
                        addMemRecTo(prefixStr .. elemIndex .. ']: x', arrElement, vtSingle, parent)
                        addMemRecTo(prefixStr .. elemIndex .. ']: y', arrElement + 0x4, vtSingle, parent)
                        addMemRecTo(prefixStr .. elemIndex .. ']: z', arrElement + 0x8, vtSingle, parent)
                    end, prefixStr, elemIndex, arrElement, parent)
                end

                function GDEmitters.PackedAddrEmitter.emitPackedColor(parent, prefixStr, elemIndex, offsetToValue, arrElement)
                    synchronize(function(prefixStr, elemIndex, arrElement, parent)
                        addMemRecTo(prefixStr .. elemIndex .. ']: R', arrElement, vtSingle, parent)
                        addMemRecTo(prefixStr .. elemIndex .. ']: G', arrElement + 0x4, vtSingle, parent)
                        addMemRecTo(prefixStr .. elemIndex .. ']: B', arrElement + 0x8, vtSingle, parent)
                        addMemRecTo(prefixStr .. elemIndex .. ']: A', arrElement + 0xC, vtSingle, parent)
                    end, prefixStr, elemIndex, arrElement, parent)
                end


        --///---///--///---///--///---///--///--///---///--///---///--///---///--/// HELPERS / SHARED HELPERS

            -- TODO: make magic dereferences more obvious

            local function getNextMapElement(mapElement)
                if GDSOf.MAJOR_VER == 4 then
                    return readPointer(mapElement)
                else
                    return readPointer(mapElement + GDSOf.MAP_NEXTELEM)
                end
            end

            local function getDictElemPairNext(mapElement)
                if GDSOf.MAJOR_VER == 4 then
                    return readPointer(mapElement)
                else
                    return readPointer(mapElement + GDSOf.DICTELEM_PAIR_NEXT)
                end
            end

            local function getDictionarySizeFromVariantPtr(variantPtr)
                -- if GDSOf.MAJOR_VER == 4 then
                --     return readInteger(readPointer(variantPtr) + GDSOf.DICT_SIZE)
                -- else
                --     return readInteger(readPointer(readPointer(variantPtr) + GDSOf.DICT_LIST) + GDSOf.DICT_SIZE)
                -- end
                return readInteger(readPointer(variantPtr) + GDSOf.DICT_SIZE)
            end

            local function isArrayEmptyFromVariantPtr(variantPtr)
                return readPointer(readPointer(variantPtr) + GDSOf.ARRAY_TOVECTOR) == 0
            end

            local function resolveScriptVariantType(mapElement, runtimeVariantType)
                
                -- debugStepIn()

                if GDSOf.MAJOR_VER < 4 then
                    -- debugStepOut()
                    return runtimeVariantType
                end

                local scriptType = readInteger(mapElement + GDSOf.VAR_NAMEINDEX_VARTYPE)
                
                -- 4.2.2 may differ TODO: make it version dependent
                if scriptType > GDSOf.MAXTYPE then
                    scriptType = readInteger(mapElement + GDSOf.VAR_NAMEINDEX_VARTYPE - 0x8)
                end

                if scriptType == runtimeVariantType then
                    -- debugStepOut()
                    return scriptType
                elseif (scriptType > runtimeVariantType) and (scriptType > 0 and scriptType <= GDSOf.MAXTYPE) then
                    -- sendDebugMessageAndStepOut('resolveScriptVariantType: fallback1, cached type is used') -- if the source is incorrect
                    return scriptType
                else
                    -- sendDebugMessageAndStepOut('resolveScriptVariantType: fallback2, cached type is used') -- let's have cached if everything is wrong
                    return runtimeVariantType
                end
            end

            local function getVariantNameFromMapElement(mapElement)
                if GDSOf.MAJOR_VER == 4 then
                    return getStringNameStr(readPointer(mapElement + GDSOf.CONSTELEM_KEYVAL))
                else
                    return getStringNameStr(readPointer(mapElement + GDSOf.MAP_KVALUE))
                end
            end

            local function prepareObjectParent(entry, emitter, parent, contextTable)
                debugStepIn()

                local shifted
                local ptr = entry.variantPtr
                local offset = rootOffset(entry, emitter)
                local currentParent = parent
                local currentContext = contextTable

                ptr, shifted = checkForVT(ptr)

                if shifted then
                    offset = offset - GDSOf.PTRSIZE
                    currentContext = { nodeAddr = contextTable.nodeAddr, nodeName = contextTable.nodeName, baseAddress = ptr }
                    currentParent = emitter.branch(currentContext, parent, "Wrapper: " .. entry.name, offset, vtPointer, "Wrapper")
                    offset = 0x0
                end

                sendDebugMessageAndStepOut("prepareObjectParent: "..("%x"):format(ptr or -1).." Object: "..entry.name)
                return currentParent, ptr, offset, currentContext
            end

            local function getFunctionMapName(mapElement)
                if isNullOrNil(mapElement) then return nil end

                if GDSOf.MAJOR_VER == 4 then
                    return getGDFunctionName(mapElement)
                end
                return getStringNameStr(readPointer(mapElement + GDSOf.MAP_KVALUE))
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
                if GDSOf.MAJOR_VER == 4 then
                    local constType = readInteger(mapElement + GDSOf.CONSTELEM_VALTYPE)
                    local offsetToValue = getVariantValueOffset(constType)
                    return
                        getAddress(mapElement + GDSOf.CONSTELEM_VALTYPE + offsetToValue), getCETypeFromGD(constType)
                else
                    local constType = readInteger(mapElement + GDSOf.CONSTELEM_VALTYPE)
                    return
                        getAddress(mapElement + GDSOf.CONSTELEM_VALVAL), getCETypeFromGD(constType)
                end
            end

            local function getFunctionMapLookupResult(mapElement)
                return readPointer(mapElement + GDSOf.FUNC_MAPVAL)
            end

            local function createNextConstContainer(currentContainer, index)
                if GDSOf.MAJOR_VER == 4 then
                    local nextElem = addStructureElem(currentContainer, 'Next[' .. index .. ']', 0x0, vtPointer)
                    nextElem.ChildStruct = createStructure('ConstNext')
                    return nextElem
                end

                local nextElem = addStructureElem(currentContainer, 'Next', GDSOf.MAP_NEXTELEM, vtPointer)
                nextElem.ChildStruct = createStructure('ConstNext')
                return nextElem
            end

            local function formatArrayEntry(entry)
                local cloned = {}
                for k, v in pairs(entry) do cloned[k] = v end
                cloned.name = "array[" .. tostring(entry.index) .. "]"
                return cloned
            end

            local function getArrayVectorInfo(arrayAddr)
                debugStepIn()

                if not isValidPointer(arrayAddr) then
                    sendDebugMessageAndStepOut('getArrayVectorInfo: arrayAddr invalid')
                    return nil
                end

                local arrVectorAddr = readPointer(arrayAddr + GDSOf.ARRAY_TOVECTOR)
                if isNullOrNil(arrVectorAddr) then
                    sendDebugMessageAndStepOut('getArrayVectorInfo: arrVectorAddr uninitialized')
                    return nil
                end

                local arrVectorSize = readInteger(arrVectorAddr - GDSOf.SIZE_VECTOR)
                if isNullOrNil(arrVectorSize) then
                    sendDebugMessageAndStepOut('getArrayVectorInfo: vector size is invalid')
                    return nil
                end

                local variantArrSize, ok = redefineVariantSizeByVector(arrVectorAddr, arrVectorSize)
                if not ok then
                    debugStepOut()
                    return nil
                end
                debugStepOut()
                return arrVectorAddr, arrVectorSize, variantArrSize
            end

            local function formatDictionaryEntry(entry)
                local cloned = {}
                for k, v in pairs(entry) do cloned[k] = v end
                cloned.name = "[ " .. tostring(entry.name) .. " ]"
                return cloned
            end

            local function decodeDictionaryKeyName(mapElement)
                local keyType, keyValueAddr

                if GDSOf.MAJOR_VER == 3 then
                    local keyPtr = readPointer(mapElement) -- key is a ptr
                    keyType = readInteger(keyPtr + GDSOf.DICTELEM_KEYTYPE)
                    keyValueAddr = getAddress(keyPtr + GDSOf.DICTELEM_KEYVAL)
                else
                    keyType = readInteger(mapElement + GDSOf.DICTELEM_KEYTYPE)  -- those can be a key , NodePath, Callable, StringName, etc
                    keyValueAddr = getAddress(mapElement + GDSOf.DICTELEM_KEYVAL)
                end

                local keyTypeName = getGDTypeName(keyType)
                local keyName = "UNKNOWN"

                if keyTypeName == 'STRING' then
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
                debugStepIn()

                if not isValidPointer(dictAddr) then
                    sendDebugMessageAndStepOut('getDictionaryInfo: dictAddr isnt pointer')
                    return nil
                end 

                local dictRoot = dictAddr
                if GDSOf.MAJOR_VER == 3 then
                    dictRoot = readPointer(dictAddr + GDSOf.DICT_LIST)
                    if isNullOrNil(dictRoot) then
                        sendDebugMessageAndStepOut('getDictionaryInfo: dictRoot isnt valid')
                        return nil
                    end
                end

                -- local dictSize = readInteger(dictRoot + GDSOf.DICT_SIZE)
                local dictSize = readInteger(dictAddr + GDSOf.DICT_SIZE)
                if isNullOrNil(dictSize) then
                    sendDebugMessageAndStepOut('getDictionaryInfo: dictSize isnt valid')
                    return nil
                end

                local dictHead = readPointer(dictRoot + GDSOf.DICT_HEAD)
                if isNullOrNil(dictHead) then
                    sendDebugMessageAndStepOut('getDictionaryInfo: dictHead isnt valid')
                    return nil
                end

                local dictTail = readPointer(dictRoot + GDSOf.DICT_TAIL)

                debugStepOut()
                return dictRoot, dictSize, dictHead, dictTail
            end

            local function createNextDictContainer(currentContainer, index)
                if GDSOf.MAJOR_VER == 4 then
                    return createChildStructElem(currentContainer, 'Next', 0x0, vtPointer, 'DictNext')
                end

                return createChildStructElem(currentContainer, 'Next', GDSOf.DICTELEM_PAIR_NEXT, vtPointer, 'DictNext')
            end

            local function getPackedArrayInfo(packedArrayAddr)
                debugStepIn()

                if not isValidPointer(packedArrayAddr) then
                    sendDebugMessageAndStepOut('getPackedArrayInfo: packedArrayAddr isnt pointer')
                    return nil
                end

                local packedDataArrAddr = readPointer(packedArrayAddr + GDSOf.P_ARRAY_TOARR)
                if isNullOrNil(packedDataArrAddr) then
                    sendDebugMessageAndStepOut('getPackedArrayInfo: packedDataArrAddr isnt pointer')
                    return nil
                end

                local packedVectorSize
                if GDSOf.MAJOR_VER == 4 then
                    packedVectorSize = readInteger(packedDataArrAddr - GDSOf.SIZE_VECTOR)
                    if isNullOrNil(packedVectorSize) or packedVectorSize > 150 then packedVectorSize = 150 end
                else
                    packedVectorSize = 150 -- no size to rely :(
                end
                if isNullOrNil(packedVectorSize) then
                    sendDebugMessageAndStepOut('getPackedArrayInfo: packedVectorSize isnt valid')
                    return nil
                end

                debugStepOut()
                return packedDataArrAddr, packedVectorSize
            end

            local function iteratePackedArrayCore(packedDataArrAddr, packedVectorSize, packedTypeName, parent, emitter)

                debugStepIn()
                sendDebugMessageAndStepOut("Packed Array: "..packedTypeName..(" address %x"):format(packedDataArrAddr or -1))
                local handler = GDHandlers.PackedArrayHandlers[packedTypeName] or GDHandlers.PackedArrayHandlers.DEFAULT
                handler(packedDataArrAddr, packedVectorSize, parent, emitter)
            end

        --///---///--///---///--///---///--///--///---///--///---///--///---///--/// READERS

            local function readNodeVariantEntry(mapElement, variantVector, variantSize, bNeedStructOffset)
                -- the vector is stored inside a GDScirptInstance and memberIndices inside the GDScript (as a BP)
                local variantIndex = readInteger(mapElement + GDSOf.VAR_NAMEINDEX_I);
                local variantPtr, runtimeType, offsetToValue = getVariantByIndex(variantVector, variantIndex, variantSize, bNeedStructOffset);
                
                local name = getVariantNameFromMapElement(mapElement);
                local finalType = resolveScriptVariantType(mapElement, runtimeType);

                local entry = {
                        index = variantIndex,
                        name = name or "UNKNOWN",
                        runtimeType = runtimeType,
                        typeId = finalType,
                        typeName = getGDTypeName(finalType) or "UNKNOWNTYPE",
                        variantPtr = variantPtr,
                        offsetToValue = offsetToValue or 0,
                        ceType = getCETypeFromGD(finalType)
                        }

                debugStepIn()
                sendDebugMessageAndStepOut("readNodeVariantEntry:\tname:\t"..entry.name.."\tIndex: "..entry.index.." type: "..entry.typeName.."\tPtr: "..('%x'):format(entry.variantPtr or -1).."\t Offset: "..("%x"):format(entry.offsetToValue or -1))

                return entry
            end

            local function readFunctionConstantEntry(funcConstantVect, variantIndex, variantSize)
                local variantPtr, runtimeType, offsetToValue = getVariantByIndex(funcConstantVect, variantIndex, variantSize, true)

                local finalType = runtimeType
                local typeName = getGDTypeName(finalType) or "UNKNOWNTYPE"

                local entry = {
                        index = variantIndex,
                        name = "Const[" .. tostring(variantIndex) .. "]",
                        runtimeType = runtimeType,
                        typeId = finalType,
                        typeName = typeName,
                        variantPtr = variantPtr,
                        offsetToValue = offsetToValue,
                        ceType = getCETypeFromGD(finalType)
                        }

                debugStepIn()
                sendDebugMessageAndStepOut("readFunctionConstantEntry: name:\t"..entry.name.."\tIndex: "..entry.index.."\ttype: "..entry.typeName.."\tPtr: "..('%x'):format(entry.variantPtr or -1).."\t Offset: "..("%x"):format(entry.offsetToValue or -1))

                return entry
            end

            local function readNodeConstEntry(mapElement)
                local constName = getNodeConstName(mapElement)
                local constType = readInteger(mapElement + GDSOf.CONSTELEM_VALTYPE)
                local offsetToValue = GDSOf.CONSTELEM_VALTYPE + getVariantValueOffset(constType)
                local constPtr = getAddress(mapElement + offsetToValue)

                local entry = {
                        index = 0,
                        name = constName or "UNKNOWN_CONST",
                        runtimeType = constType,
                        typeId = constType,
                        typeName = getGDTypeName(constType) or "UNKNOWNTYPE",
                        variantPtr = constPtr,
                        offsetToValue = offsetToValue,
                        ceType = getCETypeFromGD(constType)
                        }

                debugStepIn()
                sendDebugMessageAndStepOut("readNodeConstEntry:\tname:\t"..entry.name.."\tIndex: "..entry.index.."\ttype: "..entry.typeName.."\tPtr: "..('%x'):format(entry.variantPtr or -1).."\t Offset: "..("%x"):format(entry.offsetToValue or -1))

                return entry
            end

            -- for node search
            local function readVectorVariantEntry(variantVector, variantIndex, variantSize)
                local variantPtr, variantType = getVariantByIndex(variantVector, variantIndex, variantSize)

                return {
                    index = variantIndex,
                    typeId = variantType,
                    typeName = getGDTypeName(variantType) or "UNKNOWNTYPE",
                    variantPtr = variantPtr
                }
            end

            -- for node search
            local function readArrayValueEntry(arrVectorAddr, varIndex, variantArrSize)
                local variantPtr, variantType = getVariantByIndex(arrVectorAddr, varIndex, variantArrSize)

                return {
                    index = varIndex,
                    typeId = variantType,
                    typeName = getGDTypeName(variantType) or "UNKNOWNTYPE",
                    variantPtr = variantPtr
                }
            end

            local function readArrayContainerEntry(arrVectorAddr, varIndex, variantArrSize, bNeedStructOffset)
                local variantPtr, runtimeType, offsetToValue = getVariantByIndex(arrVectorAddr, varIndex, variantArrSize, bNeedStructOffset)

                local entry = {
                        index = varIndex,
                        name = "array[" .. tostring(varIndex) .. "]",
                        runtimeType = runtimeType,
                        typeId = runtimeType,
                        typeName = getGDTypeName(runtimeType) or "UNKNOWNTYPE",
                        variantPtr = variantPtr,
                        offsetToValue = offsetToValue,
                        ceType = getCETypeFromGD(runtimeType)
                        }

                debugStepIn()
                sendDebugMessageAndStepOut("readArrayContainerEntry:\tname:\t"..entry.name.."\tIndex: "..entry.index.."\ttype: "..entry.typeName.."\tPtr: "..('%x'):format(entry.variantPtr or -1).."\t Offset: "..("%x"):format(entry.offsetToValue or -1))

                return entry

            end

            local function readDictionaryContainerEntry(mapElement)

                local keyType, keyValueAddr, keyName = decodeDictionaryKeyName(mapElement)
                local valueType = readInteger(mapElement + GDSOf.DICTELEM_VALTYPE)
                local offsetToValue = GDSOf.DICTELEM_VALTYPE + getVariantValueOffset(valueType)
                local valueValuePtr = getAddress(mapElement + offsetToValue)

                local entry = {
                        index = 0,
                        name = keyName or ("key@" .. ("%x"):format(mapElement)),
                        runtimeType = valueType,
                        typeId = valueType,
                        typeName = getGDTypeName(valueType) or "UNKNOWNTYPE",
                        variantPtr = valueValuePtr,
                        offsetToValue = offsetToValue,
                        ceType = getCETypeFromGD(valueType),
                        keyType = keyType,
                        keyValueAddr = keyValueAddr
                        }

                debugStepIn()
                sendDebugMessageAndStepOut("readDictionaryContainerEntry:\tname:\t"..entry.name.."\tIndex: "..entry.index.."\ttype: "..entry.typeName.."\tPtr: "..('%x'):format(entry.variantPtr or -1).."\t Offset: "..("%x"):format(entry.offsetToValue or -1))

                return entry
            end

            -- for node search
            local function readDictionaryValueEntry(mapElement)
                local valueType = readInteger(mapElement + GDSOf.DICTELEM_VALTYPE)
                local offsetToValue = GDSOf.DICTELEM_VALTYPE + getVariantValueOffset(valueType)
                return {
                    typeId = valueType,
                    typeName = getGDTypeName(valueType) or "UNKNOWNTYPE",
                    variantPtr = getAddress(mapElement + offsetToValue)
                }
            end

        --///---///--///---///--///---///--///--///---///--///---///--///---///--/// TYPE HANDLERS

            GDHandlers = {}
            GDHandlers.VariantHandlers = {}

                GDHandlers.VariantHandlers.DICTIONARY = function(entry, emitter, parent, contextTable)
                    sendDebugMessage("DICTIONARY case for name: "..entry.name..(" address: %x"):format(entry.variantPtr)..(" offset: %x"):format(entry.offsetToValue))
                    local dictSize = getDictionarySizeFromVariantPtr(entry.variantPtr)

                    if isNullOrNil(dictSize) then
                        emitter.leaf(contextTable, parent, "dict (empty): " .. entry.name, rootOffset(entry, emitter), entry.ceType)
                        return;
                    end

                    local child = emitter.branch(contextTable, parent, "dict: " .. entry.name, rootOffset(entry, emitter), entry.ceType, "Dict")
                    emitter.recurseDictionary(contextTable, child, readPointer(entry.variantPtr) ) -- we pass the actual base addr

                end

                GDHandlers.VariantHandlers.ARRAY = function(entry, emitter, parent, contextTable)
                    sendDebugMessage("ARRAY case for name: "..entry.name )
                    if isArrayEmptyFromVariantPtr(entry.variantPtr) then
                        emitter.leaf(contextTable, parent, "array (empty): "..entry.name, rootOffset(entry, emitter), entry.ceType);
                        return;
                    end

                    local child = emitter.branch(contextTable, parent, "array: " .. entry.name, rootOffset(entry, emitter), entry.ceType, "Array");
                    emitter.recurseArray(contextTable, child, readPointer(entry.variantPtr))
                end

                GDHandlers.VariantHandlers.OBJECT = function(entry, emitter, parent, contextTable)
                    sendDebugMessage("OBJECT case: name: "..entry.name..(" addr: %x "):format(entry.variantPtr) )
                    local objectParent, realPtr, realOffset, objectContext = prepareObjectParent(entry, emitter, parent, contextTable);

                    if checkForGDScript(readPointer(realPtr)) then
                        if emitter == GDEmitters.StructEmitter then
                            local nodeChild = emitter.leaf(objectContext, objectParent, "mNode: "..entry.name, realOffset, vtPointer);    
                            nodeChild.BackgroundColor = 0xFF8080
                        else
                            local nodeChild = emitter.branch(objectContext, objectParent, "mNode: "..entry.name, realOffset, vtPointer, "Node");
                            nodeChild.BackgroundColor = 0xFF8080

                            if emitter.recurseNode then -- TODO: redundant?
                                emitter.recurseNode(objectContext, nodeChild, readPointer(realPtr)) -- 
                            end
                        end

                    else
                        emitter.leaf(objectContext, objectParent, "obj: " .. entry.name, realOffset, vtPointer);
                    end
                end

                GDHandlers.VariantHandlers.STRING = function(entry, emitter, parent, contextTable)
                    if emitter == GDEmitters.StructEmitter then
                        local outer = emitter.branch( contextTable, parent, "String: " .. entry.name, rootOffset(entry, emitter), vtPointer, "String" )
                        local inner = emitter.branch( contextTable, outer, "StringData: " .. entry.name, 0x0, vtUnicodeString, "stringy" )
                        --emitter.leaf( contextTable, inner, "String: " .. entry.name, 0x0, vtUnicodeString )
                    else
                        emitter.leaf( contextTable, parent, "String: " .. entry.name, rootOffset(entry, emitter), vtString )
                    end
                end

                GDHandlers.VariantHandlers.STRING_NAME = function(entry, emitter, parent, contextTable)
                    if emitter == GDEmitters.StructEmitter then
                        local outer = emitter.branch(contextTable, parent, "StringName: " .. entry.name, rootOffset(entry, emitter), vtPointer, "StringName")
                        local inner = emitter.branch(contextTable, outer, "StringName: " .. entry.name, GDSOf.STRING, vtPointer, "stringy")
                        emitter.leaf(contextTable, inner, "String: " .. entry.name, 0x0, vtUnicodeString)
                    else
                        local stringNameAddr = readPointer(entry.variantPtr)
                        if isNullOrNil(stringNameAddr) then
                            emitter.leaf(contextTable, parent, "StringName: " .. entry.name, rootOffset(entry, emitter), vtPointer)
                            return
                        end

                        local stringContext = { nodeAddr = contextTable.nodeAddr, nodeName = contextTable.nodeName, baseAddress = stringNameAddr + GDSOf.STRING }
                        emitter.leaf(stringContext, parent, "StringName: " .. entry.name, 0x0, vtString)
                    end
                    
                end

                GDHandlers.VariantHandlers.PACKED_STRING_ARRAY = function(entry, emitter, parent, contextTable)
                    sendDebugMessage("handlePackedArray: "..entry.typeName.." case for name: "..entry.name)
                    local arrayAddr = readPointer( entry.variantPtr )

                    if readPointer( arrayAddr + GDSOf.P_ARRAY_TOARR ) == 0 then
                        emitter.leaf( contextTable, parent, entry.typeName..' (empty): '..entry.name, rootOffset(entry, emitter), entry.ceType )
                    else
                        local child = emitter.branch( contextTable, parent, entry.typeName..' '..entry.name, rootOffset(entry, emitter), entry.ceType, "P_Array" )
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
                    local typeName = "Color: "
                    emitter.leaf(contextTable, parent, typeName .. entry.name .. ": R", fieldOffset(entry, emitter, 0x0), vtSingle)
                    emitter.leaf(contextTable, parent, typeName .. entry.name .. ": G", fieldOffset(entry, emitter, 0x4), vtSingle)
                    emitter.leaf(contextTable, parent, typeName .. entry.name .. ": B", fieldOffset(entry, emitter, 0x8), vtSingle)
                    emitter.leaf(contextTable, parent, typeName .. entry.name .. ": A", fieldOffset(entry, emitter, 0xC), vtSingle)
                end

                GDHandlers.VariantHandlers.VECTOR2 = function(entry, emitter, parent, contextTable)
                    local typeName = "Vec2: "
                    emitter.leaf(contextTable, parent, typeName..entry.name..': x', fieldOffset(entry, emitter, 0x0), vtSingle)
                    emitter.leaf(contextTable, parent, typeName..entry.name..': y', fieldOffset(entry, emitter, 0x4), vtSingle)
                end

                GDHandlers.VariantHandlers.VECTOR2I = function(entry, emitter, parent, contextTable)
                    local typeName = "vec2I: "
                    emitter.leaf(contextTable, parent, typeName..entry.name..': x', fieldOffset(entry, emitter, 0x0), vtDword)
                    emitter.leaf(contextTable, parent, typeName..entry.name..': y', fieldOffset(entry, emitter, 0x4), vtDword)
                end

                GDHandlers.VariantHandlers.RECT2 = function(entry, emitter, parent, contextTable)
                    local typeName = "Rect2: "
                    emitter.leaf(contextTable, parent, typeName..entry.name..': x', fieldOffset(entry, emitter, 0x0), vtSingle)
                    emitter.leaf(contextTable, parent, typeName..entry.name..': y', fieldOffset(entry, emitter, 0x4), vtSingle)
                    emitter.leaf(contextTable, parent, typeName..entry.name..': w', fieldOffset(entry, emitter, 0x8), vtSingle)
                    emitter.leaf(contextTable, parent, typeName..entry.name..': h', fieldOffset(entry, emitter, 0xC), vtSingle)
                end

                GDHandlers.VariantHandlers.RECT2I = function(entry, emitter, parent, contextTable)
                    local typeName = "Rect2I: "
                    emitter.leaf(contextTable, parent, typeName..entry.name..': x', fieldOffset(entry, emitter, 0x0), vtDword)
                    emitter.leaf(contextTable, parent, typeName..entry.name..': y', fieldOffset(entry, emitter, 0x4), vtDword)
                    emitter.leaf(contextTable, parent, typeName..entry.name..': w', fieldOffset(entry, emitter, 0x8), vtDword)
                    emitter.leaf(contextTable, parent, typeName..entry.name..': h', fieldOffset(entry, emitter, 0xC), vtDword)
                end

                GDHandlers.VariantHandlers.VECTOR3 = function(entry, emitter, parent, contextTable)
                    local typeName = "Vec3: "
                    emitter.leaf(contextTable, parent, typeName..entry.name..': x', fieldOffset(entry, emitter, 0x0), vtSingle)
                    emitter.leaf(contextTable, parent, typeName..entry.name..': y', fieldOffset(entry, emitter, 0x4), vtSingle)
                    emitter.leaf(contextTable, parent, typeName..entry.name..': z', fieldOffset(entry, emitter, 0x8), vtSingle)
                end

                GDHandlers.VariantHandlers.VECTOR3I = function(entry, emitter, parent, contextTable)
                    local typeName = "Vec3I: "
                    emitter.leaf(contextTable, parent, typeName..entry.name..': x', fieldOffset(entry, emitter, 0x0), vtDword)
                    emitter.leaf(contextTable, parent, typeName..entry.name..': y', fieldOffset(entry, emitter, 0x4), vtDword)
                    emitter.leaf(contextTable, parent, typeName..entry.name..': z', fieldOffset(entry, emitter, 0x8), vtDword)
                end

                GDHandlers.VariantHandlers.VECTOR4 = function(entry, emitter, parent, contextTable)
                    local typeName = "Vec4: "
                    emitter.leaf(contextTable, parent, typeName..entry.name..': x', fieldOffset(entry, emitter, 0x0), vtSingle)
                    emitter.leaf(contextTable, parent, typeName..entry.name..': y', fieldOffset(entry, emitter, 0x4), vtSingle)
                    emitter.leaf(contextTable, parent, typeName..entry.name..': z', fieldOffset(entry, emitter, 0x8), vtSingle)
                    emitter.leaf(contextTable, parent, typeName..entry.name..': w', fieldOffset(entry, emitter, 0xC), vtSingle)
                end

                GDHandlers.VariantHandlers.VECTOR4I = function(entry, emitter, parent, contextTable)
                    local typeName = "Vec4I: "
                    emitter.leaf(contextTable, parent, typeName..entry.name..': x', fieldOffset(entry, emitter, 0x0), vtDword)
                    emitter.leaf(contextTable, parent, typeName..entry.name..': y', fieldOffset(entry, emitter, 0x4), vtDword)
                    emitter.leaf(contextTable, parent, typeName..entry.name..': z', fieldOffset(entry, emitter, 0x8), vtDword)
                    emitter.leaf(contextTable, parent, typeName..entry.name..': w', fieldOffset(entry, emitter, 0xC), vtDword)
                end
                
                GDHandlers.VariantHandlers.DEFAULT = function(entry, emitter, parent, contextTable)
                    emitter.leaf(contextTable, parent, "var: "..entry.name.." ("..entry.typeName..")", rootOffset(entry, emitter), entry.ceType)
                end


            GDHandlers.NodeDiscoveryHandlers = {}

                GDHandlers.NodeDiscoveryHandlers.DICTIONARY = function(entry, visitor)
                    local dictSize = getDictionarySizeFromVariantPtr(entry.variantPtr)
                    if isNotNullOrNil(dictSize) then
                        visitor.recurseDictionary(readPointer(entry.variantPtr))
                    end
                end

                GDHandlers.NodeDiscoveryHandlers.ARRAY = function(entry, visitor)
                    if not isArrayEmptyFromVariantPtr(entry.variantPtr) then
                        visitor.recurseArray(readPointer(entry.variantPtr))
                    end
                end

                GDHandlers.NodeDiscoveryHandlers.OBJECT = function(entry, visitor)
                    visitor.visitObject(entry.variantPtr)
                end


            GDHandlers.PackedArrayHandlers = {}

                GDHandlers.PackedArrayHandlers.PACKED_STRING_ARRAY = function(packedDataArrAddr, packedVectorSize, parent, emitter)
                    for elemIndex = 0, packedVectorSize - 1 do
                        local offsetToValue = elemIndex * GDSOf.PTRSIZE
                        local arrElement = getAddress(packedDataArrAddr + offsetToValue)

                        if readPointer(arrElement) ~= 0 then
                            emitter.emitPackedString(parent, elemIndex, offsetToValue, arrElement)
                        end
                    end
                end

                GDHandlers.PackedArrayHandlers.PACKED_INT32_ARRAY = function(packedDataArrAddr, packedVectorSize, parent, emitter)
                    for elemIndex = 0, packedVectorSize - 1 do
                        local offsetToValue = elemIndex * 0x4
                        local arrElement = getAddress(packedDataArrAddr + offsetToValue)
                        emitter.emitPackedScalar(parent, 'pck_arr[', elemIndex, offsetToValue, arrElement, vtDword)
                    end
                end

                GDHandlers.PackedArrayHandlers.PACKED_FLOAT32_ARRAY = function(packedDataArrAddr, packedVectorSize, parent, emitter)
                    for elemIndex = 0, packedVectorSize - 1 do
                        local offsetToValue = elemIndex * 0x4
                        local arrElement = getAddress(packedDataArrAddr + offsetToValue)
                        emitter.emitPackedScalar(parent, 'pck_arr[', elemIndex, offsetToValue, arrElement, vtSingle)
                    end
                end

                GDHandlers.PackedArrayHandlers.PACKED_INT64_ARRAY = function(packedDataArrAddr, packedVectorSize, parent, emitter)
                    for elemIndex = 0, packedVectorSize - 1 do
                        local offsetToValue = elemIndex * GDSOf.PTRSIZE
                        local arrElement = getAddress(packedDataArrAddr + offsetToValue)
                        emitter.emitPackedScalar(parent, 'pck_arr[', elemIndex, offsetToValue, arrElement, vtQword)
                    end
                end

                GDHandlers.PackedArrayHandlers.PACKED_FLOAT64_ARRAY = function(packedDataArrAddr, packedVectorSize, parent, emitter)
                    for elemIndex = 0, packedVectorSize - 1 do
                        local offsetToValue = elemIndex * GDSOf.PTRSIZE
                        local arrElement = getAddress(packedDataArrAddr + offsetToValue)
                        emitter.emitPackedScalar(parent, 'pck_arr[', elemIndex, offsetToValue, arrElement, vtDouble)
                    end
                end

                GDHandlers.PackedArrayHandlers.PACKED_BYTE_ARRAY = function(packedDataArrAddr, packedVectorSize, parent, emitter)
                    for elemIndex = 0, packedVectorSize - 1 do
                        local offsetToValue = elemIndex * 0x1
                        local arrElement = getAddress(packedDataArrAddr + offsetToValue)
                        emitter.emitPackedScalar(parent, 'pck_arr[', elemIndex, offsetToValue, arrElement, vtByte)
                    end
                end

                GDHandlers.PackedArrayHandlers.PACKED_VECTOR2_ARRAY = function(packedDataArrAddr, packedVectorSize, parent, emitter)
                    for elemIndex = 0, packedVectorSize - 1 do
                        local offsetToValue = elemIndex * 0x8
                        local arrElement = getAddress(packedDataArrAddr + offsetToValue)
                        emitter.emitPackedVec2(parent, 'pck_mvec2[', elemIndex, offsetToValue, arrElement)
                    end
                end

                GDHandlers.PackedArrayHandlers.PACKED_VECTOR3_ARRAY = function(packedDataArrAddr, packedVectorSize, parent, emitter)
                    for elemIndex = 0, packedVectorSize - 1 do
                        local offsetToValue = elemIndex * 0xC
                        local arrElement = getAddress(packedDataArrAddr + offsetToValue)
                        emitter.emitPackedVec3(parent, 'pck_mvec3[', elemIndex, offsetToValue, arrElement)
                    end
                end

                GDHandlers.PackedArrayHandlers.PACKED_COLOR_ARRAY = function(packedDataArrAddr, packedVectorSize, parent, emitter)
                    for elemIndex = 0, packedVectorSize - 1 do
                        local offsetToValue = elemIndex * 0x10
                        local arrElement = getAddress(packedDataArrAddr + offsetToValue)
                        emitter.emitPackedColor(parent, 'pck_color[', elemIndex, offsetToValue, arrElement)
                    end
                end

                GDHandlers.PackedArrayHandlers.DEFAULT = function(packedDataArrAddr, packedVectorSize, parent, emitter)
                    for elemIndex = 0, packedVectorSize - 1 do
                        local offsetToValue = elemIndex * GDSOf.PTRSIZE
                        local arrElement = getAddress(packedDataArrAddr + offsetToValue)
                        emitter.emitPackedScalar(parent, '/U/ pck_arr[', elemIndex, offsetToValue, arrElement, vtPointer)
                    end
                end


        --///---///--///---///--///---///--///--///---///--///---///--///---///--/// Node

            --- returns a code with a ScriptInstance initialized
            ---@param nodeName string
            function getNodeWithGDScriptInstance(nodeName)
                assert(type(nodeName) == "string",'Node name should be a string, instead got: '..type(nodeName))
                debugStepIn()

                local childrenPtr, childrenSize = getVPChildren()
                if isNullOrNil(childrenPtr) then
                    debugStepOut()
                    return
                end

                for i=0,( childrenSize-1 ) do

                    local nodeAddr = readPointer( childrenPtr + i* GDSOf.PTRSIZE )
                    if isNullOrNil(nodeAddr) then
                        sendDebugMessageAndStepOut('getNodeWithGDScriptInstance: nodeAddr invalid')
                        return
                    end

                    local nodeNameStr = getNodeName(nodeAddr)
                    local gdScriptInsance = readQword( nodeAddr + GDSOf.GDSCRIPTINSTANCE )
                    if isNullOrNil(gdScriptInsance) then
                        sendDebugMessageAndStepOut('getNodeWithGDScriptInstance: ScriptInstance is 0/nil')
                        return
                    end

                    if nodeNameStr == nodeName then
                        debugStepOut()
                        return nodeAddr
                    end
                end
                debugStepOut()
                return
            end

            --- get a Node name by addr
            ---@param nodeAddr number
            function getNodeName( nodeAddr )
                assert(type(nodeAddr) == 'number',"getNodeName: Node Addr has to be a number, instead got: "..type(nodeAddr))

                debugStepIn()

                local nodeNamePtr = readPointer( nodeAddr + GDSOf.OBJ_STRING_NAME )
                if isNullOrNil(nodeNamePtr) or ( not isValidPointer( nodeNamePtr ) ) then
                    sendDebugMessageAndStepOut('getNodeName: nodeName invalid or not a pointer (?)')
                    return 'N??'
                end

                nodeNamePtr = readPointer( nodeNamePtr + GDSOf.STRING )
                if isNullOrNil(nodeNamePtr) then
                    sendDebugMessage('getNodeName: string address invalid, trying ASCII')

                    nodeNamePtr = readPointer( nodeAddr + GDSOf.OBJ_STRING_NAME )
                    nodeNamePtr = readPointer( nodeNamePtr + 0x8 ) -- for cases when StringName holds a static ASCII string at 0x8
                    if isNullOrNil(nodeNamePtr) then
                        sendDebugMessageAndStepOut('getNodeName: string address invalid, not ASCII either');
                        return 'N??'
                    end 
                    debugStepOut()

                    return readString( nodeNamePtr, 100 )

                end
                debugStepOut()

                return readUTFString( nodeNamePtr )
            end

            function getNodeNameFromGDScript( nodeAddr )
                assert(type(nodeAddr) == 'number',"getNodeNameFromGDScript: Node Addr has to be a number, instead got: "..type(nodeAddr))

                debugStepIn()

                local GDScriptInstanceAddr = readPointer( nodeAddr + GDSOf.GDSCRIPTINSTANCE )
                if isNullOrNil(GDScriptInstanceAddr) then
                    sendDebugMessageAndStepOut('getNodeNameFromGDScript: ScriptInstance is 0/nil')
                    return 'N??'
                end
                local GDScriptAddr = readPointer( GDScriptInstanceAddr + GDSOf.GDSCRIPT_REF )
                if isNullOrNil(GDScriptAddr) then
                    sendDebugMessageAndStepOut(' getNodeNameFromGDScript: GDScript is 0/nil')
                    return 'N??'
                end
                local GDScriptNameAddr = readPointer( GDScriptAddr + GDSOf.GDSCRIPTNAME )


                if isNullOrNil(GDScriptNameAddr) then
                    sendDebugMessageAndStepOut('getNodeNameFromGDScript: nodeName invalid or not a pointer (?)')
                    return 'N??'
                end

                local GDScriptName = readUTFString( GDScriptNameAddr )
                if GDScriptName == nil or GDScriptName == '' then
                    sendDebugMessageAndStepOut('getNodeNameFromGDScript: GDScriptName is nil/empty')
                    return 'N??'
                end

                GDScriptName = string.match( GDScriptName, "([^/]+)%.gd$" )
                if GDScriptName == nil then
                    sendDebugMessageAndStepOut('getNodeNameFromGDScript: GDScriptName is nil/empty')
                    return 'N??'
                end

                debugStepOut()

                return GDScriptName
            end

            --- Used to validate an object as a Node, returns true if valid
            ---@param nodeAddr number
            function checkForGDScript(nodeAddr)

                -- debugStepIn()

                if isNullOrNil(nodeAddr) then
                    -- sendDebugMessageAndStepOut('checkForGDScript: nodeAddr invalid'..(" address %x"):format(nodeAddr or -1))
                    return false
                end

                if (not isValidPointer( readPointer( nodeAddr ) ) ) then
                    -- sendDebugMessageAndStepOut('checkForGDScript: Node vTable invalid'..(" address %x"):format(nodeAddr or -1))
                    return false
                end

                local scriptInstance = readPointer( nodeAddr + GDSOf.GDSCRIPTINSTANCE )
                if isNullOrNil( scriptInstance ) then
                    -- sendDebugMessageAndStepOut('checkForGDScript: ScriptInstance is 0/nil'..(" address %x"):format(nodeAddr or -1))
                    return false
                end
                
                local gdscript = readPointer( scriptInstance + GDSOf.GDSCRIPT_REF )
                if isNullOrNil(gdscript) then
                    -- sendDebugMessageAndStepOut('checkForGDScript: GDScript is 0/nil'..(" address %x"):format(nodeAddr or -1))
                    return false
                end;

                if isValidPointer( gdscript ) and isValidPointer( scriptInstance ) then

                    if getGDResName( nodeAddr, 4 ) == 'res:'  then
                        -- debugStepOut()
                        return true;
                    else

                        -- sendDebugMessageAndStepOut('checkForGDScript: getGDResName returned false for res://')
                        return false;

                    end

                else
                    -- sendDebugMessageAndStepOut('checkForGDScript: Script/Instance probably not a pointer: '..string.format('gdScript %x ', gdscript)..string.format('ScriptInstance %x ', scriptInstance))

                    return false;

                end
            end
    
            function checkIfGDObjectWithChildren(objAddr)
                if isNullOrNil(objAddr) then return false end

                -- check vTable
                if not isMMVTable( readPointer( objAddr ) ) then return false end

                -- check children
                local objectChildren = readPointer( objAddr + GDSOf.CHILDREN )
                if isNullOrNil(objectChildren) then return false end

                local childrenSize;
                if GDSOf.MAJOR_VER == 4 then
                    childrenSize = readInteger( objAddr + GDSOf.CHILDREN - GDSOf.CHILDREN_SIZE ) -- size is 8 bytes behind
                -- elseif GDSOf.MAJOR_VER > 4 then -- TODO: versions before ~4.2 have size inside the array 4 bytes behind
                --     childrenSize = readInteger( objectChildren - GDSOf.CHILDREN_SIZE )
                else
                    childrenSize = readInteger( objectChildren - GDSOf.CHILDREN_SIZE )
                end
                -- if no children, we don't need it
                if isNullOrNil(childrenSize) then return false end

                -- check for StringName which should always be present?
                local objectStrNamePtr = readPointer( objAddr + GDSOf.OBJ_STRING_NAME )
                if isNullOrNil(objectStrNamePtr) then return false end

                local objName = getStringNameStr(objectStrNamePtr)
                if isNullOrNil(objName) or objName == "??" then return false end

                return true
            end

            --- builds a structure layout for a node's children array
            ---@param childrenArrStruct userdata
            ---@param nodeAddr number
            function iterateNodeChildrenToStruct( childrenArrStructElem, baseAddress )

                if not isPointerNotNull( readPointer( baseAddress + GDSOf.CHILDREN ) ) then
                    -- check if the children array points to something
                    return;
                end 
                local childrenAddr = readPointer( baseAddress + GDSOf.CHILDREN )

                local childrenSize;
                if GDSOf.MAJOR_VER == 4 then
                    childrenSize = readInteger( baseAddress + GDSOf.CHILDREN - GDSOf.CHILDREN_SIZE ) -- size is 8 bytes behind
                elseif GDSOf.MAJOR_VER > 4 then
                    childrenSize = readInteger( childrenAddr - GDSOf.CHILDREN_SIZE ) -- versions before ~4.2 have size inside the array 4 bytes behind
                else
                    childrenSize = readInteger( childrenAddr - GDSOf.CHILDREN_SIZE )
                end
                if isNullOrNil(childrenSize) then
                    return;
                end

                for i=0,(childrenSize-1) do
                    local nodeAddr = readPointer( childrenAddr + (i*GDSOf.PTRSIZE) )
                    local nodeName = getNodeName( nodeAddr )
                    if nodeName == nil or nodeName == 'N??'then
                        nodeName = getNodeNameFromGDScript( nodeAddr )
                    end

                    -- sendDebugMessage("Checking GDScript for "..nodeName)

                    if checkForGDScript( nodeAddr ) then
                        addLayoutStructElem( childrenArrStructElem, 'Ch Node: '..nodeName, 0xFF8080, (i*GDSOf.PTRSIZE), vtPointer)
                    else
                        addStructureElem( childrenArrStructElem, 'Ch Obj: '..nodeName, (i*GDSOf.PTRSIZE), vtPointer)
                    end
                end

                return
            end

            --- go over child nodes in the main nodes
            ---@param nodeAddr number
            ---@param parent userdata
            function iterateMNodeToAddr(nodeAddr, parent)
                assert( type(nodeAddr) == 'number',"iterateMNodeToAddr: node addr has to be a number, instead got: "..type(nodeAddr))
                assert( type(parent) == "userdata" ,"iterateMNodeToAddr: parent has to exist")

                debugStepIn()

                local nodeName = getNodeName( nodeAddr )
                sendDebugMessage(' iterateMNodeToAddr: MemberNode: '..tostring(nodeName) )

                for i, storedNode in ipairs(dumpedNodes) do -- check if a node was already dumped
                    if storedNode == nodeAddr then
                        sendDebugMessageAndStepOut('iterateMNodeToAddr: NODE '..tostring(nodeName)..' ALREADY DUMPED' )

                        synchronize(function(parent)
                                parent.setDescription( parent.Description .. ' /D/' ) -- let's note what nodes are copies
                                parent.Options = '[moHideChildren]'
                            end, parent
                        )

                        return
                    end
                end
                table.insert( dumpedNodes , nodeAddr )

                synchronize(function( nodeName , parent )
                        parent.setDescription( parent.Description .. ' : '..tostring( nodeName ) ) -- append node name
                    end, nodeName, parent
                )

                sendDebugMessage('iterateMNodeToAddr: STEP: Constants for: '..tostring(nodeName) )

                if GDSOf.CONST_MAP ~= 0 then
                    local newConstRec = synchronize(function(parent)
                                local addrList = getAddressList()
                                local newConstRec = addrList.createMemoryRecord()
                                newConstRec.setDescription( "Consts:" )
                                newConstRec.setAddress( 0xBABE )
                                newConstRec.setType( vtPointer )
                                newConstRec.Options = '[moHideChildren, moAllowManualCollapseAndExpand, moManualExpandCollapse]'
                                newConstRec.DontSave = true
                                newConstRec.appendToEntry( parent )
                                return newConstRec
                            end, parent
                        )
                    
                    iterateNodeConstToAddr( nodeAddr , newConstRec )
                end

                sendDebugMessage('iterateMNodeToAddr: STEP: VARIANTS for: '..tostring(nodeName) )
                iterateVecVarToAddr( nodeAddr , parent)

                debugStepOut()
                return
            end

            --- builds the structure layout for a Node when guessed
            ---@param nodeAddr number
            ---@param scriptInstStructElement userdata
            function iterateNodeToStruct(nodeAddr, scriptInstStructElement)
                debugStepIn()

                local nodeName = getNodeName( nodeAddr ) or 'NIL';
                
                sendDebugMessage('iterateNodeToStruct: Node: '..tostring(nodeName) )

                for i, storedNode in ipairs(dumpedDissectorNodes) do -- check if a node was already dumped
                    if storedNode == nodeAddr then
                        sendDebugMessageAndStepOut('iterateNodeToStruct: NODE '..tostring(nodeName)..' ALREADY DUMPED' )
                        parent.Name = parent.Name..' /D/'
                        return
                    end
                end
                table.insert( dumpedDissectorNodes , nodeAddr )

                local varVectorStructElem = addLayoutStructElem( scriptInstStructElement, 'Variants', --[[0x000080]] nil, GDSOf.VAR_VECTOR, vtPointer )
                local scriptStructElem = addLayoutStructElem( scriptInstStructElement, 'GDScript', --[[0x008080]] nil, GDSOf.GDSCRIPT_REF, vtPointer )
                local constMapStructElem = addLayoutStructElem( scriptStructElem, 'Consts', --[[0x400000]] nil, GDSOf.CONST_MAP, vtPointer )
                local functMapStructElem = addLayoutStructElem( scriptStructElem, 'Func', --[[0x400000]] nil, GDSOf.FUNC_MAP, vtPointer )

                sendDebugMessage('iterateNodeToStruct: STEP: VARIANTS for: '..tostring(nodeName) )
                varVectorStructElem.ChildStruct = createStructure( 'Vars' )
                iterateVecVarToStruct( nodeAddr , varVectorStructElem )        

                if GDSOf.CONST_MAP ~= 0 then
                    sendDebugMessage('iterateNodeToStruct: STEP: Constants for: '..tostring(nodeName) )
                    constMapStructElem.ChildStruct = createStructure( 'Consts' )
                    iterateNodeConstToStruct( nodeAddr , constMapStructElem )
                end

                if GDSOf.FUNC_MAP ~= 0 then
                    sendDebugMessage('iterateNodeToStruct: STEP: Functions for: '..tostring(nodeName) )
                    functMapStructElem.ChildStruct = createStructure( 'Funcs' )
                    iterateNodeFuncMapToStruct( nodeAddr , functMapStructElem )
                end

                debugStepOut()
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
                local name = getNodeName( nodeAddr )
                if name == nil or name == "N??" then
                    name = getNodeNameFromGDScript( nodeAddr )
                end
                
                registerSymbol( tostring( name ), nodeAddr , true )

                iterateVecVarForNodes( nodeAddr )
            end

            --- gets a GDScript name, best use to return 1st 3 chars for 'res'
            ---@param nodeAddr number
            ---@param strSize number
            function getGDResName(nodeAddr, strSize)
                assert(type(nodeAddr) == 'number',"getGDResName: nodeAddr should be a number, instead got: "..type(nodeAddr))

                debugStepIn()

                local gdScriptInstance = readPointer( nodeAddr + GDSOf.GDSCRIPTINSTANCE )
                if isNullOrNil(gdScriptInstance) then
                    sendDebugMessageAndStepOut(' getGDResName: gdScriptInstance invalid')
                    return
                end

                local gdScript = readPointer( gdScriptInstance + GDSOf.GDSCRIPT_REF )
                if isNullOrNil(gdScript) then
                    sendDebugMessageAndStepOut('getGDResName: gdScript invalid')
                    return
                end

                local gdScriptName = readPointer( gdScript + GDSOf.GDSCRIPTNAME )
                if isNullOrNil(gdScriptName) then
                    sendDebugMessageAndStepOut('getGDResName: gdScriptName invalid')
                    return
                end

                debugStepOut()

                return readUTFString( gdScriptName, strSize )
            end

            -- this monstrosity is used to check for a valid poitner and its vtable
            ---@param objectPtr number -- a ptr to an object or nullptr
            ---@return number -- returns a more valid pointer to an object
            ---@return boolean -- true if the returned pointer was shifted back to get a valid ptr
            function checkForVT( objectPtr )
                local objectAddr = readPointer( objectPtr ) -- it's either an obj ptr or zero

                if (not isMMVTable( objectAddr ) ) then -- check for vtable
                    -- debugStepIn()

                    -- sendDebugMessage('checkForVT: OBJ addr likely not a ptr, shifting back 0x8: ptr: '..string.format( '%x', tonumber(objectPtr) ) )
                    local adjustedObjectPtr = objectPtr - GDSOf.PTRSIZE; -- shift back to get a ptr
                    local wrapperAddr = readPointer( adjustedObjectPtr ) -- this will be a wrapped obj ptr
                    objectAddr = readPointer( wrapperAddr )

                    if isNullOrNil(wrapperAddr) or not isValidPointer(wrapperAddr) then -- check the wrapper
                        -- sendDebugMessageAndStepOut('checkForVT: OBJ addr still not an obj  ptr, leave it be')
                        return objectPtr, false; -- revert the value, whatever
                    end

                    if isMMVTable( objectAddr ) then -- check for vtable to be safe
                        -- sendDebugMessageAndStepOut('checkForVT: shifted OBJ addr is a ptr, returning it')
                        return wrapperAddr, true -- objects at 0x8 offsetToValue are wrapped ptrs, so we return the ptr

                    else
                        -- sendDebugMessageAndStepOut('checkForVT: OBJ addr still not a ptr, leave it be')
                        return objectPtr, false; -- revert the value, whatever
                    end
                else -- vtable valid
                    return objectPtr, false
                end
            end

            --- gets a Node by name
            ---@param nodeName string
            function getNode(nodeName)
                assert(type(nodeName) == "string",'Node name should be a string, instead got: '..type(nodeName))
                if not (gdOffsetsDefined) then
                    print('define the offsets first, silly')
                    return
                end

                local childrenPtr, childrenSize = getVPChildren()
                if isNullOrNil(childrenPtr) then return end

                for i=0,( childrenSize-1 ) do

                    local nodeAddr = readPointer( childrenPtr + i * GDSOf.PTRSIZE )
                    if isNullOrNil(nodeAddr) then
                        --sendDebugMessage('getNode: nodeAddr invalid' )
                        return
                    end

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
                if isNullOrNil(nodePtr) then
                    --sendDebugMessage("getNodeConstPtr: Node + GDSI: "..tostring(nodeName).." wasn't found")
                    return
                end

                local mapHead = getNodeConstantMap(nodePtr)
                return findMapEntryByName( mapHead, constName, getNodeConstName, getConstMapLookupResult, getNextMapElement )

            end



        --///---///--///---///--///---///--///--///---///--///---///--///---///--/// Func

            --- returns a lua string for function name
            ---@param mapElement number
            function getGDFunctionName(mapElement)
                debugStepIn()
                
                local mapElementValue = readPointer( mapElement + GDSOf.CONSTELEM_KEYVAL ) -- layout is similar?
                if isNullOrNil( mapElementValue ) then
                    sendDebugMessageAndStepOut('getGDFunctionName: (hash)mapElementKey invalid');
                    return 'F??'
                end
                local functionNameAddr = readPointer( mapElementValue + GDSOf.STRING )

                if isNullOrNil(functionNameAddr) then
                    sendDebugMessage('getGDFunctionName: functionname invalid')
                    functionNameAddr = readPointer( mapElementValue + GDSOf.PTRSIZE )
                    
                    if isNullOrNil( functionNameAddr ) then
                        sendDebugMessageAndStepOut('getGDFunctionName: string address invalid, not ASCII either')
                        return 'F??'
                    end

                    debugStepOut()
                    return readString( constNameStr, 100 ) 
                end
                debugStepOut()
                return readUTFString( functionNameAddr )
            end

            --- returns a head element, tail element and (hash)Map size
            ---@param nodeAddr number
            function getNodeFuncMap(nodeAddr, funcStructElement)
                assert(type(nodeAddr) == 'number',"getNodeFuncMap: NodePtr should be a number, instead got: "..type(nodeAddr))
                debugStepIn()

                local scriptInstanceAddr = readPointer( nodeAddr + GDSOf.GDSCRIPTINSTANCE )
                if isNullOrNil(scriptInstanceAddr) then
                    sendDebugMessageAndStepOut('getNodeFuncMap: scriptInstance is invalid')
                    return
                end

                local gdScriptAddr = readPointer( scriptInstanceAddr + GDSOf.GDSCRIPT_REF )
                if isNullOrNil(gdScriptAddr) then
                    sendDebugMessageAndStepOut(' getNodeFuncMap: GDScript is invalid');
                    return;
                end

                local mainElement = readPointer( gdScriptAddr + GDSOf.FUNC_MAP ) -- head or root depending on the version
                local lastElement = readPointer( gdScriptAddr + GDSOf.FUNC_MAP + GDSOf.PTRSIZE ) -- tail or end
                local mapSize = readInteger( gdScriptAddr + GDSOf.FUNC_MAP + GDSOf.MAP_SIZE ) -- hashmap or map
                if isNullOrNil(mainElement) or isNullOrNil(lastElement) or isNullOrNil(mapSize) then
                        sendDebugMessageAndStepOut('getNodeFuncMap: Const: (hash)map is not found')
                        return;-- return to skip if the const map is absent
                end
                debugStepOut()
                
                if GDSOf.MAJOR_VER == 4 then
                    return mainElement, lastElement, mapSize, funcStructElement
                else
                    if funcStructElement then funcStructElement.ChildStruct = createStructure('ConstMapRes') end
                    return getLeftmostMapElem( mainElement, lastElement, mapSize, funcStructElement )
                end
            end

            --- gets a functionPtr by nodename (root children) and funcname
            ---@param nodeName string
            ---@param funcName string
            function getGDFunctionPtr(nodeName, funcName)
                assert(type(nodeName) == 'string',"Node name has to be a string, instead got: "..type(nodeName))
                local nodePtr = getNodeWithGDScriptInstance(nodeName)
                if isNullOrNil(nodePtr) then sendDebugMessage( "getGDFunctionPtr: Node: "..tostring(nodeName).." wasn't found" ); return; end
                local mapHead = getNodeFuncMap(nodePtr)
                return findMapEntryByName( mapHead, funcName, getFunctionMapName, getFunctionMapLookupResult, advanceFunctionMapElement )
            end

            --- iterates a function map and adds it to a struct
            ---@param nodeAddr number
            ---@param funcStructElement userdata
            function iterateNodeFuncMapToStruct(nodeAddr, funcStructElement)
                assert( type(nodeAddr) == 'number', 'iterateNodeFuncMapToStruct: nodeAddr has to be a number, instead got: '..type(nodeAddr))

                debugStepIn()
                local headElement, tailElement, mapSize, currentContainer = getNodeFuncMap(nodeAddr, funcStructElement)
                if isNullOrNil(headElement) or isNullOrNil(mapSize) then
                    sendDebugMessageAndStepOut('iterateNodeFuncMapToStruct (hash)map empty?: '..("Address: %x "):format(nodeAddr or -1))
                    return;
                end
                local mapElement = headElement
                local index = 0;

                repeat
                    -- sendDebugMessage('iterateNodeFuncMapToStruct: Looping '..(" mapElemAddr: %x"):format(mapElement or -1 ))

                    local funcName = getFunctionMapName( mapElement ) or "UNKNOWN" -- the layout is similar to constant map's
                    
                    emitFunctionStructEntry(currentContainer, mapElement, funcName)

                    index = index+1
                    mapElement = advanceFunctionMapElement(mapElement)
                    if mapElement ~= 0 then
                        currentContainer = createNextFunctionContainer(currentContainer, index)
                    end
                until (mapElement == 0)

                debugStepOut()
                return
            end

            function iterateFuncConstantsToStruct( funcConstantVect, funcConstantStructElem )
                debugStepIn()

                if isNullOrNil(funcConstantVect) then
                    sendDebugMessageAndStepOut('iterateFuncConstantsToStruct func vector invalid')
                    return 
                end

                local vectorSize = readInteger( funcConstantVect - GDSOf.SIZE_VECTOR )
                if isNullOrNil(vectorSize) then
                    sendDebugMessageAndStepOut('iterateFuncConstantsToStruct vector size invalid')
                    return;
                end

                local variantSize, ok = redefineVariantSizeByVector( funcConstantVect, vectorSize )

                if not ok then
                    sendDebugMessageAndStepOut("iterateFuncConstantsToStruct: Variant resize failed")
                    return
                end
                local emitter = GDEmitters.StructEmitter

                for variantIndex = 0, (vectorSize - 1) do
                    local entry = readFunctionConstantEntry(funcConstantVect, variantIndex, variantSize)
                    local contextTable = { nodeAddr = 0, nodeName = "FunctionConst", baseAddress = entry.variantPtr }
                    local handler = GDHandlers.VariantHandlers[entry.typeName] or GDHandlers.VariantHandlers.DEFAULT
                    handler(entry, emitter, funcConstantStructElem, contextTable)
                end

                debugStepOut()
                return;
            end

            function iterateFuncGlobalsToStruct( funcGlobalVect, funcGlobalNameStructElem )
                debugStepIn()

                if isNullOrNil(funcGlobalVect) then
                    sendDebugMessageAndStepOut('iterateFuncGlobalsToStruct funcGlobalVect invalid')
                    return;
                end
                
                local vectorSize = readInteger( funcGlobalVect - GDSOf.SIZE_VECTOR )
                if isNullOrNil(vectorSize) then
                    sendDebugMessageAndStepOut('iterateFuncGlobalsToStruct vector size invalid')
                    return;
                end

                for variantIndex=0, (vectorSize-1) do
                    local entryOffset = variantIndex * GDSOf.PTRSIZE
                    local label = "GlobName["..variantIndex.."] stringName"
                    local stringFieldLabel = "GlobName["..variantIndex.. "] string"
                    local stringNamePtr = readPointer(funcGlobalVect + entryOffset)
                    local bUniShift = false -- TODO: with version checking that should not be an issue

                    if isPointerNotNull(stringNamePtr) then bUniShift = isPointerNotNull(stringNamePtr + GDSOf.STRING) end

                    -- sendDebugMessage('iterateFuncGlobalsToStruct: Looping: label: '..label..(" funcVector: %x"):format(funcGlobalVect))

                    emitStringNameStruct( funcGlobalNameStructElem, label, entryOffset, stringFieldLabel, bUniShift )
                end

                debugStepOut()
                return;
            end

            function defineGDFunctionEnums()
                GDF = {}

                local function buildReverseTable( tab )
                    local reversedTable = {}
                    for i, v in ipairs( tab ) do
                        reversedTable[v] = i-1
                    end
                    return reversedTable
                end

                local function cloneArray( tabl )
                    local result = {}
                    for i, val in ipairs( tabl ) do
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
                    local spec = GDF.ProfileSpecs[ version ]
                    if not spec then
                        error("Unknown version: " .. tostring( version ))
                    end

                    bVisited = bVisited or {}
                    if bVisited[ version ] then
                        error("Circular profile inheritance for version: " .. tostring( version ))
                    end
                    bVisited[ version ] = true

                    local resolvedProfileSpec = {
                        version = version,
                        decoderName = spec.decoderName,
                        orderedOpcodes = nil
                    }

                    if spec.base then
                        local parent = prepareProfileSpec( spec.base, bVisited )
                        resolvedProfileSpec.orderedOpcodes = cloneArray( parent.orderedOpcodes )

                        if spec.patches then
                            for _, patch in ipairs( spec.patches ) do
                                applyPatchOnList( resolvedProfileSpec.orderedOpcodes, patch )
                            end
                        end
                    else
                        resolvedProfileSpec.orderedOpcodes = cloneArray(spec.orderedOpcodes or {})
                    end

                    return resolvedProfileSpec
                end

                local function createProfileFromVersion( version )
                    local resolvedProfileSpec = prepareProfileSpec( version )
                    local decoder = GDF.Decoders[ resolvedProfileSpec.decoderName ]

                    if not decoder then
                        error( "Unknown decoder: " .. tostring( resolvedProfileSpec.decoderName ) )
                    end

                    local profile = {
                        version = version,
                        decoder = decoder,
                        orderedOpcodes = cloneArray( resolvedProfileSpec.orderedOpcodes ),
                        OPHandlerDefFromOPEnum = {},
                        OPEnumFromInternalOPID = {},
                        opNameFromOPEnum = {}
                    }

                    for i, internalOpcodeID in ipairs(profile.orderedOpcodes) do
                        local opcodeEnum = i - 1
                        local disasmHandlerDef = GDF.DisasmHandlers[ internalOpcodeID ]

                        if not disasmHandlerDef then
                            error("Missing DisasmHandlers entry for internalOpcodeID: " .. tostring(internalOpcodeID))
                        end

                        profile.OPHandlerDefFromOPEnum[ opcodeEnum ] = disasmHandlerDef
                        profile.OPEnumFromInternalOPID[ internalOpcodeID ] = opcodeEnum
                        profile.opNameFromOPEnum[ opcodeEnum ] = disasmHandlerDef.name
                    end

                    return profile
                end

                function GDF.createDisassemblerFromVersion( version )
                    local profile = GDF.CompiledProfiles[ version ]
                    if not profile then
                        error("Unsupported version: " .. tostring( version ))
                    end

                    local newDisassembler = {}
                    newDisassembler.version = version
                    newDisassembler.profile = profile

                    function newDisassembler:getOPNameFromOPEnum( opcodeEnum )
                        local handlerDef = self.profile.OPHandlerDefFromOPEnum[ opcodeEnum ]
                        return handlerDef and handlerDef.name or nil
                    end

                    function newDisassembler:getOPEnumFromInternalOPID( internalOpcodeID )
                        return self.profile.OPEnumFromInternalOPID[ internalOpcodeID ]
                    end

                    function newDisassembler:disassembleBytecode( codeInts, codeStructElement, instrPointer )
                        local disasmContext = {
                            opcodeName = '',
                            codeStructElement = codeStructElement,
                            instrPointer = 1,
                            codeInts = codeInts,
                            opcodeEnumRaw = nil,
                            profile = self.profile
                        }
                        
                        while disasmContext.instrPointer <= #disasmContext.codeInts do
                            
                            disasmContext.opcodeEnumRaw = disasmContext.codeInts[ disasmContext.instrPointer ]
                            if disasmContext.opcodeEnumRaw == nil then
                                break
                            end

                            local opcodeHandlerDef = self.profile.decoder.resolveOPHandlerDefFromProfile( self.profile, disasmContext.opcodeEnumRaw )            
                            if not opcodeHandlerDef then
                                sendDebugMessage('disassembleBytecode: handler not retrieved opcode: '..(disasmContext.opcodeEnumRaw or -1)..(" | hex: %x"):format(disasmContext.opcodeEnumRaw or -1))
                            end
                            sendDebugMessage( ("DB:\topcode: %-4d\thex: %-4x\tname: %s"):format((disasmContext.opcodeEnumRaw or -1), (disasmContext.opcodeEnumRaw or -1), (opcodeHandlerDef.name or "??")) )
                            disasmContext.opcodeName = opcodeHandlerDef.name
                            local nextInstrPointer = opcodeHandlerDef.handler( disasmContext )
                            if nextInstrPointer == nil then
                                error("Opcode handler returned nil for opcode: "..disasmContext.opcodeName.. " at InstrPtr "..disasmContext.instrPointer)
                            end
                            disasmContext.instrPointer = nextInstrPointer
                        end

                        return
                    end

                    return newDisassembler
                end

                if GDSOf.MAJOR_VER == 4 then

                    GDF.OP = {
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
                        -- https://github.com/godotengine/godot/blob/master/modules/gdscript/gdscript_disassembler.cpp

                        GDF.DisasmHandlers[GDF.OP.OPCODE_OPERATOR] = {
                            name = "OPCODE_OPERATOR",
                            handler = function(contextTable)
                                local _pointer_size = GDSOf.PTRSIZE / 0x4

                                local operation = contextTable.codeInts[contextTable.instrPointer + 4 ] -- operator is 4*0x4 after
                                addStructureElem( contextTable.codeStructElement, 'Operator: ', (contextTable.instrPointer-1 +4)*0x4, vtDword )

                                local operationName = GDF.OPERATOR_NAME[ operation + 1 ] or 'UNKNOWN_OPERATOR'
                                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1] )
                                addStructureElem( contextTable.codeStructElement, operand1, (contextTable.instrPointer-1 +1)*0x4, vtDword )
                                local operand2 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 2] )
                                addStructureElem( contextTable.codeStructElement, operand2, (contextTable.instrPointer-1 +2)*0x4, vtDword )
                                local operand3 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 3] ) -- where to store
                                addStructureElem( contextTable.codeStructElement, operand3, (contextTable.instrPointer-1 +3)*0x4, vtDword )

                                contextTable.opcodeName = contextTable.opcodeName..' '..operand3..' = '..operand1..' '..operationName..' '..operand2
                                addLayoutStructElem( contextTable.codeStructElement, contextTable.opcodeName, 0x808040, (contextTable.instrPointer-1 )*0x4, vtDword )

                                return contextTable.instrPointer + 7 + _pointer_size -- incr += 5; in 4.0
                            end
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_OPERATOR_VALIDATED] = {
                            name = "OPCODE_OPERATOR_VALIDATED",
                            handler = function(contextTable)

                                local operation = contextTable.codeInts[contextTable.instrPointer + 4 ] -- operator is 4*0x4 after
                                addStructureElem( contextTable.codeStructElement, 'Operator: ', (contextTable.instrPointer-1 +4)*0x4, vtDword )

                                local operationName = GDF.OPERATOR_NAME[ operation + 1 ] or 'UNKNOWN_OPERATOR' -- TODO not sure, is that the same thing: operator_names[_code_ptr[ip + 4]];
                                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1] )
                                addStructureElem( contextTable.codeStructElement, operand1, (contextTable.instrPointer-1 +1)*0x4, vtDword )
                                local operand2 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 2] )
                                addStructureElem( contextTable.codeStructElement, operand2, (contextTable.instrPointer-1 +2)*0x4, vtDword )
                                local operand3 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 3] ) -- where to store
                                addStructureElem( contextTable.codeStructElement, operand3, (contextTable.instrPointer-1 +3)*0x4, vtDword )
                                contextTable.opcodeName = contextTable.opcodeName..' '..operand3..' = '..operand1..' '..operationName..' '..operand2
                                addLayoutStructElem( contextTable.codeStructElement, contextTable.opcodeName, 0x808040, (contextTable.instrPointer-1 )*0x4, vtDword )
                                
                                return contextTable.instrPointer + 5
                            end
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_TEST_BUILTIN] = {
                            name = "OPCODE_TYPE_TEST_BUILTIN",
                            handler = function(contextTable)
                                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1] )
                                addStructureElem( contextTable.codeStructElement, operand1, (contextTable.instrPointer-1 +1)*0x4, vtDword )
                                local operand2 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 2] )
                                addStructureElem( contextTable.codeStructElement, operand2, (contextTable.instrPointer-1 +2)*0x4, vtDword )
                                local operand3 = getGDTypeName( contextTable.codeInts[contextTable.instrPointer + 3] )
                                addStructureElem( contextTable.codeStructElement, operand3, (contextTable.instrPointer-1 +3)*0x4, vtDword )
                                contextTable.opcodeName = contextTable.opcodeName..' '..operand1..' = '..operand2..' is '..operand3
                                addLayoutStructElem( contextTable.codeStructElement, contextTable.opcodeName, 0x808040, (contextTable.instrPointer-1 )*0x4, vtDword )
                                return contextTable.instrPointer + 4
                            end
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_TEST_ARRAY] = {
                            name = "OPCODE_TYPE_TEST_ARRAY",
                            handler = function(contextTable)
                                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1] )
                                addStructureElem( contextTable.codeStructElement, operand1, (contextTable.instrPointer-1 +1)*0x4, vtDword )
                                local operand2 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 2] )
                                addStructureElem( contextTable.codeStructElement, operand2, (contextTable.instrPointer-1 +2)*0x4, vtDword )

                                --TODO create function constants lookup for disassembling
                                local operand3 = getGDTypeName( contextTable.codeInts[contextTable.instrPointer + 4] )
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
                                addStructureElem( contextTable.codeStructElement, 'script_type', (contextTable.instrPointer-1 +3)*0x4, vtDword )
                                addStructureElem( contextTable.codeStructElement, operand3, (contextTable.instrPointer-1 +4)*0x4, vtDword )
                                addStructureElem( contextTable.codeStructElement, 'native_type', (contextTable.instrPointer-1 +5)*0x4, vtDword )

                                contextTable.opcodeName = contextTable.opcodeName..' '..operand1..' = '..operand2..' is Dictionary['..operand3..']'
                                addLayoutStructElem( contextTable.codeStructElement, contextTable.opcodeName, 0x808040, (contextTable.instrPointer-1 )*0x4, vtDword )
                                
                                return contextTable.instrPointer + 6

                            end
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_TEST_DICTIONARY] = {
                            name = "OPCODE_TYPE_TEST_DICTIONARY",
                            handler = function(contextTable)
                                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1] )
                                addStructureElem( contextTable.codeStructElement, operand1, (contextTable.instrPointer-1 +1)*0x4, vtDword )
                                local operand2 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 2] )
                                addStructureElem( contextTable.codeStructElement, operand2, (contextTable.instrPointer-1 +2)*0x4, vtDword )

                                local operand5 = getGDTypeName( contextTable.codeInts[contextTable.instrPointer + 5] )
                                local operand7 = getGDTypeName( contextTable.codeInts[contextTable.instrPointer + 7] )
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

                                addStructureElem( contextTable.codeStructElement, 'key_script_type', (contextTable.instrPointer-1 +3)*0x4, vtDword )
                                addStructureElem( contextTable.codeStructElement, operand5, (contextTable.instrPointer-1 +5)*0x4, vtDword )
                                addStructureElem( contextTable.codeStructElement, 'value_script_type', (contextTable.instrPointer-1 +4)*0x4, vtDword )
                                addStructureElem( contextTable.codeStructElement, operand7, (contextTable.instrPointer-1 +7)*0x4, vtDword )
                                addStructureElem( contextTable.codeStructElement, 'value_native_type', (contextTable.instrPointer-1 +8)*0x4, vtDword )

                                contextTable.opcodeName = contextTable.opcodeName..' '..operand1..' = '..operand2..' is Dictionary['..operand5..']'..', '..operand7..']'
                                addLayoutStructElem( contextTable.codeStructElement, contextTable.opcodeName, 0x808040, (contextTable.instrPointer-1 )*0x4, vtDword )
                                return contextTable.instrPointer + 9

                            end
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_TEST_NATIVE] = {
                            name = "OPCODE_TYPE_TEST_NATIVE",
                            handler = function(contextTable)
                                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1] )
                                addStructureElem( contextTable.codeStructElement, operand1, (contextTable.instrPointer-1 +1)*0x4, vtDword )
                                local operand2 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 2] )
                                addStructureElem( contextTable.codeStructElement, operand2, (contextTable.instrPointer-1 +2)*0x4, vtDword )

                                local operand3 = 'get_global_name('..(contextTable.codeInts[ contextTable.instrPointer+3])..')'
                                addStructureElem( contextTable.codeStructElement, operand3, (contextTable.instrPointer-1 +3)*0x4, vtDword )

                                contextTable.opcodeName = contextTable.opcodeName..' '..operand1..' = '..operand2..' is '..operand3

                                addLayoutStructElem( contextTable.codeStructElement, contextTable.opcodeName, 0x808040, (contextTable.instrPointer-1 )*0x4, vtDword )
                                return contextTable.instrPointer + 4
                            end
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_TEST_SCRIPT] = {
                            name = "OPCODE_TYPE_TEST_SCRIPT",
                            handler = function(contextTable)
                                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1] )
                                addStructureElem( contextTable.codeStructElement, operand1, (contextTable.instrPointer-1 +1)*0x4, vtDword )
                                local operand2 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 2] )
                                addStructureElem( contextTable.codeStructElement, operand2, (contextTable.instrPointer-1 +2)*0x4, vtDword )
                                local operand3 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 3] )
                                addStructureElem( contextTable.codeStructElement, operand3, (contextTable.instrPointer-1 +3)*0x4, vtDword )
                                contextTable.opcodeName = contextTable.opcodeName..' '..operand1..' = '..operand2..' is '..operand3
                                addLayoutStructElem( contextTable.codeStructElement, contextTable.opcodeName, 0x808040, (contextTable.instrPointer-1 )*0x4, vtDword )
                                return contextTable.instrPointer + 4

                            end
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_SET_KEYED] = {
                            name = "OPCODE_SET_KEYED",
                            handler = function(contextTable)
                                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1] )
                                addStructureElem( contextTable.codeStructElement, operand1, (contextTable.instrPointer-1 +1)*0x4, vtDword )
                                local operand2 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 2] )
                                addStructureElem( contextTable.codeStructElement, operand2, (contextTable.instrPointer-1 +2)*0x4, vtDword )
                                local operand3 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 3] )
                                addStructureElem( contextTable.codeStructElement, operand3, (contextTable.instrPointer-1 +3)*0x4, vtDword )
                                contextTable.opcodeName = contextTable.opcodeName..' '..operand1..'['..operand2..'] = '..operand3
                                addLayoutStructElem( contextTable.codeStructElement, contextTable.opcodeName, 0x808040, (contextTable.instrPointer-1 )*0x4, vtDword )
                                return contextTable.instrPointer + 4

                            end
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_SET_KEYED_VALIDATED] = {
                            name = "OPCODE_SET_KEYED_VALIDATED",
                            handler = function(contextTable)
                                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1] )
                                addStructureElem( contextTable.codeStructElement, operand1, (contextTable.instrPointer-1 +1)*0x4, vtDword )
                                local operand2 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 2] )
                                addStructureElem( contextTable.codeStructElement, operand2, (contextTable.instrPointer-1 +2)*0x4, vtDword )
                                local operand3 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 3] )
                                addStructureElem( contextTable.codeStructElement, operand3, (contextTable.instrPointer-1 +3)*0x4, vtDword )

                                contextTable.opcodeName = contextTable.opcodeName..' '..operand1..'['..operand2..'] = '..operand3

                                addLayoutStructElem( contextTable.codeStructElement, contextTable.opcodeName, 0x808040, (contextTable.instrPointer-1 )*0x4, vtDword )
                                return contextTable.instrPointer + 5

                            end
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_SET_INDEXED_VALIDATED] = {
                            name = "OPCODE_SET_INDEXED_VALIDATED",
                            handler = function(contextTable)
                                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1] )
                                addStructureElem( contextTable.codeStructElement, operand1, (contextTable.instrPointer-1 +1)*0x4, vtDword )
                                local operand2 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 2] )
                                addStructureElem( contextTable.codeStructElement, operand2, (contextTable.instrPointer-1 +2)*0x4, vtDword )
                                local operand3 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 3] )
                                addStructureElem( contextTable.codeStructElement, operand3, (contextTable.instrPointer-1 +3)*0x4, vtDword )

                                contextTable.opcodeName = contextTable.opcodeName..' '..operand1..'['..operand2..'] = '..operand3
                                
                                addLayoutStructElem( contextTable.codeStructElement, contextTable.opcodeName, 0x808040, (contextTable.instrPointer-1 )*0x4, vtDword )
                                return contextTable.instrPointer + 5

                            end
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_GET_KEYED] = {
                            name = "OPCODE_GET_KEYED",
                            handler = function(contextTable)
                                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1] )
                                addStructureElem( contextTable.codeStructElement, operand1, (contextTable.instrPointer-1 +1)*0x4, vtDword )
                                local operand2 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 2] )
                                addStructureElem( contextTable.codeStructElement, operand2, (contextTable.instrPointer-1 +2)*0x4, vtDword )
                                local operand3 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 3] )
                                addStructureElem( contextTable.codeStructElement, operand3, (contextTable.instrPointer-1 +3)*0x4, vtDword )

                                contextTable.opcodeName = contextTable.opcodeName..' '..operand3..'['..operand1..'] = '..operand2
                                
                                addLayoutStructElem( contextTable.codeStructElement, contextTable.opcodeName, 0x808040, (contextTable.instrPointer-1 )*0x4, vtDword )

                                return contextTable.instrPointer + 4

                            end
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_GET_KEYED_VALIDATED] = {
                            name = "OPCODE_GET_KEYED_VALIDATED",
                            handler = function(contextTable)
                                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1] )
                                addStructureElem( contextTable.codeStructElement, operand1, (contextTable.instrPointer-1 +1)*0x4, vtDword )
                                local operand2 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 2] )
                                addStructureElem( contextTable.codeStructElement, operand2, (contextTable.instrPointer-1 +2)*0x4, vtDword )
                                local operand3 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 3] )
                                addStructureElem( contextTable.codeStructElement, operand3, (contextTable.instrPointer-1 +3)*0x4, vtDword )

                                contextTable.opcodeName = contextTable.opcodeName..' '..operand3..'['..operand1..'] = '..operand2
                                
                                addLayoutStructElem( contextTable.codeStructElement, contextTable.opcodeName, 0x808040, (contextTable.instrPointer-1 )*0x4, vtDword )

                                return contextTable.instrPointer + 5

                            end
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_GET_INDEXED_VALIDATED] = {
                            name = "OPCODE_GET_INDEXED_VALIDATED",
                            handler = function(contextTable)
                                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1] )
                                addStructureElem( contextTable.codeStructElement, operand1, (contextTable.instrPointer-1 +1)*0x4, vtDword )
                                local operand2 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 2] )
                                addStructureElem( contextTable.codeStructElement, operand2, (contextTable.instrPointer-1 +2)*0x4, vtDword )
                                local operand3 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 3] )
                                addStructureElem( contextTable.codeStructElement, operand3, (contextTable.instrPointer-1 +3)*0x4, vtDword )

                                contextTable.opcodeName = contextTable.opcodeName..' '..operand3..'['..operand1..'] = '..operand2
                                
                                addLayoutStructElem( contextTable.codeStructElement, contextTable.opcodeName, 0x808040, (contextTable.instrPointer-1 )*0x4, vtDword )

                                return contextTable.instrPointer + 5

                            end
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_SET_NAMED] = {
                            name = "OPCODE_SET_NAMED",
                            handler = function(contextTable)
                                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1] )
                                addStructureElem( contextTable.codeStructElement, operand1, (contextTable.instrPointer-1 +1)*0x4, vtDword )
                                local operand2 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 2] )
                                addStructureElem( contextTable.codeStructElement, operand2, (contextTable.instrPointer-1 +2)*0x4, vtDword )
                                local operand3 = 'Globals['..contextTable.codeInts[contextTable.instrPointer+3]..']'
                                addStructureElem( contextTable.codeStructElement, operand3, (contextTable.instrPointer-1 +3)*0x4, vtDword )

                                contextTable.opcodeName = contextTable.opcodeName..' '..operand1..'["'..operand3..'"] = '..operand2
                                
                                addLayoutStructElem( contextTable.codeStructElement, contextTable.opcodeName, 0x808040, (contextTable.instrPointer-1 )*0x4, vtDword )

                                return contextTable.instrPointer + 4

                            end
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_SET_NAMED_VALIDATED] = {
                            name = "OPCODE_SET_NAMED_VALIDATED",
                            handler = function(contextTable)
                                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1] )
                                addStructureElem( contextTable.codeStructElement, operand1, (contextTable.instrPointer-1 +1)*0x4, vtDword )
                                local operand2 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 2] )
                                addStructureElem( contextTable.codeStructElement, operand2, (contextTable.instrPointer-1 +2)*0x4, vtDword )
                                local operand3 = 'setter_names['..(contextTable.codeInts[ contextTable.instrPointer+3])..']'
                                addStructureElem( contextTable.codeStructElement, operand3, (contextTable.instrPointer-1 +3)*0x4, vtDword )

                                contextTable.opcodeName = contextTable.opcodeName..' '..operand1..'["'..operand3..'"] = '..operand2
                                
                                addLayoutStructElem( contextTable.codeStructElement, contextTable.opcodeName, 0x808040, (contextTable.instrPointer-1 )*0x4, vtDword )

                                return contextTable.instrPointer + 4

                            end
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_GET_NAMED] = {
                            name = "OPCODE_GET_NAMED",
                            handler = function(contextTable)
                                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1] )
                                addStructureElem( contextTable.codeStructElement, operand1, (contextTable.instrPointer-1 +1)*0x4, vtDword )
                                local operand2 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 2] )
                                addStructureElem( contextTable.codeStructElement, operand2, (contextTable.instrPointer-1 +2)*0x4, vtDword )
                                local operand3 = 'Globals['..contextTable.codeInts[contextTable.instrPointer+3]..']'
                                addStructureElem( contextTable.codeStructElement, operand3, (contextTable.instrPointer-1 +3)*0x4, vtDword )

                                contextTable.opcodeName = contextTable.opcodeName..' '..operand2..' = '..operand1..'["'..operand3..'"]'
                                
                                addLayoutStructElem( contextTable.codeStructElement, contextTable.opcodeName, 0x808040, (contextTable.instrPointer-1 )*0x4, vtDword )

                                return contextTable.instrPointer + 4

                            end
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_GET_NAMED_VALIDATED] = {
                            name = "OPCODE_GET_NAMED_VALIDATED",
                            handler = function(contextTable)
                                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1] )
                                addStructureElem( contextTable.codeStructElement, operand1, (contextTable.instrPointer-1 +1)*0x4, vtDword )
                                local operand2 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 2] )
                                addStructureElem( contextTable.codeStructElement, operand2, (contextTable.instrPointer-1 +2)*0x4, vtDword )
                                local operand3 = 'getter_names[operand3]' --TODO
                                addStructureElem( contextTable.codeStructElement, operand3, (contextTable.instrPointer-1 +3)*0x4, vtDword )

                                contextTable.opcodeName = contextTable.opcodeName..' '..operand2..' = '..operand1..'["'..operand3..'"]'

                                addLayoutStructElem( contextTable.codeStructElement, contextTable.opcodeName, 0x808040, (contextTable.instrPointer-1 )*0x4, vtDword )

                                return contextTable.instrPointer + 4

                            end
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_SET_MEMBER] = {
                            name = "OPCODE_SET_MEMBER",
                            handler = function(contextTable)
                                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1] )
                                addStructureElem( contextTable.codeStructElement, operand1, (contextTable.instrPointer-1 +1)*0x4, vtDword )
                                local operand2 = 'Globals['..contextTable.codeInts[contextTable.instrPointer+2]..']'
                                addStructureElem( contextTable.codeStructElement, operand2, (contextTable.instrPointer-1 +2)*0x4, vtDword )

                                contextTable.opcodeName = contextTable.opcodeName..' '..'["'..operand2..'"] = '..operand1

                                addLayoutStructElem( contextTable.codeStructElement, contextTable.opcodeName, 0x808040, (contextTable.instrPointer-1 )*0x4, vtDword )

                                return contextTable.instrPointer + 3

                            end
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_GET_MEMBER] = {
                            name = "OPCODE_GET_MEMBER",
                            handler = function(contextTable)
                                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1] )
                                addStructureElem( contextTable.codeStructElement, operand1, (contextTable.instrPointer-1 +1)*0x4, vtDword )
                                local operand2 = 'Globals['..contextTable.codeInts[contextTable.instrPointer+2]..']'
                                addStructureElem( contextTable.codeStructElement, operand2, (contextTable.instrPointer-1 +2)*0x4, vtDword )

                                contextTable.opcodeName = contextTable.opcodeName..' '..operand1..' = ["'..operand2..'"]'

                                addLayoutStructElem( contextTable.codeStructElement, contextTable.opcodeName, 0x808040, (contextTable.instrPointer-1 )*0x4, vtDword )

                                return contextTable.instrPointer + 3

                            end
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_SET_STATIC_VARIABLE] = {
                            name = "OPCODE_SET_STATIC_VARIABLE",
                            handler = function(contextTable)
                                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1] )
                                addStructureElem( contextTable.codeStructElement, operand1, (contextTable.instrPointer-1 +1)*0x4, vtDword )
                                local operand2 = 'gdscript' -- TODO
                                addStructureElem( contextTable.codeStructElement, operand2, (contextTable.instrPointer-1 +2)*0x4, vtDword )
                                local operand3 = 'debug_get_static_var_by_index(operand3)'
                                addStructureElem( contextTable.codeStructElement, operand3, (contextTable.instrPointer-1 +3)*0x4, vtDword )

                                contextTable.opcodeName = contextTable.opcodeName..' script(scriptname)['..operand3..'] = '..operand1
                                
                                addLayoutStructElem( contextTable.codeStructElement, contextTable.opcodeName, 0x808040, (contextTable.instrPointer-1 )*0x4, vtDword )

                                return contextTable.instrPointer + 4

                            end
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_GET_STATIC_VARIABLE] = {
                            name = "OPCODE_GET_STATIC_VARIABLE",
                            handler = function(contextTable)
                                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1] )
                                addStructureElem( contextTable.codeStructElement, operand1, (contextTable.instrPointer-1 +1)*0x4, vtDword )
                                local operand2 = 'gdscript' -- TODO
                                addStructureElem( contextTable.codeStructElement, operand2, (contextTable.instrPointer-1 +2)*0x4, vtDword )
                                local operand3 = 'debug_get_static_var_by_index(operand3)'
                                addStructureElem( contextTable.codeStructElement, operand3, (contextTable.instrPointer-1 +3)*0x4, vtDword )

                                contextTable.opcodeName = contextTable.opcodeName..' '..operand1..' = script(scriptname)['..operand3..']'
                                
                                addLayoutStructElem( contextTable.codeStructElement, contextTable.opcodeName, 0x808040, (contextTable.instrPointer-1 )*0x4, vtDword )

                                return contextTable.instrPointer + 4

                            end
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_ASSIGN] = {
                            name = "OPCODE_ASSIGN",
                            handler = function(contextTable)
                                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1] )
                                addStructureElem( contextTable.codeStructElement, operand1, (contextTable.instrPointer-1 +1)*0x4, vtDword )
                                local operand2 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 2] )
                                addStructureElem( contextTable.codeStructElement, operand2, (contextTable.instrPointer-1 +2)*0x4, vtDword )

                                contextTable.opcodeName = contextTable.opcodeName..' '..operand1..' = '..operand2
                                
                                addLayoutStructElem( contextTable.codeStructElement, contextTable.opcodeName, 0x808040, (contextTable.instrPointer-1 )*0x4, vtDword )

                                return contextTable.instrPointer + 3

                            end
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_ASSIGN_NULL] = {
                            name = "OPCODE_ASSIGN_NULL",
                            handler = function(contextTable)
                                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1] )
                                addStructureElem( contextTable.codeStructElement, operand1, (contextTable.instrPointer-1 +1)*0x4, vtDword )

                                contextTable.opcodeName = contextTable.opcodeName..' '..operand1..' = NULL'
                                
                                addLayoutStructElem( contextTable.codeStructElement, contextTable.opcodeName, 0x808040, (contextTable.instrPointer-1 )*0x4, vtDword )

                                return contextTable.instrPointer + 2

                            end
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_ASSIGN_TRUE] = {
                            name = "OPCODE_ASSIGN_TRUE",
                            handler = function(contextTable)
                                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1] )
                                addStructureElem( contextTable.codeStructElement, operand1, (contextTable.instrPointer-1 +1)*0x4, vtDword )

                                contextTable.opcodeName = contextTable.opcodeName..' '..operand1..' = TRUE'
                                
                                addLayoutStructElem( contextTable.codeStructElement, contextTable.opcodeName, 0x808040, (contextTable.instrPointer-1 )*0x4, vtDword )

                                return contextTable.instrPointer + 2

                            end
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_ASSIGN_FALSE] = {
                            name = "OPCODE_ASSIGN_FALSE",
                            handler = function(contextTable)
                                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1] )
                                addStructureElem( contextTable.codeStructElement, operand1, (contextTable.instrPointer-1 +1)*0x4, vtDword )

                                contextTable.opcodeName = contextTable.opcodeName..' '..operand1..' = FALSE'
                                
                                addLayoutStructElem( contextTable.codeStructElement, contextTable.opcodeName, 0x808040, (contextTable.instrPointer-1 )*0x4, vtDword )

                                return contextTable.instrPointer + 2

                            end
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_ASSIGN_TYPED_BUILTIN] = {
                            name = "OPCODE_ASSIGN_TYPED_BUILTIN",
                            handler = function(contextTable)
                                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1] )
                                addStructureElem( contextTable.codeStructElement, operand1, (contextTable.instrPointer-1 +1)*0x4, vtDword )
                                local operand2 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 2] )
                                addStructureElem( contextTable.codeStructElement, operand2, (contextTable.instrPointer-1 +2)*0x4, vtDword )
                                local operand3 = getGDTypeName( contextTable.codeInts[contextTable.instrPointer + 3] )
                                addStructureElem( contextTable.codeStructElement, operand3, (contextTable.instrPointer-1 +3)*0x4, vtDword )

                                contextTable.opcodeName = contextTable.opcodeName..' ('..operand3..') '..operand1..' = '..operand2

                                addLayoutStructElem( contextTable.codeStructElement, contextTable.opcodeName, 0x808040, (contextTable.instrPointer-1 )*0x4, vtDword )

                                return contextTable.instrPointer + 4

                            end
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_ASSIGN_TYPED_ARRAY] = {
                            name = "OPCODE_ASSIGN_TYPED_ARRAY",
                            handler = function(contextTable)
                                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1] )
                                addStructureElem( contextTable.codeStructElement, operand1, (contextTable.instrPointer-1 +1)*0x4, vtDword )
                                local operand2 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 2] )
                                addStructureElem( contextTable.codeStructElement, operand2, (contextTable.instrPointer-1 +2)*0x4, vtDword )

                                contextTable.opcodeName = contextTable.opcodeName..' '..operand1..' = '..operand2

                                addLayoutStructElem( contextTable.codeStructElement, contextTable.opcodeName, 0x808040, (contextTable.instrPointer-1 )*0x4, vtDword )

                                return contextTable.instrPointer + 6

                            end
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_ASSIGN_TYPED_DICTIONARY] = {
                            name = "OPCODE_ASSIGN_TYPED_DICTIONARY",
                            handler = function(contextTable)
                                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1] )
                                addStructureElem( contextTable.codeStructElement, operand1, (contextTable.instrPointer-1 +1)*0x4, vtDword )
                                local operand2 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 2] )
                                addStructureElem( contextTable.codeStructElement, operand2, (contextTable.instrPointer-1 +2)*0x4, vtDword )

                                contextTable.opcodeName = contextTable.opcodeName..' '..operand1..' = '..operand2
                                
                                addLayoutStructElem( contextTable.codeStructElement, contextTable.opcodeName, 0x808040, (contextTable.instrPointer-1 )*0x4, vtDword )

                                return contextTable.instrPointer + 9

                            end
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_ASSIGN_TYPED_NATIVE] = {
                            name = "OPCODE_ASSIGN_TYPED_NATIVE",
                            handler = function(contextTable)
                                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1] )
                                addStructureElem( contextTable.codeStructElement, operand1, (contextTable.instrPointer-1 +1)*0x4, vtDword )
                                local operand2 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 2] )
                                addStructureElem( contextTable.codeStructElement, operand2, (contextTable.instrPointer-1 +2)*0x4, vtDword )
                                local operand3 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 3] )
                                addStructureElem( contextTable.codeStructElement, operand3, (contextTable.instrPointer-1 +3)*0x4, vtDword )

                                contextTable.opcodeName = contextTable.opcodeName..' ('..operand3..')'..operand1..' = '..operand2
                                
                                addLayoutStructElem( contextTable.codeStructElement, contextTable.opcodeName, 0x808040, (contextTable.instrPointer-1 )*0x4, vtDword )

                                return contextTable.instrPointer + 4

                            end
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_ASSIGN_TYPED_SCRIPT] = {
                            name = "OPCODE_ASSIGN_TYPED_SCRIPT",
                            handler = function(contextTable)
                                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1] )
                                addStructureElem( contextTable.codeStructElement, operand1, (contextTable.instrPointer-1 +1)*0x4, vtDword )
                                local operand2 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 2] )
                                addStructureElem( contextTable.codeStructElement, operand2, (contextTable.instrPointer-1 +2)*0x4, vtDword )
                                local operand3 = 'debug_get_script_name(get_constant(operand3))' --TODO
                                addStructureElem( contextTable.codeStructElement, operand3, (contextTable.instrPointer-1 +3)*0x4, vtDword )

                                contextTable.opcodeName = contextTable.opcodeName..' ('..operand3..') '..operand1..' = '..operand2
                                
                                addLayoutStructElem( contextTable.codeStructElement, contextTable.opcodeName, 0x808040, (contextTable.instrPointer-1 )*0x4, vtDword )

                                return contextTable.instrPointer + 4

                            end
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_CAST_TO_BUILTIN] = {
                            name = "OPCODE_CAST_TO_BUILTIN",
                            handler = function(contextTable)
                                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1] )
                                addStructureElem( contextTable.codeStructElement, operand1, (contextTable.instrPointer-1 +1)*0x4, vtDword )
                                local operand2 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 2] )
                                addStructureElem( contextTable.codeStructElement, operand2, (contextTable.instrPointer-1 +2)*0x4, vtDword )
                                local operand1_n = getGDTypeName( contextTable.codeInts[contextTable.instrPointer + 1] )

                                contextTable.opcodeName = contextTable.opcodeName..' '..operand2..' = '..operand1..' as '..operand1_n
                                
                                addLayoutStructElem( contextTable.codeStructElement, contextTable.opcodeName, 0x808040, (contextTable.instrPointer-1 )*0x4, vtDword )

                                return contextTable.instrPointer + 4

                            end
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_CAST_TO_NATIVE] = {
                            name = "OPCODE_CAST_TO_NATIVE",
                            handler = function(contextTable)
                                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1] )
                                addStructureElem( contextTable.codeStructElement, operand1, (contextTable.instrPointer-1 +1)*0x4, vtDword )
                                local operand2 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 2] )
                                addStructureElem( contextTable.codeStructElement, operand2, (contextTable.instrPointer-1 +2)*0x4, vtDword )
                                local operand3 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 3] )
                                addStructureElem( contextTable.codeStructElement, operand3, (contextTable.instrPointer-1 +3)*0x4, vtDword )

                                contextTable.opcodeName = contextTable.opcodeName..' '..operand2..' = '..operand1..' as '..operand3
                                
                                addLayoutStructElem( contextTable.codeStructElement, contextTable.opcodeName, 0x808040, (contextTable.instrPointer-1 )*0x4, vtDword )

                                return contextTable.instrPointer + 4

                            end
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_CAST_TO_SCRIPT] = {
                            name = "OPCODE_CAST_TO_SCRIPT",
                            handler = function(contextTable)
                                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1] )
                                addStructureElem( contextTable.codeStructElement, operand1, (contextTable.instrPointer-1 +1)*0x4, vtDword )
                                local operand2 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 2] )
                                addStructureElem( contextTable.codeStructElement, operand2, (contextTable.instrPointer-1 +2)*0x4, vtDword )
                                local operand3 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 3] )
                                addStructureElem( contextTable.codeStructElement, operand3, (contextTable.instrPointer-1 +3)*0x4, vtDword )

                                contextTable.opcodeName = contextTable.opcodeName..' '..operand2..' = '..operand1..' as '..operand3
                                
                                addLayoutStructElem( contextTable.codeStructElement, contextTable.opcodeName, 0x808040, (contextTable.instrPointer-1 )*0x4, vtDword )

                                return contextTable.instrPointer + 4

                            end
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_CONSTRUCT] = {
                            name = "OPCODE_CONSTRUCT",
                            handler = function(contextTable)
                                contextTable.instrPointer = contextTable.instrPointer + 1
                                local instr_var_args = contextTable.codeInts[contextTable.instrPointer]
                                addStructureElem( contextTable.codeStructElement, 'instr_var_args:', (contextTable.instrPointer-1)*0x4, vtDword )

                                local typeName = getGDTypeName( contextTable.codeInts[contextTable.instrPointer + 3 + instr_var_args] )
                                addStructureElem( contextTable.codeStructElement, typeName, (contextTable.instrPointer-1 + 3+instr_var_args)*0x4, vtDword )
                                local argc = contextTable.codeInts[contextTable.instrPointer + 1 + instr_var_args]
                                addStructureElem( contextTable.codeStructElement, 'argc:', (contextTable.instrPointer-1 + 1+instr_var_args)*0x4, vtDword )

                                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1 + argc] )
                                addStructureElem( contextTable.codeStructElement, operand1, (contextTable.instrPointer-1 + 1+argc)*0x4, vtDword )
                                local operandArg = '';
                                
                                for i=0, argc-1 do
                                    if i>0 then operandArg = operandArg..', ' end
                                    operandArg = operandArg..formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + i + 1] )
                                    addStructureElem( contextTable.codeStructElement, 'arg: '..formatDisassembledAddress( contextTable.codeInts[i + 1] ) , (contextTable.instrPointer-1 + i+1)*0x4, vtDword )    
                                end

                                contextTable.opcodeName = contextTable.opcodeName..' '..operand1..' = '..typeName..'('..operandArg..')'
                                
                                addLayoutStructElem( contextTable.codeStructElement, contextTable.opcodeName, 0x808040, (contextTable.instrPointer-1-1 )*0x4, vtDword )

                                return contextTable.instrPointer + 3 + instr_var_args

                            end
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_CONSTRUCT_VALIDATED] = {
                            name = "OPCODE_CONSTRUCT_VALIDATED",
                            handler = function(contextTable)
                                contextTable.instrPointer = contextTable.instrPointer + 1
                                local instr_var_args = contextTable.codeInts[contextTable.instrPointer]
                                addStructureElem( contextTable.codeStructElement, 'instr_var_args:', (contextTable.instrPointer-1)*0x4, vtDword )
                                local argc = contextTable.codeInts[contextTable.instrPointer + 1 + instr_var_args]
                                addStructureElem( contextTable.codeStructElement, 'argc:', (contextTable.instrPointer-1 + 1+instr_var_args)*0x4, vtDword )

                                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1 + argc] )
                                addStructureElem( contextTable.codeStructElement, operand1, (contextTable.instrPointer-1 + 1+argc)*0x4, vtDword )
                                local operandArg = '';
                                local operand3 = 'constructors_names['..(contextTable.codeInts[contextTable.instrPointer+3+argc])..']'
                                addStructureElem( contextTable.codeStructElement, operand3, (contextTable.instrPointer-1 + 3+argc)*0x4, vtDword )

                                for i=0, argc-1 do
                                    if i>0 then operandArg = operandArg..', ' end
                                    operandArg = operandArg..formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + i + 1] )
                                    addStructureElem( contextTable.codeStructElement, 'arg: '..formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + i + 1] ) , (contextTable.instrPointer-1 + i+1)*0x4, vtDword )    
                                end

                                contextTable.opcodeName = contextTable.opcodeName..' '..operand1..' = '..operand3..'('..operandArg..')'
                                
                                addLayoutStructElem( contextTable.codeStructElement, contextTable.opcodeName, 0x808040, (contextTable.instrPointer-1-1 )*0x4, vtDword )

                                return contextTable.instrPointer + 3 + instr_var_args

                            end
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_CONSTRUCT_ARRAY] = {
                            name = "OPCODE_CONSTRUCT_ARRAY",
                            handler = function(contextTable)
                                contextTable.instrPointer = contextTable.instrPointer + 1
                                local instr_var_args = contextTable.codeInts[contextTable.instrPointer]
                                addStructureElem( contextTable.codeStructElement, 'instr_var_args:', (contextTable.instrPointer-1)*0x4, vtDword )
                                local argc = contextTable.codeInts[contextTable.instrPointer + 1 + instr_var_args]
                                addStructureElem( contextTable.codeStructElement, 'argc:', (contextTable.instrPointer-1 + 1+instr_var_args)*0x4, vtDword )

                                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1 + argc] )
                                addStructureElem( contextTable.codeStructElement, operand1, (contextTable.instrPointer-1 + 1+argc)*0x4, vtDword )
                                local operandArg = '';

                                for i=0, argc-1 do
                                    if i>0 then operandArg = operandArg..', ' end
                                    operandArg = operandArg..formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + i + 1] )
                                    addStructureElem( contextTable.codeStructElement, 'arg: '..formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + i + 1] ) , (contextTable.instrPointer-1 + i+1)*0x4, vtDword )    
                                end

                                contextTable.opcodeName = contextTable.opcodeName..' '..operand1..' = '..'['..operandArg..']'

                                addLayoutStructElem( contextTable.codeStructElement, contextTable.opcodeName, 0x808040, (contextTable.instrPointer-1-1 )*0x4, vtDword )

                                return contextTable.instrPointer + 3 + instr_var_args

                            end
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_CONSTRUCT_TYPED_ARRAY] = {
                            name = "OPCODE_CONSTRUCT_TYPED_ARRAY",
                            handler = function(contextTable)
                                contextTable.instrPointer = contextTable.instrPointer + 1
                                local instr_var_args = contextTable.codeInts[contextTable.instrPointer]
                                addStructureElem( contextTable.codeStructElement, 'instr_var_args:', (contextTable.instrPointer-1)*0x4, vtDword )
                                local argc = contextTable.codeInts[contextTable.instrPointer + 1 + instr_var_args]
                                addStructureElem( contextTable.codeStructElement, 'argc:', (contextTable.instrPointer-1 + 1+instr_var_args)*0x4, vtDword )

                                local operand2 = 'get_constant('..(contextTable.codeInts[contextTable.instrPointer+argc+2] & GDF.EADDRESS["ADDR_MASK"] )..')'
                                addStructureElem( contextTable.codeStructElement, operand2, (contextTable.instrPointer-1 + argc+2)*0x4, vtDword )
                                local operand4 = getGDTypeName( contextTable.codeInts[contextTable.instrPointer + argc+4] )
                                addStructureElem( contextTable.codeStructElement, operand4, (contextTable.instrPointer-1 + argc+4)*0x4, vtDword )
                                local operand5 = 'get_global_name('..(contextTable.codeInts[contextTable.instrPointer+argc+5])..')'
                                addStructureElem( contextTable.codeStructElement, operand5, (contextTable.instrPointer-1 + argc+5)*0x4, vtDword )

                                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1 + argc] )
                                addStructureElem( contextTable.codeStructElement, operand1, (contextTable.instrPointer-1 + 1+argc)*0x4, vtDword )
                                local operandArg = '';

                                for i=0, argc-1 do
                                    if i>0 then operandArg = operandArg..', ' end
                                    operandArg = operandArg..formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + i + 1] )
                                    addStructureElem( contextTable.codeStructElement, 'arg: '..formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + i + 1] ) , (contextTable.instrPointer-1 + i+1)*0x4, vtDword )    
                                end

                                contextTable.opcodeName = contextTable.opcodeName..' ('..operand4..') '..operand1..' = '..'['..operandArg..']'

                                addLayoutStructElem( contextTable.codeStructElement, contextTable.opcodeName, 0x808040, (contextTable.instrPointer-1-1 )*0x4, vtDword )

                                return contextTable.instrPointer + 6 + instr_var_args

                            end
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_CONSTRUCT_DICTIONARY] = {
                            name = "OPCODE_CONSTRUCT_DICTIONARY",
                            handler = function(contextTable)
                                contextTable.instrPointer = contextTable.instrPointer + 1
                                local instr_var_args = contextTable.codeInts[contextTable.instrPointer]
                                addStructureElem( contextTable.codeStructElement, 'instr_var_args:', (contextTable.instrPointer-1)*0x4, vtDword )
                                local argc = contextTable.codeInts[contextTable.instrPointer + 1 + instr_var_args]
                                addStructureElem( contextTable.codeStructElement, 'argc:', (contextTable.instrPointer-1 + 1+instr_var_args)*0x4, vtDword )

                                local operand3 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1 + argc * 2] )
                                addStructureElem( contextTable.codeStructElement, operand3, (contextTable.instrPointer-1 + 1+argc*2)*0x4, vtDword )

                                local operandArg = '';

                                for i=0, argc-1 do
                                    if i>0 then operandArg = operandArg..', ' end
                                    operandArg = operandArg..formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1 + i * 2 + 0] )
                                    addStructureElem( contextTable.codeStructElement, 'argK: '..formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1 + i * 2 + 0] ) , (contextTable.instrPointer-1 + 1 + i * 2 + 0)*0x4, vtDword )
                                    operandArg = operandArg..': '..formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1 + i * 2 + 1] )
                                    addStructureElem( contextTable.codeStructElement, 'argV: '..formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1 + i * 2 + 1] ) , (contextTable.instrPointer-1 + 1 + i * 2 + 1)*0x4, vtDword )
                                end

                                contextTable.opcodeName = contextTable.opcodeName..' '..operand3..' = {'..operandArg..'}'

                                addLayoutStructElem( contextTable.codeStructElement, contextTable.opcodeName, 0x808040, (contextTable.instrPointer-1-1 )*0x4, vtDword )

                                return contextTable.instrPointer + 3 + argc * 2

                            end
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_CONSTRUCT_TYPED_DICTIONARY] = {
                            name = "OPCODE_CONSTRUCT_TYPED_DICTIONARY",
                            handler = function(contextTable)
                                contextTable.instrPointer = contextTable.instrPointer + 1
                                local instr_var_args = contextTable.codeInts[contextTable.instrPointer]
                                addStructureElem( contextTable.codeStructElement, 'instr_var_args:', (contextTable.instrPointer-1)*0x4, vtDword )
                                local argc = contextTable.codeInts[contextTable.instrPointer + 1 + instr_var_args]
                                addStructureElem( contextTable.codeStructElement, 'argc:', (contextTable.instrPointer-1 + 1+instr_var_args)*0x4, vtDword )

                                local operand2_2 = 'get_constant('..(contextTable.codeInts[contextTable.instrPointer+argc*2+2] & GDF.EADDRESS["ADDR_MASK"] )..')'
                                addStructureElem( contextTable.codeStructElement, operand2_2, (contextTable.instrPointer-1 + argc*2+2)*0x4, vtDword )
                                local operand2_5 = getGDTypeName( contextTable.codeInts[contextTable.instrPointer +  argc*2+5] )
                                addStructureElem( contextTable.codeStructElement, operand2_5, (contextTable.instrPointer-1 + argc*2+5)*0x4, vtDword )
                                local operand2_6 = 'get_global_name('..(contextTable.codeInts[contextTable.instrPointer+argc*2+6])..')'
                                addStructureElem( contextTable.codeStructElement, operand2_6, (contextTable.instrPointer-1 + argc*2+6)*0x4, vtDword )

                                local operand2_3 = 'get_constant('..(contextTable.codeInts[contextTable.instrPointer+argc*2+3] & GDF.EADDRESS["ADDR_MASK"] )..')'
                                addStructureElem( contextTable.codeStructElement, operand2_3, (contextTable.instrPointer-1 + argc*2+3)*0x4, vtDword )
                                local operand2_7 = getGDTypeName( contextTable.codeInts[contextTable.instrPointer +  argc*2+7] )
                                addStructureElem( contextTable.codeStructElement, operand2_7, (contextTable.instrPointer-1 + argc*2+7)*0x4, vtDword )
                                local operand2_8 = 'get_global_name('..(contextTable.codeInts[contextTable.instrPointer+argc*2+8])..')'
                                addStructureElem( contextTable.codeStructElement, operand2_8, (contextTable.instrPointer-1 + argc*2+8)*0x4, vtDword )

                                local operand2 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1+argc*2] )
                                addStructureElem( contextTable.codeStructElement, operand2, (contextTable.instrPointer-1 + 1+argc*2)*0x4, vtDword )

                                local operandArg = '';

                                for i=0, argc-1 do
                                    if i>0 then operandArg = operandArg..', ' end
                                    operandArg = operandArg..formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1 + i * 2 + 0] )
                                    addStructureElem( contextTable.codeStructElement, 'argK: '..formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1 + i * 2 + 0] ) , (contextTable.instrPointer-1 + 1 + i * 2 + 0)*0x4, vtDword )
                                    operandArg = operandArg..': '..formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1 + i * 2 + 1] )
                                    addStructureElem( contextTable.codeStructElement, 'argV: '..formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1 + i * 2 + 1] ) , (contextTable.instrPointer-1 + 1 + i * 2 + 1)*0x4, vtDword )
                                end

                                contextTable.opcodeName = contextTable.opcodeName..' ('..operand2_5..', '..operand2_7..') '..operand2..' = {'..operandArg..'}'

                                addLayoutStructElem( contextTable.codeStructElement, contextTable.opcodeName, 0x808040, (contextTable.instrPointer-1-1 )*0x4, vtDword )

                                return contextTable.instrPointer + 9 + argc * 2

                            end
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_CALL] = {
                            name = "OPCODE_CALL",
                            handler = function(contextTable)
                                local ret = contextTable.codeInts[contextTable.instrPointer] == GDF.CurrentDisassembler:getOPEnumFromInternalOPID( GDF.OP.OPCODE_CALL_RETURN )
                                local async = contextTable.codeInts[contextTable.instrPointer] == GDF.CurrentDisassembler:getOPEnumFromInternalOPID( GDF.OP.OPCODE_CALL_ASYNC )

                                contextTable.instrPointer = contextTable.instrPointer + 1
                                local instr_var_args = contextTable.codeInts[contextTable.instrPointer]
                                addStructureElem( contextTable.codeStructElement, 'instr_var_args:', (contextTable.instrPointer-1)*0x4, vtDword )

                                local operand2 = '';
                                local argc = contextTable.codeInts[contextTable.instrPointer + 1 + instr_var_args]
                                addStructureElem( contextTable.codeStructElement, 'argc:', (contextTable.instrPointer-1 + 1+instr_var_args)*0x4, vtDword )

                                if (ret or async) then
                                    operand2 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + argc+2] )
                                    addStructureElem( contextTable.codeStructElement, operand2, (contextTable.instrPointer-1 + argc+2)*0x4, vtDword )
                                    operand2 = operand2..' = '
                                end

                                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1+argc] )
                                addStructureElem( contextTable.codeStructElement, operand1, (contextTable.instrPointer-1 + 1+argc)*0x4, vtDword )
                                operand1 = operand1..'.'

                                -- TODO: there's value before argc and after (latter references call index from globalnames)
                                local operandArg = '';

                                for i=0, argc-1 do
                                    if i>0 then operandArg = operandArg..', ' end
                                    operandArg = operandArg..formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + i + 1] )
                                    addStructureElem( contextTable.codeStructElement, 'arg: '..formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + i+1] ) , (contextTable.instrPointer-1 + i+1)*0x4, vtDword )    
                                end

                                local operand3 = 'Globals['..(contextTable.codeInts[ contextTable.instrPointer + instr_var_args + 2 ])..']'
                                addStructureElem( contextTable.codeStructElement, operand3, (contextTable.instrPointer-1 + instr_var_args + 2)*0x4, vtDword )

                                contextTable.opcodeName = contextTable.opcodeName..' '..operand2..operand1..operand3..']'..'('..operandArg..')' -- original representation 'GlobalNames[FuncCode['..(contextTable.instrPointer-1 + instr_var_args+2)..']]'

                                addLayoutStructElem( contextTable.codeStructElement, contextTable.opcodeName, 0x808040, (contextTable.instrPointer-1-1 )*0x4, vtDword )

                                return contextTable.instrPointer + 5 + argc

                            end
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_RETURN] = {
                            name = "OPCODE_CALL_RETURN",
                            handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_ASYNC] = {
                            name = "OPCODE_CALL_ASYNC",
                            handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_UTILITY] = {
                            name = "OPCODE_CALL_UTILITY",
                            handler = function(contextTable)
                                contextTable.instrPointer = contextTable.instrPointer + 1
                                local instr_var_args = contextTable.codeInts[contextTable.instrPointer]
                                addStructureElem( contextTable.codeStructElement, 'instr_var_args:', (contextTable.instrPointer-1)*0x4, vtDword )
                                local argc = contextTable.codeInts[contextTable.instrPointer + 1 + instr_var_args]
                                addStructureElem( contextTable.codeStructElement, 'argc:', (contextTable.instrPointer-1 + 1+instr_var_args)*0x4, vtDword )

                                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1+argc] )
                                addStructureElem( contextTable.codeStructElement, operand1, (contextTable.instrPointer-1 + 1+argc)*0x4, vtDword )

                                local operandArg = '';

                                for i=0, argc-1 do
                                    if i>0 then operandArg = operandArg..', ' end
                                    operandArg = operandArg..formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + i + 1] )
                                    addStructureElem( contextTable.codeStructElement, 'arg: '..formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + i + 1] ) , (contextTable.instrPointer-1 + i+1)*0x4, vtDword )    
                                end

                                local operand2 = 'Globals['..contextTable.codeInts[contextTable.instrPointer+2+instr_var_args]..']'
                                addStructureElem( contextTable.codeStructElement, operand2, (contextTable.instrPointer-1 + 2+instr_var_args)*0x4, vtDword )

                                contextTable.opcodeName = contextTable.opcodeName..' '..operand1..' = '..operand2..'('..operandArg..')'

                                addLayoutStructElem( contextTable.codeStructElement, contextTable.opcodeName, 0x808040, (contextTable.instrPointer-1-1 )*0x4, vtDword )

                                return contextTable.instrPointer + 4 + argc

                            end
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_UTILITY_VALIDATED] = {
                            name = "OPCODE_CALL_UTILITY_VALIDATED",
                            handler = function(contextTable)
                                contextTable.instrPointer = contextTable.instrPointer + 1
                                local instr_var_args = contextTable.codeInts[contextTable.instrPointer]
                                addStructureElem( contextTable.codeStructElement, 'instr_var_args:', (contextTable.instrPointer-1)*0x4, vtDword )
                                local argc = contextTable.codeInts[contextTable.instrPointer + 1 + instr_var_args]
                                addStructureElem( contextTable.codeStructElement, 'argc:', (contextTable.instrPointer-1 + 1+instr_var_args)*0x4, vtDword )

                                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1+argc] )
                                addStructureElem( contextTable.codeStructElement, operand1, (contextTable.instrPointer-1 + 1+argc)*0x4, vtDword )

                                local operandArg = '';

                                for i=0, argc-1 do
                                    if i>0 then operandArg = operandArg..', ' end
                                    operandArg = operandArg..formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + i + 1] )
                                    addStructureElem( contextTable.codeStructElement, 'arg: '..formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + i + 1] ) , (contextTable.instrPointer-1 + i+1)*0x4, vtDword )    
                                end

                                local operand3 = 'utilities_names['..contextTable.codeInts[contextTable.instrPointer+3+argc]..']'
                                addStructureElem( contextTable.codeStructElement, operand3, (contextTable.instrPointer-1 + 3+argc)*0x4, vtDword )

                                contextTable.opcodeName = contextTable.opcodeName..' '..operand1..' = '..operand3..'('..operandArg..')'

                                addLayoutStructElem( contextTable.codeStructElement, contextTable.opcodeName, 0x808040, (contextTable.instrPointer-1-1 )*0x4, vtDword )

                                return contextTable.instrPointer + 4 + argc

                            end
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_GDSCRIPT_UTILITY] = {
                            name = "OPCODE_CALL_GDSCRIPT_UTILITY",
                            handler = function(contextTable)
                                contextTable.instrPointer = contextTable.instrPointer + 1
                                local instr_var_args = contextTable.codeInts[contextTable.instrPointer]
                                addStructureElem( contextTable.codeStructElement, 'instr_var_args:', (contextTable.instrPointer-1)*0x4, vtDword )
                                local argc = contextTable.codeInts[contextTable.instrPointer + 1 + instr_var_args]
                                addStructureElem( contextTable.codeStructElement, 'argc:', (contextTable.instrPointer-1 + 1+instr_var_args)*0x4, vtDword )
                                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1+argc] )
                                addStructureElem( contextTable.codeStructElement, operand1, (contextTable.instrPointer-1 + 1+argc)*0x4, vtDword )

                                local operandArg = '';

                                for i=0, argc-1 do
                                    if i>0 then operandArg = operandArg..', ' end
                                    operandArg = operandArg..formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + i + 1] )
                                    addStructureElem( contextTable.codeStructElement, 'arg: '..formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + i + 1] ) , (contextTable.instrPointer-1 + i+1)*0x4, vtDword )    
                                end

                                local operand3 = 'gds_utilities_names['..contextTable.codeInts[contextTable.instrPointer+3+argc]..']'
                                addStructureElem( contextTable.codeStructElement, operand3, (contextTable.instrPointer-1 + 3+argc)*0x4, vtDword )

                                contextTable.opcodeName = contextTable.opcodeName..' '..operand1..' = '..operand3..'('..operandArg..')'
                                addLayoutStructElem( contextTable.codeStructElement, contextTable.opcodeName, 0x808040, (contextTable.instrPointer-1-1 )*0x4, vtDword )

                                return contextTable.instrPointer + 4 + argc

                            end
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_BUILTIN_TYPE_VALIDATED] = {
                            name = "OPCODE_CALL_BUILTIN_TYPE_VALIDATED",
                            handler = function(contextTable)
                                contextTable.instrPointer = contextTable.instrPointer + 1
                                local instr_var_args = contextTable.codeInts[contextTable.instrPointer]
                                addStructureElem( contextTable.codeStructElement, 'instr_var_args:', (contextTable.instrPointer-1)*0x4, vtDword )
                                local argc = contextTable.codeInts[contextTable.instrPointer + 1 + instr_var_args]
                                addStructureElem( contextTable.codeStructElement, 'argc:', (contextTable.instrPointer-1 + 1+instr_var_args)*0x4, vtDword )

                                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1] )
                                addStructureElem( contextTable.codeStructElement, operand1, (contextTable.instrPointer-1 + 1)*0x4, vtDword )
                                local operand2 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 2 + argc] )
                                addStructureElem( contextTable.codeStructElement, operand2, (contextTable.instrPointer-1 + 2+argc)*0x4, vtDword )

                                local operandArg = '';

                                for i=0, argc-1 do
                                    if i>0 then operandArg = operandArg..', ' end
                                    operandArg = operandArg..formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + i + 1] )
                                    addStructureElem( contextTable.codeStructElement, 'arg: '..formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + i + 1] ) , (contextTable.instrPointer-1 + i+1)*0x4, vtDword )    
                                end

                                local operand4 = 'builtin_methods_names['..(contextTable.codeInts[contextTable.instrPointer+4+argc])..']'
                                addStructureElem( contextTable.codeStructElement, operand4, (contextTable.instrPointer-1 + 4+argc)*0x4, vtDword )

                                contextTable.opcodeName = contextTable.opcodeName..' '..operand2..' = '..operand1..'.'..operand4..'('..operandArg..')'

                                addLayoutStructElem( contextTable.codeStructElement, contextTable.opcodeName, 0x808040, (contextTable.instrPointer-1-1 )*0x4, vtDword )

                                return contextTable.instrPointer + 5 + argc

                            end
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_SELF_BASE] = {
                            name = "OPCODE_CALL_SELF_BASE",
                            handler = function(contextTable)
                                contextTable.instrPointer = contextTable.instrPointer + 1
                                local instr_var_args = contextTable.codeInts[contextTable.instrPointer]
                                addStructureElem( contextTable.codeStructElement, 'instr_var_args:', (contextTable.instrPointer-1)*0x4, vtDword )
                                local argc = contextTable.codeInts[contextTable.instrPointer + 1 + instr_var_args]
                                addStructureElem( contextTable.codeStructElement, 'argc:', (contextTable.instrPointer-1 + 1+instr_var_args)*0x4, vtDword )
                                local operand2 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 2+argc] )
                                addStructureElem( contextTable.codeStructElement, operand2, (contextTable.instrPointer-1 + 2+argc)*0x4, vtDword )

                                local operandArg = '';

                                for i=0, argc-1 do
                                    if i>0 then operandArg = operandArg..', ' end
                                    operandArg = operandArg..formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + i + 1] )
                                    addStructureElem( contextTable.codeStructElement, 'arg: '..formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + i + 1] ) , (contextTable.instrPointer-1 + i+1)*0x4, vtDword )    
                                end
                                
                                local operand3 = 'Globals['..contextTable.codeInts[contextTable.instrPointer+2+instr_var_args]..']'
                                addStructureElem( contextTable.codeStructElement, operand3, (contextTable.instrPointer-1 + 2+instr_var_args)*0x4, vtDword )

                                contextTable.opcodeName = contextTable.opcodeName..' '..operand2..' = '..operand3..'('..operandArg..')'
                                addLayoutStructElem( contextTable.codeStructElement, contextTable.opcodeName, 0x808040, (contextTable.instrPointer-1-1 )*0x4, vtDword )

                                return contextTable.instrPointer + 4 + argc

                            end
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_METHOD_BIND] = {
                            name = "OPCODE_CALL_METHOD_BIND",
                            handler = function(contextTable)
                                local ret = contextTable.codeInts[contextTable.instrPointer] == GDF.CurrentDisassembler:getOPEnumFromInternalOPID( GDF.OP.OPCODE_CALL_METHOD_BIND_RET )
                                contextTable.instrPointer = contextTable.instrPointer + 1
                                local instr_var_args = contextTable.codeInts[contextTable.instrPointer]
                                addStructureElem( contextTable.codeStructElement, 'instr_var_args:', (contextTable.instrPointer-1)*0x4, vtDword )
                                local operand2 = '';
                                local argc = contextTable.codeInts[contextTable.instrPointer + 1 + instr_var_args]
                                addStructureElem( contextTable.codeStructElement, 'argc:', (contextTable.instrPointer-1 + 1+instr_var_args)*0x4, vtDword )

                                if (ret) then
                                    operand2 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + argc+2] )
                                    addStructureElem( contextTable.codeStructElement, operand2, (contextTable.instrPointer-1 + argc+2)*0x4, vtDword )
                                    operand2 = operand2..' = '
                                end

                                local operand3 = '_methods_ptr['..contextTable.codeInts[contextTable.instrPointer+2+instr_var_args]..']' -- TODO: workaround
                                addStructureElem( contextTable.codeStructElement, operand3, (contextTable.instrPointer-1 + 2+instr_var_args)*0x4, vtDword )

                                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1+argc] )
                                addStructureElem( contextTable.codeStructElement, operand1, (contextTable.instrPointer-1 + 1+argc)*0x4, vtDword )
                                operand1 = operand1..'.'
                                operand1 = operand1..operand3..'->get_name()' --TODO
                                local operandArg = '';

                                for i=0, argc-1 do
                                    if i>0 then operandArg = operandArg..', ' end
                                    operandArg = operandArg..formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + i + 1] )
                                    addStructureElem( contextTable.codeStructElement, 'arg: '..formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + i+1] ) , (contextTable.instrPointer-1 + i+1)*0x4, vtDword )    
                                end

                                contextTable.opcodeName = contextTable.opcodeName..' '..operand2..operand1..'('..operandArg..')' --TODO retrieve the funciton name
                                addLayoutStructElem( contextTable.codeStructElement, contextTable.opcodeName, 0x808040, (contextTable.instrPointer-1-1 )*0x4, vtDword )

                                return contextTable.instrPointer + 5 + argc

                            end
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_METHOD_BIND_RET] = {
                            name = "OPCODE_CALL_METHOD_BIND_RET",
                            handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_METHOD_BIND].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_BUILTIN_STATIC] = {
                            name = "OPCODE_CALL_BUILTIN_STATIC",
                            handler = function(contextTable)
                                contextTable.instrPointer = contextTable.instrPointer + 1
                                local instr_var_args = contextTable.codeInts[contextTable.instrPointer]
                                addStructureElem( contextTable.codeStructElement, 'instr_var_args:', (contextTable.instrPointer-1)*0x4, vtDword )
                                local typeName = getGDTypeName( contextTable.codeInts[contextTable.instrPointer + 1 + instr_var_args] )
                                addStructureElem( contextTable.codeStructElement, 'typeName:', (contextTable.instrPointer-1 + 3+instr_var_args)*0x4, vtDword )

                                local argc = contextTable.codeInts[contextTable.instrPointer + 1 + instr_var_args]
                                addStructureElem( contextTable.codeStructElement, 'argc:', (contextTable.instrPointer-1 + 1+instr_var_args)*0x4, vtDword )

                                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1 + argc] )
                                addStructureElem( contextTable.codeStructElement, operand1, (contextTable.instrPointer-1 + 1+argc)*0x4, vtDword )
                                local operandArg = '';

                                for i=0, argc-1 do
                                    if i>0 then operandArg = operandArg..', ' end
                                    operandArg = operandArg..formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + i + 1] )
                                    addStructureElem( contextTable.codeStructElement, 'arg: '..formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + i + 1] ) , (contextTable.instrPointer-1 + i+1)*0x4, vtDword )    
                                end

                                local operand2 = 'Globals['..contextTable.codeInts[contextTable.instrPointer+2+instr_var_args]..']'
                                addStructureElem( contextTable.codeStructElement, operand2, (contextTable.instrPointer-1 + 2+instr_var_args)*0x4, vtDword )

                                contextTable.opcodeName = contextTable.opcodeName..' '..operand1..' = '..typeName..'.'..operand2..'.operator String()'..'('..operandArg..')'

                                addLayoutStructElem( contextTable.codeStructElement, contextTable.opcodeName, 0x808040, (contextTable.instrPointer-1-1 )*0x4, vtDword )

                                return contextTable.instrPointer + 5 + argc

                            end
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_NATIVE_STATIC] = {
                            name = "OPCODE_CALL_NATIVE_STATIC",
                            handler = function(contextTable)
                                contextTable.instrPointer = contextTable.instrPointer + 1
                                local instr_var_args = contextTable.codeInts[contextTable.instrPointer]
                                addStructureElem( contextTable.codeStructElement, 'instr_var_args:', (contextTable.instrPointer-1)*0x4, vtDword )
                                local argc = contextTable.codeInts[contextTable.instrPointer + 2 + instr_var_args]
                                addStructureElem( contextTable.codeStructElement, 'argc:', (contextTable.instrPointer-1 + 2+instr_var_args)*0x4, vtDword )

                                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1 + argc] )
                                addStructureElem( contextTable.codeStructElement, operand1, (contextTable.instrPointer-1 + 1+argc)*0x4, vtDword )
                                local operandArg = '';

                                for i=0, argc-1 do
                                    if i>0 then operandArg = operandArg..', ' end
                                    operandArg = operandArg..formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + i + 1] )
                                    addStructureElem( contextTable.codeStructElement, 'arg: '..formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + i + 1] ) , (contextTable.instrPointer-1 + i+1)*0x4, vtDword )    
                                end

                                contextTable.opcodeName = contextTable.opcodeName..' '..operand1..' = '..'method->get_instance_class()'..'.'..'method->get_name()'..'('..operandArg..')'

                                addLayoutStructElem( contextTable.codeStructElement, contextTable.opcodeName, 0x808040, (contextTable.instrPointer-1-1 )*0x4, vtDword )

                                return contextTable.instrPointer + 4 + argc

                            end
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_NATIVE_STATIC_VALIDATED_RETURN] = {
                            name = "OPCODE_CALL_NATIVE_STATIC_VALIDATED_RETURN",
                            handler = function(contextTable)
                                contextTable.instrPointer = contextTable.instrPointer + 1
                                local instr_var_args = contextTable.codeInts[contextTable.instrPointer]
                                addStructureElem( contextTable.codeStructElement, 'instr_var_args:', (contextTable.instrPointer-1)*0x4, vtDword )
                                local argc = contextTable.codeInts[contextTable.instrPointer + 1 + instr_var_args]
                                addStructureElem( contextTable.codeStructElement, 'argc:', (contextTable.instrPointer-1 + 1+instr_var_args)*0x4, vtDword )

                                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1 + argc] )
                                addStructureElem( contextTable.codeStructElement, operand1, (contextTable.instrPointer-1 + 1+argc)*0x4, vtDword )
                                local operandArg = '';

                                for i=0, argc-1 do
                                    if i>0 then operandArg = operandArg..', ' end
                                    operandArg = operandArg..formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + i + 1] )
                                    addStructureElem( contextTable.codeStructElement, 'arg: '..formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + i + 1] ) , (contextTable.instrPointer-1 + i+1)*0x4, vtDword )    
                                end

                                contextTable.opcodeName = contextTable.opcodeName..' '..operand1..' = '..'method->get_instance_class()'..'.'..'method->get_name()'..'('..operandArg..')'

                                addLayoutStructElem( contextTable.codeStructElement, contextTable.opcodeName, 0x808040, (contextTable.instrPointer-1-1 )*0x4, vtDword )

                                return contextTable.instrPointer + 4 + argc

                            end
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_NATIVE_STATIC_VALIDATED_NO_RETURN] = {
                            name = "OPCODE_CALL_NATIVE_STATIC_VALIDATED_NO_RETURN",
                            handler = function(contextTable)
                                contextTable.instrPointer = contextTable.instrPointer + 1
                                local instr_var_args = contextTable.codeInts[contextTable.instrPointer]
                                addStructureElem( contextTable.codeStructElement, 'instr_var_args:', (contextTable.instrPointer-1)*0x4, vtDword )
                                local argc = contextTable.codeInts[contextTable.instrPointer + 1 + instr_var_args]
                                addStructureElem( contextTable.codeStructElement, 'argc:', (contextTable.instrPointer-1 + 1+instr_var_args)*0x4, vtDword )

                                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1 + argc] )
                                addStructureElem( contextTable.codeStructElement, operand1, (contextTable.instrPointer-1 + 1+argc)*0x4, vtDword )
                                local operandArg = '';

                                for i=0, argc-1 do
                                    if i>0 then operandArg = operandArg..', ' end
                                    operandArg = operandArg..formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + i + 1] )
                                    addStructureElem( contextTable.codeStructElement, 'arg: '..formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + i + 1] ) , (contextTable.instrPointer-1 + i+1)*0x4, vtDword )    
                                end

                                contextTable.opcodeName = contextTable.opcodeName..' '..operand1..' = '..'method->get_instance_class()'..'.'..'method->get_name()'..'('..operandArg..')'

                                addLayoutStructElem( contextTable.codeStructElement, contextTable.opcodeName, 0x808040, (contextTable.instrPointer-1-1 )*0x4, vtDword )

                                return contextTable.instrPointer + 4 + argc

                            end
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_METHOD_BIND_VALIDATED_RETURN] = {
                            name = "OPCODE_CALL_METHOD_BIND_VALIDATED_RETURN",
                            handler = function(contextTable)
                                contextTable.instrPointer = contextTable.instrPointer + 1
                                local instr_var_args = contextTable.codeInts[contextTable.instrPointer]
                                addStructureElem( contextTable.codeStructElement, 'instr_var_args:', (contextTable.instrPointer-1)*0x4, vtDword )
                                local argc = contextTable.codeInts[contextTable.instrPointer + 1 + instr_var_args]
                                addStructureElem( contextTable.codeStructElement, 'argc:', (contextTable.instrPointer-1 + 1+instr_var_args)*0x4, vtDword )

                                local operand2 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 2 + argc] )
                                addStructureElem( contextTable.codeStructElement, operand2, (contextTable.instrPointer-1 + 2+argc)*0x4, vtDword )

                                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1 + argc] )
                                addStructureElem( contextTable.codeStructElement, operand1, (contextTable.instrPointer-1 + 1+argc)*0x4, vtDword )
                                local operandArg = '';

                                for i=0, argc-1 do
                                    if i>0 then operandArg = operandArg..', ' end
                                    operandArg = operandArg..formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + i + 1] )
                                    addStructureElem( contextTable.codeStructElement, 'arg: '..formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + i + 1] ) , (contextTable.instrPointer-1 + i+1)*0x4, vtDword )    
                                end

                                local operand3 = '_methods_ptr['..contextTable.codeInts[contextTable.instrPointer+2+instr_var_args]..']' -- TODO: workaround
                                addStructureElem( contextTable.codeStructElement, operand3, (contextTable.instrPointer-1 + 2+instr_var_args)*0x4, vtDword )

                                contextTable.opcodeName = contextTable.opcodeName..' '..operand2..' = '..operand1..'.'..operand3..'->get_name()'..'('..operandArg..')'

                                addLayoutStructElem( contextTable.codeStructElement, contextTable.opcodeName, 0x808040, (contextTable.instrPointer-1-1 )*0x4, vtDword )

                                return contextTable.instrPointer + 5 + argc

                            end
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_METHOD_BIND_VALIDATED_NO_RETURN] = {
                            name = "OPCODE_CALL_METHOD_BIND_VALIDATED_NO_RETURN",
                            handler = function(contextTable)
                                contextTable.instrPointer = contextTable.instrPointer + 1
                                local instr_var_args = contextTable.codeInts[contextTable.instrPointer]
                                addStructureElem( contextTable.codeStructElement, 'instr_var_args:', (contextTable.instrPointer-1)*0x4, vtDword )
                                local argc = contextTable.codeInts[contextTable.instrPointer + 1 + instr_var_args]
                                addStructureElem( contextTable.codeStructElement, 'argc:', (contextTable.instrPointer-1 + 1+instr_var_args)*0x4, vtDword )

                                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1 + argc] )
                                addStructureElem( contextTable.codeStructElement, operand1, (contextTable.instrPointer-1 + 1+argc)*0x4, vtDword )
                                local operandArg = '';

                                for i=0, argc-1 do
                                    if i>0 then operandArg = operandArg..', ' end
                                    operandArg = operandArg..formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + i + 1] )
                                    addStructureElem( contextTable.codeStructElement, 'arg: '..formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + i + 1] ) , (contextTable.instrPointer-1 + i+1)*0x4, vtDword )    
                                end

                                local operand3 = '_methods_ptr['..contextTable.codeInts[contextTable.instrPointer+2+instr_var_args]..']' -- TODO: workaround
                                addStructureElem( contextTable.codeStructElement, operand3, (contextTable.instrPointer-1 + 2+instr_var_args)*0x4, vtDword )

                                contextTable.opcodeName = contextTable.opcodeName..' '..operand1..'.'..operand3..'->get_name()'..'('..operandArg..')'

                                addLayoutStructElem( contextTable.codeStructElement, contextTable.opcodeName, 0x808040, (contextTable.instrPointer-1-1 )*0x4, vtDword )

                                return contextTable.instrPointer + 5 + argc

                            end
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_AWAIT] = {
                            name = "OPCODE_AWAIT",
                            handler = function(contextTable)
                                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1] )
                                addStructureElem( contextTable.codeStructElement, operand1, (contextTable.instrPointer-1 + 1)*0x4, vtDword )
                                contextTable.opcodeName = contextTable.opcodeName..' '..operand1

                                addLayoutStructElem( contextTable.codeStructElement, contextTable.opcodeName, 0x808040, (contextTable.instrPointer-1 )*0x4, vtDword )
                                return contextTable.instrPointer + 2

                            end
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_AWAIT_RESUME] = {
                            name = "OPCODE_AWAIT_RESUME",
                            handler = GDF.DisasmHandlers[GDF.OP.OPCODE_AWAIT].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_CREATE_LAMBDA] = {
                            name = "OPCODE_CREATE_LAMBDA",
                            handler = function(contextTable)
                                contextTable.instrPointer = contextTable.instrPointer + 1
                                local instr_var_args = contextTable.codeInts[contextTable.instrPointer]
                                addStructureElem( contextTable.codeStructElement, 'instr_var_args:', (contextTable.instrPointer-1)*0x4, vtDword )
                                
                                local operand2 = '_lambdas_ptr['(contextTable.codeInts[contextTable.instrPointer+2+instr_var_args])']'
                                addStructureElem( contextTable.codeStructElement, operand2, (contextTable.instrPointer-1 + 2+instr_var_args)*0x4, vtDword )
                                local captures_count = contextTable.codeInts[contextTable.instrPointer + 1 + instr_var_args]
                                addStructureElem( contextTable.codeStructElement, 'argc:', (contextTable.instrPointer-1 + 1+instr_var_args)*0x4, vtDword )
                                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1+captures_count] )
                                addStructureElem( contextTable.codeStructElement, operand1, (contextTable.instrPointer-1 + 1+captures_count)*0x4, vtDword )

                                local operandArg = '';

                                for i=0, captures_count-1 do
                                    if i>0 then operandArg = operandArg..', ' end
                                    operandArg = operandArg..formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + i + 1] )
                                    addStructureElem( contextTable.codeStructElement, 'captures_count: '..formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + i + 1] ) , (contextTable.instrPointer-1 + i+1)*0x4, vtDword )    
                                end

                                contextTable.opcodeName = contextTable.opcodeName..' '..operand1..' create lambda from '..operand2..'->name.operator String()'..' function, captures ('..operandArg..')'
                                addLayoutStructElem( contextTable.codeStructElement, contextTable.opcodeName, 0x808040, (contextTable.instrPointer-1-1 )*0x4, vtDword )

                                return contextTable.instrPointer + 4 + captures_count

                            end
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_CREATE_SELF_LAMBDA] = {
                            name = "OPCODE_CREATE_SELF_LAMBDA",
                            handler = function(contextTable)
                                contextTable.instrPointer = contextTable.instrPointer + 1
                                local instr_var_args = contextTable.codeInts[contextTable.instrPointer]
                                addStructureElem( contextTable.codeStructElement, 'instr_var_args:', (contextTable.instrPointer-1)*0x4, vtDword )
                                local operand2 = '_lambdas_ptr['..(contextTable.codeInts[contextTable.instrPointer+2+instr_var_args])..']'
                                addStructureElem( contextTable.codeStructElement, operand2, (contextTable.instrPointer-1 + 2+instr_var_args)*0x4, vtDword )
                                local captures_count = contextTable.codeInts[contextTable.instrPointer + 1 + instr_var_args]
                                addStructureElem( contextTable.codeStructElement, 'argc:', (contextTable.instrPointer-1 + 1+instr_var_args)*0x4, vtDword )
                                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1+captures_count] )
                                addStructureElem( contextTable.codeStructElement, operand1, (contextTable.instrPointer-1 + 1+captures_count)*0x4, vtDword )

                                local operandArg = '';

                                for i=0, captures_count-1 do
                                    if i>0 then operandArg = operandArg..', ' end
                                    operandArg = operandArg..formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + i + 1] )
                                    addStructureElem( contextTable.codeStructElement, 'captures_count: '..formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + i + 1] ) , (contextTable.instrPointer-1 + i+1)*0x4, vtDword )    
                                end

                                contextTable.opcodeName = contextTable.opcodeName..' '..operand1..' create lambda from '..operand2..'->name.operator String()'..' function, captures ('..operandArg..')'
                                addLayoutStructElem( contextTable.codeStructElement, contextTable.opcodeName, 0x808040, (contextTable.instrPointer-1-1 )*0x4, vtDword )

                                return contextTable.instrPointer + 4 + captures_count

                            end
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_JUMP] = {
                            name = "OPCODE_JUMP",
                            handler = function(contextTable)
                                local operand1 = ("%X"):format( contextTable.codeInts[contextTable.instrPointer + 1] * 0x4 ) -- where to jump in hex representation, 4byte step
                                local elem = addStructureElem( contextTable.codeStructElement, "JUMP to "..operand1, (contextTable.instrPointer-1 + 1)*0x4, vtDword )
                                elem.DisplayMethod = 'dtHexadecimal'
                                elem.ShowAsHex = true
                                contextTable.opcodeName = contextTable.opcodeName..' -> '..operand1

                                addLayoutStructElem( contextTable.codeStructElement, contextTable.opcodeName, 0x808040, (contextTable.instrPointer-1 )*0x4, vtDword )

                                return contextTable.instrPointer + 2

                            end
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_JUMP_IF] = {
                            name = "OPCODE_JUMP_IF",
                            handler = function(contextTable)
                                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1] )
                                addStructureElem( contextTable.codeStructElement, operand1, (contextTable.instrPointer-1 +1)*0x4, vtDword )

                                local operand2 = ("%X"):format( contextTable.codeInts[contextTable.instrPointer + 2] * 0x4 ) -- where to jump
                                local elem = addStructureElem( contextTable.codeStructElement, "JUMP to "..operand2, (contextTable.instrPointer-1 + 2)*0x4, vtDword )
                                elem.DisplayMethod = 'dtHexadecimal'
                                elem.ShowAsHex = true
                                contextTable.opcodeName = contextTable.opcodeName..' '..operand1..' -> '..operand2

                                addLayoutStructElem( contextTable.codeStructElement, contextTable.opcodeName, 0x808040, (contextTable.instrPointer-1 )*0x4, vtDword )

                                return contextTable.instrPointer + 3

                            end
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_JUMP_IF_NOT] = {
                            name = "OPCODE_JUMP_IF_NOT",
                            handler = GDF.DisasmHandlers[GDF.OP.OPCODE_JUMP_IF].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_JUMP_TO_DEF_ARGUMENT] = {
                            name = "OPCODE_JUMP_TO_DEF_ARGUMENT",
                            handler = function(contextTable)
                                addLayoutStructElem( contextTable.codeStructElement, contextTable.opcodeName, 0x808040, (contextTable.instrPointer-1 )*0x4, vtDword )
                                return contextTable.instrPointer + 1

                            end
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_JUMP_IF_SHARED] = {
                            name = "OPCODE_JUMP_IF_SHARED",
                            handler = GDF.DisasmHandlers[GDF.OP.OPCODE_JUMP_IF].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_RETURN] = {
                            name = "OPCODE_RETURN",
                            handler = function(contextTable)
                                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1] )
                                addStructureElem( contextTable.codeStructElement, operand1, (contextTable.instrPointer-1 +1)*0x4, vtDword )
                                contextTable.opcodeName = contextTable.opcodeName..' '..operand1
                                addLayoutStructElem( contextTable.codeStructElement, contextTable.opcodeName, 0x808040, (contextTable.instrPointer-1 )*0x4, vtDword )

                                return contextTable.instrPointer + 2

                            end
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_RETURN_TYPED_BUILTIN] = {
                            name = "OPCODE_RETURN_TYPED_BUILTIN",
                            handler = function(contextTable)
                                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1] )
                                addStructureElem( contextTable.codeStructElement, operand1, (contextTable.instrPointer-1 +1)*0x4, vtDword )
                                local operand2 = getGDTypeName( contextTable.codeInts[contextTable.instrPointer + 2] )
                                addStructureElem( contextTable.codeStructElement, operand2, (contextTable.instrPointer-1 +2)*0x4, vtDword )

                                contextTable.opcodeName = contextTable.opcodeName..' ('..operand2..')'..' '..operand1
                                addLayoutStructElem( contextTable.codeStructElement, contextTable.opcodeName, 0x808040, (contextTable.instrPointer-1 )*0x4, vtDword )

                                return contextTable.instrPointer + 3

                            end
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_RETURN_TYPED_ARRAY] = {
                            name = "OPCODE_RETURN_TYPED_ARRAY",
                            handler = function(contextTable)
                                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1] )
                                addStructureElem( contextTable.codeStructElement, operand1, (contextTable.instrPointer-1 +1)*0x4, vtDword )

                                contextTable.opcodeName = contextTable.opcodeName..' '..operand1
                                addLayoutStructElem( contextTable.codeStructElement, contextTable.opcodeName, 0x808040, (contextTable.instrPointer-1 )*0x4, vtDword )

                                return contextTable.instrPointer + 5

                            end
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_RETURN_TYPED_DICTIONARY] = {
                            name = "OPCODE_RETURN_TYPED_DICTIONARY",
                            handler = function(contextTable)
                                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1] )
                                addStructureElem( contextTable.codeStructElement, operand1, (contextTable.instrPointer-1 +1)*0x4, vtDword )

                                contextTable.opcodeName = contextTable.opcodeName..' '..operand1
                                addLayoutStructElem( contextTable.codeStructElement, contextTable.opcodeName, 0x808040, (contextTable.instrPointer-1 )*0x4, vtDword )

                                return contextTable.instrPointer + 8

                            end
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_RETURN_TYPED_NATIVE] = {
                            name = "OPCODE_RETURN_TYPED_NATIVE",
                            handler = function(contextTable)
                                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1] )
                                addStructureElem( contextTable.codeStructElement, operand1, (contextTable.instrPointer-1 +1)*0x4, vtDword )
                                local operand2 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 2] )
                                addStructureElem( contextTable.codeStructElement, operand2, (contextTable.instrPointer-1 +2)*0x4, vtDword )

                                contextTable.opcodeName = contextTable.opcodeName..' ('..operand2..') '..operand1
                                addLayoutStructElem( contextTable.codeStructElement, contextTable.opcodeName, 0x808040, (contextTable.instrPointer-1 )*0x4, vtDword )

                                return contextTable.instrPointer + 3

                            end
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_RETURN_TYPED_SCRIPT] = {
                            name = "OPCODE_RETURN_TYPED_SCRIPT",
                            handler = function(contextTable)
                                
                                local operand2 = 'get_constant('..(contextTable.codeInts[contextTable.instrPointer+2] & GDF.EADDRESS["ADDR_MASK"] )..')'
                                addStructureElem( contextTable.codeStructElement, operand2, (contextTable.instrPointer-1 +2)*0x4, vtDword )

                                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1] )
                                addStructureElem( contextTable.codeStructElement, operand1, (contextTable.instrPointer-1 +1)*0x4, vtDword )

                                contextTable.opcodeName = contextTable.opcodeName..' ('..'GDScript::debug_get_script_name('..operand2..')'..') '..operand1
                                addLayoutStructElem( contextTable.codeStructElement, contextTable.opcodeName, 0x808040, (contextTable.instrPointer-1 )*0x4, vtDword )

                                return contextTable.instrPointer + 3

                            end
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN] = {
                            name = "OPCODE_ITERATE_BEGIN",
                            handler = function(contextTable)
                                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1] )
                                addStructureElem( contextTable.codeStructElement, operand1, (contextTable.instrPointer-1 +1)*0x4, vtDword )
                                local operand2 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 2] )
                                addStructureElem( contextTable.codeStructElement, operand2, (contextTable.instrPointer-1 +2)*0x4, vtDword )
                                local operand3 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 3] )
                                addStructureElem( contextTable.codeStructElement, operand3, (contextTable.instrPointer-1 +3)*0x4, vtDword )
                                addStructureElem( contextTable.codeStructElement, 'end: ', (contextTable.instrPointer-1 +4)*0x4, vtDword )

                                contextTable.opcodeName = contextTable.opcodeName..' for-init '..operand3..' in '..operand2..' counter '..operand1..' end '..tostring(contextTable.codeInts[contextTable.instrPointer + 4])
                                addLayoutStructElem( contextTable.codeStructElement, contextTable.opcodeName, 0x808040, (contextTable.instrPointer-1 )*0x4, vtDword )

                                return contextTable.instrPointer + 5

                            end
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_INT] = {
                            name = "OPCODE_ITERATE_BEGIN_INT",
                            handler = function(contextTable)
                                    local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1] )
                                    addStructureElem( contextTable.codeStructElement, operand1, (contextTable.instrPointer-1 +1)*0x4, vtDword )
                                    local operand2 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 2] )
                                    addStructureElem( contextTable.codeStructElement, operand2, (contextTable.instrPointer-1 +2)*0x4, vtDword )
                                    local operand3 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 3] )
                                    addStructureElem( contextTable.codeStructElement, operand3, (contextTable.instrPointer-1 +3)*0x4, vtDword )
                                    addStructureElem( contextTable.codeStructElement, 'end: ', (contextTable.instrPointer-1 +4)*0x4, vtDword )

                                    local opcodeType = contextTable.opcodeName:gsub('OPCODE_ITERATE_BEGIN_','')
                                    contextTable.opcodeName = contextTable.opcodeName..' for-init (typed '..opcodeType..') '..operand3..' in '..operand2..' counter '..operand1..' end '..tostring(contextTable.codeInts[contextTable.instrPointer + 4])
                                    addLayoutStructElem( contextTable.codeStructElement, contextTable.opcodeName, 0x808040, (contextTable.instrPointer-1 )*0x4, vtDword )

                                    return contextTable.instrPointer + 5

                            end
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_FLOAT] = {
                            name = "OPCODE_ITERATE_BEGIN_FLOAT",
                            handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_INT].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_VECTOR2] = {
                            name = "OPCODE_ITERATE_BEGIN_VECTOR2",
                            handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_INT].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_VECTOR2I] = {
                            name = "OPCODE_ITERATE_BEGIN_VECTOR2I",
                            handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_INT].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_VECTOR3] = {
                            name = "OPCODE_ITERATE_BEGIN_VECTOR3",
                            handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_INT].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_VECTOR3I] = {
                            name = "OPCODE_ITERATE_BEGIN_VECTOR3I",
                            handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_INT].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_STRING] = {
                            name = "OPCODE_ITERATE_BEGIN_STRING",
                            handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_INT].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_DICTIONARY] = {
                            name = "OPCODE_ITERATE_BEGIN_DICTIONARY",
                            handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_INT].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_ARRAY] = {
                            name = "OPCODE_ITERATE_BEGIN_ARRAY",
                            handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_INT].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_PACKED_BYTE_ARRAY] = {
                            name = "OPCODE_ITERATE_BEGIN_PACKED_BYTE_ARRAY",
                            handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_INT].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_PACKED_INT32_ARRAY] = {
                            name = "OPCODE_ITERATE_BEGIN_PACKED_INT32_ARRAY",
                            handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_INT].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_PACKED_INT64_ARRAY] = {
                            name = "OPCODE_ITERATE_BEGIN_PACKED_INT64_ARRAY",
                            handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_INT].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_PACKED_FLOAT32_ARRAY] = {
                            name = "OPCODE_ITERATE_BEGIN_PACKED_FLOAT32_ARRAY",
                            handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_INT].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_PACKED_FLOAT64_ARRAY] = {
                            name = "OPCODE_ITERATE_BEGIN_PACKED_FLOAT64_ARRAY",
                            handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_INT].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_PACKED_STRING_ARRAY] = {
                            name = "OPCODE_ITERATE_BEGIN_PACKED_STRING_ARRAY",
                            handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_INT].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_PACKED_VECTOR2_ARRAY] = {
                            name = "OPCODE_ITERATE_BEGIN_PACKED_VECTOR2_ARRAY",
                            handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_INT].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_PACKED_VECTOR3_ARRAY] = {
                            name = "OPCODE_ITERATE_BEGIN_PACKED_VECTOR3_ARRAY",
                            handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_INT].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_PACKED_COLOR_ARRAY] = {
                            name = "OPCODE_ITERATE_BEGIN_PACKED_COLOR_ARRAY",
                            handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_INT].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_PACKED_VECTOR4_ARRAY] = {
                            name = "OPCODE_ITERATE_BEGIN_PACKED_VECTOR4_ARRAY",
                            handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_INT].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_OBJECT] = {
                            name = "OPCODE_ITERATE_BEGIN_OBJECT",
                            handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_INT].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_RANGE] = {
                            name = "OPCODE_ITERATE_BEGIN_RANGE",
                            handler = function(contextTable)
                                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1] )
                                addStructureElem( contextTable.codeStructElement, operand1, (contextTable.instrPointer-1 +1)*0x4, vtDword )

                                local operand2 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 2] )
                                addStructureElem( contextTable.codeStructElement, operand2, (contextTable.instrPointer-1 +2)*0x4, vtDword )

                                local operand3 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 3] )
                                addStructureElem( contextTable.codeStructElement, operand3, (contextTable.instrPointer-1 +3)*0x4, vtDword )

                                local operand4 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 4] )
                                addStructureElem( contextTable.codeStructElement, operand4, (contextTable.instrPointer-1 +4)*0x4, vtDword )

                                local operand5 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 5] )
                                addStructureElem( contextTable.codeStructElement, operand5, (contextTable.instrPointer-1 +5)*0x4, vtDword )

                                addStructureElem( contextTable.codeStructElement, 'end: ', (contextTable.instrPointer-1 +4)*0x4, vtDword )

                                contextTable.opcodeName = contextTable.opcodeName..' for-init '..operand5..' in range from '..operand2..' to '..operand3..' step '..operand4..' counter '..operand1..' end '..tostring(contextTable.codeInts[contextTable.instrPointer + 4])
                                addLayoutStructElem( contextTable.codeStructElement, contextTable.opcodeName, 0x808040, (contextTable.instrPointer-1 )*0x4, vtDword )

                                return contextTable.instrPointer + 7

                            end
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE] = {
                            name = "OPCODE_ITERATE",
                            handler = function(contextTable)
                                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1] )
                                addStructureElem( contextTable.codeStructElement, operand1, (contextTable.instrPointer-1 +1)*0x4, vtDword )
                                local operand2 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 2] )
                                addStructureElem( contextTable.codeStructElement, operand2, (contextTable.instrPointer-1 +2)*0x4, vtDword )
                                local operand3 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 3] )
                                addStructureElem( contextTable.codeStructElement, operand3, (contextTable.instrPointer-1 +3)*0x4, vtDword )
                                addStructureElem( contextTable.codeStructElement, 'end: ', (contextTable.instrPointer-1 +4)*0x4, vtDword )

                                contextTable.opcodeName = contextTable.opcodeName..' for-loop '..operand2..' in '..operand2..' counter '..operand1..' end '..tostring(contextTable.codeInts[contextTable.instrPointer + 4])
                                addLayoutStructElem( contextTable.codeStructElement, contextTable.opcodeName, 0x808040, (contextTable.instrPointer-1 )*0x4, vtDword )

                                return contextTable.instrPointer + 5

                            end
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_INT] = {
                            name = "OPCODE_ITERATE_INT",
                            handler = function(contextTable)
                                    local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1] )
                                    addStructureElem( contextTable.codeStructElement, operand1, (contextTable.instrPointer-1 +1)*0x4, vtDword )
                                    local operand2 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 2] )
                                    addStructureElem( contextTable.codeStructElement, operand2, (contextTable.instrPointer-1 +2)*0x4, vtDword )
                                    local operand3 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 3] )
                                    addStructureElem( contextTable.codeStructElement, operand3, (contextTable.instrPointer-1 +3)*0x4, vtDword )
                                    addStructureElem( contextTable.codeStructElement, 'end: ', (contextTable.instrPointer-1 +4)*0x4, vtDword )

                                    local opcodeType = contextTable.opcodeName:gsub('OPCODE_ITERATE_','')
                                    contextTable.opcodeName = contextTable.opcodeName..' for-init (typed '..opcodeType..') '..operand3..' in '..operand2..' counter '..operand1..' end '..tostring(contextTable.codeInts[contextTable.instrPointer + 4])
                                    addLayoutStructElem( contextTable.codeStructElement, contextTable.opcodeName, 0x808040, (contextTable.instrPointer-1 )*0x4, vtDword )

                                    return contextTable.instrPointer + 5

                            end
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_FLOAT] = {
                            name = "OPCODE_ITERATE_FLOAT",
                            handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_INT].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_VECTOR2] = {
                            name = "OPCODE_ITERATE_VECTOR2",
                            handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_INT].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_VECTOR2I] = {
                            name = "OPCODE_ITERATE_VECTOR2I",
                            handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_INT].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_VECTOR3] = {
                            name = "OPCODE_ITERATE_VECTOR3",
                            handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_INT].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_VECTOR3I] = {
                            name = "OPCODE_ITERATE_VECTOR3I",
                            handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_INT].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_STRING] = {
                            name = "OPCODE_ITERATE_STRING",
                            handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_INT].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_DICTIONARY] = {
                            name = "OPCODE_ITERATE_DICTIONARY",
                            handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_INT].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_ARRAY] = {
                            name = "OPCODE_ITERATE_ARRAY",
                            handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_INT].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_PACKED_BYTE_ARRAY] = {
                            name = "OPCODE_ITERATE_PACKED_BYTE_ARRAY",
                            handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_INT].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_PACKED_INT32_ARRAY] = {
                            name = "OPCODE_ITERATE_PACKED_INT32_ARRAY",
                            handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_INT].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_PACKED_INT64_ARRAY] = {
                            name = "OPCODE_ITERATE_PACKED_INT64_ARRAY",
                            handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_INT].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_PACKED_FLOAT32_ARRAY] = {
                            name = "OPCODE_ITERATE_PACKED_FLOAT32_ARRAY",
                            handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_INT].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_PACKED_FLOAT64_ARRAY] = {
                            name = "OPCODE_ITERATE_PACKED_FLOAT64_ARRAY",
                            handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_INT].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_PACKED_STRING_ARRAY] = {
                            name = "OPCODE_ITERATE_PACKED_STRING_ARRAY",
                            handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_INT].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_PACKED_VECTOR2_ARRAY] = {
                            name = "OPCODE_ITERATE_PACKED_VECTOR2_ARRAY",
                            handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_INT].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_PACKED_VECTOR3_ARRAY] = {
                            name = "OPCODE_ITERATE_PACKED_VECTOR3_ARRAY",
                            handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_INT].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_PACKED_COLOR_ARRAY] = {
                            name = "OPCODE_ITERATE_PACKED_COLOR_ARRAY",
                            handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_INT].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_PACKED_VECTOR4_ARRAY] = {
                            name = "OPCODE_ITERATE_PACKED_VECTOR4_ARRAY",
                            handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_INT].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_OBJECT] = {
                            name = "OPCODE_ITERATE_OBJECT",
                            handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_INT].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_RANGE] = {
                            name = "OPCODE_ITERATE_RANGE",
                            handler = function(contextTable)
                                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1] )
                                addStructureElem( contextTable.codeStructElement, operand1, (contextTable.instrPointer-1 +1)*0x4, vtDword )

                                local operand2 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 2] )
                                addStructureElem( contextTable.codeStructElement, operand2, (contextTable.instrPointer-1 +2)*0x4, vtDword )

                                local operand3 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 3] )
                                addStructureElem( contextTable.codeStructElement, operand3, (contextTable.instrPointer-1 +3)*0x4, vtDword )

                                local operand4 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 4] )
                                addStructureElem( contextTable.codeStructElement, operand4, (contextTable.instrPointer-1 +4)*0x4, vtDword )

                                addStructureElem( contextTable.codeStructElement, 'end: ', (contextTable.instrPointer-1 +4)*0x4, vtDword )

                                contextTable.opcodeName = contextTable.opcodeName..' for-loop '..operand4..' in range to '..operand2..' step '..operand3..' counter '..operand1..' end '..tostring(contextTable.codeInts[contextTable.instrPointer + 4])
                                addLayoutStructElem( contextTable.codeStructElement, contextTable.opcodeName, 0x808040, (contextTable.instrPointer-1 )*0x4, vtDword )

                                return contextTable.instrPointer + 6

                            end
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_STORE_GLOBAL] = {
                            name = "OPCODE_STORE_GLOBAL",
                            handler = function(contextTable)
                                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1] )
                                addStructureElem( contextTable.codeStructElement, operand1, (contextTable.instrPointer-1 +1)*0x4, vtDword )

                                local operand2 = 'String::num_int64('..(contextTable.codeInts[contextTable.instrPointer+2])..')' -- TODO number to string representation, is it base 10 here?
                                addStructureElem( contextTable.codeStructElement, operand2, (contextTable.instrPointer-1 +2)*0x4, vtDword )
                                contextTable.opcodeName = contextTable.opcodeName..' '..operand1..' = '..operand2
                                addLayoutStructElem( contextTable.codeStructElement, contextTable.opcodeName, 0x808040, (contextTable.instrPointer-1 )*0x4, vtDword )

                                return contextTable.instrPointer + 3

                            end
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_STORE_NAMED_GLOBAL] = {
                            name = "OPCODE_STORE_NAMED_GLOBAL",
                            handler = function(contextTable)
                                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1] )
                                addStructureElem( contextTable.codeStructElement, operand1, (contextTable.instrPointer-1 +1)*0x4, vtDword )
                                local operand2 = 'Globals['..contextTable.codeInts[contextTable.instrPointer+2]..']'
                                addStructureElem( contextTable.codeStructElement, operand2, (contextTable.instrPointer-1 +2)*0x4, vtDword )
                                contextTable.opcodeName = contextTable.opcodeName..' '..operand1..' = '..operand2
                                addLayoutStructElem( contextTable.codeStructElement, contextTable.opcodeName, 0x808040, (contextTable.instrPointer-1 )*0x4, vtDword )

                                return contextTable.instrPointer + 3

                            end
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL] = {
                            name = "OPCODE_TYPE_ADJUST_BOOL",
                            handler = function(contextTable)
                                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1] )
                                addStructureElem( contextTable.codeStructElement, operand1, (contextTable.instrPointer-1 +1)*0x4, vtDword )
                                local opcodeType = contextTable.opcodeName:gsub('OPCODE_TYPE_ADJUST_','')
                                contextTable.opcodeName = contextTable.opcodeName..' ('..opcodeType..') '..operand1
                                addLayoutStructElem( contextTable.codeStructElement, contextTable.opcodeName, 0x808040, (contextTable.instrPointer-1 )*0x4, vtDword )
                                return contextTable.instrPointer + 2

                            end
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_INT] = {
                            name = "OPCODE_TYPE_ADJUST_INT",
                            handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_FLOAT] = {
                            name = "OPCODE_TYPE_ADJUST_FLOAT",
                            handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_STRING] = {
                            name = "OPCODE_TYPE_ADJUST_STRING",
                            handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_VECTOR2] = {
                            name = "OPCODE_TYPE_ADJUST_VECTOR2",
                            handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_VECTOR2I] = {
                            name = "OPCODE_TYPE_ADJUST_VECTOR2I",
                            handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_RECT2] = {
                            name = "OPCODE_TYPE_ADJUST_RECT2",
                            handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_RECT2I] = {
                            name = "OPCODE_TYPE_ADJUST_RECT2I",
                            handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_VECTOR3] = {
                            name = "OPCODE_TYPE_ADJUST_VECTOR3",
                            handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_VECTOR3I] = {
                            name = "OPCODE_TYPE_ADJUST_VECTOR3I",
                            handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_TRANSFORM2D] = {
                            name = "OPCODE_TYPE_ADJUST_TRANSFORM2D",
                            handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_VECTOR4] = {
                            name = "OPCODE_TYPE_ADJUST_VECTOR4",
                            handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_VECTOR4I] = {
                            name = "OPCODE_TYPE_ADJUST_VECTOR4I",
                            handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_PLANE] = {
                            name = "OPCODE_TYPE_ADJUST_PLANE",
                            handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_QUATERNION] = {
                            name = "OPCODE_TYPE_ADJUST_QUATERNION",
                            handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_AABB] = {
                            name = "OPCODE_TYPE_ADJUST_AABB",
                            handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BASIS] = {
                            name = "OPCODE_TYPE_ADJUST_BASIS",
                            handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_TRANSFORM3D] = {
                            name = "OPCODE_TYPE_ADJUST_TRANSFORM3D",
                            handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_PROJECTION] = {
                            name = "OPCODE_TYPE_ADJUST_PROJECTION",
                            handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_COLOR] = {
                            name = "OPCODE_TYPE_ADJUST_COLOR",
                            handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_STRING_NAME] = {
                            name = "OPCODE_TYPE_ADJUST_STRING_NAME",
                            handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_NODE_PATH] = {
                            name = "OPCODE_TYPE_ADJUST_NODE_PATH",
                            handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_RID] = {
                            name = "OPCODE_TYPE_ADJUST_RID",
                            handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_OBJECT] = {
                            name = "OPCODE_TYPE_ADJUST_OBJECT",
                            handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_CALLABLE] = {
                            name = "OPCODE_TYPE_ADJUST_CALLABLE",
                            handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_SIGNAL] = {
                            name = "OPCODE_TYPE_ADJUST_SIGNAL",
                            handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_DICTIONARY] = {
                            name = "OPCODE_TYPE_ADJUST_DICTIONARY",
                            handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_ARRAY] = {
                            name = "OPCODE_TYPE_ADJUST_ARRAY",
                            handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_PACKED_BYTE_ARRAY] = {
                            name = "OPCODE_TYPE_ADJUST_PACKED_BYTE_ARRAY",
                            handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_PACKED_INT32_ARRAY] = {
                            name = "OPCODE_TYPE_ADJUST_PACKED_INT32_ARRAY",
                            handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_PACKED_INT64_ARRAY] = {
                            name = "OPCODE_TYPE_ADJUST_PACKED_INT64_ARRAY",
                            handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_PACKED_FLOAT32_ARRAY] = {
                            name = "OPCODE_TYPE_ADJUST_PACKED_FLOAT32_ARRAY",
                            handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_PACKED_FLOAT64_ARRAY] = {
                            name = "OPCODE_TYPE_ADJUST_PACKED_FLOAT64_ARRAY",
                            handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_PACKED_STRING_ARRAY] = {
                            name = "OPCODE_TYPE_ADJUST_PACKED_STRING_ARRAY",
                            handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_PACKED_VECTOR2_ARRAY] = {
                            name = "OPCODE_TYPE_ADJUST_PACKED_VECTOR2_ARRAY",
                            handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_PACKED_VECTOR3_ARRAY] = {
                            name = "OPCODE_TYPE_ADJUST_PACKED_VECTOR3_ARRAY",
                            handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_PACKED_COLOR_ARRAY] = {
                            name = "OPCODE_TYPE_ADJUST_PACKED_COLOR_ARRAY",
                            handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_PACKED_VECTOR4_ARRAY] = {
                            name = "OPCODE_TYPE_ADJUST_PACKED_VECTOR4_ARRAY",
                            handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_ASSERT] = {
                            name = "OPCODE_ASSERT",
                            handler = function(contextTable)
                                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1] )
                                addStructureElem( contextTable.codeStructElement, operand1, (contextTable.instrPointer-1 +1)*0x4, vtDword )
                                local operand2 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 2] )
                                addStructureElem( contextTable.codeStructElement, operand2, (contextTable.instrPointer-1 +2)*0x4, vtDword )
                                
                                contextTable.opcodeName = contextTable.opcodeName..' ('..operand1..', '..operand2..')'

                                addLayoutStructElem( contextTable.codeStructElement, contextTable.opcodeName, 0x808040, (contextTable.instrPointer-1 )*0x4, vtDword )
                                return contextTable.instrPointer + 3

                            end
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_BREAKPOINT] = {
                            name = "OPCODE_BREAKPOINT",
                            handler = function(contextTable)
                                addLayoutStructElem( contextTable.codeStructElement, contextTable.opcodeName, 0x808040, (contextTable.instrPointer-1)*0x4, vtDword )
                                return contextTable.instrPointer + 1

                            end
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_LINE] = {
                            name = "OPCODE_LINE",
                            handler = function(contextTable)
                                local line = contextTable.codeInts[contextTable.instrPointer + 1] - 1
                                if line > 0 --[[and line < p_code_lines.size()]] then
                                    contextTable.opcodeName = contextTable.opcodeName..' '..tostring(line + 1)..': '
                                else
                                    contextTable.opcodeName = ''
                                end
                                addStructureElem( contextTable.codeStructElement, 'line: ', (contextTable.instrPointer-1 + 1)*0x4, vtDword )
                                addLayoutStructElem( contextTable.codeStructElement, contextTable.opcodeName, 0x808040, (contextTable.instrPointer-1 )*0x4, vtDword )
                                return contextTable.instrPointer + 2

                            end
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_END] = {
                            name = "OPCODE_END",
                            handler = function(contextTable)
                                addLayoutStructElem( contextTable.codeStructElement, '>>>END.', 0x808040, (contextTable.instrPointer-1)*0x4, vtDword )
                                return contextTable.instrPointer + 1

                            end
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_NO_RETURN] = {
                                name = "OPCODE_CALL_PTRCALL_NO_RETURN",
                                handler = function(contextTable)
                                    
                                    contextTable.instrPointer = contextTable.instrPointer + 1
                                    local instr_var_args = contextTable.codeInts[contextTable.instrPointer]
                                    addStructureElem( contextTable.codeStructElement, 'instr_var_args:', (contextTable.instrPointer-1)*0x4, vtDword )
                                    local argc = contextTable.codeInts[contextTable.instrPointer + 1 + instr_var_args]
                                    addStructureElem( contextTable.codeStructElement, 'argc:', (contextTable.instrPointer-1 + 1+instr_var_args)*0x4, vtDword )

                                    local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1+argc] )
                                    addStructureElem( contextTable.codeStructElement, operand1, (contextTable.instrPointer-1 + 1+argc)*0x4, vtDword )
                                    operand1 = operand1..'.'

                                    local operandArg = '';

                                    for i=0, argc-1 do
                                        if i>0 then operandArg = operandArg..', ' end
                                        operandArg = operandArg..formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + i + 1] )
                                        addStructureElem( contextTable.codeStructElement, 'arg: '..formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + i+1] ) , (contextTable.instrPointer-1 + i+1)*0x4, vtDword )    
                                    end

                                    local operand3 = '_methods_ptr['..contextTable.codeInts[contextTable.instrPointer+2+instr_var_args]..']' -- TODO: workaround
                                    addStructureElem( contextTable.codeStructElement, operand3, (contextTable.instrPointer-1 + 2+instr_var_args)*0x4, vtDword )

                                    contextTable.opcodeName = contextTable.opcodeName..' '..operand1..operand3..'->getname()'..'('..operandArg..')' -- TODO: retrieve the funciton name

                                    addLayoutStructElem( contextTable.codeStructElement, contextTable.opcodeName, 0x808040, (contextTable.instrPointer-1-1 )*0x4, vtDword )

                                    return contextTable.instrPointer + 5 + argc

                                end
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL] = {
                                name = "OPCODE_CALL_PTRCALL_BOOL",
                                handler = function(contextTable)

                                    contextTable.instrPointer = contextTable.instrPointer + 1
                                    local instr_var_args = contextTable.codeInts[contextTable.instrPointer]
                                    addStructureElem( contextTable.codeStructElement, 'instr_var_args:', (contextTable.instrPointer-1)*0x4, vtDword )
                                    
                                    local argc = contextTable.codeInts[contextTable.instrPointer + 1 + instr_var_args]
                                    addStructureElem( contextTable.codeStructElement, 'argc:', (contextTable.instrPointer-1 + 1+instr_var_args)*0x4, vtDword )

                                    local operand2 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 2+argc] )
                                    addStructureElem( contextTable.codeStructElement, operand2, (contextTable.instrPointer-1 +1)*0x4, vtDword )

                                    local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1+argc] )
                                    addStructureElem( contextTable.codeStructElement, operand1, (contextTable.instrPointer-1 + 1+argc)*0x4, vtDword )
                                    operand1 = operand1..'.'

                                    local operandArg = '';

                                    for i=0, argc-1 do
                                        if i>0 then operandArg = operandArg..', ' end
                                        operandArg = operandArg..formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + i + 1] )
                                        addStructureElem( contextTable.codeStructElement, 'arg: '..formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + i+1] ) , (contextTable.instrPointer-1 + i+1)*0x4, vtDword )    
                                    end

                                    local operand3 = '_methods_ptr['..contextTable.codeInts[contextTable.instrPointer+2+instr_var_args]..']' -- TODO: workaround
                                    addStructureElem( contextTable.codeStructElement, operand3, (contextTable.instrPointer-1 + 2+instr_var_args)*0x4, vtDword )

                                    local opcodeType = contextTable.opcodeName:gsub('OPCODE_TYPE_ADJUST_','')
                                    contextTable.opcodeName = contextTable.opcodeName..'(return '..opcodeType..') '..operand2..' = '..operand1..operand3..'->getname()'..'('..operandArg..')'
                                    addLayoutStructElem( contextTable.codeStructElement, contextTable.opcodeName, 0x808040, (contextTable.instrPointer-1-1 )*0x4, vtDword )

                                    return contextTable.instrPointer + 5 + argc
                                end
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_INT] = {
                                name = "OPCODE_CALL_PTRCALL_INT",
                                handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_FLOAT] = {
                                name = "OPCODE_CALL_PTRCALL_FLOAT",
                                handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_STRING] = {
                                name = "OPCODE_CALL_PTRCALL_STRING",
                                handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_VECTOR2] = {
                                name = "OPCODE_CALL_PTRCALL_VECTOR2",
                                handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_VECTOR2I] = {
                                name = "OPCODE_CALL_PTRCALL_VECTOR2I",
                                handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_RECT2] = {
                                name = "OPCODE_CALL_PTRCALL_RECT2",
                                handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_RECT2I] = {
                                name = "OPCODE_CALL_PTRCALL_RECT2I",
                                handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_VECTOR3] = {
                                name = "OPCODE_CALL_PTRCALL_VECTOR3",
                                handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_VECTOR3I] = {
                                name = "OPCODE_CALL_PTRCALL_VECTOR3I",
                                handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_TRANSFORM2D] = {
                                name = "OPCODE_CALL_PTRCALL_TRANSFORM2D",
                                handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_VECTOR4] = {
                                name = "OPCODE_CALL_PTRCALL_VECTOR4",
                                handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_VECTOR4I] = {
                                name = "OPCODE_CALL_PTRCALL_VECTOR4I",
                                handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_PLANE] = {
                                name = "OPCODE_CALL_PTRCALL_PLANE",
                                handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_QUATERNION] = {
                                name = "OPCODE_CALL_PTRCALL_QUATERNION",
                                handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_AABB] = {
                                name = "OPCODE_CALL_PTRCALL_AABB",
                                handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BASIS] = {
                                name = "OPCODE_CALL_PTRCALL_BASIS",
                                handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_TRANSFORM3D] = {
                                name = "OPCODE_CALL_PTRCALL_TRANSFORM3D",
                                handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_PROJECTION] = {
                                name = "OPCODE_CALL_PTRCALL_PROJECTION",
                                handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_COLOR] = {
                                name = "OPCODE_CALL_PTRCALL_COLOR",
                                handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_STRING_NAME] = {
                                name = "OPCODE_CALL_PTRCALL_STRING_NAME",
                                handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_NODE_PATH] = {
                                name = "OPCODE_CALL_PTRCALL_NODE_PATH",
                                handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_RID] = {
                                name = "OPCODE_CALL_PTRCALL_RID",
                                handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_OBJECT] = {
                                name = "OPCODE_CALL_PTRCALL_OBJECT",
                                handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_CALLABLE] = {
                                name = "OPCODE_CALL_PTRCALL_CALLABLE",
                                handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_SIGNAL] = {
                                name = "OPCODE_CALL_PTRCALL_SIGNAL",
                                handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_DICTIONARY] = {
                                name = "OPCODE_CALL_PTRCALL_DICTIONARY",
                                handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_ARRAY] = {
                                name = "OPCODE_CALL_PTRCALL_ARRAY",
                                handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_PACKED_BYTE_ARRAY] = {
                                name = "OPCODE_CALL_PTRCALL_PACKED_BYTE_ARRAY",
                                handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_PACKED_INT32_ARRAY] = {
                                name = "OPCODE_CALL_PTRCALL_PACKED_INT32_ARRAY",
                                handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_PACKED_INT64_ARRAY] = {
                                name = "OPCODE_CALL_PTRCALL_PACKED_INT64_ARRAY",
                                handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_PACKED_FLOAT32_ARRAY] = {
                                name = "OPCODE_CALL_PTRCALL_PACKED_FLOAT32_ARRAY",
                                handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_PACKED_FLOAT64_ARRAY] = {
                                name = "OPCODE_CALL_PTRCALL_PACKED_FLOAT64_ARRAY",
                                handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_PACKED_STRING_ARRAY] = {
                                name = "OPCODE_CALL_PTRCALL_PACKED_STRING_ARRAY",
                                handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_PACKED_VECTOR2_ARRAY] = {
                                name = "OPCODE_CALL_PTRCALL_PACKED_VECTOR2_ARRAY",
                                handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_PACKED_VECTOR3_ARRAY] = {
                                name = "OPCODE_CALL_PTRCALL_PACKED_VECTOR3_ARRAY",
                                handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
                        }
                        GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_PACKED_COLOR_ARRAY] = {
                                name = "OPCODE_CALL_PTRCALL_PACKED_COLOR_ARRAY",
                                handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
                        }


                    GDF.Decoders = {}

                        GDF.Decoders.BytecodeV0 = {
                            name = "BytecodeV0",
                            resolveOPHandlerDefFromProfile = function( profile, opcodeEnum )
                                return profile.OPHandlerDefFromOPEnum[ opcodeEnum ]
                            end
                        }
                        GDF.Decoders.BytecodeV1 = {
                            name = "BytecodeV1",
                            resolveOPHandlerDefFromProfile = function( profile, opcodeEnum )
                                -- for other versions redefine the handler on the fly
                                -- for example, in 4.0 GDF.OP.OPCODE_OPERATOR takes more operands than future versions TODO
                                return profile.OPHandlerDefFromOPEnum[ opcodeEnum ]
                            end
                        }


                    GDF.ProfileSpecs = {
                        ["4.0"] = {
                            decoderName = "BytecodeV0",
                            orderedOpcodes = {
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

                        ["4.1"] = {
                            base = "4.0",
                            decoderName = "BytecodeV0",
                            patches = {
                                { kind = "insertValueAfter", anchor = GDF.OP.OPCODE_GET_MEMBER, value = GDF.OP.OPCODE_SET_STATIC_VARIABLE },
                                { kind = "insertValueAfter", anchor = GDF.OP.OPCODE_SET_STATIC_VARIABLE, value = GDF.OP.OPCODE_GET_STATIC_VARIABLE }
                            }
                        },

                        ["4.2"] = {
                            base = "4.1",
                            decoderName = "BytecodeV0",
                            patches = {
                                { kind = "insertValueAfter", anchor = GDF.OP.OPCODE_CALL_NATIVE_STATIC, value = GDF.OP.OPCODE_CALL_METHOD_BIND_VALIDATED_RETURN },
                                { kind = "insertValueAfter", anchor = GDF.OP.OPCODE_CALL_METHOD_BIND_VALIDATED_RETURN, value = GDF.OP.OPCODE_CALL_METHOD_BIND_VALIDATED_NO_RETURN },
                                { kind = "removeValue", value = GDF.OP.OPCODE_CALL_PTRCALL_NO_RETURN },
                                { kind = "removeValue", value = GDF.OP.OPCODE_CALL_PTRCALL_BOOL },
                                { kind = "removeValue", value = GDF.OP.OPCODE_CALL_PTRCALL_INT },
                                { kind = "removeValue", value = GDF.OP.OPCODE_CALL_PTRCALL_FLOAT },
                                { kind = "removeValue", value = GDF.OP.OPCODE_CALL_PTRCALL_STRING },
                                { kind = "removeValue", value = GDF.OP.OPCODE_CALL_PTRCALL_VECTOR2 },
                                { kind = "removeValue", value = GDF.OP.OPCODE_CALL_PTRCALL_VECTOR2I },
                                { kind = "removeValue", value = GDF.OP.OPCODE_CALL_PTRCALL_RECT2 },
                                { kind = "removeValue", value = GDF.OP.OPCODE_CALL_PTRCALL_RECT2I },
                                { kind = "removeValue", value = GDF.OP.OPCODE_CALL_PTRCALL_VECTOR3 },
                                { kind = "removeValue", value = GDF.OP.OPCODE_CALL_PTRCALL_VECTOR3I },
                                { kind = "removeValue", value = GDF.OP.OPCODE_CALL_PTRCALL_TRANSFORM2D },
                                { kind = "removeValue", value = GDF.OP.OPCODE_CALL_PTRCALL_VECTOR4 },
                                { kind = "removeValue", value = GDF.OP.OPCODE_CALL_PTRCALL_VECTOR4I },
                                { kind = "removeValue", value = GDF.OP.OPCODE_CALL_PTRCALL_PLANE },
                                { kind = "removeValue", value = GDF.OP.OPCODE_CALL_PTRCALL_QUATERNION },
                                { kind = "removeValue", value = GDF.OP.OPCODE_CALL_PTRCALL_AABB },
                                { kind = "removeValue", value = GDF.OP.OPCODE_CALL_PTRCALL_BASIS },
                                { kind = "removeValue", value = GDF.OP.OPCODE_CALL_PTRCALL_TRANSFORM3D },
                                { kind = "removeValue", value = GDF.OP.OPCODE_CALL_PTRCALL_PROJECTION },
                                { kind = "removeValue", value = GDF.OP.OPCODE_CALL_PTRCALL_COLOR },
                                { kind = "removeValue", value = GDF.OP.OPCODE_CALL_PTRCALL_STRING_NAME },
                                { kind = "removeValue", value = GDF.OP.OPCODE_CALL_PTRCALL_NODE_PATH },
                                { kind = "removeValue", value = GDF.OP.OPCODE_CALL_PTRCALL_RID },
                                { kind = "removeValue", value = GDF.OP.OPCODE_CALL_PTRCALL_OBJECT },
                                { kind = "removeValue", value = GDF.OP.OPCODE_CALL_PTRCALL_CALLABLE },
                                { kind = "removeValue", value = GDF.OP.OPCODE_CALL_PTRCALL_SIGNAL },
                                { kind = "removeValue", value = GDF.OP.OPCODE_CALL_PTRCALL_DICTIONARY },
                                { kind = "removeValue", value = GDF.OP.OPCODE_CALL_PTRCALL_ARRAY },
                                { kind = "removeValue", value = GDF.OP.OPCODE_CALL_PTRCALL_PACKED_BYTE_ARRAY },
                                { kind = "removeValue", value = GDF.OP.OPCODE_CALL_PTRCALL_PACKED_INT32_ARRAY },
                                { kind = "removeValue", value = GDF.OP.OPCODE_CALL_PTRCALL_PACKED_INT64_ARRAY },
                                { kind = "removeValue", value = GDF.OP.OPCODE_CALL_PTRCALL_PACKED_FLOAT32_ARRAY },
                                { kind = "removeValue", value = GDF.OP.OPCODE_CALL_PTRCALL_PACKED_FLOAT64_ARRAY },
                                { kind = "removeValue", value = GDF.OP.OPCODE_CALL_PTRCALL_PACKED_STRING_ARRAY },
                                { kind = "removeValue", value = GDF.OP.OPCODE_CALL_PTRCALL_PACKED_VECTOR2_ARRAY },
                                { kind = "removeValue", value = GDF.OP.OPCODE_CALL_PTRCALL_PACKED_VECTOR3_ARRAY },
                                { kind = "removeValue", value = GDF.OP.OPCODE_CALL_PTRCALL_PACKED_COLOR_ARRAY }
                            }
                        },

                        ["4.3"] = {
                            base = "4.2",
                            decoderName = "BytecodeV0",
                            patches = {
                                { kind = "insertValueAfter", anchor = GDF.OP.OPCODE_ASSIGN, value = GDF.OP.OPCODE_ASSIGN_NULL },
                                { kind = "insertValueAfter", anchor = GDF.OP.OPCODE_CALL_NATIVE_STATIC, value = GDF.OP.OPCODE_CALL_NATIVE_STATIC_VALIDATED_RETURN },
                                { kind = "insertValueAfter", anchor = GDF.OP.OPCODE_CALL_NATIVE_STATIC_VALIDATED_RETURN, value = GDF.OP.OPCODE_CALL_NATIVE_STATIC_VALIDATED_NO_RETURN },
                                { kind = "insertValueAfter", anchor = GDF.OP.OPCODE_ITERATE_BEGIN_PACKED_COLOR_ARRAY, value = GDF.OP.OPCODE_ITERATE_BEGIN_PACKED_VECTOR4_ARRAY },
                                { kind = "insertValueAfter", anchor = GDF.OP.OPCODE_ITERATE_PACKED_COLOR_ARRAY, value = GDF.OP.OPCODE_ITERATE_PACKED_VECTOR4_ARRAY },
                                { kind = "insertValueAfter", anchor = GDF.OP.OPCODE_TYPE_ADJUST_PACKED_COLOR_ARRAY, value = GDF.OP.OPCODE_TYPE_ADJUST_PACKED_VECTOR4_ARRAY }

                            }
                        },

                        ["4.4"] = {
                            base = "4.3",
                            decoderName = "BytecodeV0",
                            patches = {
                                { kind = "insertValueAfter", anchor = GDF.OP.OPCODE_TYPE_TEST_ARRAY, value = GDF.OP.OPCODE_TYPE_TEST_DICTIONARY },
                                { kind = "insertValueAfter", anchor = GDF.OP.OPCODE_ASSIGN_TYPED_ARRAY, value = GDF.OP.OPCODE_ASSIGN_TYPED_DICTIONARY },
                                { kind = "insertValueAfter", anchor = GDF.OP.OPCODE_CONSTRUCT_DICTIONARY, value = GDF.OP.OPCODE_CONSTRUCT_TYPED_DICTIONARY },
                                { kind = "insertValueAfter", anchor = GDF.OP.OPCODE_RETURN_TYPED_ARRAY, value = GDF.OP.OPCODE_RETURN_TYPED_DICTIONARY }
                            }
                        },

                        ["4.5"] = {
                            base = "4.4",
                            decoderName = "BytecodeV0",
                            patches = {
                                { kind = "insertValueAfter", anchor = GDF.OP.OPCODE_ITERATE_BEGIN_OBJECT, value = GDF.OP.OPCODE_ITERATE_BEGIN_RANGE },
                                { kind = "insertValueAfter", anchor = GDF.OP.OPCODE_ITERATE_OBJECT, value = GDF.OP.OPCODE_ITERATE_RANGE }
                            }
                        },

                        ["4.6"] = {
                            base = "4.5",
                            decoderName = "BytecodeV0",
                            patches = {}
                        }
                    }
                    GDF.CompiledProfiles = {}
                    GDF.EADDRESS = {
                        ['ADDR_BITS'] = 24,
                        ['ADDR_MASK'] = ((1 << 24) - 1), -- ((1 << ADDR_BITS) - 1)
                        ['ADDR_TYPE_MASK'] = ~((1 << 24) - 1),
                        ['ADDR_TYPE_STACK'] = 0,
                        ['ADDR_TYPE_CONSTANT'] = 1,
                        ['ADDR_TYPE_MEMBER'] = 2,
                        ['ADDR_TYPE_MAX'] = 3
                    }
                    GDF.EFIXEDADDRESSES = {
                        ['ADDR_STACK_SELF'] = 0,
                        ['ADDR_STACK_CLASS'] = 1,
                        ['ADDR_STACK_NIL'] = 2,
                        ['FIXED_ADDRESSES_MAX'] = 3,
                        ['ADDR_SELF'] = 0 | GDF.EADDRESS['ADDR_TYPE_STACK'] << GDF.EADDRESS['ADDR_BITS'],
                        ['ADDR_CLASS' ] = 1 | GDF.EADDRESS['ADDR_TYPE_STACK'] << GDF.EADDRESS['ADDR_BITS'],
                        ['ADDR_NIL' ] = 2 | GDF.EADDRESS['ADDR_TYPE_STACK'] << GDF.EADDRESS['ADDR_BITS']
                    }
                    GDF.OPERATOR_NAME = {
                        --comparison
                        "OP_EQUAL",
                        "OP_NOT_EQUAL",
                        "OP_LESS",
                        "OP_LESS_EQUAL",
                        "OP_GREATER",
                        "OP_GREATER_EQUAL",
                        --mathematic
                        "OP_ADD",
                        "OP_SUBTRACT",
                        "OP_MULTIPLY",
                        "OP_DIVIDE",
                        "OP_NEGATE",
                        "OP_POSITIVE",
                        "OP_MODULE",
                        "OP_POWER",
                        --bitwise
                        "OP_SHIFT_LEFT",
                        "OP_SHIFT_RIGHT",
                        "OP_BIT_AND",
                        "OP_BIT_OR",
                        "OP_BIT_XOR",
                        "OP_BIT_NEGATE",
                        --logic
                        "OP_AND",
                        "OP_OR",
                        "OP_XOR",
                        "OP_NOT",
                        --containment
                        "OP_IN",
                        "OP_MAX" -- 25
                    }

                    for version, _ in pairs(GDF.ProfileSpecs) do
                        GDF.CompiledProfiles[ version ] = createProfileFromVersion( version )
                    end

                    if GDSOf.VERSION_STRING then
                        GDF.CurrentDisassembler = GDF.createDisassemblerFromVersion( GDSOf.VERSION_STRING )
                    end

                else
                    --TODO for 3.x
                end
            end

            function disassembleGDFunctionCodeToStruct( funcAddr, funcStruct )
                assert( (type(funcAddr) == 'number') and (funcAddr ~= 0),'disassembleGDFunctionCode: funcAddr has to be a valid pointer, instead got: '..type(funcAddr) )
                
                if GDF == nil then defineGDFunctionEnums() end

                debugStepIn()

                -- TODO: resolve that with a a helper
                local codeAddr = readPointer( funcAddr + GDSOf.FUNC_CODE )
                funcStruct.Name = 'ScriptFunc'
                local codeStructElement = funcStruct.addElement()
                codeStructElement.Name = 'FuncCode'
                codeStructElement.Offset = GDSOf.FUNC_CODE
                codeStructElement.VarType = vtPointer
                codeStructElement.ChildStruct = createStructure( 'FuncCode' )
                
                local funcConstantStructElem = funcStruct.addElement()
                funcConstantStructElem.Name = 'Constants'
                funcConstantStructElem.Offset = GDSOf.FUNC_CONST
                funcConstantStructElem.VarType = vtPointer
                funcConstantStructElem.ChildStruct = createStructure('GDFConst')
                local funcConstAddr = readPointer( funcAddr + GDSOf.FUNC_CONST )
                iterateFuncConstantsToStruct( funcConstAddr, funcConstantStructElem )

                local funcGlobalNameStructElem = funcStruct.addElement()
                funcGlobalNameStructElem.Name = 'Globals'
                funcGlobalNameStructElem.Offset = GDSOf.FUNC_GLOBNAMEPTR
                funcGlobalNameStructElem.VarType = vtPointer
                funcGlobalNameStructElem.ChildStruct = createStructure('GDFGlobals')
                local funcGlobalAddr = readPointer( funcAddr + GDSOf.FUNC_GLOBNAMEPTR )
                iterateFuncGlobalsToStruct( funcGlobalAddr, funcGlobalNameStructElem )

                local codeInts = {}
                local codeSize, currIndx, currOpcode = 0,0,0
                while true do
                    codeSize = codeSize + 1
                    currOpcode = readInteger( codeAddr + currIndx*0x4 )
                    table.insert( codeInts, currOpcode )

                    
                    if currOpcode == GDF.CurrentDisassembler:getOPEnumFromInternalOPID( GDF.OP.OPCODE_END ) then
                        break
                    end
                    currIndx = currIndx+1
                end
                sendDebugMessage('disassembleGDFunctionCode: codeSize: '..tostring(codeSize) )

                GDF.CurrentDisassembler:disassembleBytecode( codeInts, codeStructElement )

                debugStepOut()
                return
            end

            function formatDisassembledAddress( addrInt )
                local addrIndex  = addrInt & (GDF.EADDRESS['ADDR_MASK']) -- lower 24 bits are indices
                local addrType = (addrInt >> GDF.EADDRESS['ADDR_BITS']) -- the higher 8 would be types: shift to the beginning and mask

                if addrType == 0 and (addrIndex >= 0 and addrIndex <= 2)  then
                    if addrIndex == GDF.EFIXEDADDRESSES['ADDR_STACK_SELF'] then return "stack(self)" end
                    if addrIndex == GDF.EFIXEDADDRESSES['ADDR_STACK_CLASS'] then return "stack(class)" end
                    if addrIndex == GDF.EFIXEDADDRESSES['ADDR_STACK_NIL'] then return "stack(nil)" end
                    return 'stack['..tostring(addrIndex)..']'
                end

                if     ( addrType == GDF.EADDRESS['ADDR_TYPE_STACK'] )    then return ("stack[%d]"):format(addrIndex)
                elseif ( addrType == GDF.EADDRESS['ADDR_TYPE_CONSTANT'] ) then return ("Constants[%d]"):format(addrIndex)
                elseif ( addrType == GDF.EADDRESS['ADDR_TYPE_MEMBER'] )   then return ("Variants[%d]"):format(addrIndex) -- for clarity ("member[%d]"):format(addrIndex)
                else                                                           return ("addr?(0x%08X)"):format(addrInt)
                end
            end

            function checkIfGDFunction( funcAddr )

                local funcStringNameAddr = readPointer( funcAddr ) -- StringName name;
                local funcResStringNameAddr = readPointer( funcAddr + GDSOf.PTRSIZE ) -- StringName source;
                local funcCodeAddr = readPointer( funcAddr + GDSOf.FUNC_CODE )

                if isNotNullOrNil(funcStringNameAddr) and isNotNullOrNil(funcResStringNameAddr) and isNotNullOrNil(funcCodeAddr) --[[ isPointerNotNull( funcAddr + GDSOf.FUNC_CODE ) ]] then

                    local funcStringAddr = readPointer(funcStringNameAddr + GDSOf.STRING)
                    if isNullOrNil( funcStringAddr ) then
                        funcStringAddr = readPointer( funcStringNameAddr + 0x8 )
                        if isNullOrNil( funcStringAddr ) then
                            return false
                        end
                    end

                    local resStringAddr = readPointer( funcResStringNameAddr + GDSOf.STRING )

                    if isNullOrNil( resStringAddr ) and readUTFString( resStringAddr, 4 ) ~= 'res:' then
                        return false
                    end

                    return true
                end

                return false
            end

        --///---///--///---///--///---///--///--///---///--///---///--///---///--/// Const

            --- returns a head element, tail element and (hash)Map size
            ---@param nodeAddr number
            function getNodeConstMap(nodeAddr, constStructElement) 
                assert(type(nodeAddr) == 'number',"getNodeConstMap: NodePtr should be a number, instead got: "..type(nodeAddr))
                debugStepIn()

                local scriptInstanceAddr = readPointer( nodeAddr + GDSOf.GDSCRIPTINSTANCE )
                if isNullOrNil(scriptInstanceAddr) then
                    sendDebugMessageAndStepOut('getNodeConstMap: scriptInstance is invalid');
                    return;
                end

                local gdScriptAddr = readPointer( scriptInstanceAddr + GDSOf.GDSCRIPT_REF )
                if isNullOrNil(gdScriptAddr) then
                    sendDebugMessageAndStepOut('getNodeConstMap: GDScript is invalid')
                    return;
                end

                local mainElement = readPointer( gdScriptAddr + GDSOf.CONST_MAP ) -- head or root depending on the version
                local lastElement = readPointer( gdScriptAddr + GDSOf.CONST_MAP + GDSOf.PTRSIZE ) -- tail or end
                local mapSize = readInteger( gdScriptAddr + GDSOf.CONST_MAP + GDSOf.MAP_SIZE ) -- hashmap or map
                if isNullOrNil(mainElement) or isNullOrNil(lastElement) or isNullOrNil(mapSize) then
                        sendDebugMessageAndStepOut('getNodeConstMap: Const: (hash)map is not found')
                        return;
                end
                debugStepOut()
                
                if GDSOf.MAJOR_VER == 4 then  -- TODO: the function can be segmented
                    return mainElement, lastElement, mapSize, constStructElement
                else
                    if constStructElement then constStructElement.ChildStruct = createStructure('ConstMapRes') end
                    return getLeftmostMapElem( mainElement, lastElement, mapSize, constStructElement )
                end
            end

            --- returns a lua string for const name
            ---@param mapElement number
            function getNodeConstName(mapElement)
                debugStepIn()

                local mapElementKey = readPointer( mapElement + GDSOf.CONSTELEM_KEYVAL )
                if isNullOrNil(mapElementKey) then
                    sendDebugMessageAndStepOut('getNodeConstName: (hash)mapElementKey invalid');
                    return 'C??'
                end

                local constNameStr = readPointer( mapElementKey + GDSOf.STRING )

                if isNullOrNil(constNameStr) then
                    sendDebugMessage('getNodeConstName: string address invalid, trying ASCII');
                    constNameStr = readPointer( mapElementKey + 0x8 ) -- for cases when StringName holds a static ASCII string at 0x8
                    if isNullOrNil(constNameStr) then
                        sendDebugMessageAndStepOut('getNodeName: string address invalid, not ASCII either')
                        return 'C??'
                    end
                    debugStepOut()

                    return readString( constNameStr, 100 )
                end

                debugStepOut()

                return readUTFString( constNameStr )
            end

            -- iterates over const (hash)map of a node and creates addresses for it
            ---@param nodeAddr number
            ---@param parent userdata
            function iterateNodeConstToAddr(nodeAddr, parent)
                assert(type(nodeAddr) == 'number',"iterateNodeConstToAddr Node addr has to be a number, instead got: "..type(nodeAddr))

                debugStepIn()

                local nodeName = getNodeName( nodeAddr ) or "UnknownNode"
                if not checkForGDScript( nodeAddr ) then
                    sendDebugMessageAndStepOut("iterateNodeConstToAddr: Node "..tostring(nodeName).." with NO GDScript")
                    synchronize( function(parent) parent.Destroy() end, parent )
                    return;
                end;

                local headElement, tailElement, mapSize = getNodeConstMap(nodeAddr)
                if isNullOrNil(headElement) or isNullOrNil(mapSize) then
                    sendDebugMessageAndStepOut('iterateNodeConstToAddr (hash)map empty?: '..('Address: %x '):format( nodeAddr or -1 ) )
                    synchronize( function(parent) parent.Destroy() end, parent )
                    return;
                end

                local emitter = GDEmitters.AddrEmitter
                local mapElement = headElement

                repeat
                    local entry = readNodeConstEntry(mapElement)
                    entry.name = "CONST: " .. entry.name
                    local contextTable = { nodeAddr = nodeAddr, nodeName = nodeName or "UnknownNode", baseAddress = entry.variantPtr }
                    local handler = GDHandlers.VariantHandlers[entry.typeName] or GDHandlers.VariantHandlers.DEFAULT
                    handler(entry, emitter, parent, contextTable)
                    mapElement = getNextMapElement(mapElement)

                until (mapElement == 0)
                debugStepOut()
                return
            end

            -- iterates over const (hash)map of a node and builds the structure for it
            ---@param nodeAddr number
            ---@param constStructElement userdata
            function iterateNodeConstToStruct(nodeAddr, constStructElement) -- TODO: MAKE IT UNIVERSAL
                assert(type(nodeAddr) == 'number',"iterateNodeConstToStruct Node addr has to be a number, instead got: "..type(nodeAddr))

                debugStepIn()

                local headElement, _, mapSize, constStructElement = getNodeConstMap( nodeAddr, constStructElement)
                if isNullOrNil(headElement) or isNullOrNil(mapSize) then
                    sendDebugMessageAndStepOut('iterateNodeConstToStruct (hash)map empty?: '..('Address: %x '):format(nodeAddr or -1 ) )
                    return;
                end

                local mapElement = headElement
                local emitter = GDEmitters.StructEmitter
                local currentContainer = constStructElement
                local index = 0;
                local nodeName = getNodeName(nodeAddr) or "UnknownNode"

                repeat
                    local entry = readNodeConstEntry(mapElement)
                    entry.name = "CONST: " .. entry.name
                    local contextTable = { nodeAddr = nodeAddr, nodeName = nodeName, baseAddress = entry.variantPtr }
                    local handler = GDHandlers.VariantHandlers[entry.typeName] or GDHandlers.VariantHandlers.DEFAULT
                    handler(entry, emitter, currentContainer, contextTable)

                    mapElement = getNextMapElement(mapElement)
                    index = index+1

                    if mapElement ~= 0 then
                        currentContainer = createNextConstContainer(currentContainer, index)
                    end
                    
                until (mapElement == 0)
                debugStepOut()
                return
            end

        --///---///--///---///--///---///--///--///---///--///---///--///---///--/// Dictionary


            local function iterateDictionary(dictHead, parent, emitter, options, contextSeed)

                options = options or {}
                local mapElement = dictHead
                local currentContainer = parent
                local index = 0

                repeat
                    local entry = readDictionaryContainerEntry(mapElement)
                    local formatted = formatDictionaryEntry(entry)
                    local contextTable = { nodeAddr = contextSeed and contextSeed.nodeAddr or 0, nodeName = contextSeed and contextSeed.nodeName or "Dictionary", baseAddress = entry.variantPtr }

                    local handler = GDHandlers.VariantHandlers[formatted.typeName] or GDHandlers.VariantHandlers.DEFAULT
                    handler(formatted, emitter, currentContainer, contextTable)

                    mapElement = getDictElemPairNext(mapElement)
                    index = index + 1

                    if isNotNullOrNil(mapElement) and options.nextContainerFactory then
                        currentContainer = options.nextContainerFactory(currentContainer, index)
                    end

                until (mapElement == 0)
                return
            end

            --- iterates a dictionary and adds it to a class
            ---@param dictAddr number
            ---@param parent userdata
            function iterateDictionaryToAddr(dictAddr, parent)
                assert( type(dictAddr) == 'number', 'iterateDictionaryToAddr: dictAddr has to be a number, instead got: '..type(dictAddr))

                local dictRoot, dictSize, dictHead, dictTail = getDictionaryInfo(dictAddr)
                if isNullOrNil(dictRoot) or isNullOrNil(dictSize) then return end

                iterateDictionary( dictHead, parent, GDEmitters.AddrEmitter, { bNeedStructOffset = false }, { nodeAddr = 0, nodeName = "Dictionary" } )
                return
            end

            --- iterates a dictionary and adds it to a struct
            ---@param dictAddr number
            ---@param dictStructElement userdata
            function iterateDictionaryToStruct(dictAddr, dictStructElement)

                local dictRoot, dictSize, dictHead, dictTail = getDictionaryInfo(dictAddr)
                if isNullOrNil(dictRoot) then return end
                local currentRoot = dictStructElement

                if GDSOf.MAJOR_VER == 3 then
                    currentRoot = createChildStructElem(currentRoot, 'dictList', GDSOf.DICT_LIST, vtPointer, 'dictList')
                end

                local headContainer = createChildStructElem(currentRoot, 'dictHead', GDSOf.DICT_HEAD, vtPointer, 'dictHead')

                iterateDictionary( dictHead, headContainer, GDEmitters.StructEmitter, { bNeedStructOffset = true, nextContainerFactory = createNextDictContainer }, { nodeAddr = 0, nodeName = "Dictionary" } )

                return
            end

            --- iterates a dictionary for nodes
            ---@param dictAddr number
            function iterateDictionaryForNodes(dictAddr)
                assert( type(dictAddr) == 'number', 'iterateDictionaryForNodes: dictAddr has to be a number, instead got: '..type(dictAddr))
                if (not (dictAddr > 0)) then return; end

                local dictRoot = dictAddr
                if GDSOf.MAJOR_VER == 3 then
                    dictRoot = readPointer( dictAddr + GDSOf.DICT_LIST ) -- for 3.x it's dictList actually
                end

                -- local dictSize = readInteger(dictRoot + GDSOf.DICT_SIZE)
                local dictSize = readInteger( dictAddr + GDSOf.DICT_SIZE )

                if isNullOrNil(dictSize) then
                    return;
                end

                local mapElement = readPointer( dictRoot + GDSOf.DICT_HEAD )
                if isNullOrNil(mapElement) then
                    return
                end
                local visitor = NodeVisitor

                repeat
                    local entry = readDictionaryValueEntry(mapElement)
                    local handler = GDHandlers.NodeDiscoveryHandlers[entry.typeName]
                    if handler then handler(entry, visitor) end
                    mapElement = getDictElemPairNext(mapElement)
                until (mapElement == 0)
            end

        --///---///--///---///--///---///--///--///---///--///---///--///---///--/// Array


            local function iterateArray(arrVectorAddr, arrVectorSize, variantArrSize, parent, emitter, options, contextSeed)
                assert(type(arrVectorAddr) == 'number', "iterateArray: arrayAddr has to be a number, instead got: " .. type(arrVectorAddr))

                options = options or {}
                for varIndex = 0, arrVectorSize - 1 do
                    local entry = readArrayContainerEntry(arrVectorAddr, varIndex, variantArrSize, options.bNeedStructOffset)
                    if isNullOrNil(entry.variantPtr) then goto continue end
                    local formatted = formatArrayEntry(entry)
                    local contextTable = { nodeAddr = contextSeed and contextSeed.nodeAddr or 0, nodeName = contextSeed and contextSeed.nodeName or "Array", baseAddress = entry.variantPtr }
                    local handler = GDHandlers.VariantHandlers[formatted.typeName] or GDHandlers.VariantHandlers.DEFAULT
                    handler(formatted, emitter, parent, contextTable)

                    ::continue::
                end
            end

            --- takes in an array address and address owner to append to
            ---@param arrayAddr number
            ---@param parent userdata
            function iterateArrayToAddr(arrayAddr, parent)
                assert(type(arrayAddr) == 'number',"Array "..tostring(arrayAddr).." has to be a number, instead got: "..type(arrayAddr))

                local arrVectorAddr, arrVectorSize, variantArrSize = getArrayVectorInfo(arrayAddr)
                if isNullOrNil(arrVectorAddr) then
                    return;
                end  

                iterateArray( arrVectorAddr, arrVectorSize, variantArrSize, parent, GDEmitters.AddrEmitter, { bNeedStructOffset = false }, { nodeAddr = 0, nodeName = "Array" } )

                return
            end

            --- takes in an array address and struct owner to append to
            ---@param arrayAddr number
            ---@param parent userdata
            function iterateArrayToStruct(arrayAddr, arrayStructElement)
                assert(type(arrayAddr) == 'number', "iterateArrayToStruct: Array " .. tostring(arrayAddr) .. " has to be a number, instead got: " .. type(arrayAddr))

                local arrVectorAddr, arrVectorSize, variantArrSize = getArrayVectorInfo(arrayAddr)
                if isNullOrNil(arrVectorAddr) then
                    return;
                end

                arrayStructElement = addStructureElem( arrayStructElement, 'VectorArray', GDSOf.ARRAY_TOVECTOR, vtPointer )
                arrayStructElement.ChildStruct = createStructure('ArrayData')
                iterateArray( arrVectorAddr, arrVectorSize, variantArrSize, arrayStructElement, GDEmitters.StructEmitter, { bNeedStructOffset = true }, { nodeAddr = 0, nodeName = "Array" } )
                return
            end

            --- iterates an array for nodes
            ---@param arrayAddr number
            function iterateArrayForNodes(arrayAddr)
                assert(type(arrayAddr) == 'number',"iterateArrayForNodes: array "..tostring(arrayAddr).." has to be a number, instead got: "..type(arrayAddr))

                local arrVectorAddr = readPointer( arrayAddr + GDSOf.ARRAY_TOVECTOR )
                if isNullOrNil(arrVectorAddr) then return; end        
                local arrVectorSize = readInteger(arrVectorAddr - GDSOf.SIZE_VECTOR )
                if isNullOrNil(arrVectorSize) then return; end

                local variantArrSize, ok = redefineVariantSizeByVector( arrVectorAddr , arrVectorSize )
                if not ok then return; end

                local visitor = NodeVisitor

                for varIndex=0, arrVectorSize-1 do

                    local entry = readArrayValueEntry(arrVectorAddr, varIndex, variantArrSize)

                    if isNotNullOrNil(entry.variantPtr) then
                        local handler = GDHandlers.NodeDiscoveryHandlers[entry.typeName]
                        if handler then handler(entry, visitor) end
                    end
                end
            end

            --- iterates a packed array and adds it to a class
            ---@param packedArrayAddr number
            ---@param packedTypeName string
            ---@param parent userdata
            function iteratePackedArrayToAddr(packedArrayAddr, packedTypeName, parent)
                assert(type(packedArrayAddr) == 'number',"Packed Array has to be a number, instead got: "..type(packedArrayAddr))
                assert(type(packedTypeName) == 'string',"TypeName has to be a string, instead got: "..type(packedTypeName))

                local packedDataArrAddr, packedVectorSize = getPackedArrayInfo(packedArrayAddr)
                if isNullOrNil(packedDataArrAddr) then return end;

                iteratePackedArrayCore(packedDataArrAddr, packedVectorSize, packedTypeName, parent, GDEmitters.PackedAddrEmitter)
                return
            end

            --- iterates a packed array and adds it to a struct
            ---@param packedArrayAddr number
            ---@param packedTypeName string
            ---@param pArrayStructElement userdata
            function iteratePackedArrayToStruct(packedArrayAddr, packedTypeName, pArrayStructElement)
                assert(type(packedArrayAddr) == 'number',"Packed Array "..tostring(packedArrayAddr).." has to be a number, instead got: "..type(packedArrayAddr))
                assert(type(packedTypeName) == 'string',"TypeName "..tostring(packedTypeName).." has to be a string, instead got: "..type(packedTypeName))

                local packedDataArrAddr, packedVectorSize = getPackedArrayInfo(packedArrayAddr)
                if isNullOrNil(packedDataArrAddr) then return end;
                pArrayStructElement = addStructureElem(pArrayStructElement, 'PckArray', GDSOf.P_ARRAY_TOARR, vtPointer)
                pArrayStructElement.ChildStruct = createStructure('PArrayData')

                iteratePackedArrayCore(packedDataArrAddr, packedVectorSize, packedTypeName, pArrayStructElement, GDEmitters.PackedStructEmitter)
                
                return
            end

        --///---///--///---///--///---///--///--///---///--///---///--///---///--/// Variant

            ---@param nodeAddr number
            ---@param parent userdata
            ---@param emitter table
            ---@param options table
            function iterateVectorVariants(nodeAddr, parent, emitter, options)
                assert(type(nodeAddr) == 'number',"Node addr has to be a number, instead got: "..type(nodeAddr));

                debugStepIn()

                local nodeName = getNodeName( nodeAddr ) or "UnknownNode";
                
                options = options or {}

                if options.requireGDScript and not checkForGDScript(nodeAddr) then
                    sendDebugMessageAndStepOut(" iterateVectorVariants: Node has NO GDScript: "..nodeName)
                    -- synchronize(function(parent) parent.Destroy() end, parent ) -- TODO: compare the emitter?
                    return;
                end

                local headElement, tailElement, mapSize = getNodeVariantMap(nodeAddr)
                if isNullOrNil(headElement) or isNullOrNil(mapSize) then
                    sendDebugMessageAndStepOut('iterateVectorVariants (hash)Map empty?: '..nodeName)
                    return;
                end 
                
                local variantVector, vectorSize = getNodeVariantVector(nodeAddr)
                local variantSize, ok = redefineVariantSizeByVector(variantVector, vectorSize)
                if not ok then
                    sendDebugMessageAndStepOut("iterateVectorVariants: Variant resize strangely failed")
                    return;
                end
                
                local mapElement = headElement

                repeat
                    local entry = readNodeVariantEntry(mapElement, variantVector, variantSize, options.bNeedStructOffset)
                    local contextTable = { nodeAddr = nodeAddr, nodeName = nodeName, baseAddress = entry.variantPtr }
                    local handler = GDHandlers.VariantHandlers[entry.typeName] or GDHandlers.VariantHandlers.DEFAULT;
                    handler(entry, emitter, parent, contextTable);

                    mapElement = getNextMapElement(mapElement)
                until (mapElement == 0)

                debugStepOut()
                return
            end

            --- nodeAddr and owner to append to
            ---@param nodeAddr number
            ---@param parent userdata
            function iterateVecVarToAddr(nodeAddr, parent)
                local options = { bNeedStructOffset = false, requireGDScript = true };
                iterateVectorVariants(nodeAddr, parent, GDEmitters.AddrEmitter, options);
            end

            --- nodeAddr and ownerStruct to append to
            ---@param nodeAddr number
            ---@param varStructElement userdata
            function iterateVecVarToStruct(nodeAddr, varStructElement)
                local options = { bNeedStructOffset = true, requireGDScript = false }
                iterateVectorVariants( nodeAddr, varStructElement, GDEmitters.StructEmitter, options )
            end
            --- iterate nodes only and owner to append to
            ---@param nodeAddr number
            function iterateVecVarForNodes(nodeAddr)
                assert(type(nodeAddr) == 'number',"iterateVecVarToAddr: Node addr has to be a number, instead got: "..type(nodeAddr))

                if not checkForGDScript( nodeAddr ) then return; end;
                local variantVector, vectorSize = getNodeVariantVector(nodeAddr)
                if isNullOrNil(vectorSize) then return; end

                local variantSize, ok = redefineVariantSizeByVector(variantVector, vectorSize)
                if not ok then return; end

                local visitor = NodeVisitor

                for variantIndex=0, vectorSize-1 do
                    local entry = readVectorVariantEntry(variantVector, variantIndex, variantSize)
                    local handler = GDHandlers.NodeDiscoveryHandlers[entry.typeName]
                    if handler then handler(entry, visitor) end
                end
            end

            --- returns a vector pointer and its size via
            ---@param nodeAddr number
            function getNodeVariantVector(nodeAddr)
                assert(type(nodeAddr) == 'number',"nodeAddr should be a number, instead got: "..type(nodeAddr))

                debugStepIn()

                local scriptInstance = readPointer( nodeAddr + GDSOf.GDSCRIPTINSTANCE )
                if isNullOrNil(scriptInstance) then
                    sendDebugMessageAndStepOut('getNodeVariantVector: scriptInstance is absent for '..string.format(' %x', nodeAddr))
                    return;
                end

                local vectorPtr = readPointer( scriptInstance + GDSOf.VAR_VECTOR )
                local vectorSize = readInteger( vectorPtr - GDSOf.SIZE_VECTOR )

                if isNullOrNil(vectorPtr) then
                    sendDebugMessageAndStepOut('getNodeVariantVector: vector is absent for '..string.format(' %x', nodeAddr))
                    return;
                end
                if isNullOrNil(vectorSize) then
                    sendDebugMessageAndStepOut('getNodeVariantVector: vector size is 0/nil, node '..string.format(' %x', nodeAddr))
                    return;
                end
                

                debugStepOut()

                return vectorPtr, vectorSize
            end

            --- returns a VariantData's (hash) map head, tail and size via a nodeAddr
            ---@param nodeAddr number
            function getNodeVariantMap(nodeAddr)
                assert(type(nodeAddr) == 'number',"nodeAddr should be a number, instead got: "..type(nodeAddr))

                debugStepIn()

                local scriptInstanceAddr = readPointer( nodeAddr + GDSOf.GDSCRIPTINSTANCE )
                if isNullOrNil(scriptInstanceAddr) then
                    sendDebugMessageAndStepOut('getNodeVariantMap: scriptInstance is absent for '..string.format(' %x', nodeAddr));
                    return;
                end

                local gdScriptAddr = readPointer( scriptInstanceAddr + GDSOf.GDSCRIPT_REF )
                if isNullOrNil(gdScriptAddr) then
                    sendDebugMessageAndStepOut('getNodeVariantMap: GDScript is absent for '..string.format(' %x', nodeAddr));
                    return;
                end

                local mainElement = readPointer( gdScriptAddr + GDSOf.VAR_NAMEINDEX_MAP ) -- head / root
                local endElement = readPointer( gdScriptAddr + GDSOf.VAR_NAMEINDEX_MAP + GDSOf.PTRSIZE ) -- tail / end
                local mapSize = readInteger( gdScriptAddr + GDSOf.VAR_NAMEINDEX_MAP + GDSOf.MAP_SIZE )

                if isNullOrNil(mainElement) or isNullOrNil(endElement) or isNullOrNil(mapSize) then    
                    sendDebugMessage('getNodeVariantMap: Variant: (hash)map is not found')
                    return;
                end

                debugStepOut()
                if GDSOf.MAJOR_VER == 4 then
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

                debugStepIn()

                if ( index > ( readInteger( vectorAddr - GDSOf.SIZE_VECTOR) - 1 ) ) then
                    sendDebugMessage("getVariantByIndex: index is out of vector size, pass index: "..tostring(index)..' VecSize: '..tostring(( readInteger( vectorAddr - GDSOf.SIZE_VECTOR) - 1 )) )
                end

                local variantType = readInteger( vectorAddr + varSize * index )
                local offsetToValue = getVariantValueOffset( variantType )

                local offset = varSize * index + offsetToValue
                local variantAddr = getAddress( vectorAddr + offset )

                if ( variantType == nil) or (variantAddr == nil) then  -- variantType == 0 -- zero is nil which happens for uninitialized -- zero is possible for uninitialized variantPtr == 0 or 
                    sendDebugMessage('getVariantByIndex: variant ptr or type invalid'); error('getVariantByIndex: variant ptr or type invalid')
                end

                debugStepOut()
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
                debugStepIn()

                local mapElement = readPointer( rootElement + GDSOf.MAP_LELEM )
                if isNullOrNil(mapElement) then
                    sendDebugMessageAndStepOut('getLeftmostMapElem: mapElement is likely non-existent: root : '..('%x'):format(rootElement or -1 )..(' last %x'):format(endElement or -1 )..(' size %x'):format(mapSize or -1 )  );
                    return 0, endElement, mapSize  -- return 0 as a head element
                end

                local leftStructElem
                if struct then
                    leftStructElem = addStructureElem( struct, 'rootElem', GDSOf.MAP_LELEM, vtPointer )
                    leftStructElem.ChildStruct = createStructure('rootElem')
                end

                if ( mapElement == endElement ) then
                    debugStepOut();
                    return mapElement, endElement, mapSize -- not sure that's possible
                else
                    while readPointer( mapElement + GDSOf.MAP_LELEM ) ~= endElement do
                        mapElement = readPointer( mapElement + GDSOf.MAP_LELEM )
                        if struct then
                            leftStructElem = addStructureElem( leftStructElem, 'goLeft', GDSOf.MAP_LELEM, vtPointer )
                            leftStructElem.ChildStruct = createStructure('goLeft')
                        end
                    end
                    
                    if isNullOrNil(mapElement) then
                        sendDebugMessageAndStepOut('getLeftmostMapElem: mapElement is likely non-existent: root : '..('%x'):format(rootElement or -1 )..(' last %x'):format(endElement or -1 )..(' size %x'):format(mapSize or -1 )  );
                        return 0, endElement, mapSize
                    end -- return 0 as a head element
                    
                    debugStepOut();
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

                --debugStepIn()

                if isNullOrNil(vectorSize) then
                    --sendDebugMessageAndStepOut('redefineVariantSizeByVector: Bad vector size for '..('%x'):format(vectorPtr));
                    return 0x18, true;
                end

                if GDSOf.MAJOR_VER == 4 then

                    if (vectorSize == 1) and ( readInteger(vectorPtr) == 27 ) then
                        --sendDebugMessageAndStepOut(" 1-sized Vector: Variant was resized to 0x30 (vector: "..('%x '):format(vectorPtr))

                        return 0x30, true;

                    elseif (vectorSize == 1) then
                        --sendDebugMessageAndStepOut("1-sized Vector: Variant was left 0x18 long (vector: "..('%x '):format(vectorPtr))

                        return 0x18, true;

                    end

                    if (vectorSize == 2) and getGDTypeName( readInteger( vectorPtr ) ) and getGDTypeName( readInteger( vectorPtr + 0x18 ) ) then -- is it a valid variant Type?
                        --debugStepOut()

                        return 0x18, true;

                    elseif (vectorSize == 2) and getGDTypeName( readInteger( vectorPtr ) ) and getGDTypeName( readInteger( vectorPtr + 0x30 ) ) then  -- if it's 0x30
                        --sendDebugMessageAndStepOut("Variant was resized to 0x30 (vector: "..('%x'):format(vectorPtr)..")")

                        return 0x30, true;

                    elseif (vectorSize == 2) and getGDTypeName( readInteger( vectorPtr ) ) and getGDTypeName( readInteger( vectorPtr + 0x40 ) ) then -- if it's 0x40
                        --sendDebugMessageAndStepOut(" Variant was resized to 0x40 (vector: "..('%x'):format(vectorPtr)..")")

                        return 0x40, true;

                    end

                    if getGDTypeName( readInteger( vectorPtr ) ) and getGDTypeName( readInteger( vectorPtr + 0x18 ) ) and getGDTypeName( readInteger( vectorPtr + 0x18*2 ) ) then -- is it a valid variant Type?
                        --debugStepOut()

                        return 0x18, true;

                    elseif getGDTypeName( readInteger( vectorPtr ) ) and getGDTypeName( readInteger( vectorPtr + 0x30 ) ) and getGDTypeName( readInteger( vectorPtr + 0x30*2 ) ) then
                        --sendDebugMessageAndStepOut("Variant was resized to 0x30 (vector: "..('%x'):format(vectorPtr)..")")

                        return 0x30, true;

                    elseif getGDTypeName( readInteger( vectorPtr ) ) and getGDTypeName( readInteger( vectorPtr + 0x40 ) ) and getGDTypeName( readInteger( vectorPtr + 0x40*2 ) ) then
                        --sendDebugMessageAndStepOut("Variant was resized to 0x40 (vector: "..('%x'):format(vectorPtr)..")")

                        return 0x40, true;

                    end

                else

                    if (vectorSize == 1) and ( getGDTypeName( vectorPtr ) == 'DICTIONARY' ) then -- for some reasons single-sized vectors with dict were 0x30
                        --sendDebugMessageAndStepOut("redefineVariantSizeByVector: 1-sized Vector: Variant was resized to 0x30 (vector: "..('%x '):format(vectorPtr))

                        return 0x20, true;

                    elseif (vectorSize == 1) then
                        --sendDebugMessageAndStepOut("redefineVariantSizeByVector: 1-sized Vector: Variant was left 0x18 long (vector: "..('%x '):format(vectorPtr))

                        return 0x18, true; -- Usual size is 0x18 in 3.x

                    end

                    if (vectorSize == 2) and getGDTypeName( readInteger( vectorPtr ) ) and getGDTypeName( readInteger( vectorPtr + 0x18 ) ) then -- is it a valid variant Type?
                        --debugStepOut()

                        return 0x18, true; -- Usual size is 0x18 in 3.x

                    elseif (vectorSize == 2) and getGDTypeName( readInteger( vectorPtr ) ) and getGDTypeName( readInteger( vectorPtr + 0x20 ) ) then 
                        --sendDebugMessageAndStepOut("redefineVariantSizeByVector: 2s Variant was resized to 0x20 (vector: "..('%x'):format(vectorPtr)..")")

                        return 0x20, true;

                    elseif (vectorSize == 2) and getGDTypeName( readInteger( vectorPtr ) ) and getGDTypeName( readInteger( vectorPtr + 0x30 ) ) then
                        --sendDebugMessageAndStepOut("redefineVariantSizeByVector: 2s Variant was resized to 0x30 (vector: "..('%x'):format(vectorPtr)..")")

                        return 0x30, true; -- what's the longest for 3.x?
                    end

                    if getGDTypeName( readInteger( vectorPtr ) ) and getGDTypeName( readInteger( vectorPtr + 0x18 ) ) and getGDTypeName( readInteger( vectorPtr + 0x18*2 ) ) then -- is it a valid variant Type?
                        --debugStepOut()

                        return 0x18, true; -- Usual size is 0x18 in 3.x

                    elseif getGDTypeName( readInteger( vectorPtr ) ) and getGDTypeName( readInteger( vectorPtr + 0x20 ) ) and getGDTypeName( readInteger( vectorPtr + 0x20*2 ) ) then
                        --sendDebugMessageAndStepOut("redefineVariantSizeByVector: Variant was resized to 0x20 (vector: "..('%x'):format(vectorPtr)..")")

                        return 0x20, true;

                    elseif getGDTypeName( readInteger( vectorPtr ) ) and getGDTypeName( readInteger( vectorPtr + 0x30 ) ) and getGDTypeName( readInteger( vectorPtr + 0x30*2 ) ) then
                        --sendDebugMessageAndStepOut(" redefineVariantSizeByVector: Variant was resized to 0x30 (vector: "..('%x'):format(vectorPtr)..")")

                        return 0x30, true; -- what's the longest for 3.x?
                    end

                end

                --sendDebugMessageAndStepOut("redefineVariantSizeByVector: Variant resize failed past 4 cases (vector: "..('%x'):format(vectorPtr)..")")
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

                if GDSOf.MAJOR_VER == 4 then -- TODO make it patchable 
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
                    if (gdType == 20) then return vtSingle end
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
                    return vtPointer -- whatever
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
                    return vtPointer -- whatever
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
                if type(typeInt) ~= "number" then
                    --sendDebugMessage("getGDTypeName: input not a number, instead: "..tostring(typeInt))
                    return false;
                end

                if GDSOf.MAJOR_VER == 4 then
                    if (typeInt == 2) then return "INT" end -- these go first
                    if (typeInt == 1) then return "BOOL" end
                    if (typeInt == 3) then return "FLOAT" end
                    if (typeInt == 4) then return "STRING" end
                    if (typeInt == 27) then return "DICTIONARY" end
                    if (typeInt == 28) then return "ARRAY" end
                    if (typeInt == 24) then return "OBJECT" end
                    if (typeInt == 21) then return "STRING_NAME" end
                    if (typeInt == 0) then return "NIL" end

                    if (typeInt == 5) then return "VECTOR2" end -- (x,y)
                    if (typeInt == 6) then return "VECTOR2I" end -- (x,y): int
                    if (typeInt == 7) then return "RECT2" end -- (vector2,vector2)
                    if (typeInt == 8) then return "RECT2I" end -- (vector2i,vector2i)
                    if (typeInt == 9) then return "VECTOR3" end -- (x,y,z)
                    if (typeInt == 10) then return "VECTOR3I" end -- (x,y,z): int
                    if (typeInt == 11) then return "TRANSFORM2D" end
                    if (typeInt == 12) then return "VECTOR4" end -- (x,y,z,w)
                    if (typeInt == 13) then return "VECTOR4I" end -- (x,y,z,w): int
                    if (typeInt == 14) then return "PLANE" end
                    if (typeInt == 15) then return "QUATERNION" end
                    if (typeInt == 16) then return "AABB" end
                    if (typeInt == 17) then return "BASIS" end
                    if (typeInt == 18) then return "TRANSFORM3D" end -- basis: 3x3 matix, origin: vector3
                    if (typeInt == 19) then return "PROJECTION" end
                    if (typeInt == 20) then return "COLOR" end -- color is 4 floats (r,g,b,a)
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
                    return "BEYOND_VARIANT_MAX"
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
                    return "BEYOND_VARIANT_MAX"
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
                            if i + 1 > strSize then i = strSize + 1; return 0xFFFD end

                            local byte2 = str:byte( i + 1 )
                            if ( byte2 & 0xC0 ) ~= 0x80 then i = i + 1; return 0xFFFD end -- lead

                            local codePoint = ( (byte1 & 0x1F) << 6 ) | ( byte2 & 0x3F ) -- payload bits
                            i = i + 2
                            return codePoint

                        -- 3-byte | 0xE0–0xEF
                        elseif byte1 < 0xF0 then
                            if i + 2 > strSize then i = strSize + 1; return 0xFFFD end

                            local byte2, byte3 = str:byte( i + 1 ), str:byte( i + 2 )
                            if ( byte2 & 0xC0 ) ~= 0x80 or ( byte3 & 0xC0 ) ~= 0x80 then i = i + 1; return 0xFFFD end -- lead

                            local codePoint = ( ( byte1 & 0x0F ) << 12 ) | ( ( byte2 & 0x3F ) << 6 ) | ( byte3 & 0x3F )  -- payload bits
                            -- reject surrogates
                            if codePoint >= 0xD800 and codePoint <= 0xDFFF then codePoint = 0xFFFD end
                            i = i + 3
                            return codePoint

                        -- 4-byte | 0xF0–0xF7
                        elseif byte1 < 0xF5 then
                            if i + 3 > strSize then i = strSize + 1; return 0xFFFD end

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
                    local MAX_CHARS_TO_READ = 15000
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
                        if codePoint < 0 or codePoint > 0x10FFFF or codePoint >= 0xD800 and codePoint <= 0xDFFF then codePoint = 0xFFFD end

                        writeInteger( address + idx * 0x4, codePoint )
                        idx = idx + 1
                    end

                    -- null terminator
                    writeInteger(address + idx * 4, 0x0)

                    return readByte( address ) or 0x0
                    --return string.byte( str, 1 ) -- bullshit, from what I suggest, CE stores the last 8bytes (?) of the orig memory in advance and after the callback it writes
                                                    --those 8 bytes replacing the first byte with a 0x0 (if returned nothing here)
                end


                if GDSOf.MAJOR_VER == 4 then
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
                if isNullOrNil(childrenAddr) then return end

                local nodeDict = {}

                for i=0,(childrenSize-1) do

                    local nodePtr = readPointer( childrenAddr + i * GDSOf.PTRSIZE )
                    if isNullOrNil(nodePtr) then error('getMainNodeDict: NO MAIN NODES') end

                    local nodeNameStr = getNodeName(nodePtr)
                    nodeNameStr = tostring(nodeNameStr)
                    registerSymbol( nodeNameStr , nodePtr , true) -- let's have them registered

                    if GDSOf.MAJOR_VER == 4 then

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
                if isNullOrNil(childrenAddr) or isNullOrNil(childrenSize) then error('getMainNodeDict: VP Children not valid') end

                local nodeTable = {}

                for i=0,(childrenSize-1) do

                    local nodeAddr = readPointer( childrenAddr + i * GDSOf.PTRSIZE )
                    if isNullOrNil(nodeAddr) then error('getMainNodeDict: NO MAIN NODES') end

                    local nodeNameStr = getNodeName( nodeAddr )
                    nodeNameStr = tostring( nodeNameStr )
                    registerSymbol( nodeNameStr , nodeAddr , true) -- let's have them registered when we do structs
                    table.insert( nodeTable, nodeAddr)
                end
                return nodeTable
            end

            --- gets a dumped Node by name
            ---@param nodeName string
            function getDumpedNode(nodeName)
                assert(type(nodeName) == "string",'Node name should be a string, instead got: '..type(nodeName))
                if not (gdOffsetsDefined) then print('define the offsets first, silly') return end

                if (not dumpedMonitorNodes) or #dumpedMonitorNodes == 0 then
                    --sendDebugMessage('getDumpedNode: dumped nodes table is nil, dump the game first')
                    return;
                end
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
                if (not dumpedMonitorNodes) or #dumpedMonitorNodes == 0 then
                    --sendDebugMessage('printDumpedNodes: dumped nodes table is nil, dump the game first')
                    return;
                end
                if not (gdOffsetsDefined) then print('define the offsets first, silly') return end

                for _,nodeAddr in ipairs(dumpedMonitorNodes) do
                    local nodeNameStr = getNodeName( nodeAddr )
                    printf(">Node name: %s \t Node addr: %x", tostring(nodeNameStr), tonumber(nodeAddr))
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
                if not checkForGDScript( nodeAddr ) then
                    --sendDebugMessage('DumpNodeToAddr: node '..nodeNameStr..' doesnt have GDScript/Inst')
                    return
                end
                --sendDebugMessage('DumpNodeToAddr: node '..tostring(nodeNameStr)..('addr: %x'):format(nodeAddr) )

                synchronize(function(parentMemrec)
                        if parentMemrec.Count ~= 0 then -- let's clear all children
                            while parentMemrec.Child[0] ~= nil do
                                parentMemrec.Child[0].Destroy()
                            end
                        end
                    end, parentMemrec
                )

                if bDoConstants and (GDSOf.CONST_MAP ~= 0) then
                    --sendDebugMessage('DumpNodeToAddr: constants for node: '..tostring(nodeNameStr) )

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
                    --sendDebugMessage('DumpNodeToAddr: variants for node: '..tostring(nodeNameStr) )
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
                    sendDebugMessage('MAIN: loop. STEP: Constants for: '..key)

                    if GDSOf.CONST_MAP ~= 0 then
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
                    end

                    sendDebugMessage('MAIN: loop. STEP: VARIANTS for: '..key)
                    iterateVecVarToAddr( value.PTR , value.MEMREC )
                end

                debugPrefix = 1;
                print('MAIN: DUMP PROCESS FINISHED')

            end


        if not (targetIsGodot) then --[[print('target is not godot')--]] return; end;
        defineGDOffsets( config )
    end;

    godotRegisterPreinit()