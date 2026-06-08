-- GDDumperModules/GDFunctionStructDisassembler.lua
local Module = {}

function Module.install(contextTable)

    local function getStoredOffsetsFromVersion(verStr)

      local verStr = verStr or GDDEFS.VERSION_STRING
      -- offsets in Node/Objects in debug versions are shifted by 0x8 in most cases; function code/constants/globals are shifted less often

      local offsets = {}

      if verStr == "4.8" then
        GDDEFS.DICT_HEAD = 0x20
        GDDEFS.DICT_TAIL = 0x28
        GDDEFS.DICT_SIZE = 0x34
        GDDEFS.STRING = 0x8 -- we need it for correct addr/struct representation
        GDDEFS.GET_TYPE_INDX = 10
        GDDEFS.CALLP_INDX = GDDEFS.GET_TYPE_INDX + 4

        offsets.VPChildren = 0x140
        offsets.VPObjStringName = 0x190
        offsets.NodeGDScriptInstance = 0x60
        offsets.NodeGDScriptName = 0xF0
        offsets.GDScriptFunctionMap = 0x230
        offsets.GDScriptConstantMap = 0x208
        offsets.GDScriptVariantNameHM = 0x180
        offsets.oVariantVector = 0x28
        -- offsets.GDScriptVariantNameType = 0x44 -- 4.x
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

      elseif verStr == "4.7" then
        GDDEFS.DICT_HEAD = 0x20
        GDDEFS.DICT_TAIL = 0x28
        GDDEFS.DICT_SIZE = 0x34
        GDDEFS.STRING = 0x8 -- we need it for correct addr/struct representation
        GDDEFS.GET_TYPE_INDX = 10
        GDDEFS.CALLP_INDX = GDDEFS.GET_TYPE_INDX + 4
        -- timer 2D0 time_left | 2D8 isactive | 2C0 waittime

        offsets.VPChildren = 0x140
        offsets.VPObjStringName = 0x190
        offsets.NodeGDScriptInstance = 0x60
        offsets.NodeGDScriptName = 0xF0
        offsets.GDScriptFunctionMap = 0x230
        offsets.GDScriptConstantMap = 0x208
        offsets.GDScriptVariantNameHM = 0x180
        offsets.oVariantVector = 0x28
        -- offsets.GDScriptVariantNameType = 0x44 -- 4.x
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
      elseif verStr == "4.6" then
        
        GDDEFS.STRING = 0x8 -- we need it for correct addr/struct representation
        if GDDEFS._x64 then
          GDDEFS.DICT_HEAD = 0x20
          GDDEFS.DICT_TAIL = 0x28
          GDDEFS.DICT_SIZE = 0x34 --0x3C
          GDDEFS.GET_TYPE_INDX = 10
          GDDEFS.CALLP_INDX = GDDEFS.GET_TYPE_INDX + 4
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
          -- offsets.GDScriptVariantNameType = 0x44 -- 4.x
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
          -- offsets.GDScriptVariantNameType = 0x20 -- 4.x
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

      elseif verStr == "4.5" then
        GDDEFS.DICT_HEAD = 0x20
        GDDEFS.DICT_TAIL = 0x28
        GDDEFS.DICT_SIZE = 0x34 -- 0x3C
        GDDEFS.STRING = 0x8 -- we need it for correct addr/struct representation
        GDDEFS.GET_TYPE_INDX = 9
        GDDEFS.CALLP_INDX = GDDEFS.GET_TYPE_INDX + 5 -- 14
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
        -- offsets.GDScriptVariantNameType = 0x48 -- 4.x
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

      elseif verStr == "4.4" then
        GDDEFS.GET_TYPE_INDX = 8
        GDDEFS.CALLP_INDX = GDDEFS.GET_TYPE_INDX + 5 -- 13
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
        -- offsets.GDScriptVariantNameType = 0x48 -- 4.x
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

      elseif verStr == "4.3" then
        GDDEFS.GET_TYPE_INDX = 8
        GDDEFS.CALLP_INDX = GDDEFS.GET_TYPE_INDX + 5 -- 13
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
        -- offsets.GDScriptVariantNameType = 0x40 -- 4.x
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
          -- offsets.GDScriptVariantNameType = offsets.GDScriptVariantNameType + 0x8 -- 4.x

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
          -- offsets.GDScriptVariantNameType = offsets.GDScriptVariantNameType + 0x8 -- 4.x
          offsets.GDScriptRealoadIndex = offsets.GDScriptRealoadIndex - 1
        end

        return offsets

      elseif verStr == "4.2" then
        GDDEFS.GET_TYPE_INDX = 8
        GDDEFS.CALLP_INDX = GDDEFS.GET_TYPE_INDX + 5 -- 13
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
        -- offsets.GDScriptVariantNameType = 0x40 -- 4.x
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
          -- offsets.GDScriptVariantNameType = offsets.GDScriptVariantNameType + 0x8 -- 4.x
          offsets.GDScriptRealoadIndex = offsets.GDScriptRealoadIndex + 17

        end 
        if GDDEFS.CUSTOMVER then
          -- GDDEFS.STRING = 0x8
          -- Godot Engine 4.2.3 
          -- godot.windows.template_release.double.x86_64.exe 
          offsets.VPChildren = offsets.VPChildren + 0x48
          offsets.VPObjStringName = offsets.VPObjStringName + 0x48
          offsets.NodeGDScriptName = offsets.NodeGDScriptName + 0x48
          offsets.GDScriptFunctionMap = offsets.GDScriptFunctionMap + 0x48
          offsets.GDScriptConstantMap = offsets.GDScriptConstantMap + 0x48
          offsets.GDScriptVariantNameHM = offsets.GDScriptVariantNameHM + 0x48
          -- offsets.GDScriptVariantNameType = offsets.GDScriptVariantNameType + 0x8 -- 4.x
          -- offsets.GDScriptRealoadIndex = offsets.GDScriptRealoadIndex + 0
          offsets.GDScriptFunctionCode = offsets.GDScriptFunctionCode + 0x20
          offsets.GDScriptFunctionCodeConsts = offsets.GDScriptFunctionCodeConsts + 0x20
          offsets.GDScriptFunctionCodeGlobals = offsets.GDScriptFunctionCodeGlobals + 0x20
          offsets.GDScriptRealoadIndex = offsets.GDScriptRealoadIndex - 1
        end

        if GDDEFS.USES_DOUBLE_REALT then
          -- GDDEFS.STRING = 0x8
          -- Godot Engine 4.2.3 
          -- godot.windows.template_release.double.x86_64.exe 
          offsets.VPChildren = offsets.VPChildren + 0x10
          offsets.VPObjStringName = offsets.VPObjStringName + 0x10
          offsets.NodeGDScriptName = offsets.NodeGDScriptName + 0x10
          offsets.GDScriptFunctionMap = offsets.GDScriptFunctionMap +0x10
          offsets.GDScriptConstantMap = offsets.GDScriptConstantMap + 0x10
          offsets.GDScriptVariantNameHM = offsets.GDScriptVariantNameHM + 0x10
          -- offsets.GDScriptRealoadIndex = offsets.GDScriptRealoadIndex + 0
        end

        return offsets

      elseif verStr == "4.1" then
        GDDEFS.GET_TYPE_INDX = 8
        GDDEFS.CALLP_INDX = GDDEFS.GET_TYPE_INDX + 5 -- 13
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
        -- offsets.GDScriptVariantNameType = 0x40 -- 4.x
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

      elseif verStr == "4.0" then
        GDDEFS.GET_TYPE_INDX = 8
        GDDEFS.CALLP_INDX = GDDEFS.GET_TYPE_INDX + 5 -- 13
        offsets.VPChildren = 0x168
        offsets.VPObjStringName = 0x1C0
        offsets.NodeGDScriptInstance = 0x68
        offsets.NodeGDScriptName = 0x178
        offsets.GDScriptFunctionMap = 0x270
        offsets.GDScriptConstantMap = 0x238
        offsets.GDScriptVariantNameHM = 0x2A8
        offsets.oVariantVector = 0x28
        -- offsets.GDScriptVariantNameType = 0x40 -- 4.x
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

      elseif verStr == "3.6" then
        GDDEFS.GET_TYPE_INDX = 6
        GDDEFS.CALLP_INDX = GDDEFS.GET_TYPE_INDX + 6 -- 12
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
        -- offsets.GDScriptVariantNameType = nil -- 4.x
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

      elseif verStr == "3.5" then
        GDDEFS.GET_TYPE_INDX = 6
        GDDEFS.CALLP_INDX = GDDEFS.GET_TYPE_INDX + 6 -- 12
        if GDDEFS._x64 then
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
          -- offsets.GDScriptVariantNameType = nil -- 4.x
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
          -- offsets.GDScriptVariantNameType = 0x34 -- 4.x
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

      elseif verStr == "3.4" then
        GDDEFS.GET_TYPE_INDX = 6
        GDDEFS.CALLP_INDX = GDDEFS.GET_TYPE_INDX + 6 -- 12
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
        -- offsets.GDScriptVariantNameType = nil -- 4.x
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

      elseif verStr == "3.3" then
        GDDEFS.GET_TYPE_INDX = 6
        GDDEFS.CALLP_INDX = GDDEFS.GET_TYPE_INDX + 6 -- 12
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
        -- offsets.GDScriptVariantNameType = nil -- 4.x
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

      elseif verStr == "3.2" then
        GDDEFS.GET_TYPE_INDX = 6
        GDDEFS.CALLP_INDX = GDDEFS.GET_TYPE_INDX + 6 -- 12
        -- error("Not defined yet")
        offsets.VPChildren = 0x108
        offsets.VPObjStringName = 0x120
        offsets.NodeGDScriptInstance = 0x50
        offsets.NodeGDScriptName = 0x100
        offsets.GDScriptFunctionMap = 0x1B0
        offsets.GDScriptConstantMap = 0x198
        offsets.GDScriptVariantNameHM = 0x1C8
        offsets.oVariantVector = 0x20
        -- offsets.GDScriptVariantNameType = nil -- 4.x
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

      elseif verStr == "3.1" then
        print("No recorded version found")
        error("Not defined yet")
      elseif verStr == "3.0" then
        -- 3.0.6.stable.official
        GDDEFS.GET_TYPE_INDX = 6
        GDDEFS.CALLP_INDX = GDDEFS.GET_TYPE_INDX + 6 -- 12
        offsets.VPChildren = 0x100
        offsets.VPObjStringName = 0x118
        offsets.NodeGDScriptInstance = 0x50
        offsets.NodeGDScriptName = 0xF8
        offsets.GDScriptFunctionMap = 0x1B0
        offsets.GDScriptConstantMap = 0x198
        offsets.GDScriptVariantNameHM = 0x1C8
        offsets.oVariantVector = 0x18
        -- offsets.GDScriptVariantNameType = nil -- 4.x
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
      elseif verStr == "2.1" then
        -- Godot Engine v2.1.7.rc.custom_build
        -- godot.windows.opt.64.exe

        GDDEFS.GET_TYPE_INDX = 7
        offsets.VPChildren = 0xC8
        offsets.VPObjStringName = 0xE0
        offsets.NodeGDScriptInstance = 0x58
        offsets.NodeGDScriptName = 0xC0
        offsets.GDScriptFunctionMap = 0x160
        offsets.GDScriptConstantMap = 0x148
        offsets.GDScriptVariantNameHM = 0x178
        offsets.oVariantVector = 0x30
        -- offsets.GDScriptVariantNameType = nil -- 4.x
        offsets.NodeVariantVectorSizeOffset = 0x4
        offsets.GDScriptVariantNamesIndex = 0x38 -- 3.x
        offsets.GDScriptFunctionCode = 0x50
        offsets.GDScriptFunctionCodeConsts = 0x20
        offsets.GDScriptFunctionCodeGlobals = 0x30

        if GDDEFS.DEBUGVER then
          -- offsets.VPChildren = offsets.VPChildren + 0x8
          -- offsets.VPObjStringName = offsets.VPObjStringName + 0x8
          -- offsets.NodeGDScriptInstance = offsets.NodeGDScriptInstance + 0x8
          -- offsets.NodeGDScriptName = offsets.NodeGDScriptName + 0x8
          -- offsets.GDScriptFunctionMap = offsets.GDScriptFunctionMap + 0x8
          -- offsets.GDScriptConstantMap = offsets.GDScriptConstantMap + 0x8
          -- offsets.GDScriptVariantNameHM = offsets.GDScriptVariantNameHM + 0x8
          -- offsets.oVariantVector = offsets.oVariantVector + 0x18
        end
        if GDDEFS.CUSTOMVER then
          offsets.VPChildren = offsets.VPChildren - 0x10
          offsets.VPObjStringName = offsets.VPObjStringName - 0x10
          offsets.NodeGDScriptInstance = offsets.NodeGDScriptInstance - 0x10
          offsets.NodeGDScriptName = offsets.NodeGDScriptName - 0x10
          offsets.GDScriptFunctionMap = offsets.GDScriptFunctionMap - 0x20
          offsets.GDScriptConstantMap = offsets.GDScriptConstantMap - 0x20
          offsets.GDScriptVariantNameHM = offsets.GDScriptVariantNameHM - 0x20
          offsets.oVariantVector = offsets.oVariantVector - 0x18
        end

        return offsets

      else
        print( "No recorded version found, report here: https://github.com/palepine/GDDumper/issues" )
        error( "No recorded version found, report here: https://github.com/palepine/GDDumper/issues" )
        return offsets
      end
    end

  return getStoredOffsetsFromVersion
end

return Module -- exporting