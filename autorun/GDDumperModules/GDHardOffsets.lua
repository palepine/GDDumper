local Module = {}

-- TODO: metatables, profiles, full semver instead of ifelse mess when it will make sense

local function alignOffset(offset, alignment)
  local remaining = offset % alignment -- get remaining bytes for alignment
  if remaining ~= 0 then
    offset = offset + (alignment - remaining)
  end
  return offset
end

function Module.install(contextTable)

    local function getAssumed( offsets )
      if gd_assumeOffsets and type(gd_assumeOffsets) == 'function' then
        print('ASSUMING OFFSETS FALLBACK FOR AN UNRECORDED VERSION/RELEASE')
        local assumed = gd_assumeOffsets()
        offsets.VPChildren = assumed.CHILDREN or 0
        offsets.VPObjStringName = assumed.OBJ_STRING_NAME or 0
        offsets.NodeGDScriptInstance = assumed.SCRIPT_INSTANCE or 0
        offsets.NodeGDScriptName = assumed.SCRIPT_NAME or 0
        offsets.GDScriptFunctionMap = assumed.FUNC_MAP or 0
        offsets.GDScriptConstantMap = assumed.CONST_MAP or 0
        offsets.GDScriptVariantNameHM = assumed.VARIANT_MAP or 0
        offsets.oVariantVector = assumed.VARIANT_VECTOR or 0
        offsets.NodeVariantVectorSizeOffset = assumed.VARIANT_VECTOR_SIZE or 0
        offsets.GDScriptFunctionCode = assumed.FUNC_CODE or 0
        offsets.GDScriptFunctionCodeConsts = assumed.FUNC_CONST or 0
        offsets.GDScriptFunctionCodeGlobals = assumed.FUNC_GLOBALS or 0
        return offsets
      end
      -- error('Unhandled version')
      return nil
    end

    local function getStoredOffsetsFromVersion(verStr)

      local verStr = verStr or GDDEFS.VERSION_STRING
      -- offsets in Node/Objects in debug versions are shifted by 0x8 in most cases; function code/constants/globals are shifted less often

      local assumed = {}
      local offsets = {}

      -- non-stable versions should be handled by the else clause
      -- stable ones

      if verStr == "4.7" then
        GDDEFS.STRING = 0x8
        GDDEFS.GET_TYPE_INDX = 10
        GDDEFS.CALLP_INDX = GDDEFS.GET_TYPE_INDX + 4

        -- Godot Engine v4.7.stable.official 
        -- godot.windows.template_release.x86_64.exe 
        offsets.VPChildren = 0x140
        offsets.VPObjStringName = 0x190
        offsets.NodeGDScriptInstance = 0x60
        offsets.NodeGDScriptName = 0xF8 -- new field before scriptname, avalanche for maps
        offsets.GDScriptFunctionMap = 0x238
        offsets.GDScriptConstantMap = 0x210
        offsets.GDScriptVariantNameHM = 0x188
        offsets.oVariantVector = 0x28
        offsets.NodeVariantVectorSizeOffset = 0x10
        offsets.GDScriptFunctionCode = 0x160 -- 0x18 less, TightLocalVector<Pair<int, Variant::Type>> for HashMap<int, Variant::Type>
        offsets.GDScriptFunctionCodeConsts = 0x180
        offsets.GDScriptFunctionCodeGlobals = 0x1B8 -- not relatively consistent anymore?
        offsets.GDScriptFunctionCodeArg = 0xF4
        offsets.GDScriptRealoadIndex = 45 -- diff by -1

        if GDDEFS.DEBUGVER then
          offsets.VPChildren = offsets.VPChildren + 0x8
          offsets.VPObjStringName = offsets.VPObjStringName + 0x8
          offsets.NodeGDScriptInstance = offsets.NodeGDScriptInstance + 0x8
          offsets.NodeGDScriptName = offsets.NodeGDScriptName + 0x8
          offsets.GDScriptFunctionMap = offsets.GDScriptFunctionMap + 0x8
          offsets.GDScriptConstantMap = offsets.GDScriptConstantMap + 0x8
          offsets.GDScriptVariantNameHM = offsets.GDScriptVariantNameHM + 0x8
          offsets.oVariantVector = offsets.oVariantVector + 0x28
          offsets.GDScriptRealoadIndex = offsets.GDScriptRealoadIndex + 20
        end

        if GDDEFS.CUSTOMVER then
          -- offsets.VPChildren = offsets.VPChildren + 0x48
          -- offsets.VPObjStringName = offsets.VPObjStringName + 0x48
          -- offsets.NodeGDScriptName = offsets.NodeGDScriptName + 0x48
          -- offsets.GDScriptFunctionMap = offsets.GDScriptFunctionMap + 0x48
          -- offsets.GDScriptConstantMap = offsets.GDScriptConstantMap + 0x48
          -- offsets.GDScriptVariantNameHM = offsets.GDScriptVariantNameHM + 0x48
          -- offsets.GDScriptRealoadIndex = offsets.GDScriptRealoadIndex - 1
          offsets = getAssumed(offsets)
          if offsets == nil then error("Not defined yet") end
        end

        if not GDDEFS._x64 then
          offsets = getAssumed(offsets)
          if offsets == nil then error("Not defined yet") end
        end

        return offsets

      elseif verStr == "4.6" then
        GDDEFS.STRING = 0x8
        GDDEFS.GET_TYPE_INDX = 10
        GDDEFS.CALLP_INDX = GDDEFS.GET_TYPE_INDX + 4

        if GDDEFS._x64 then
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
          offsets.NodeVariantVectorSizeOffset = 0x10
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
          end

          if GDDEFS.CUSTOMVER then
            offsets.VPChildren = offsets.VPChildren + 0x48
            offsets.VPObjStringName = offsets.VPObjStringName + 0x48
            offsets.NodeGDScriptName = offsets.NodeGDScriptName + 0x48
            offsets.GDScriptFunctionMap = offsets.GDScriptFunctionMap + 0x48
            offsets.GDScriptConstantMap = offsets.GDScriptConstantMap + 0x48
            offsets.GDScriptVariantNameHM = offsets.GDScriptVariantNameHM + 0x48
            offsets.GDScriptRealoadIndex = offsets.GDScriptRealoadIndex - 1
          end
        else

          -- custom
          offsets.VPChildren = 0xF0
          offsets.VPObjStringName = 0x12C
          offsets.NodeGDScriptInstance = 0x40
          offsets.NodeGDScriptName = 0xC4
          offsets.GDScriptFunctionMap = 0x178
          offsets.GDScriptConstantMap = 0x160
          offsets.GDScriptVariantNameHM = 0x110
          offsets.oVariantVector = 0x1C
          offsets.NodeVariantVectorSizeOffset = 0x8
          offsets.GDScriptFunctionCode = 0xE8
          offsets.GDScriptFunctionCodeConsts = 0x140
          offsets.GDScriptFunctionCodeGlobals = 0x100
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
          end

          if GDDEFS.CUSTOMVER then
            offsets = getAssumed(offsets)
            if offsets == nil then error("Not defined yet") end
          end


        end

        return offsets

      elseif verStr == "4.5" then

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
        offsets.GDScriptConstantMap = 0x240 --0x208
        offsets.GDScriptVariantNameHM = 0x1B8
        offsets.oVariantVector = 0x28
        offsets.NodeVariantVectorSizeOffset = 0x8
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

        if not GDDEFS._x64 then
          offsets = getAssumed(offsets)
          if offsets == nil then error("Not defined yet") end
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
        offsets.NodeVariantVectorSizeOffset = 0x8
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

        if not GDDEFS._x64 then
          offsets = getAssumed(offsets)
          if offsets == nil then error("Not defined yet") end
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
        offsets.NodeVariantVectorSizeOffset = 0x8
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
          offsets.GDScriptRealoadIndex = offsets.GDScriptRealoadIndex - 1
        end
        
        if not GDDEFS._x64 then
          offsets = getAssumed(offsets)
          if offsets == nil then error("Not defined yet") end
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
        offsets.NodeVariantVectorSizeOffset = 0x4
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

        if not GDDEFS._x64 then
          offsets = getAssumed(offsets)
          if offsets == nil then error("Not defined yet") end
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
        offsets.NodeVariantVectorSizeOffset = 0x4
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

        if not GDDEFS._x64 then
          offsets = getAssumed(offsets)
          if offsets == nil then error("Not defined yet") end
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
        offsets.NodeVariantVectorSizeOffset = 0x8
        offsets.GDScriptFunctionCode = 0x118
        offsets.GDScriptFunctionCodeConsts = 0x100
        offsets.GDScriptFunctionCodeGlobals = 0xF0
        offsets.GDScriptFunctionCodeArg = 0xA0
        
        if GDDEFS.DEBUGVER then
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
          -- offsets.VPChildren = offsets.VPChildren + 0x48
          -- offsets.VPObjStringName = offsets.VPObjStringName + 0x48
          -- offsets.NodeGDScriptName = offsets.NodeGDScriptName + 0x48
          -- offsets.GDScriptFunctionMap = offsets.GDScriptFunctionMap + 0x48
          -- offsets.GDScriptConstantMap = offsets.GDScriptConstantMap + 0x48
          -- offsets.GDScriptVariantNameHM = offsets.GDScriptVariantNameHM + 0x48
          offsets = getAssumed(offsets)
          if offsets == nil then error("Not defined yet") end
        end

        if not GDDEFS._x64 then
          offsets = getAssumed(offsets)
          if offsets == nil then error("Not defined yet") end
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
        offsets.NodeVariantVectorSizeOffset = 0x4
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
          GDDEFS.STRING = 0x10
          offsets.VPChildren = offsets.VPChildren --[[+0x48]]
          offsets.VPObjStringName = offsets.VPObjStringName --[[+0x48]]
          offsets.NodeGDScriptName = offsets.NodeGDScriptName --[[+0x48]]
          offsets.GDScriptFunctionMap = offsets.GDScriptFunctionMap --[[+0x48]]
          offsets.GDScriptConstantMap = offsets.GDScriptConstantMap --[[+0x48]]
          offsets.GDScriptVariantNameHM = offsets.GDScriptVariantNameHM --[[+0x48]]
        end

        if not GDDEFS._x64 then
          offsets = getAssumed(offsets)
          if offsets == nil then error("Not defined yet") end
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
          offsets.NodeVariantVectorSizeOffset = 0x4
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
          offsets.NodeVariantVectorSizeOffset = 0x4
          offsets.GDScriptFunctionCode = 0x38
          offsets.GDScriptFunctionCodeConsts = 0x20
          offsets.GDScriptFunctionCodeGlobals = 0x28

          if GDDEFS.DEBUGVER then
            -- offsets.VPChildren = offsets.VPChildren + 0x4
            -- offsets.VPObjStringName = offsets.VPObjStringName + 0x4
            -- offsets.NodeGDScriptInstance = offsets.NodeGDScriptInstance + 0x4
            -- offsets.NodeGDScriptName = offsets.NodeGDScriptName + 0x4
            -- offsets.GDScriptFunctionMap = offsets.GDScriptFunctionMap + 0x4
            -- offsets.GDScriptConstantMap = offsets.GDScriptConstantMap + 0x4
            -- offsets.GDScriptVariantNameHM = offsets.GDScriptVariantNameHM + 0x4
            -- offsets.oVariantVector = offsets.oVariantVector + 0x0C
            offsets = getAssumed(offsets)
            if offsets == nil then error("Not defined yet") end

          end

          if GDDEFS.CUSTOMVER then
            -- offsets.VPChildren = offsets.VPChildren+0x48
            -- offsets.VPObjStringName = offsets.VPObjStringName+0x48
            -- offsets.NodeGDScriptName = offsets.NodeGDScriptName+0x48
            -- offsets.GDScriptFunctionMap = offsets.GDScriptFunctionMap+0x48
            -- offsets.GDScriptConstantMap = offsets.GDScriptConstantMap+0x48
            -- offsets.GDScriptVariantNameHM = offsets.GDScriptVariantNameHM+0x48
            --  offsets.oVariantVector = offsets.oVariantVector+0x18
            offsets = getAssumed(offsets)
            if offsets == nil then error("Not defined yet") end
          end

        if not GDDEFS._x64 then
          offsets = getAssumed(offsets)
          if offsets == nil then error("Not defined yet") end
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
        offsets.NodeVariantVectorSizeOffset = 0x4
        offsets.GDScriptFunctionCode = 0x50
        offsets.GDScriptFunctionCodeConsts = 0x20
        offsets.GDScriptFunctionCodeGlobals = 0x30
        -- timer 1E0 (float) waittime 1E8 time_left 1F0 paused?
        offsets.GDScriptFunctionCodeArg = 0xA0
        offsets.GDScriptRealoadIndex = 42
        
        if GDDEFS.DEBUGVER then
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
          -- GDDEFS.STRING = 0x8
          -- offsets.VPChildren = offsets.VPChildren + 0x48
          -- offsets.VPObjStringName = offsets.VPObjStringName + 0x48
          -- offsets.NodeGDScriptName = offsets.NodeGDScriptName + 0x48
          -- offsets.GDScriptFunctionMap = offsets.GDScriptFunctionMap + 0x48
          -- offsets.GDScriptConstantMap = offsets.GDScriptConstantMap + 0x48
          -- offsets.GDScriptVariantNameHM = offsets.GDScriptVariantNameHM + 0x48
          -- offsets.oVariantVector = offsets.oVariantVector + 0x18
          offsets = getAssumed(offsets)
          if offsets == nil then error("Not defined yet") end

        end
        
        if not GDDEFS._x64 then
          offsets = getAssumed(offsets)
          if offsets == nil then error("Not defined yet") end
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
        offsets.NodeVariantVectorSizeOffset = 0x4
        offsets.GDScriptFunctionCode = 0x50
        offsets.GDScriptFunctionCodeConsts = 0x20
        offsets.GDScriptFunctionCodeGlobals = 0x30
        offsets.GDScriptFunctionCodeArg = 0xA0
        offsets.GDScriptRealoadIndex = 41
        
        if GDDEFS.DEBUGVER then
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
          -- GDDEFS.STRING = 0x8
          -- offsets.VPChildren = offsets.VPChildren + 0x48
          -- offsets.VPObjStringName = offsets.VPObjStringName + 0x48
          -- offsets.NodeGDScriptName = offsets.NodeGDScriptName + 0x48
          -- offsets.GDScriptFunctionMap = offsets.GDScriptFunctionMap + 0x48
          -- offsets.GDScriptConstantMap = offsets.GDScriptConstantMap + 0x48
          -- offsets.GDScriptVariantNameHM = offsets.GDScriptVariantNameHM + 0x48
          -- offsets.oVariantVector = offsets.oVariantVector + 0x18
          offsets = getAssumed(offsets)
          if offsets == nil then error("Not defined yet") end
        end

        if not GDDEFS._x64 then
          offsets = getAssumed(offsets)
          if offsets == nil then error("Not defined yet") end
        end

        return offsets

      elseif verStr == "3.2" then
        GDDEFS.GET_TYPE_INDX = 6
        GDDEFS.CALLP_INDX = GDDEFS.GET_TYPE_INDX + 6 -- 12

        offsets.VPChildren = 0x108
        offsets.VPObjStringName = 0x120
        offsets.NodeGDScriptInstance = 0x50
        offsets.NodeGDScriptName = 0x100
        offsets.GDScriptFunctionMap = 0x1B0
        offsets.GDScriptConstantMap = 0x198
        offsets.GDScriptVariantNameHM = 0x1C8
        offsets.oVariantVector = 0x20
        offsets.NodeVariantVectorSizeOffset = 0x4
        offsets.GDScriptFunctionCode = 0x50
        offsets.GDScriptFunctionCodeConsts = 0x20
        offsets.GDScriptFunctionCodeGlobals = 0x30
        offsets.GDScriptFunctionCodeArg = 0xA0
        
        if GDDEFS.DEBUGVER then
          -- GDDEFS.STRING = 0x8
          -- offsets.VPChildren = offsets.VPChildren + 0x8
          -- offsets.VPObjStringName = offsets.VPObjStringName + 0x8
          -- offsets.NodeGDScriptInstance = offsets.NodeGDScriptInstance + 0x8
          -- offsets.NodeGDScriptName = offsets.NodeGDScriptName + 0x8
          -- offsets.GDScriptFunctionMap = offsets.GDScriptFunctionMap + 0x8
          -- offsets.GDScriptConstantMap = offsets.GDScriptConstantMap + 0x8
          -- offsets.GDScriptVariantNameHM = offsets.GDScriptVariantNameHM + 0x8
          -- offsets.oVariantVector = offsets.oVariantVector + 0x18
          offsets = getAssumed(offsets)
          if offsets == nil then error("Not defined yet") end
        end
        if GDDEFS.CUSTOMVER then
          -- godot.windows.opt.64.exe
          -- Godot Engine v3.2.stable.custom_build
          offsets.VPChildren = offsets.VPChildren + 0x8
          offsets.VPObjStringName = offsets.VPObjStringName + 0x8
          offsets.GDScriptFunctionMap = offsets.GDScriptFunctionMap + 0x8
          offsets.GDScriptConstantMap = offsets.GDScriptConstantMap + 0x8
          offsets.GDScriptVariantNameHM = offsets.GDScriptVariantNameHM + 0x8
        end

        if not GDDEFS._x64 then
          offsets = getAssumed(offsets)
          if offsets == nil then error("Not defined yet") end
        end

        return offsets

      elseif verStr == "3.1" then

        offsets = getAssumed(offsets)
        if offsets == nil then error("Not defined yet") end
        return offsets

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
        offsets.NodeVariantVectorSizeOffset = 0x4
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
          offsets = getAssumed(offsets)
          if offsets == nil then error("Not defined yet") end
        end
        if GDDEFS.CUSTOMVER then
          -- offsets.VPChildren = offsets.VPChildren + 0x8
          -- offsets.VPObjStringName = offsets.VPObjStringName + 0x8
          -- offsets.NodeGDScriptName = offsets.NodeGDScriptName + 0x8
          -- offsets.GDScriptFunctionMap = offsets.GDScriptFunctionMap + 0x8
          -- offsets.GDScriptConstantMap = offsets.GDScriptConstantMap + 0x8
          -- offsets.GDScriptVariantNameHM = offsets.GDScriptVariantNameHM + 0x8
          offsets = getAssumed(offsets)
          if offsets == nil then error("Not defined yet") end
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
        offsets.NodeVariantVectorSizeOffset = 0x4
        offsets.GDScriptFunctionCode = 0x50
        offsets.GDScriptFunctionCodeConsts = 0x20
        offsets.GDScriptFunctionCodeGlobals = 0x30

        if GDDEFS.DEBUGVER then

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

      elseif verStr == "2.0" then
        error("Not defined yet")
      elseif verStr == "1.1" then
        error("Not defined yet")
      elseif verStr == "1.0" then
        error("Not defined yet")
      else

        -- latest verion fallback with assumption
        if gd_assumeOffsets and type(gd_assumeOffsets) == 'function' then
          print( "UNRECORDED or UNSTABLE version " .. (verStr or '?') ..  " , fallback to assumption heuristic" )
          GDDEFS.STRING = 0x8 -- we need it for correct addr/struct representation
          GDDEFS.GET_TYPE_INDX = 10
          GDDEFS.CALLP_INDX = GDDEFS.GET_TYPE_INDX + 4
          -- timer 2D0 time_left | 2D8 isactive | 2C0 waittime

          offsets = getAssumed(offsets)
          return offsets
        end

        print( "No recorded version found, report here: https://github.com/palepine/GDDumper/issues" )
        error( "No recorded version found, report here: https://github.com/palepine/GDDumper/issues" )
      end
    end

  return getStoredOffsetsFromVersion
end

return Module -- exporting