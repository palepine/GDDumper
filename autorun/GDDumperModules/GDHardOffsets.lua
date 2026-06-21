local Module = {}

local function alignOffset(offset, alignment)
  local remaining = offset % alignment -- get remaining bytes for alignment
  if remaining ~= 0 then
    offset = offset + (alignment - remaining)
  end
  return offset
end

local OffsetProfiles = {}
-- MAJOR DECLATIONS
  OffsetProfiles[4] = {}
  OffsetProfiles[3] = {}
  OffsetProfiles[2] = {}
  OffsetProfiles[1] = {}
-- MAJOR DECLATIONS END

function Module.install(contextTable)

  local PTRSIZE = targetIs64Bit() and 0x8 or 0x4
  local sendDebugMessage = contextTable.sendDebugMessage
-- OFFSET DEFINITION

  OffsetProfiles[4][7] =
    {
      default =
      {
        GET_TYPE_INDX = 10,
        CALLP_DELTA = 4,
        GDScriptRealoadIndex = 45, -- diff by -1
      },
      -- releases
      ["*"] =
        {
          x64 =
          {
            VPChildren = 0x140,
            VPObjStringName = 0x190,
            NodeGDScriptInstance = 0x60,
            NodeGDScriptName = 0xF8, -- new field before scriptname, avalanche for maps
            GDScriptFunctionMap = 0x238,
            GDScriptConstantMap = 0x210,
            GDScriptVariantNameHM = 0x188,
            oVariantVector = 0x28,
            NodeVariantVectorSizeOffset = 0x10,

            GDScriptFunctionCode = 0x160, -- 0x18 less, TightLocalVector<Pair<int, Variant::Type>> for HashMap<int, Variant::Type>
            GDScriptFunctionCodeConsts = 0x180,
            GDScriptFunctionCodeGlobals = 0x1B8, -- not relatively consistent anymore?
            GDScriptFunctionCodeArg = 0xF4,
          },
          x86 =
          {
            fallback = true,
          },

          -- modifiers
          debug =
          {
            add =
            {
              VPChildren = 0x8,
              VPObjStringName = 0x8,
              NodeGDScriptInstance = 0x8,
              NodeGDScriptName = 0x8,
              GDScriptFunctionMap = 0x8,
              GDScriptConstantMap = 0x8,
              GDScriptVariantNameHM = 0x8,
              oVariantVector = 0x28,
              GDScriptRealoadIndex = 20,
            }
          },

          tools =
          {
            fallback = true,
          },

          usesDouble =
          {
            fallback = true,
          },
        },
    }

  OffsetProfiles[4][6] =
    {
      default =
      {
        GET_TYPE_INDX = 10,
        CALLP_DELTA = 4,
        GDScriptRealoadIndex = 46,
      },
      -- releases
      ["*"] =
        {
          x64 =
          {
            -- godot.windows.template_release.x86_64.exe
            -- Godot Engine v4.6.stable.official.89cea1439
            VPChildren = 0x140,
            VPObjStringName = 0x190,
            NodeGDScriptInstance = 0x60,
            NodeGDScriptName = 0xF0,
            GDScriptFunctionMap = 0x230,
            GDScriptConstantMap = 0x208,
            GDScriptVariantNameHM = 0x180,
            oVariantVector = 0x28,
            NodeVariantVectorSizeOffset = 0x10,

            GDScriptFunctionCode = 0x178,
            GDScriptFunctionCodeConsts = 0x198,
            GDScriptFunctionCodeGlobals = 0x1A8,
            GDScriptFunctionCodeArg = 0xA0,

            -- timer 2D0 time_left | 2D8 isactive | 2C0 waittime
          },
          x86 =
          {
            -- VPChildren = 0xF0,
            -- VPObjStringName = 0x12C,
            -- NodeGDScriptInstance = 0x40,
            -- NodeGDScriptName = 0xC4,
            -- GDScriptFunctionMap = 0x178,
            -- GDScriptConstantMap = 0x160,
            -- GDScriptVariantNameHM = 0x110,
            -- oVariantVector = 0x1C,
            -- NodeVariantVectorSizeOffset = 0x8,
            -- GDScriptFunctionCode = 0xE8,
            -- GDScriptFunctionCodeConsts = 0x140,
            -- GDScriptFunctionCodeGlobals = 0x100,
            -- offsets.GDScriptFunctionCodeArg = 0xA0 -- 0xf4 argc
          },

          -- modifiers
          debug =
          {
            add =
            {
              VPChildren = 0x8,
              VPObjStringName = 0x8,
              NodeGDScriptInstance = 0x8,
              NodeGDScriptName = 0x8,
              GDScriptFunctionMap = 0x8,
              GDScriptConstantMap = 0x8,
              GDScriptVariantNameHM = 0x8,
              oVariantVector = 0x28,
              GDScriptRealoadIndex = 0, -- todo
            }
          },

          tools =
          {
            -- fallback = true,
            set =
            {
              VPChildren = 0xF0,
              VPObjStringName = 0x12C,
              NodeGDScriptInstance = 0x40,
              NodeGDScriptName = 0xC4,
              GDScriptFunctionMap = 0x178,
              GDScriptConstantMap = 0x160,
              GDScriptVariantNameHM = 0x110,
              oVariantVector = 0x1C,
              NodeVariantVectorSizeOffset = 0x8,
              GDScriptFunctionCode = 0xE8,
              GDScriptFunctionCodeConsts = 0x140,
              GDScriptFunctionCodeGlobals = 0x100,
            }
          },

          usesDouble =
          {
            fallback = true,
          },
        },
    }

  OffsetProfiles[4][5] =
    {
      default =
      {
        GET_TYPE_INDX = 9,
        CALLP_DELTA = 5, -- 14
        GDScriptRealoadIndex = 47,
      },
      -- releases
      ["*"] =
        {
          x64 =
          {
            -- godot.windows.template_release.x86_64.exe
            -- Godot Engine v4.5.1.stable.official.f62fdbde1
            VPChildren = 0x170,
            VPObjStringName = 0x1C0,
            NodeGDScriptInstance = 0x68,
            NodeGDScriptName = 0x120,
            GDScriptFunctionMap = 0x268,
            GDScriptConstantMap = 0x240,
            GDScriptVariantNameHM = 0x1B8,
            oVariantVector = 0x28,
            NodeVariantVectorSizeOffset = 0x8,

            GDScriptFunctionCode = 0x180,
            GDScriptFunctionCodeConsts = 0x1A0,
            GDScriptFunctionCodeGlobals = 0x1B0,
            GDScriptFunctionCodeArg = 0xA0,
            -- A0 Vector<GDScriptDataType> argument_types; including parameter names
            -- f4 argcount
          },
          x86 =
          {
            fallback = true,
          },

          -- modifiers
          debug =
          {
            add =
            {
              -- godot.windows.template_debug.x86_64.exe
              -- Godot Engine v4.5.1.stable.official
              VPChildren = 0x8,
              VPObjStringName = 0x8,
              NodeGDScriptInstance = 0x8,
              NodeGDScriptName = 0x8,
              GDScriptFunctionMap = 0x8,
              GDScriptConstantMap = 0x8,
              GDScriptVariantNameHM = 0x8,
              oVariantVector = 0x28,
              GDScriptRealoadIndex = 19,
            }
          },

          tools =
          {
            add =
            {
              -- godot.windows.template_release.x86_64.exe
              -- Godot Engine v4.5.1.stable.custom_build
              VPChildren = 0x48,
              VPObjStringName = 0x48,
              NodeGDScriptName = 0x48,
              GDScriptFunctionMap = 0x48,
              GDScriptConstantMap = 0x48,
              GDScriptVariantNameHM = 0x48,
              GDScriptRealoadIndex = 0,
            }
          },

          usesDouble =
          {
            fallback = true,
          },
        },
    }

  OffsetProfiles[4][4] =
    {
      default =
      {
        GET_TYPE_INDX = 8,
        CALLP_DELTA = 5, -- 13
        -- STRING = 0x4+0x4 + GDDEFS.PTRSIZE,
        GDScriptRealoadIndex = 46,
      },
      -- releases
      ["*"] =
        {
          x64 =
          {
            -- godot.windows.template_release.x86_64.exe
            -- Godot Engine v4.4.stable.official.4c311cbee
            VPChildren = 0x188,
            VPObjStringName = 0x1E0,
            NodeGDScriptInstance = 0x68,
            NodeGDScriptName = 0x130,
            GDScriptFunctionMap = 0x2D8,
            GDScriptConstantMap = 0x2A8,
            GDScriptVariantNameHM = 0x210,
            oVariantVector = 0x28,
            NodeVariantVectorSizeOffset = 0x8,

            GDScriptFunctionCode = 0x178,
            GDScriptFunctionCodeConsts = 0x198,
            GDScriptFunctionCodeGlobals = 0x1A8,
            GDScriptFunctionCodeArg = 0xA0,
          },
          x86 =
          {
            fallback = true,
          },

          -- modifiers
          debug =
          {
            add =
            {
              -- godot.windows.template_debug.x86_64.exe
              -- Godot Engine v4.4.1.stable.official
              -- godot.windows.template_debug.x86_64.mono.exe
              -- Godot Engine v4.4.stable.mono.official
              VPChildren = 0x8,
              VPObjStringName = 0x8,
              NodeGDScriptInstance = 0x8,
              NodeGDScriptName = 0x8,
              GDScriptFunctionMap = 0x8,
              GDScriptConstantMap = 0x8,
              GDScriptVariantNameHM = 0x8,
              oVariantVector = 0x30,
              GDScriptRealoadIndex = 19,
            }
          },

          tools =
          {
            add =
            {
              -- godot.windows.template_release.x86_64.exe
              -- Godot Engine v4.5.1.stable.custom_build
              VPChildren = 0x48,
              VPObjStringName = 0x48,
              NodeGDScriptName = 0x48,
              GDScriptFunctionMap = 0x48,
              GDScriptConstantMap = 0x48,
              GDScriptVariantNameHM = 0x48,
              GDScriptRealoadIndex = -1,
            }
          },

          usesDouble =
          {
            fallback = true,
          },
        },
    }

  OffsetProfiles[4][3] =
    {
      default =
      {
        GET_TYPE_INDX = 8,
        CALLP_DELTA = 5, -- 13
        GDScriptRealoadIndex = 44,
      },
      -- releases
      ["*"] =
        {
          x64 =
          {
            -- godot.windows.template_release.x86_64.exe
            -- Godot Engine v4.3.stable.official
            VPChildren = 0x178,
            VPObjStringName = 0x1D0,
            NodeGDScriptInstance = 0x68,
            NodeGDScriptName = 0x120,
            GDScriptFunctionMap = 0x280,
            GDScriptConstantMap = 0x250,
            GDScriptVariantNameHM = 0x1B8,
            oVariantVector = 0x28,
            NodeVariantVectorSizeOffset = 0x8,

            GDScriptFunctionCode = 0x178,
            GDScriptFunctionCodeConsts = 0x198,
            GDScriptFunctionCodeGlobals = 0x1A8,
            GDScriptFunctionCodeArg = 0xA0,
          },
          x86 =
          {
            fallback = true,
          },

          -- modifiers
          debug =
          {
            add =
            {
              -- godot.windows.template_debug.x86_64.exe
              -- Godot Engine v4.3.stable.official
              VPChildren = 0x8,
              VPObjStringName = 0x8,
              NodeGDScriptInstance = 0x8,
              NodeGDScriptName = 0x8,
              GDScriptFunctionMap = 0x8,
              GDScriptConstantMap = 0x8,
              GDScriptVariantNameHM = 0x8,
              oVariantVector = 0x30,
              GDScriptRealoadIndex = 0, -- todo
            }
          },

          tools =
          {
            add =
            {
              -- godot.windows.template_release.x86_64.exe
              -- Godot Engine v4.5.1.stable.custom_build
              VPChildren = 0x48,
              VPObjStringName = 0x48,
              NodeGDScriptName = 0x48,
              GDScriptFunctionMap = 0x48,
              GDScriptConstantMap = 0x48,
              GDScriptVariantNameHM = 0x48,
              GDScriptRealoadIndex = -1,
            }
          },

          usesDouble =
          {
            fallback = true,
          },
        },
    }

  OffsetProfiles[4][2] =
    {
      default =
      {
        GET_TYPE_INDX = 8,
        CALLP_DELTA = 5, -- 13
        GDScriptRealoadIndex = 44,
      },
      -- releases
      ["*"] =
        {
          x64 =
          {
            -- godot.windows.template_release.x86_64.exe
            -- Godot Engine v4.2.1.stable.official.b09f793f5
            VPChildren = 0x178,
            VPObjStringName = 0x1D0,
            NodeGDScriptInstance = 0x68,
            NodeGDScriptName = 0x120,
            GDScriptFunctionMap = 0x280,
            GDScriptConstantMap = 0x250,
            GDScriptVariantNameHM = 0x1B8,
            oVariantVector = 0x28,
            NodeVariantVectorSizeOffset = 0x4,

            GDScriptFunctionCode = 0x170,
            GDScriptFunctionCodeConsts = 0x190,
            GDScriptFunctionCodeGlobals = 0x1A0,
            GDScriptFunctionCodeArg = 0xA0,
          },
          x86 =
          {
            fallback = true,
          },

          -- modifiers
          debug =
          {
            add =
            {
              -- godot.windows.template_debug.x86_64.exe
              --  Godot Engine v4.2.2.stable.official
              VPChildren = 0x8,
              VPObjStringName = 0x8,
              NodeGDScriptInstance = 0x8,
              NodeGDScriptName = 0x8,
              GDScriptFunctionMap = 0x8,
              GDScriptConstantMap = 0x8,
              GDScriptVariantNameHM = 0x8,
              oVariantVector = 0x30,
              GDScriptRealoadIndex = 17,
            }
          },

          tools =
          {
            add =
            {
              -- Godot Engine 4.2.3 
              -- godot.windows.template_release.double.x86_64.exe 
              VPChildren = 0x48,
              VPObjStringName = 0x48,
              NodeGDScriptName = 0x48,
              GDScriptFunctionMap = 0x48,
              GDScriptConstantMap = 0x48,
              GDScriptVariantNameHM = 0x48,

              GDScriptFunctionCode = 0x20,
              GDScriptFunctionCodeConsts = 0x20,
              GDScriptFunctionCodeGlobals = 0x20,

              GDScriptRealoadIndex = -1,
            }
          },

          usesDouble =
          {
            add =
            {
              -- Godot Engine 4.2.3 
              -- godot.windows.template_release.double.x86_64.exe 
              VPChildren = 0x10,
              VPObjStringName = 0x10,
              NodeGDScriptName = 0x10,
              GDScriptFunctionMap =0x10,
              GDScriptConstantMap = 0x10,
              GDScriptVariantNameHM = 0x10,
              GDScriptRealoadIndex = 0,
            }
          },
        },
    }


  OffsetProfiles[4][1] =
    {
      default =
      {
        GET_TYPE_INDX = 8,
        CALLP_DELTA = 5, -- 13
        GDScriptRealoadIndex = 44,
      },
      -- releases
      ["*"] =
        {
          x64 =
          {
            -- godot.windows.template_release.x86_64.exe
            -- Godot Engine v4.2.1.stable.official.b09f793f5
            VPChildren = 0x178,
            VPObjStringName = 0x1D0,
            NodeGDScriptInstance = 0x68,
            NodeGDScriptName = 0x148,
            GDScriptFunctionMap = 0x260,
            GDScriptConstantMap = 0x1F0,
            GDScriptVariantNameHM = 0x290,
            oVariantVector = 0x28,
            NodeVariantVectorSizeOffset = 0x4,

            GDScriptFunctionCode = 0x118,
            GDScriptFunctionCodeConsts = 0x100,
            GDScriptFunctionCodeGlobals = 0xF0,
            GDScriptFunctionCodeArg = 0xA0,
          },
          x86 =
          {
            fallback = true,
          },

          -- modifiers
          debug =
          {
            add =
            {
              -- godot.windows.template_debug.x86_64.exe
              --  Godot Engine v4.1.1.stable.official
              VPChildren = 0x8,
              VPObjStringName = 0x8,
              NodeGDScriptInstance = 0x8,
              NodeGDScriptName = 0x8,
              GDScriptFunctionMap = 0x8,
              GDScriptConstantMap = 0x8,
              GDScriptVariantNameHM = 0x8,
              oVariantVector = 0x30,
              GDScriptRealoadIndex = 0,
            }
          },

          tools =
          {
            add =
            {
              -- Godot Engine v4.1.2.rc.custom_build
              VPChildren = 0x48,
              VPObjStringName = 0x48,
              NodeGDScriptName = 0x48,
              GDScriptFunctionMap = 0x48,
              GDScriptConstantMap = 0x48,
              GDScriptVariantNameHM = 0x48,

              GDScriptRealoadIndex = 2,
            },
            set =
            {
              GDScriptFunctionCodeConsts = 0x118 + 0x58, -- 0x170, only 64
              GDScriptFunctionCodeGlobals = 0x118 + 0x58 + 0x10, -- 0x180
            }
          },

          usesDouble =
          {
            fallback = true,
          },
        },
    }

  OffsetProfiles[4][0] =
    {
      default =
      {
        GET_TYPE_INDX = 8,
        CALLP_DELTA = 5, -- 13
        GDScriptRealoadIndex = 44, -- todo
      },
      -- releases
      ["*"] =
        {
          x64 =
          {
            VPChildren = 0x168,
            VPObjStringName = 0x1C0,
            NodeGDScriptInstance = 0x68,
            NodeGDScriptName = 0x178,
            GDScriptFunctionMap = 0x270,
            GDScriptConstantMap = 0x238,
            GDScriptVariantNameHM = 0x2A8,
            oVariantVector = 0x28,
            NodeVariantVectorSizeOffset = 0x8,

            GDScriptFunctionCode = 0x118,
            GDScriptFunctionCodeConsts = 0x100,
            GDScriptFunctionCodeGlobals = 0xF0,
            GDScriptFunctionCodeArg = 0xA0,
          },
          x86 =
          {
            fallback = true,
          },

          -- modifiers
          debug =
          {
            add =
            {
              VPChildren = 0x8,
              VPObjStringName = 0x8,
              NodeGDScriptInstance = 0x8,
              NodeGDScriptName = 0x8,
              GDScriptFunctionMap = 0x8,
              GDScriptConstantMap = 0x8,
              GDScriptVariantNameHM = 0x8,
              oVariantVector = 0x30,
              GDScriptRealoadIndex = 0,
            }
          },

          tools =
          {
            fallback = true,
          },

          usesDouble =
          {
            fallback = true,
          },
        },
    }

  OffsetProfiles[3][6] =
    {
      default =
      {
        GET_TYPE_INDX = 6,
        CALLP_DELTA = 6, -- 12
        GDScriptRealoadIndex = 42,
      },
      -- releases
      ["*"] =
        {
          x64 =
          {
            -- godot.windows.opt.64.exe
            --  Godot Engine v3.6.stable.custom_build.de2f0f147
            VPChildren = 0x108,
            VPObjStringName = 0x130,
            NodeGDScriptInstance = 0x58,
            NodeGDScriptName = 0x108,
            GDScriptFunctionMap = 0x1A8,
            GDScriptConstantMap = 0x190,
            GDScriptVariantNameHM = 0x1C0,
            oVariantVector = 0x20,
            NodeVariantVectorSizeOffset = 0x4,

            GDScriptFunctionCode = 0x50,
            GDScriptFunctionCodeConsts = 0x20,
            GDScriptFunctionCodeGlobals = 0x30,
          },
          x86 =
          {
            fallback = true,
          },

          -- modifiers
          debug =
          {
            add =
            {
              -- godot.windows.opt.debug.64.exe
              VPChildren = 0x8,
              VPObjStringName = 0x8,
              NodeGDScriptInstance = 0x8,
              NodeGDScriptName = 0x8,
              GDScriptFunctionMap = 0x8,
              GDScriptConstantMap = 0x8,
              GDScriptVariantNameHM = 0x8,
              oVariantVector = 0x18,
              GDScriptRealoadIndex = 0,
            }
          },

          tools =
          {
            fallback = true,
          },

          usesDouble =
          {
            fallback = true,
          },
        },
    }


  OffsetProfiles[3][5] =
    {
      default =
      {
        GET_TYPE_INDX = 6,
        CALLP_DELTA = 6, -- 12
        GDScriptRealoadIndex = 42,
      },
      -- releases
      ["*"] =
        {
          x64 =
          {
            -- godot.windows.opt.64.exe
            -- Godot Engine v3.5.1.stable.official
            VPChildren = 0x108,
            VPObjStringName = 0x130,
            NodeGDScriptInstance = 0x58,
            NodeGDScriptName = 0x108,
            GDScriptFunctionMap = 0x1A8,
            GDScriptConstantMap = 0x190,
            GDScriptVariantNameHM = 0x1C0,
            oVariantVector = 0x20,
            NodeVariantVectorSizeOffset = 0x4,

            GDScriptFunctionCode = 0x50,
            GDScriptFunctionCodeConsts = 0x20,
            GDScriptFunctionCodeGlobals = 0x30,
            GDScriptFunctionCodeArg = 0xA0,
          },
          x86 =
          {
            -- godot.windows.opt.32.exe
            -- Godot Engine v3.5.3.stable.official
            VPChildren = 0x90,
            VPObjStringName = 0xB0,
            NodeGDScriptInstance = 0x38,
            NodeGDScriptName = 0x94,
            GDScriptFunctionMap = 0xE8,
            GDScriptConstantMap = 0xDC,
            GDScriptVariantNameHM = 0xF4,
            oVariantVector = 0x10,
            NodeVariantVectorSizeOffset = 0x4,

            GDScriptFunctionCode = 0x38,
            GDScriptFunctionCodeConsts = 0x20,
            GDScriptFunctionCodeGlobals = 0x28,
          },

          -- modifiers
          debug =
          {
            add =
            {
              -- godot.windows.opt.debug.64.exe
              -- Godot Engine 3.5.2.stable
              VPChildren = alignOffset(4, PTRSIZE),
              VPObjStringName = alignOffset(4, PTRSIZE),
              NodeGDScriptInstance = alignOffset(4, PTRSIZE),
              NodeGDScriptName = alignOffset(4, PTRSIZE),
              GDScriptFunctionMap = alignOffset(4, PTRSIZE),
              GDScriptConstantMap = alignOffset(4, PTRSIZE),
              GDScriptVariantNameHM = alignOffset(4, PTRSIZE),
              oVariantVector = alignOffset(4, PTRSIZE) + PTRSIZE*2,
              GDScriptRealoadIndex = 0,
            }
          },

          tools =
          {
            add =
            {
              GDScriptRealoadIndex = -1,
            }
          },

          usesDouble =
          {
            fallback = true,
          },
        },
    }

  OffsetProfiles[3][4] =
    {
      default =
      {
        GET_TYPE_INDX = 6,
        CALLP_DELTA = 6, -- 12
        GDScriptRealoadIndex = 42,
      },
      -- releases
      ["*"] =
        {
          x64 =
          {
            -- godot.windows.opt.64.exe
            -- Godot Engine v3.4.4.stable.official.419e713a2
            VPChildren = 0x108,
            VPObjStringName = 0x120,
            NodeGDScriptInstance = 0x58,
            NodeGDScriptName = 0x108,
            GDScriptFunctionMap = 0x1A8,
            GDScriptConstantMap = 0x190,
            GDScriptVariantNameHM = 0x1C0,
            oVariantVector = 0x20,
            NodeVariantVectorSizeOffset = 0x4,

            GDScriptFunctionCode = 0x50,
            GDScriptFunctionCodeConsts = 0x20,
            GDScriptFunctionCodeGlobals = 0x30,
            GDScriptFunctionCodeArg = 0xA0,
          },
          x86 =
          {
            fallback = true,
          },

          -- modifiers
          debug =
          {
            add =
            {
              VPChildren = 0x8,
              VPObjStringName = 0x8,
              NodeGDScriptInstance = 0x8,
              NodeGDScriptName = 0x8,
              GDScriptFunctionMap = 0x8,
              GDScriptConstantMap = 0x8,
              GDScriptVariantNameHM = 0x8,
              oVariantVector = 0x18,
              GDScriptRealoadIndex = 0,
            }
          },

          tools =
          {
            fallback = true,
          },

          usesDouble =
          {
            fallback = true,
          },
        },
    }


  OffsetProfiles[3][3] =
    {
      default =
      {
        GET_TYPE_INDX = 6,
        CALLP_DELTA = 6, -- 12
        GDScriptRealoadIndex = 41,
      },
      -- releases
      ["*"] =
        {
          x64 =
          {
            -- godot.windows.opt.64.exe
            -- Godot Engine v3.4.4.stable.official.419e713a2
            VPChildren = 0x100,
            VPObjStringName = 0x118,
            NodeGDScriptInstance = 0x50,
            NodeGDScriptName = 0x100,
            GDScriptFunctionMap = 0x1A0,
            GDScriptConstantMap = 0x188,
            GDScriptVariantNameHM = 0x1B8,
            oVariantVector = 0x20,
            NodeVariantVectorSizeOffset = 0x4,

            GDScriptFunctionCode = 0x50,
            GDScriptFunctionCodeConsts = 0x20,
            GDScriptFunctionCodeGlobals = 0x30,
            GDScriptFunctionCodeArg = 0xA0,
          },
          x86 =
          {
            fallback = true,
          },

          -- modifiers
          debug =
          {
            add =
            {
              VPChildren = 0x8,
              VPObjStringName = 0x8,
              NodeGDScriptInstance = 0x8,
              NodeGDScriptName = 0x8,
              GDScriptFunctionMap = 0x8,
              GDScriptConstantMap = 0x8,
              GDScriptVariantNameHM = 0x8,
              oVariantVector = 0x18,
              GDScriptRealoadIndex = 0,
            }
          },

          tools =
          {
            fallback = true,
          },

          usesDouble =
          {
            fallback = true,
          },
        },
    }

  OffsetProfiles[3][2] =
    {
      default =
      {
        GET_TYPE_INDX = 6,
        CALLP_DELTA = 6, -- 12
        GDScriptRealoadIndex = 41, -- todo
      },
      -- releases
      ["*"] =
        {
          x64 =
          {
            VPChildren = 0x108,
            VPObjStringName = 0x120,
            NodeGDScriptInstance = 0x50,
            NodeGDScriptName = 0x100,
            GDScriptFunctionMap = 0x1B0,
            GDScriptConstantMap = 0x198,
            GDScriptVariantNameHM = 0x1C8,
            oVariantVector = 0x20,
            NodeVariantVectorSizeOffset = 0x4,

            GDScriptFunctionCode = 0x50,
            GDScriptFunctionCodeConsts = 0x20,
            GDScriptFunctionCodeGlobals = 0x30,
            GDScriptFunctionCodeArg = 0xA0,
          },
          x86 =
          {
            fallback = true,
          },

          -- modifiers
          debug =
          {
            fallback = true,
          },

          tools =
          {
            add =
            {
              -- godot.windows.opt.64.exe
              -- Godot Engine v3.2.stable.custom_build
              VPChildren = 0x8,
              VPObjStringName = 0x8,
              GDScriptFunctionMap = 0x8,
              GDScriptConstantMap = 0x8,
              GDScriptVariantNameHM = 0x8,
            }
          },

          usesDouble =
          {
            fallback = true,
          },
        },
    }

  OffsetProfiles[3][1] =
    {
      default =
      {
        GET_TYPE_INDX = 6,
        CALLP_DELTA = 6, -- 12
        GDScriptRealoadIndex = 41, -- todo
      },
      -- releases
      ["*"] =
        {
          x64 =
          {
            fallback = true,
          },
          x86 =
          {
            fallback = true,
          },

          -- modifiers
          debug =
          {
            fallback = true,
          },

          tools =
          {
            fallback = true,
          },

          usesDouble =
          {
            fallback = true,
          },
        },
    }


  OffsetProfiles[3][0] =
    {
      default =
      {
        GET_TYPE_INDX = 6,
        CALLP_DELTA = 6, -- 12
        GDScriptRealoadIndex = 41, -- todo
      },
      -- releases
      ["*"] =
        {
          x64 =
          {
            -- 3.0.6.stable.official
            VPChildren = 0x100,
            VPObjStringName = 0x118,
            NodeGDScriptInstance = 0x50,
            NodeGDScriptName = 0xF8,
            GDScriptFunctionMap = 0x1B0,
            GDScriptConstantMap = 0x198,
            GDScriptVariantNameHM = 0x1C8,
            oVariantVector = 0x18,
            NodeVariantVectorSizeOffset = 0x4,

            GDScriptFunctionCode = 0x50,
            GDScriptFunctionCodeConsts = 0x20,
            GDScriptFunctionCodeGlobals = 0x30,

          },
          x86 =
          {
            fallback = true,
          },

          -- modifiers
          debug =
          {
            fallback = true,
          },

          tools =
          {
            fallback = true,
          },

          usesDouble =
          {
            fallback = true,
          },
        },
    }


  OffsetProfiles[2][1] =
    {
      default =
      {
        GET_TYPE_INDX = 7,
        CALLP_DELTA = 6, -- todo
        GDScriptRealoadIndex = 41, -- todo
      },
      -- releases
      ["*"] =
        {
          x64 =
          {
            -- Godot Engine v2.1.7.rc.custom_build
            -- godot.windows.opt.64.exe
            VPChildren = 0xC8,
            VPObjStringName = 0xE0,
            NodeGDScriptInstance = 0x58,
            NodeGDScriptName = 0xC0,
            GDScriptFunctionMap = 0x160,
            GDScriptConstantMap = 0x148,
            GDScriptVariantNameHM = 0x178,
            oVariantVector = 0x30,
            NodeVariantVectorSizeOffset = 0x4,

            GDScriptFunctionCode = 0x50,
            GDScriptFunctionCodeConsts = 0x20,
            GDScriptFunctionCodeGlobals = 0x30,

          },
          x86 =
          {
            fallback = true,
          },

          -- modifiers
          debug =
          {
            fallback = true,
          },

          tools =
          {
            add =
            { -- todo ??
              VPChildren = -0x10,
              VPObjStringName = -0x10,
              NodeGDScriptInstance = -0x10,
              NodeGDScriptName = -0x10,
              GDScriptFunctionMap = -0x20,
              GDScriptConstantMap = -0x20,
              GDScriptVariantNameHM = -0x20,
              oVariantVector = -0x18,
            }
          },

          usesDouble =
          {
            fallback = true,
          },
        },
    }

  OffsetProfiles[2][0] =
    {
      default =
      {
        GET_TYPE_INDX = 7,
        CALLP_DELTA = 6, -- todo
        GDScriptRealoadIndex = 41, -- todo
      },
      -- releases
      ["*"] =
        {
          x64 =
          {
            fallback = true,
          },
          x86 =
          {
            fallback = true,
          },

          -- modifiers
          debug =
          {
            fallback = true,
          },

          tools =
          {
            fallback = true,
          },

          usesDouble =
          {
            fallback = true,
          },
        },
    }

  OffsetProfiles[1][1] =
    {
      default =
      {
        GET_TYPE_INDX = 7,
        CALLP_DELTA = 6, -- todo
        GDScriptRealoadIndex = 41, -- todo
      },
      -- releases
      ["*"] =
        {
          x64 =
          {
            fallback = true,
          },
          x86 =
          {
            fallback = true,
          },

          -- modifiers
          debug =
          {
            fallback = true,
          },

          tools =
          {
            fallback = true,
          },

          usesDouble =
          {
            fallback = true,
          },
        },
    }

  OffsetProfiles[1][0] =
    {
      default =
      {
        GET_TYPE_INDX = 7,
        CALLP_DELTA = 6, -- todo
        GDScriptRealoadIndex = 41, -- todo
      },
      -- releases
      ["*"] =
        {
          x64 =
          {
            fallback = true,
          },
          x86 =
          {
            fallback = true,
          },

          -- modifiers
          debug =
          {
            fallback = true,
          },

          tools =
          {
            fallback = true,
          },

          usesDouble =
          {
            fallback = true,
          },
        },
    }

-- OFFSET DEFINITION END

  -- HELPERS START
    local function copyTable(source)
      local copy = {}
      if not source then return copy end

      for key, value in pairs(source) do copy[key] = value end

      return copy
    end

    local function getAssumed(offsets)
      offsets = offsets or {}
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

        offsets.STRING = 0x4+0x4+GDDEFS.PTRSIZE
        -- offsets.GET_TYPE_INDX = 10
        -- offsets.CALLP_INDX = offsets.GET_TYPE_INDX + 4
        return offsets
      end
      print( "No recorded version found, report here: https://github.com/palepine/GDDumper/issues" )
      error( "No recorded version found, report here: https://github.com/palepine/GDDumper/issues" )
    end

    local function applyDefaults(offsets, profile)
      if not profile.default then
        sendDebugMessage('No default values...')
        return
      end
      offsets.STRING = profile.default.STRING
      offsets.GET_TYPE_INDX = profile.default.GET_TYPE_INDX
      offsets.CALLP_INDX = offsets.GET_TYPE_INDX + profile.default.CALLP_DELTA
      offsets.GDScriptRealoadIndex = profile.default.GDScriptRealoadIndex
      return offsets
    end

    local function applyModifier(offsets, modifier, opName)
      if not modifier then return offsets end

      if modifier.fallback then
        sendDebugMessage('Fallback case for: ' .. (opName or ''))
        local assumed = getAssumed(offsets)
        if assumed == nil then error(opName .. " offsets are not defined and assumption failed") end
        return assumed
      end

      if modifier.add then
        -- sendDebugMessage('Add case for: ' .. (opName or '') )
        for key, delta in pairs( modifier.add ) do
          offsets[key] = (offsets[key] or 0) + delta
        end
      end

      if modifier.set then
        -- sendDebugMessage('Set case for: ' .. (opName or '') )
        for key, value in pairs( modifier.set ) do
          offsets[key] = value
        end
      end

      return offsets
    end

    local function getArchitectureOffsets(minorProfile, architecture)

      local arcitectureProfile = minorProfile[ architecture ]
      if not arcitectureProfile then
        sendDebugMessage('Arch offsets not found, nil returned')
        return nil
      end
      if arcitectureProfile.fallback then
        sendDebugMessage('Architecture doesnt have offsets, fallback')
        return getAssumed( {} )
      end

      return copyTable( arcitectureProfile )
    end

    local function getStoredOffsets(version)
      local offsets = {}

      -- get major and check
      local majorTable = OffsetProfiles[version.major]
      if majorTable == nil then
        sendDebugMessage('Major profile table not found, fallback')
        offsets = getAssumed( {} )
        return offsets
      end

      -- get minor and check
      local minorTable = majorTable[version.minor]
      if minorTable == nil then
        sendDebugMessage('Minor profile table not found, fallback')
        offsets = getAssumed( {} )
        return offsets
      end

      -- get default release or specification
      local release_profile = (version.release and minorTable[version.release]) or minorTable["*"]

      -- get architecture-specific offsets
      local architecture = version.x64 and "x64" or "x86"
      local offsets = getArchitectureOffsets(release_profile, architecture)

      if offsets == nil then
        sendDebugMessage('Offsets not found, fallback')
        offsets = getAssumed( {} )
        if offsets == nil then error("No offsets for requested architecture") end
      end

      -- defaults
      offsets = applyDefaults( offsets, minorTable )

      -- modifiers applied sequentially
      if version.debug then offsets =       applyModifier( offsets, release_profile.debug, "debug" ) end
      if version.tools then offsets =       applyModifier( offsets, release_profile.tools, "tools" ) end
      if version.usesDouble then offsets =  applyModifier( offsets, release_profile.usesDouble, "usesDouble" ) end

      return offsets
    end

  -- HELPERS END

  local function getStoredOffsetsFromVersion(major, minor, patch)
    local version =
    {
      major = major,
      minor = minor,
      release = patch,
      x64 = GDDEFS._x64,
      debug = GDDEFS.DEBUGVER,
      tools = GDDEFS.CUSTOMVER,
      usesDouble = GDDEFS.USES_DOUBLE_REALT,
    }
    local offsets = getStoredOffsets(version)

    return offsets
  end

  return getStoredOffsetsFromVersion
end

return Module -- exporting