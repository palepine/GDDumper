local Module =
{
  Profile = {},
}

local LATEST_SEMVER_SUPPORTED = "4.7" -- Update me to the latest supported version when support is provided

function Module.install(GDD)
  local GDDEFS = GDD.Config.Defs

  function Module.Profile.installVersionFallback(tab, lastVersion)
    local metatable = 
      {
        __index = function(table, version)
          local fallback = rawget(table, lastVersion)
          if fallback then
            print( ("[TYPES] Version %s is not defined, do that; falling back to %s") :format( tostring(version), tostring(lastVersion) ) )
          end
          return fallback
        end
      }
    setmetatable(tab, metatable)
  end

  function Module.Profile.defineVariantTypeProfile()
    if GDDEFS.VARIANT_TYPE_PROFILE then
      return GDDEFS.VARIANT_TYPE_PROFILE
    end

    function Module.Profile.cloneArray(tabl)
      local result = {}
      for i, val in ipairs(tabl) do result[i] = val end
      return result
    end

    function Module.Profile.insertValueBefore(list, anchor, valueToInsert)
      for i, val in ipairs(list) do
        if val == anchor then
          table.insert(list, i, valueToInsert)
          return
        end
      end
      error("Module.Profile.insertValueBefore: anchor not found: " .. tostring(anchor))
    end

    function Module.Profile.insertValueAfter(list, anchor, valueToInsert)
      for i, val in ipairs(list) do
        if val == anchor then
          table.insert(list, i + 1, valueToInsert)
          return
        end
      end
      error("Module.Profile.insertValueAfter: anchor not found: " .. tostring(anchor))
    end

    function Module.Profile.removeValue(list, valueToRemove)
      for i, val in ipairs(list) do
        if val == valueToRemove then
          table.remove(list, i)
          return
        end
      end
      error("Module.Profile.removeValue: value not found: " .. tostring(valueToRemove))
    end

    function Module.Profile.applyPatchOnList(list, patch)
      if patch.kind == "insertValueBefore" then
        Module.Profile.insertValueBefore(list, patch.anchor, patch.value)
      elseif patch.kind == "insertValueAfter" then
        Module.Profile.insertValueAfter(list, patch.anchor, patch.value)
      elseif patch.kind == "removeValue" then
        Module.Profile.removeValue(list, patch.value)
      else
        error("Unknown patch kind: " .. tostring(patch.kind))
      end
    end

    function Module.Profile.prepareProfileSpec(version, specs, visited)
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
        local parent = Module.Profile.prepareProfileSpec(spec.base, specs, visited)
        resolved.orderedTypes = Module.Profile.cloneArray(parent.orderedTypes)

        if spec.patches then
          for _, patch in ipairs(spec.patches) do
            Module.Profile.applyPatchOnList(resolved.orderedTypes, patch)
          end
        end
      else
        resolved.orderedTypes = Module.Profile.cloneArray(spec.orderedTypes or {})
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
        INPUT_EVENT = vtPointer,
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
        ["2.0"] =
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
              "TRANSFORM2D", -- MATRIX32
              "PLANE",
              "QUATERNION", -- QUAT
              "AABB",
              "BASIS", -- MATRIX3
              "TRANSFORM3D",
              "COLOR",
              "IMAGE",
              "NODE_PATH",
              "RID", -- _RID
              "OBJECT",
              "INPUT_EVENT",
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
        ["2.1"] = { base = "2.0", patches = {} },

        -- no changes on major-minor
        ["3.0"] =
          {
            base = "2.1",
            patches =
              { 
                { kind = "removeValue", value = "IMAGE" },
                { kind = "removeValue", value = "INPUT_EVENT" }
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
        ["4.4"] = { base = "4.3", patches = { { kind = "insertValueAfter", anchor = "PACKED_COLOR_ARRAY", value = "PACKED_VECTOR4_ARRAY" } } },
        ["4.5"] = { base = "4.4", patches = {} },
        ["4.6"] = { base = "4.5", patches = {} },
        ["4.7"] = { base = "4.6", patches = {} },
      }

    Module.Profile.installVersionFallback( specs, LATEST_SEMVER_SUPPORTED )

    local version = GDDEFS.VERSION_STRING
    local resolved = Module.Profile.prepareProfileSpec(version, specs)

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

  Module.Profile.defineVariantTypeProfile()

  return
    {
      ok = true
    }
end

return Module -- exporting