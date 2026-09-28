--[[
  Cheat Engine Godot Dumper — Copyright (C) 2026 palepine

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
]]

local Module = {}

local function copyTable(source)
  local result = {}
  if source then
    for key, value in pairs(source) do result[key] = value end
  end
  return result
end

local function mergeTable(base, overrides)
  local result = copyTable(base)
  if overrides then
    for key, value in pairs(overrides) do result[key] = value end
  end
  return result
end

local function compareVersionParts(aMajor, aMinor, aPatch, bMajor, bMinor, bPatch)
  aMajor, aMinor, aPatch = aMajor or 0, aMinor or 0, aPatch or 0
  bMajor, bMinor, bPatch = bMajor or 0, bMinor or 0, bPatch or 0

  if aMajor ~= bMajor then return aMajor < bMajor and -1 or 1 end
  if aMinor ~= bMinor then return aMinor < bMinor and -1 or 1 end
  if aPatch ~= bPatch then return aPatch < bPatch and -1 or 1 end
  return 0
end

local function parseVersionString(version)
  if type(version) ~= 'string' then return nil, nil end
  local major, minor = version:match('^(%d+)%.(%d+)$')
  return tonumber(major), tonumber(minor)
end

local function findNearestKnownVersion(available, requestedVersion)
  local requestedMajor, requestedMinor = parseVersionString(requestedVersion)
  if not requestedMajor then return nil, nil end

  local selectedVersion
  local selectedMinor = -1
  for candidateVersion in pairs(available) do
    local candidateMajor, candidateMinor = parseVersionString(candidateVersion)
    if candidateMajor == requestedMajor and candidateMinor <= requestedMinor and candidateMinor > selectedMinor then
      selectedVersion = candidateVersion
      selectedMinor = candidateMinor
    end
  end

  return selectedVersion and rawget(available, selectedVersion) or nil, selectedVersion
end

local function matchesVersion(target, match)
  if match == nil then return false end
  if match.major ~= nil and target.major ~= match.major then return false end
  if match.minor ~= nil and target.minor ~= match.minor then return false end
  if match.patch ~= nil and target.patch ~= match.patch then return false end

  if match.min then
    if compareVersionParts(target.major, target.minor, target.patch, match.min[1], match.min[2], match.min[3]) < 0 then
      return false
    end
  end

  if match.max then
    if compareVersionParts(target.major, target.minor, target.patch, match.max[1], match.max[2], match.max[3]) > 0 then
      return false
    end
  end

  return true
end

local function makeImmutable(values, label)
  return setmetatable({},
    {
      __index = values,
      __newindex = function()
        error( (label or 'table') .. ' is immutable', 2 )
      end,
      __pairs = function()
        return next, values, nil
      end,
      __metatable = false,
    }
  )
end

local ProfileResolver = {}
ProfileResolver.__index = ProfileResolver

function ProfileResolver.new()
  return setmetatable( { specs = {}, compiled = {} }, ProfileResolver )
end

function ProfileResolver:register(spec)
  assert( type(spec) == 'table', 'profile spec must be a table' )
  assert( type(spec.id) == 'string' and spec.id ~= '', 'profile id must be a non-empty string' )
  assert( self.specs[ spec.id ] == nil, 'duplicate version profile: ' .. spec.id )
  self.specs[ spec.id ] = spec
  self.compiled = {}
  return self
end

function ProfileResolver:compile(profileId, visited)
  if self.compiled[profileId] then return self.compiled[profileId] end

  local spec = self.specs[profileId]
  assert(spec, 'unknown version profile: ' .. tostring(profileId))

  visited = visited or {}
  assert( not visited[profileId], 'circular version profile inheritance: ' .. profileId )
  visited[profileId] = true

  local parent = {}
  if spec.extends then parent = self:compile( spec.extends, visited ) end

  local supported = parent.supported
  if spec.supported ~= nil then supported = spec.supported end

  local compiled =
  {
    id = spec.id,
    priority = spec.priority or parent.priority or 0,
    supported = supported,
    capabilities = mergeTable( parent.capabilities, spec.capabilities ),
    layouts = mergeTable( parent.layouts, spec.layouts ),
  }

  self.compiled[profileId] = compiled
  visited[profileId] = nil
  return compiled
end

function ProfileResolver:resolve(target)
  local selectedSpec
  for _, spec in pairs(self.specs) do

    if spec.match and matchesVersion( target, spec.match ) then
      if not selectedSpec or (spec.priority or 0) > (selectedSpec.priority or 0) then
        selectedSpec = spec
      end
    end

  end

  selectedSpec = selectedSpec or self.specs.base
  assert( selectedSpec, 'no base version profile is registered' )
  return self:compile(selectedSpec.id)
end

local function defineProfiles()
  local resolver = ProfileResolver.new()
  -- each child inherits from base/parent, replacing only implementations
  --[[
  unsupported won't work
  base
    └─ godot4
        └─ godot4_1_plus
              └─ godot4_6
  ]]

  resolver:register(
    {
      id = 'base',
      priority = 0,
      supported = false,
      capabilities =
      {
        engineInterface = 'none',
        containerFamily = 'unknown',
        stringEncoding = 'unknown',
        bytecodeFamily = 'unknown',
        objectMetadataLayout = 'unknown',
      },
    }
  )

  resolver:register(
    {
      id = 'godot2',
      extends = 'base',
      priority = 20,
      match = { min = {2, 0, 0}, max = {2, 1, 999999} },
      supported = true,
      capabilities =
      {
        engineInterface = 'none',
        containerFamily = 'legacyTree',
        stringEncoding = 'utf16',
        bytecodeFamily = 'legacy',
        objectMetadataLayout = 'stringName',
      },
    }
  )

  resolver:register(
    {
      id = 'godot3_family',
      extends = 'base',
      priority = 20,
      match = { major = 3 },
      supported = false,
      capabilities =
      {
        engineInterface = 'gdnative',
        containerFamily = 'legacyTree',
        stringEncoding = 'utf16',
        bytecodeFamily = 'legacy',
        objectMetadataLayout = 'stringName',
      },
    }
  )

  resolver:register(
    {
      id = 'godot3',
      extends = 'godot3_family',
      priority = 30,
      match = { min = {3, 0, 0}, max = {3, 6, 999999} },
      supported = true,
    }
  )

  resolver:register(
    {
      id = 'godot4',
      extends = 'base',
      priority = 20,
      match = { major = 4 },
      supported = false,
      capabilities =
      {
        containerFamily = 'modernHash',
        stringEncoding = 'utf32',
        bytecodeFamily = 'modern',
      },
    }
  )

  resolver:register(
    {
      id = 'godot4_0',
      extends = 'godot4',
      priority = 30,
      match = { major = 4, minor = 0 },
      supported = true,
      capabilities =
      {
        engineInterface = 'none',
        objectMetadataLayout = 'stringName',
      },
    }
  )

  resolver:register(
    {
      id = 'godot4_1_plus',
      extends = 'godot4',
      priority = 25,
      match = { min = {4, 1, 0}, max = {4, 999999, 999999} },
      supported = false,
      capabilities =
      {
        engineInterface = 'gdextension',
      },
    }
  )

  resolver:register(
    {
      id = 'godot4_1_to_4_5',
      extends = 'godot4_1_plus',
      priority = 30,
      match = { min = {4, 1, 0}, max = {4, 5, 999999} },
      supported = true,
      capabilities =
      {
        objectMetadataLayout = 'stringName',
      },
    }
  )

  resolver:register(
    {
      id = 'godot4_6',
      extends = 'godot4_1_plus',
      priority = 40,
      match = { major = 4, minor = 6 },
      supported = true,
      capabilities =
      {
        objectMetadataLayout = 'gdTypeV1',
      },
    }
  )

  resolver:register(
    {
      id = 'godot4_7',
      extends = 'godot4_1_plus',
      priority = 40,
      match = { major = 4, minor = 7 },
      supported = true,
      capabilities =
      {
        objectMetadataLayout = 'gdTypeV2',
      },
    }
  )

  return resolver
end

function Module.install(GDD, sendDebugMessage)
  local GDDEFS = GDD.Config.Defs
  assert( GDDEFS, 'versioning requires initialized definitions' )
  assert( type(GDDEFS.MAJOR_VER) == 'number', 'versioning requires a detected major version' )
  assert( type(GDDEFS.MINOR_VER) == 'number', 'versioning requires a detected minor version' )

  local targetValues =
  {
    major = GDDEFS.MAJOR_VER,
    minor = GDDEFS.MINOR_VER,
    patch = GDDEFS.PATCH_VER or 0,
    versionString = GDDEFS.VERSION_STRING,
    fullVersionString = GDDEFS.FULL_GDVERSION_STRING,
    x64 = GDDEFS._x64 == true,
    pointerSize = GDDEFS.PTRSIZE,
    debug = GDDEFS.DEBUGVER == true,
    mono = GDDEFS.MONO == true,
    custom = GDDEFS.CUSTOMVER == true,
    usesDouble = GDDEFS.USES_DOUBLE_REALT == true,
  }

  local target = makeImmutable(targetValues, 'Godot target descriptor')
  local resolver = defineProfiles()
  local profile = resolver:resolve(target)
  local runtime =
  {
    target = target,
    profile = profile,
    capabilities = copyTable(profile.capabilities),
    layouts = copyTable(profile.layouts),
    implementation = {},
    ProfileResolver = ProfileResolver,
  }

  function runtime:isAtLeast(major, minor, patch)
    return compareVersionParts(target.major, target.minor, target.patch, major, minor, patch) >= 0
  end

  function runtime:isBefore(major, minor, patch)
    return compareVersionParts(target.major, target.minor, target.patch, major, minor, patch) < 0
  end

  function runtime:findNearestKnownVersion(available, requestedVersion)
    return findNearestKnownVersion(available, requestedVersion)
  end

  GDD.Runtime = runtime
  GDDEFS.RUNTIME = runtime

  if sendDebugMessage then
    sendDebugMessage(
                      ('[VERSION] target=%s profile=%s supported=%s')
                      :format( tostring(target.versionString), tostring(profile.id), tostring(profile.supported == true) )
                    )
  end

  return runtime
end

Module.ProfileResolver = ProfileResolver
Module.compareVersionParts = compareVersionParts
Module.findNearestKnownVersion = findNearestKnownVersion

return Module
