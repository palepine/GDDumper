local Module = {}

local function isNullOrNil(toCheck)
  return toCheck == nil or toCheck == 0
end

local function isNotNullOrNil(toCheck)
  return toCheck ~= nil and toCheck ~= 0
end

local function isValidPointer(addr)
  local success, result = pcall(readPointer, addr)
  return success and result ~= nil
end

local function isInvalidPointer(addr)
  return isValidPointer(addr) == false
end

local function isPointerNotNull(addr)
  return isValidPointer(addr) and readPointer(addr) ~= 0
end

local function getVtable(addr)
  return readPointer(addr)
end

local function numtohexstr(num)
  return ("%X"):format(num or -1)
end

local function alignOffset(offset, alignment)
  local remaining = offset % alignment -- get remaining bytes for alignment
  if remaining ~= 0 then
    offset = offset + (alignment - remaining)
  end
  return offset
end

local function previousAlignedOffset(offset, alignment)
  if offset <= 0 then return 0 end -- don't need negative
  local remaining = offset % alignment -- get remaining bytes for alignment
  if remaining ~= 0 then
    offset = offset + - remaining
  end
  return offset - alignment
end

local function nextAlignedOffset(offset, alignment)
  if offset <= 0 then return 0 end -- don't need negative
  local remaining = offset % alignment -- get remaining bytes for alignment
  if remaining ~= 0 then
    offset = offset + (alignment - remaining)
  else
    offset = offset + alignment
  end
  return offset
end

function Module.install(contextTable)
  -- TODO: extract certain code to functions

  local GDDEFS = contextTable.GDDEFS
  local getMainModuleInfo = contextTable.getMainModuleInfo
  local getSectionBounds = contextTable.getSectionBounds
  local sendDebugMessage = contextTable.sendDebugMessage
  local getStringNameStr = contextTable.getStringNameStr
  local readUTFString = contextTable.readUTFString

  local tryRegSceneTree = contextTable.tryRegSceneTree
  local setSTtoVPoffset = contextTable.setSTtoVPoffset

  local MAIN_MODULE_INFO = getMainModuleInfo()
  local TEXT_SECTION_INFO = getSectionBounds(".text")
  local BSS_SECTION_INFO = getSectionBounds(".bss")

  local sizeOfVariant = GDDEFS.USES_DOUBLE_REALT and 0x28 or 0x18
  local assumedOffsets =
    {
      CHILDREN = nil,
      OBJ_STRING_NAME = nil,
      SCRIPT_INSTANCE = nil,
      SCRIPT_REF = nil,
      VARIANT_VECTOR = nil,
    }

  -- if GDDEFS.MAJOR_VER >= 4 then
  --   if GDDEFS.MINOR_VER <= 4 then
  --     GDDEFS.GET_TYPE_INDX = 8
  --   elseif GDDEFS.MINOR_VER == 5 then
  --     GDDEFS.GET_TYPE_INDX = 9
  --   elseif GDDEFS.MINOR_VER >= 6 then
  --     GDDEFS.GET_TYPE_INDX = 10
  --   end
  -- else
  --   GDDEFS.GET_TYPE_INDX = 6
  -- end

  local viewport = readPointer("ptVP")
  if isNullOrNil(viewport) then 
    return
  --   if tryRegSceneTree() and setSTtoVPoffset() then registerSymbol('ptVP', '[pSceneTree]+oSTtoVP', false) else
  --     return
  --   end
  end

  -- HELPERS
    
    local function isInsideSectionRange(addr, sectionInfo)
      if addr == nil or addr == 0 then return false end
      if addr > sectionInfo.startAddress and sectionInfo.endAddress > addr then return true end
    end

    local function isBSSData(addr)
      if isNullOrNil(addr) then return false end
      if isInsideSectionRange(addr, BSS_SECTION_INFO) then
        return true
      end
      return false
    end

    local function isVtable(VTAddr)
      if VTAddr == nil or VTAddr == 0 then return false end

      if MAIN_MODULE_INFO.moduleStart < VTAddr and VTAddr < MAIN_MODULE_INFO.moduleEnd then
        -- iterate a few pointers and confirm if they are executable
        local pmethod = readPointer(VTAddr) -- just check the first
        for i = 0, 3 do
          local pmethod = readPointer(VTAddr + GDDEFS.PTRSIZE * i)
          if not isInsideSectionRange(pmethod, TEXT_SECTION_INFO) then
            return false
          end
        end
      else -- outside the main module
        return false
      end

      return true
    end

    local function getVtableValidated(addr)
      -- if isInvalidPointer(addr) then return nil end
      local vtable = readPointer(addr)
      if not isVtable(vtable) then return nil end
      return vtable
    end


    local function getMainNodeTable()
      local childrenAddr = readPointer( viewport + assumedOffsets.CHILDREN )
      local childrenSize
      if GDDEFS.MAJOR_VER >= 4 then
        childrenSize = readInteger( viewport + assumedOffsets.CHILDREN - 0x8 ) -- size is int+int bytes behind for ~4.2+
      else
        childrenSize = readInteger( childrenAddr - 0x4 ) -- size is 4 bytes behind the 1st item in the array
      end

      local nodeTable = {}
      if isNullOrNil(childrenAddr) or isNullOrNil(childrenSize) then return nodeTable end

      for i = 0, (childrenSize - 1) do
        local nodeAddr = readPointer(childrenAddr + i * GDDEFS.PTRSIZE)
        table.insert(nodeTable, nodeAddr)
      end
      return nodeTable
    end

    local function isValidVariantType(typeId)
      local maxType = GDDEFS.VARIANT_TYPE_PROFILE.enums.VARIANT_MAX
      return type(typeId) == "number" and typeId >= 0 and typeId < maxType
    end

    local function validateVariantStride(vectorAddr, vectorSize)
      if vectorSize <= 0 then return false end
      for index = 0, vectorSize - 1 do
        local typeId = readInteger(vectorAddr + index * sizeOfVariant)
        if not isValidVariantType(typeId) then return false end
      end
      return true
    end

    local function makeIsPassableVariantValue( currentElem, offsetToType )
      -- closure factory
      local hits = 0 -- let's catch 2, ok?

      return function(currentElem, offsetToType) -- closure
        local variantType = readInteger(currentElem + offsetToType)
        if not isValidVariantType(variantType) then return false end

        local typeName = GDDEFS.VARIANT_TYPE_PROFILE.names[variantType]
        local offsetToValue = (typeName == 'OBJECT') and 0x10 or 0x8

        if typeName == 'NIL' then return false end

        if typeName == 'INT' and readInteger(currentElem + offsetToType + offsetToValue) ~= 0 then
          hits = hits + 1
        end

        if typeName == 'BOOL' and readByte(currentElem + offsetToType + offsetToValue) ~= 0 then
          hits = hits + 1
        end

        if typeName == 'FLOAT' and readDouble(currentElem + offsetToType + offsetToValue) ~= 0.0 then
          hits = hits + 1
        end

        if readQword(currentElem + offsetToType + offsetToValue) ~= 0 then
          hits = hits + 1
        end

        return hits >= 2
      end -- closure end
    end

    local function checkIfGDFunction( funcAddr, HMFuncSNameAddr )
      local funcStringNameAddr, funcResStringNameAddr, funcCodeAddr, funcCodeLastIdx, lastOpcode
      if GDDEFS.MAJOR_VER <= 3 or GDDEFS.VERSION_STRING == "4.1" then
        funcResStringNameAddr = readPointer(funcAddr) -- StringName source at 0x0;
        funcStringNameAddr = 0xBAAAAABE -- just a placeholder
      else
        funcStringNameAddr = readPointer(funcAddr) -- StringName funct name;
        funcResStringNameAddr = readPointer(funcAddr + GDDEFS.PTRSIZE) -- StringName source;
        if HMFuncSNameAddr ~= funcStringNameAddr then return false end -- should be fine?
      end

      if isNullOrNil(funcResStringNameAddr) or isNullOrNil(funcStringNameAddr) then return false end

      if not (  getStringNameStr(funcResStringNameAddr) or ''  ):match("res://") then return false end

      return true
    end

    local function reportFailedOffsets()
      if not assumedOffsets.CHILDREN then sendDebugMessage('[WALK] CHILDREN - FAIL') end
      if not assumedOffsets.OBJ_STRING_NAME then sendDebugMessage('[WALK] OBJ STRINGNAME - FAIL') end

      if not assumedOffsets.SCRIPT_INSTANCE then sendDebugMessage('[WALK] SCRIPT INSTANCE - FAIL') end
      if not assumedOffsets.SCRIPT_REF then sendDebugMessage('[WALK] SCRIPT REF - FAIL') end

      if not assumedOffsets.SCRIPT_NAME then sendDebugMessage('[WALK] SCRIPT NAME - FAIL') end
      if not assumedOffsets.VARIANT_MAP then sendDebugMessage('[WALK] VARIANT MAP - FAIL') end
      if not assumedOffsets.CONST_MAP then sendDebugMessage('[WALK] CONST MAP - FAIL') end
      if not assumedOffsets.FUNC_MAP then sendDebugMessage('[WALK] FUNC MAP - FAIL') end

      if not assumedOffsets.VARIANT_VECTOR then sendDebugMessage('[WALK] VAR VECTOR - FAIL') end
      if not assumedOffsets.VARIANT_VECTOR_SIZE then sendDebugMessage('[WALK] VAR VECTOR SIZE - FAIL') end
    end

    local function getNodeChildrenInfo(nodeAddr)
      local childrenAddr = readPointer(nodeAddr + assumedOffsets.CHILDREN)
      if isNullOrNil(childrenAddr) then return nil, nil; end

      local childrenSize;
      if GDDEFS.MAJOR_VER >= 4 then
        childrenSize = readInteger( nodeAddr + assumedOffsets.CHILDREN - 0x8) -- size is 8 bytes behind
      else
        childrenSize = readInteger(childrenAddr - 0x4)
      end

      return childrenAddr, childrenSize
    end

    local function offsetCount()
      local count = 0

      for _, value in pairs(assumedOffsets) do
        if value ~= nil then count = count + 1 end
      end

      return count
    end

    local function allOffsetsResolved()
      if not assumedOffsets.CHILDREN then return false end
      if not assumedOffsets.OBJ_STRING_NAME then return false end
      if not assumedOffsets.SCRIPT_INSTANCE then return false end
      if not assumedOffsets.SCRIPT_REF then return false end
      if not assumedOffsets.SCRIPT_NAME then return false end

      if GDDEFS.MONO then return true end

      if not assumedOffsets.VARIANT_MAP then return false end
      if not assumedOffsets.VARIANT_VECTOR then return false end
      if not assumedOffsets.VARIANT_VECTOR_SIZE then return false end
      if not assumedOffsets.CONST_MAP then return false end
      if not assumedOffsets.FUNC_MAP then return false end

      return true
    end

    local function makeNodeSample(nodeAddr)
      local sample = { nodeAddr = nodeAddr, }

      if not assumedOffsets.SCRIPT_INSTANCE then return sample end
      if not assumedOffsets.SCRIPT_REF then return sample end

      sample.scriptInst = readPointer(nodeAddr + assumedOffsets.SCRIPT_INSTANCE)

      if isNullOrNil(sample.scriptInst) then return sample end

      sample.scriptAddr = readPointer(sample.scriptInst + assumedOffsets.SCRIPT_REF)

      return sample
    end

  -- HELPERS END

  -- EVIDENCE-BASED HELERS START
    local RESOLVER_CONFIG =
      {
        maxNodes = 256,
        maxDepth = 8,
        maxChildren = 256,
        maxUniqueScripts = 64,

        requiredHits = 2,
        requiredScripts = 2,
        requiredScore = 8,

        holdoutModulo = 4,
      }

    local evidence = {}

    local function makeCandidate(offset, score, extra)
      local candidate = extra or {}
      candidate.offset = offset
      candidate.score = score or 1
      return candidate
    end

    local function evidenceKey(candidate)
      local key = numtohexstr(candidate.offset)

      if candidate.sizeOffset then
        key = key .. ":" .. numtohexstr(candidate.sizeOffset)
      end

      return key
    end

    local function recordCandidate(category, candidate, sample)
      if not candidate or not candidate.offset then return end

      evidence[category] = evidence[category] or {}

      local key = evidenceKey(candidate)
      local entry = evidence[category][key]

      if not entry then
        entry =
          {
            candidate = candidate,
            score = 0,
            hits = 0,
            nodes = {},
            scripts = {},
          }

        evidence[category][key] = entry
      end

      entry.score = entry.score + (candidate.score or 1)

      if sample.nodeAddr and not entry.nodes[sample.nodeAddr] then
        entry.nodes[sample.nodeAddr] = true
        entry.hits = entry.hits + 1
      end

      if sample.scriptAddr then
        entry.scripts[sample.scriptAddr] = true
      end
    end

    local function countTableEntries(values)
      local count = 0
      for _ in pairs(values or {}) do
        count = count + 1
      end
      return count
    end

    local function chooseBestCandidate(category, options)
      options = options or {}

      local best
      local candidates = evidence[category] or {}

      for _, entry in pairs(candidates) do
        local scriptHits = countTableEntries(entry.scripts)

        if entry.hits < (options.requiredHits or RESOLVER_CONFIG.requiredHits) then goto continue end

        if scriptHits < (options.requiredScripts or RESOLVER_CONFIG.requiredScripts) then goto continue end

        if entry.score < (options.requiredScore or RESOLVER_CONFIG.requiredScore) then goto continue end

        if best and best.score >= entry.score then goto continue end

        best = entry

        ::continue::
      end

      return best and best.candidate or nil
    end

    local function collectNodeSamples(rootNodes)
      local queue = {}
      local queueIndex = 1
      local visited = {}
      local samples = {}

      for _, nodeAddr in ipairs(rootNodes) do
        table.insert(queue, { nodeAddr = nodeAddr, depth = 0 })
      end

      while queueIndex <= #queue and #samples < RESOLVER_CONFIG.maxNodes do
        local current = queue[queueIndex]
        queueIndex = queueIndex + 1

        local nodeAddr = current.nodeAddr
        if isNullOrNil(nodeAddr) then goto continue end
        if visited[nodeAddr] then goto continue end
        if not getVtableValidated(nodeAddr) then goto continue end

        visited[nodeAddr] = true

        table.insert( samples, { nodeAddr = nodeAddr, depth = current.depth, } )

        if current.depth >= RESOLVER_CONFIG.maxDepth then goto continue end

        local childrenAddr, childrenSize = getNodeChildrenInfo(nodeAddr)

        if isNullOrNil(childrenAddr) then goto continue end
        if isNullOrNil(childrenSize) then goto continue end
        if childrenSize > RESOLVER_CONFIG.maxChildren then goto continue end

        for i = 0, childrenSize - 1 do
          local childAddr = readPointer(childrenAddr + i * GDDEFS.PTRSIZE)
          if isNullOrNil(childAddr) then goto child_continue end
          if visited[childAddr] then goto child_continue end

          table.insert( queue, { nodeAddr = childAddr, depth = current.depth + 1, } )

          ::child_continue::
        end

        ::continue::
      end

      return samples
    end

    local function enrichScriptSamples(nodeSamples)
      local seenScripts = {}
      local uniqueScriptCount = 0

      for _, sample in ipairs(nodeSamples) do
        local nodeAddr = sample.nodeAddr

        local scriptInst = readPointer(nodeAddr + assumedOffsets.SCRIPT_INSTANCE)

        if isNullOrNil(scriptInst) then goto continue end

        local scriptAddr = readPointer(scriptInst + assumedOffsets.SCRIPT_REF)

        if isNullOrNil(scriptAddr) then goto continue end

        sample.scriptInst = scriptInst
        sample.scriptAddr = scriptAddr

        if seenScripts[scriptAddr] then
          sample.duplicateScript = true
          goto continue
        end

        seenScripts[scriptAddr] = true
        uniqueScriptCount = uniqueScriptCount + 1

        if uniqueScriptCount >= RESOLVER_CONFIG.maxUniqueScripts then break end

        ::continue::
      end

      return nodeSamples
    end

    local function splitSamples(samples)
      local training = {}
      local holdout = {}

      for index, sample in ipairs(samples) do
        if index % RESOLVER_CONFIG.holdoutModulo == 0 then
          table.insert(holdout, sample)
        else
          table.insert(training, sample)
        end
      end

      return training, holdout
    end


    local function clearEvidence()
      evidence = {}
    end

    local function clearAssumedOffsets()
      for key in pairs(assumedOffsets) do assumedOffsets[key] = nil end
    end

    local function formatOffsets()
      return
        ("CHILDREN: 0x%X\n" ..
        "OBJ_STRING_NAME: 0x%X\n" ..
        "SCRIPT_INSTANCE: 0x%X\n" ..
        "SCRIPT_REF: 0x%X\n" ..
        "VARIANT_VECTOR: 0x%X\n" ..
        "VARIANT_VECTOR_SIZE: 0x%X\n" ..
        "SCRIPT_NAME: 0x%X\n" ..
        "FUNC_MAP: 0x%X\n" ..
        "CONST_MAP: 0x%X\n" ..
        "VARIANT_MAP: 0x%X"):format(
          assumedOffsets.CHILDREN or 0,
          assumedOffsets.OBJ_STRING_NAME or 0,
          assumedOffsets.SCRIPT_INSTANCE or 0,
          assumedOffsets.SCRIPT_REF or 0,
          assumedOffsets.VARIANT_VECTOR or 0,
          assumedOffsets.VARIANT_VECTOR_SIZE or 0,
          assumedOffsets.SCRIPT_NAME or 0,
          assumedOffsets.FUNC_MAP or 0,
          assumedOffsets.CONST_MAP or 0,
          assumedOffsets.VARIANT_MAP or 0
        )
    end

    local function printCurrentOffsets()
      print(formatOffsets())
    end

    local function candidateConflictsWithCommittedMap(candidate, category)
      if category ~= "VARIANT_MAP" and candidate.offset == assumedOffsets.VARIANT_MAP then
        return true
      end

      if category ~= "CONST_MAP" and candidate.offset == assumedOffsets.CONST_MAP then
        return true
      end

      if category ~= "FUNC_MAP" and candidate.offset == assumedOffsets.FUNC_MAP then
        return true
      end

      return false
    end

    local function recordFilteredCandidates(category, candidates, sample)
      for _, candidate in ipairs(candidates or {}) do
        if candidateConflictsWithCommittedMap(candidate, category) then
          goto continue
        end

        recordCandidate(category, candidate, sample)

        ::continue::
      end
    end

  -- EVIDENCE-BASED HELPERS END

  -- CHILDREN START
    local function assumeChildrenOffset()
      local CHILDREN;
      local childrenSize, childrenAddr, nodeAddr;
      local found = false
      local viewport = readPointer("ptVP")

      for i=0, (0x300/GDDEFS.PTRSIZE) do
        CHILDREN = 0x20 + i * GDDEFS.PTRSIZE

        -- get children and validate the size
        childrenAddr = readPointer( viewport + CHILDREN )
        if isNullOrNil(childrenAddr) then goto continue end
        if GDDEFS.MAJOR_VER >= 4 then
          childrenSize = readInteger( viewport + CHILDREN - 0x8 ) -- TODO: size is int+int bytes behind for ~4.2+
        else
          childrenSize = readInteger( childrenAddr - 0x4 ) -- size is 4 bytes behind the 1st item in the array
        end
        if isInvalidPointer(childrenAddr) or isNullOrNil(childrenSize) or childrenSize > 200 then goto continue end

        -- validate all children as valid vtabled object
        for j=0, childrenSize-1 do
          nodeAddr = readPointer( childrenAddr + j * GDDEFS.PTRSIZE )
          if isNullOrNil(nodeAddr) or not getVtableValidated(nodeAddr) then
            goto continue -- to outer
          end
        end

        -- successful case
        sendDebugMessage('Valid Children offset 0x' .. numtohexstr( CHILDREN ) )
        found = true
        break

        -- fails
        ::continue::
      end

      if found then
        assumedOffsets.CHILDREN = CHILDREN
        return CHILDREN;
      end
    end
  -- CHILDREN END

  -- OBJ NAME START
    local function assumeObjNameOffset()
      local OBJ_STRING_NAME, nodenameAddr;
      local found = false

      for i=1, (0x300/GDDEFS.PTRSIZE) do
        OBJ_STRING_NAME = (assumedOffsets.CHILDREN or 0x30) + i * GDDEFS.PTRSIZE

        nodenameAddr = readPointer( viewport + OBJ_STRING_NAME )
        if isNullOrNil(nodenameAddr) then goto continue end
        if getStringNameStr(nodenameAddr) ~= 'root' then goto continue end

        -- successful case
        sendDebugMessage('Valid Object Name offset 0x' .. numtohexstr( OBJ_STRING_NAME ) )
        found = true
        break

        -- fails
        ::continue::
      end

      if found then
        assumedOffsets.OBJ_STRING_NAME = OBJ_STRING_NAME
        return OBJ_STRING_NAME;
      end

    end
  -- OBJ NAME END

  -- SCRIPT INSTANCE START
    local function assumeScriptInstanceOffset(nodeAddr)
      if assumedOffsets.SCRIPT_INSTANCE then return assumedOffsets.SCRIPT_INSTANCE end
      if isNullOrNil(nodeAddr) then return end

      local SCRIPT_INSTANCE, scriptInst, NODE_REF;
      local found = false

      for i=1, (0x100/GDDEFS.PTRSIZE) do
        SCRIPT_INSTANCE = 0x30 + i * GDDEFS.PTRSIZE

        scriptInst = readPointer( nodeAddr + SCRIPT_INSTANCE )
        if isInvalidPointer(scriptInst) or not getVtableValidated(scriptInst) then
          goto continue
        end

        -- validate the owner node ref, try 4 after vtable
        local ownerRefFound = false
        for j=0, 3 do
          -- after the vtable
          NODE_REF = GDDEFS.PTRSIZE + j * GDDEFS.PTRSIZE
          local ownerNode = readPointer( scriptInst + NODE_REF )
          if isNotNullOrNil(ownerNode) and getVtableValidated(ownerNode) and ownerNode == nodeAddr then
            ownerRefFound = true
            break
          end
        end

        if not ownerRefFound then goto continue end

        -- successful case
        sendDebugMessage('Valid Script Instance offset 0x' .. numtohexstr( SCRIPT_INSTANCE ) )
        found = true
        break

        -- fails
        ::continue::
      end

      if found then
        assumedOffsets.SCRIPT_INSTANCE = SCRIPT_INSTANCE
        assumedOffsets.SCRIPT_REF = NODE_REF + GDDEFS.PTRSIZE
        return SCRIPT_INSTANCE;
      end

    end
  -- SCRIPT INSTANCE END

  -- VARIANT VECTOR START

    local function assumeVariantVector(nodeAddr)
      if assumedOffsets.VARIANT_VECTOR then return assumedOffsets.VARIANT_VECTOR end
      if not assumedOffsets.VARIANT_MAP then return end

      if isNullOrNil(nodeAddr) then return end
      if GDDEFS.MONO then
        sendDebugMessage('Target uses mono, skipping vector offset')
        return
      end

      local VARIANT_VECTOR, VARIANT_VECTOR_SIZE, vectorAddr;
      local found = false
      
      -- retrieve gdscript variant (hash)map size
      local scriptInst = readPointer( nodeAddr + assumedOffsets.SCRIPT_INSTANCE )
      if isNullOrNil(scriptInst) then return end
      local scriptAddr = readPointer( scriptInst + assumedOffsets.SCRIPT_REF )
      if isNullOrNil(scriptAddr) then return end
      local vectorMapSize = readInteger( scriptAddr + assumedOffsets.VARIANT_MAP_SIZE )
      if isNullOrNil(vectorMapSize) then return end

      for i=4, (0x100/GDDEFS.PTRSIZE) do
        VARIANT_VECTOR = i * GDDEFS.PTRSIZE

        vectorAddr = readPointer( scriptInst + VARIANT_VECTOR )
        if isNullOrNil(vectorAddr) or not isValidVariantType( readInteger(vectorAddr) ) then goto continue end

        local sizeFound = false
        -- validate the vector size and vectot itself via the size
        for j=1, 4 do
          VARIANT_VECTOR_SIZE = j * 4
          local vectorSize = readInteger( vectorAddr - VARIANT_VECTOR_SIZE )
          if isNotNullOrNil(vectorSize) and vectorSize < 2000 and vectorMapSize == vectorSize and validateVariantStride(vectorAddr, vectorSize) then
            sizeFound= true
            break
          end
        end

        if not sizeFound then goto continue end

        -- successful case
        sendDebugMessage('Valid Vector offset 0x' .. numtohexstr( VARIANT_VECTOR ) )
        found = true
        break

        -- fails
        ::continue::
      end

      if found then
        assumedOffsets.VARIANT_VECTOR = VARIANT_VECTOR
        assumedOffsets.VARIANT_VECTOR_SIZE = VARIANT_VECTOR_SIZE
        return VARIANT_VECTOR;
      end

    end

    local function probeVariantVectorCandidates(sample, mapCandidate)
      local results = {}

      if not mapCandidate then return results end
      if isNullOrNil(mapCandidate.mapSize) then return results end

      for i = 4, (0x100 / GDDEFS.PTRSIZE) do
        local vectorOffset = i * GDDEFS.PTRSIZE
        local vectorAddr = readPointer(sample.scriptInst + vectorOffset)

        if isNullOrNil(vectorAddr) then goto continue end

        for j = 1, 4 do
          local sizeOffset = j * 4
          local vectorSize = readInteger(vectorAddr - sizeOffset)

          if isNullOrNil(vectorSize) then goto size_continue end
          if vectorSize > 2000 then goto size_continue end
          if vectorSize ~= mapCandidate.mapSize then goto size_continue end
          if not validateVariantStride(vectorAddr, vectorSize) then
            goto size_continue
          end

          table.insert( results, makeCandidate( vectorOffset, 5, { sizeOffset=sizeOffset, vectorAddr=vectorAddr, vectorSize=vectorSize, mapOffset=mapCandidate.offset, } ) )

          ::size_continue::
        end

        ::continue::
      end

      return results
    end

  -- VARIANT VECTOR END

  -- SCRIPT NAME START

    local function assumeScriptNameOffset(scriptAddr)
      if assumedOffsets.SCRIPT_NAME then return assumedOffsets.SCRIPT_NAME end
      local SCRIPT_NAME, scriptnameAddr;
      local found = false

      for i=1, (0x300/GDDEFS.PTRSIZE) do
        SCRIPT_NAME = 0x20 + i * GDDEFS.PTRSIZE

        scriptnameAddr = readPointer( scriptAddr + SCRIPT_NAME )
        if isNullOrNil(scriptnameAddr) then goto continue end
        if readUTFString( scriptnameAddr, 4 ) ~= 'res:' then goto continue end

        -- successful case
        sendDebugMessage('Valid Script Name offset 0x' .. numtohexstr( SCRIPT_NAME ) )
        found = true
        break

        -- fails
        ::continue::
      end

      if found then
        assumedOffsets.SCRIPT_NAME = SCRIPT_NAME
        return SCRIPT_NAME;
      end

    end

    local function probeScriptNameCandidates( sample )
      local results = {}

      for i=1, (0x300 / GDDEFS.PTRSIZE) do
        local offset = 0x20 + i * GDDEFS.PTRSIZE
        local stringAddr = readPointer(sample.scriptAddr + offset)

        if isNullOrNil(stringAddr) then goto continue end
        if readUTFString(stringAddr, 4) ~= "res:" then goto continue end

        table.insert(results, makeCandidate(offset, 5))

        ::continue::
      end

      return results
    end

  -- SCRIPT NAME END

  -- VARIANT MAP START

    local function assumeVariantMapOffset(scriptAddr)
      if assumedOffsets.VARIANT_MAP then return assumedOffsets.VARIANT_MAP end
      local VARIANT_MAP, VARIANT_MAP_SIZE
      local endmapAddr, leftAddr, rightAddr, color, elementIndex;
      local found = false

      if GDDEFS.MAJOR_VER >= 4 then
        -- if not assumedOffsets.FUNC_MAP then return end

        local startFrom = assumedOffsets.SCRIPT_NAME + GDDEFS.PTRSIZE*3

        local limit = 0x300

        if assumedOffsets.CONST_MAP then
          limit = assumedOffsets.CONST_MAP
        end

        if assumedOffsets.FUNC_MAP then
          limit = assumedOffsets.FUNC_MAP
        end

        for i=0, (limit/GDDEFS.PTRSIZE) do
          VARIANT_MAP = startFrom + i * GDDEFS.PTRSIZE

          local mapAddr =   readPointer( scriptAddr + VARIANT_MAP )
          local hashAddr =  readPointer( scriptAddr + VARIANT_MAP + GDDEFS.PTRSIZE )
          local headAddr =  readPointer( scriptAddr + VARIANT_MAP + GDDEFS.PTRSIZE * 2 )
          local tailAddr =  readPointer( scriptAddr + VARIANT_MAP + GDDEFS.PTRSIZE * 3 )
          local capacity =  readInteger( scriptAddr + VARIANT_MAP + GDDEFS.PTRSIZE * 4 )
          local mapSize =   readInteger( scriptAddr + VARIANT_MAP + GDDEFS.PTRSIZE * 4 + 0x4 )
          if isNullOrNil(mapAddr) or
            isNullOrNil(hashAddr) or
            isNullOrNil(headAddr) or
            tailAddr == nil or -- can be 1-sized
            isNullOrNil(capacity) or 
            isNullOrNil(mapSize) or
            mapSize > 2000 then
              goto continue
          end

          local nextAddr =  readPointer( headAddr )
          local prevAddr =  readPointer( headAddr + GDDEFS.PTRSIZE )
          local nameAddr =  readPointer( headAddr + GDDEFS.PTRSIZE * 2 )
          local index =     readInteger( headAddr + GDDEFS.PTRSIZE * 3 )
          local lastIndex = readInteger( tailAddr + GDDEFS.PTRSIZE * 3 )
          if isNullOrNil(nextAddr) or isInvalidPointer( nextAddr ) or
            isNotNullOrNil(prevAddr) or
            isNullOrNil(nameAddr) or isInvalidPointer( nameAddr ) or
            index ~= 0 or
            lastIndex ~= (mapSize-1) then
              goto continue
          end

          -- successful case
          VARIANT_MAP_SIZE = VARIANT_MAP + GDDEFS.PTRSIZE * 4 + 0x4
          VARIANT_MAP = VARIANT_MAP + GDDEFS.PTRSIZE * 2
          sendDebugMessage('Valid Variant HashMap offset 0x' .. numtohexstr( VARIANT_MAP ) )
          found = true
          break
        
          ::continue::
        end


      else --[[ if GDDEFS.MAJOR_VER <= 3 then ]]
        -- for more precise assumption, function map is the most reliable
        if not assumedOffsets.FUNC_MAP then return end
        local startFrom = assumedOffsets.SCRIPT_NAME + GDDEFS.PTRSIZE*3
        local limit = 0x100

        if assumedOffsets.CONST_MAP then
          startFrom = assumedOffsets.CONST_MAP + GDDEFS.PTRSIZE*2
          limit = assumedOffsets.CONST_MAP + 0x60
        end

        if assumedOffsets.FUNC_MAP then
          startFrom = assumedOffsets.FUNC_MAP + GDDEFS.PTRSIZE*2
          limit = assumedOffsets.FUNC_MAP + 0x40
        end

        for i=0, (limit/GDDEFS.PTRSIZE) do
          VARIANT_MAP = startFrom + i * GDDEFS.PTRSIZE

          -- script field 
          local mapAddr =     readPointer( scriptAddr + VARIANT_MAP )
          local endmapAddr =  readPointer( scriptAddr + VARIANT_MAP + GDDEFS.PTRSIZE )
          local mapSize =     readInteger( scriptAddr + VARIANT_MAP + GDDEFS.PTRSIZE * 2 )
          if isNullOrNil(mapAddr) or
            not isBSSData(endmapAddr) or 
            isNullOrNil(mapSize) or
            mapSize > 2000 then
              goto continue
          end

          -- root's
          local base = mapAddr
          local ptrBase = base + alignOffset(0x4, GDDEFS.PTRSIZE)

          local color =    readInteger( base )
          local right =    readPointer( ptrBase + GDDEFS.PTRSIZE * 0 )
          local left =     readPointer( ptrBase + GDDEFS.PTRSIZE * 1 )
          local parent =   readPointer( ptrBase + GDDEFS.PTRSIZE * 2 )
          if color ~= 1 or
            isNullOrNil( right ) or isInvalidPointer( right ) or not isBSSData( right ) or
            isNullOrNil( left ) or isInvalidPointer( left ) or
            isNullOrNil( parent ) or isInvalidPointer( parent ) or not isBSSData( parent ) then
              goto continue
          end

          local base = left
          local ptrBase = base + alignOffset(0x4, GDDEFS.PTRSIZE)

          local color =    readInteger( base )
          local right =    readPointer( ptrBase + GDDEFS.PTRSIZE * 0 )
          local left =     readPointer( ptrBase + GDDEFS.PTRSIZE * 1 )
          local parent =   readPointer( ptrBase + GDDEFS.PTRSIZE * 2 )
          local _next =    readPointer( ptrBase + GDDEFS.PTRSIZE * 3 )
          local _prev =    readPointer( ptrBase + GDDEFS.PTRSIZE * 4 )
          local sName =    readPointer( ptrBase + GDDEFS.PTRSIZE * 5 )
          local elidx =    readInteger( ptrBase + GDDEFS.PTRSIZE * 6 )

          if color > 1 or
            isNullOrNil( right ) or isInvalidPointer( right )  or
            isNullOrNil( left ) or isInvalidPointer( left ) or
            isNullOrNil( parent ) or isInvalidPointer( parent ) or
            isNullOrNil( _next ) or isInvalidPointer( _next ) or
            isNullOrNil( _prev ) or isInvalidPointer( _prev ) or
            isNullOrNil( sName ) or isInvalidPointer( sName ) or
            elidx == nil or elidx > mapSize then
              goto continue
          end

          -- successful case
          VARIANT_MAP_SIZE = VARIANT_MAP + GDDEFS.PTRSIZE * 2

          sendDebugMessage('Valid Variant (RBT) Map offset 0x' .. numtohexstr( VARIANT_MAP ) )
          found = true
          break
        
          ::continue::
        end
      end -- END VERSION

      if found then
        assumedOffsets.VARIANT_MAP = VARIANT_MAP
        assumedOffsets.VARIANT_MAP_SIZE = VARIANT_MAP_SIZE

        return VARIANT_MAP;
      end

    end

    local function probeVariantMapCandidates(sample)
      local results = {}
      local scriptAddr = sample.scriptAddr

      if isNullOrNil(scriptAddr) then return results end
      if not assumedOffsets.SCRIPT_NAME then return results end

      local scanStart = assumedOffsets.SCRIPT_NAME + GDDEFS.PTRSIZE * 3
      local scanEnd = 0x400

      for candidateOffset = scanStart, scanEnd, GDDEFS.PTRSIZE do
        if GDDEFS.MAJOR_VER >= 4 then

          local mapAddr = readPointer(scriptAddr + candidateOffset)
          local hashAddr = readPointer(scriptAddr + candidateOffset + GDDEFS.PTRSIZE)
          local headAddr = readPointer(scriptAddr + candidateOffset + GDDEFS.PTRSIZE * 2)
          local tailAddr = readPointer(scriptAddr + candidateOffset + GDDEFS.PTRSIZE * 3)
          local capacity = readInteger(scriptAddr + candidateOffset + GDDEFS.PTRSIZE * 4)
          local mapSize = readInteger(scriptAddr + candidateOffset + GDDEFS.PTRSIZE * 4 + 0x4)
          if isNullOrNil(mapAddr) then goto continue end
          if isNullOrNil(hashAddr) then goto continue end
          if isNullOrNil(headAddr) then goto continue end
          if tailAddr == nil then goto continue end
          if isNullOrNil(capacity) then goto continue end
          if isNullOrNil(mapSize) then goto continue end
          if mapSize > 2000 then goto continue end

          local nextAddr = readPointer(headAddr)
          local prevAddr = readPointer(headAddr + GDDEFS.PTRSIZE)
          local nameAddr = readPointer(headAddr + GDDEFS.PTRSIZE * 2)
          local firstIndex = readInteger(headAddr + GDDEFS.PTRSIZE * 3)
          local lastIndex = readInteger(tailAddr + GDDEFS.PTRSIZE * 3)
          if isNullOrNil(nameAddr) then goto continue end
          if isInvalidPointer(nameAddr) then goto continue end
          if isNotNullOrNil(prevAddr) then goto continue end

          if mapSize > 1 and isNullOrNil(nextAddr) then goto continue end
          if isNotNullOrNil(nextAddr) and isInvalidPointer(nextAddr) then goto continue end

          local score = 3

          local name = getStringNameStr(nameAddr) -- TODO: remove?
          if name and name ~= "" then score = score + 2 end

          if firstIndex == 0 then score = score + 2 end

          if lastIndex < mapSize then score = score + 1 end

          -- HashMap object's beginning.
          local reportedOffset = candidateOffset + GDDEFS.PTRSIZE * 2

          table.insert(results, makeCandidate(reportedOffset, score,
          {
            mapSize = mapSize,
            mapSizeAddress = scriptAddr + candidateOffset + GDDEFS.PTRSIZE * 4 + 0x4,
            mapSizeOffset = candidateOffset + GDDEFS.PTRSIZE * 4 + 0x4,

            mapObjectOffset = candidateOffset,
            mapAddr = mapAddr,
            hashAddr = hashAddr,
            rootAddr = headAddr,
            endAddr = tailAddr,

            firstIndex = firstIndex,
            lastIndex = lastIndex,
            indexOffset = GDDEFS.PTRSIZE * 3,
          }))

        else
          local mapAddr = readPointer(scriptAddr + candidateOffset)
          local endmapAddr = readPointer(scriptAddr + candidateOffset + GDDEFS.PTRSIZE)
          local mapSize = readInteger(scriptAddr + candidateOffset + GDDEFS.PTRSIZE * 2)

          if isNullOrNil(mapAddr) then goto continue end
          if not isBSSData(endmapAddr) then goto continue end
          if isNullOrNil(mapSize) then goto continue end
          if mapSize > 2000 then goto continue end

          local rootBase = mapAddr
          local rootPtrBase = rootBase + alignOffset(0x4, GDDEFS.PTRSIZE)
          local rootColor = readInteger(rootBase)
          local rootRight = readPointer(rootPtrBase + GDDEFS.PTRSIZE * 0)
          local rootLeft = readPointer(rootPtrBase + GDDEFS.PTRSIZE * 1)
          local rootParent = readPointer(rootPtrBase + GDDEFS.PTRSIZE * 2)
          if rootColor ~= 1 then goto continue end
          if isNullOrNil(rootRight) then goto continue end
          if isInvalidPointer(rootRight) then goto continue end
          if not isBSSData(rootRight) then goto continue end
          if isNullOrNil(rootLeft) then goto continue end
          if isInvalidPointer(rootLeft) then goto continue end
          if isNullOrNil(rootParent) then goto continue end
          if isInvalidPointer(rootParent) then goto continue end
          if not isBSSData(rootParent) then goto continue end

          local elementBase = rootLeft
          local elementPtrBase = elementBase + alignOffset(0x4, GDDEFS.PTRSIZE)
          local elementColor = readInteger(elementBase)
          local elementRight = readPointer(elementPtrBase + GDDEFS.PTRSIZE * 0)
          local elementLeft = readPointer(elementPtrBase + GDDEFS.PTRSIZE * 1)
          local elementParent = readPointer(elementPtrBase + GDDEFS.PTRSIZE * 2)
          local nextElement = readPointer(elementPtrBase + GDDEFS.PTRSIZE * 3)
          local previousElement = readPointer(elementPtrBase + GDDEFS.PTRSIZE * 4)
          local nameAddr = readPointer(elementPtrBase + GDDEFS.PTRSIZE * 5)
          local firstIndex = readInteger(elementPtrBase + GDDEFS.PTRSIZE * 6)

          if elementColor > 1 then goto continue end
          if isNullOrNil(elementRight) then goto continue end
          if isInvalidPointer(elementRight) then goto continue end
          if isNullOrNil(elementLeft) then goto continue end
          if isInvalidPointer(elementLeft) then goto continue end
          if isNullOrNil(elementParent) then goto continue end
          if isInvalidPointer(elementParent) then goto continue end
          if isNullOrNil(nextElement) then goto continue end
          if isInvalidPointer(nextElement) then goto continue end
          if isNullOrNil(previousElement) then goto continue end
          if isInvalidPointer(previousElement) then goto continue end
          if isNullOrNil(nameAddr) then goto continue end
          if isInvalidPointer(nameAddr) then goto continue end
          if firstIndex >= mapSize then goto continue end

          local score = 3

          local name = getStringNameStr(nameAddr)
          if name and name ~= "" then score = score + 2 end

          if firstIndex == 0 then score = score + 2 end

          table.insert(results, makeCandidate(candidateOffset, score,
          {
            mapSize = mapSize,
            mapSizeAddress = scriptAddr + candidateOffset + GDDEFS.PTRSIZE * 2,
            mapSizeOffset = candidateOffset + GDDEFS.PTRSIZE * 2,
            rootAddr = mapAddr,
            endAddr = endmapAddr,
            firstElement = elementBase,
            firstIndex = firstIndex,
            indexOffset = alignOffset(0x4, GDDEFS.PTRSIZE) + GDDEFS.PTRSIZE * 6,
          }))
        end

        ::continue::
      end
      return results
    end

  -- VARIANT MAP END

  -- CONST MAP START

    local function assumeConstMapOffset(scriptAddr)
      if assumedOffsets.CONST_MAP then return assumedOffsets.CONST_MAP end
      local CONST_MAP
      -- local endmapAddr, leftAddr, rightAddr, color, elementIndex;
      local found = false

      if GDDEFS.MAJOR_VER >= 4 then
        if not assumedOffsets.VARIANT_MAP then return end

        local startFrom = assumedOffsets.SCRIPT_NAME + GDDEFS.PTRSIZE*3
        local limit = 0x300

        if assumedOffsets.SCRIPT_NAME then
          startFrom = assumedOffsets.SCRIPT_NAME + GDDEFS.PTRSIZE*4
          limit = 0x200
        end

        if assumedOffsets.VARIANT_MAP then
          startFrom = assumedOffsets.VARIANT_MAP + GDDEFS.PTRSIZE*4
          limit = 0x100
        end

        if assumedOffsets.FUNC_MAP then
          limit = assumedOffsets.FUNC_MAP
        end

        for i=0, (limit/GDDEFS.PTRSIZE) do
          CONST_MAP = startFrom + i * GDDEFS.PTRSIZE

          local mapAddr =   readPointer( scriptAddr + CONST_MAP )
          local hashAddr =  readPointer( scriptAddr + CONST_MAP + GDDEFS.PTRSIZE )
          local headAddr =  readPointer( scriptAddr + CONST_MAP + GDDEFS.PTRSIZE * 2 )
          local tailAddr =  readPointer( scriptAddr + CONST_MAP + GDDEFS.PTRSIZE * 3 )
          local capacity =  readInteger( scriptAddr + CONST_MAP + GDDEFS.PTRSIZE * 4 )
          local mapSize =   readInteger( scriptAddr + CONST_MAP + GDDEFS.PTRSIZE * 4 + 0x4 )
          if isNullOrNil(mapAddr) or
            isNullOrNil(hashAddr) or
            isNullOrNil(headAddr) or
            tailAddr == nil or -- can be 1-sized
            isNullOrNil(capacity) or 
            isNullOrNil(mapSize) or 
            mapSize > 2000 then
              goto continue
          end

          local nextAddr =    readPointer( headAddr )
          local prevAddr =    readPointer( headAddr + GDDEFS.PTRSIZE )
          local nameAddr =    readPointer( headAddr + GDDEFS.PTRSIZE * 2 )
          local variantType = readInteger( headAddr + GDDEFS.PTRSIZE * 3 )
          if isNullOrNil(nextAddr) or isInvalidPointer( nextAddr ) or
            isNotNullOrNil(prevAddr) or 
            isNullOrNil(nameAddr) or isInvalidPointer( nameAddr ) or
            not isValidVariantType(variantType) then
              goto continue
          end

          local typeName = GDDEFS.VARIANT_TYPE_PROFILE.names[variantType]
          local offsetToValue = (typeName == 'OBJECT') and 0x10 or 0x8
          offsetToValue =  GDDEFS.PTRSIZE * 3 + offsetToValue

          if mapSize == 1 and readPointer(headAddr + offsetToValue) == 0 then goto continue end

          -- walk the hashmap; ugly
          local typeHit = false
          local currentElem = headAddr
          local isPassableVariantValue = makeIsPassableVariantValue()

          repeat
            if isPassableVariantValue(currentElem, GDDEFS.PTRSIZE * 3) then
              typeHit = true
              break
            end
            currentElem = readPointer( currentElem ) -- next at 0x0
          until ( isNullOrNil(currentElem) )

          -- successful case
          if typeHit then
            CONST_MAP = CONST_MAP + GDDEFS.PTRSIZE * 2
            sendDebugMessage('Valid-ish Constant HashMap offset 0x' .. numtohexstr( CONST_MAP ) )
            found = true
            break
          end

          ::continue::
        end
        
      else --[[ if GDDEFS.MAJOR_VER <= 3 then ]]
        if not assumedOffsets.FUNC_MAP then return end
        local startFrom = assumedOffsets.SCRIPT_NAME + GDDEFS.PTRSIZE*3
        local limit = 0x100

        if assumedOffsets.VARIANT_MAP then
          limit = assumedOffsets.VARIANT_MAP
        end

        if assumedOffsets.FUNC_MAP then
          limit = assumedOffsets.FUNC_MAP
        end

        for i=0, (limit/GDDEFS.PTRSIZE) do
          CONST_MAP = startFrom + i * GDDEFS.PTRSIZE

          -- script field
          local mapAddr =     readPointer( scriptAddr + CONST_MAP )
          local endmapAddr =  readPointer( scriptAddr + CONST_MAP + GDDEFS.PTRSIZE )
          local mapSize =     readInteger( scriptAddr + CONST_MAP + GDDEFS.PTRSIZE * 2 )
          if isNullOrNil(mapAddr) or
            not isBSSData(endmapAddr) or 
            isNullOrNil(mapSize) or
            mapSize > 2000 then
              goto continue
          end

          -- root's
          local base = mapAddr
          local ptrBase = base + alignOffset(0x4, GDDEFS.PTRSIZE)
          local color =      readInteger( base )
          local right =      readPointer( ptrBase + GDDEFS.PTRSIZE * 0 )
          local left =       readPointer( ptrBase + GDDEFS.PTRSIZE * 1 )
          local parent =     readPointer( ptrBase + GDDEFS.PTRSIZE * 2 )
          if color ~= 1 or
            isNullOrNil( right ) or isInvalidPointer( right ) or not isBSSData( right ) or
            isNullOrNil( left ) or isInvalidPointer( left ) or
            isNullOrNil( parent ) or isInvalidPointer( parent ) or not isBSSData( parent ) then
              goto continue
          end
          local mapElement = readPointer( ptrBase + GDDEFS.PTRSIZE * 1 ) -- to get leftmost

          -- element's
          local base = left
          local ptrBase = base + alignOffset(0x4, GDDEFS.PTRSIZE)
          local color =    readInteger( base )
          local right =    readPointer( ptrBase + GDDEFS.PTRSIZE * 0 )
          local left =     readPointer( ptrBase + GDDEFS.PTRSIZE * 1 )
          local parent =   readPointer( ptrBase + GDDEFS.PTRSIZE * 2 )
          local _next =    readPointer( ptrBase + GDDEFS.PTRSIZE * 3 )
          local _prev =    readPointer( ptrBase + GDDEFS.PTRSIZE * 4 )
          local sName =    readPointer( ptrBase + GDDEFS.PTRSIZE * 5 )
          local elType =   readInteger( ptrBase + GDDEFS.PTRSIZE * 6 )
          if color > 1 or
            isNullOrNil( right ) or isInvalidPointer( right ) or
            isNullOrNil( left ) or isInvalidPointer( left ) or
            isNullOrNil( parent ) or isInvalidPointer( parent ) or
            isNullOrNil( _next ) or isInvalidPointer( _next ) or
            isNullOrNil( _prev ) or isInvalidPointer( _prev ) or
            isNullOrNil( sName ) or isInvalidPointer( sName ) or
            not isValidVariantType(elType) then
              goto continue
          end

          local typeName = GDDEFS.VARIANT_TYPE_PROFILE.names[elType]
          local offsetToValue = (typeName == 'OBJECT') and 0x10 or 0x8

          if mapSize == 1 and readPointer( base + alignOffset(0x4, GDDEFS.PTRSIZE) + GDDEFS.PTRSIZE * 6 + offsetToValue) == 0 then goto continue end

          -- walk the hashmap; ugly
          local typeHit = false
          local isPassableVariantValue = makeIsPassableVariantValue()

          -- get leftmost
          while readPointer(mapElement + GDDEFS.MAP_LELEM) ~= endmapAddr do
            mapElement = readPointer(mapElement + alignOffset(0x4, GDDEFS.PTRSIZE) + GDDEFS.PTRSIZE * 1 )
          end

          local currentElem = mapElement

          repeat
            if isPassableVariantValue(currentElem, alignOffset(0x4, GDDEFS.PTRSIZE) + GDDEFS.PTRSIZE * 6 ) then
              typeHit = true
              break
            end
            currentElem = readPointer( currentElem + alignOffset(0x4, GDDEFS.PTRSIZE) + GDDEFS.PTRSIZE * 3 ) -- next
          until ( isNullOrNil(currentElem) )



          -- successful case
          if typeHit then
            sendDebugMessage('Valid-ish Const (RBT) Map offset 0x' .. numtohexstr( CONST_MAP ) )
            found = true
            break
          end

          ::continue::
        end
      end -- END VERSION

      if found then
        assumedOffsets.CONST_MAP = CONST_MAP
        return CONST_MAP;
      end

    end

    local function probeConstMapCandidates(sample)
      local results = {}
      local scriptAddr = sample.scriptAddr

      if isNullOrNil(scriptAddr) then return results end
      if not assumedOffsets.SCRIPT_NAME then return results end

      local scanStart = assumedOffsets.SCRIPT_NAME + GDDEFS.PTRSIZE * 3

      local scanEnd = 0x400

      for candidateOffset = scanStart, scanEnd, GDDEFS.PTRSIZE do
        if GDDEFS.MAJOR_VER >= 4 then

          local mapAddr = readPointer(scriptAddr + candidateOffset)
          local hashAddr = readPointer(scriptAddr + candidateOffset + GDDEFS.PTRSIZE)
          local headAddr = readPointer(scriptAddr + candidateOffset + GDDEFS.PTRSIZE * 2)
          local tailAddr = readPointer(scriptAddr + candidateOffset + GDDEFS.PTRSIZE * 3)
          local capacity = readInteger(scriptAddr + candidateOffset + GDDEFS.PTRSIZE * 4)
          local mapSize = readInteger(scriptAddr + candidateOffset + GDDEFS.PTRSIZE * 4 + 0x4)
          if isNullOrNil(mapAddr) then goto continue end
          if isNullOrNil(hashAddr) then goto continue end
          if isNullOrNil(headAddr) then goto continue end
          if tailAddr == nil then goto continue end
          if isNullOrNil(capacity) then goto continue end
          if isNullOrNil(mapSize) then goto continue end
          if mapSize > 2000 then goto continue end

          local nextAddr = readPointer(headAddr)
          local prevAddr = readPointer(headAddr + GDDEFS.PTRSIZE)
          local nameAddr = readPointer(headAddr + GDDEFS.PTRSIZE * 2)
          local variantType = readInteger(headAddr + GDDEFS.PTRSIZE * 3)
          if isNotNullOrNil(prevAddr) then goto continue end
          if isNullOrNil(nameAddr) then goto continue end
          if isInvalidPointer(nameAddr) then goto continue end
          if not isValidVariantType(variantType) then goto continue end
          if mapSize > 1 and isNullOrNil(nextAddr) then goto continue end

          if isNotNullOrNil(nextAddr) and isInvalidPointer(nextAddr) then goto continue end

          local name = getStringNameStr(nameAddr)
          if not name or name == "" then goto continue end

          local currentElem = headAddr
          local visited = {}
          local validValues = 0
          local validNames = 0
          local walked = 0

          while isNotNullOrNil(currentElem) and walked < mapSize do
            if visited[currentElem] then goto continue end
            visited[currentElem] = true
            walked = walked + 1

            local currentNameAddr = readPointer(currentElem + GDDEFS.PTRSIZE * 2)

            local currentName = getStringNameStr(currentNameAddr)

            local currentType = readInteger(currentElem + GDDEFS.PTRSIZE * 3)

            if currentName and currentName ~= "" then validNames = validNames + 1 end

            if isValidVariantType(currentType) then validValues = validValues + 1 end

            currentElem = readPointer(currentElem)
          end

          if walked == 0 then goto continue end
          if validNames ~= walked then goto continue end
          if validValues ~= walked then goto continue end

          local score = 3
          score = score + math.min(validNames, 3)
          score = score + math.min(validValues, 3)

          if walked == mapSize then score = score + 2 end

          -- GDDumper expects the head pointer offset.
          local reportedOffset = candidateOffset + GDDEFS.PTRSIZE * 2

          table.insert(results, makeCandidate(reportedOffset, score,
          {
            mapSize = mapSize,
            mapObjectOffset = candidateOffset,
            mapSizeOffset = candidateOffset + GDDEFS.PTRSIZE * 4 + 0x4,
            mapSizeAddress = scriptAddr + candidateOffset + GDDEFS.PTRSIZE * 4 + 0x4,
            mapAddr = mapAddr,
            hashAddr = hashAddr,
            rootAddr = headAddr,
            endAddr = tailAddr,
            keyOffset = GDDEFS.PTRSIZE * 2,
            typeOffset = GDDEFS.PTRSIZE * 3,
            validatedElements = walked,
            validatedNames = validNames,
            validatedValues = validValues,
          }))

        else
          local mapAddr = readPointer(scriptAddr + candidateOffset)
          local endmapAddr = readPointer(scriptAddr + candidateOffset + GDDEFS.PTRSIZE)
          local mapSize = readInteger(scriptAddr + candidateOffset + GDDEFS.PTRSIZE * 2)
          if isNullOrNil(mapAddr) then goto continue end
          if not isBSSData(endmapAddr) then goto continue end
          if isNullOrNil(mapSize) then goto continue end
          if mapSize > 2000 then goto continue end

          local rootPtrBase = mapAddr + alignOffset(0x4, GDDEFS.PTRSIZE)
          local rootColor = readInteger(mapAddr)
          local rootRight = readPointer(rootPtrBase + GDDEFS.PTRSIZE * 0)
          local rootLeft = readPointer(rootPtrBase + GDDEFS.PTRSIZE * 1)
          local rootParent = readPointer(rootPtrBase + GDDEFS.PTRSIZE * 2)
          if rootColor ~= 1 then goto continue end
          if isNullOrNil(rootRight) then goto continue end
          if isInvalidPointer(rootRight) then goto continue end
          if not isBSSData(rootRight) then goto continue end
          if isNullOrNil(rootLeft) then goto continue end
          if isInvalidPointer(rootLeft) then goto continue end
          if isNullOrNil(rootParent) then goto continue end
          if isInvalidPointer(rootParent) then goto continue end
          if not isBSSData(rootParent) then goto continue end

          local elementPtrBase = rootLeft + alignOffset(0x4, GDDEFS.PTRSIZE)
          local elementColor = readInteger(rootLeft)
          local elementRight = readPointer(elementPtrBase + GDDEFS.PTRSIZE * 0)
          local elementLeft = readPointer(elementPtrBase + GDDEFS.PTRSIZE * 1)
          local elementParent = readPointer(elementPtrBase + GDDEFS.PTRSIZE * 2)
          local nextElement = readPointer(elementPtrBase + GDDEFS.PTRSIZE * 3)
          local previousElement = readPointer(elementPtrBase + GDDEFS.PTRSIZE * 4)
          local nameAddr = readPointer(elementPtrBase + GDDEFS.PTRSIZE * 5)
          local variantType = readInteger(elementPtrBase + GDDEFS.PTRSIZE * 6)
          if elementColor > 1 then goto continue end
          if isNullOrNil(elementRight) then goto continue end
          if isInvalidPointer(elementRight) then goto continue end
          if isNullOrNil(elementLeft) then goto continue end
          if isInvalidPointer(elementLeft) then goto continue end
          if isNullOrNil(elementParent) then goto continue end
          if isInvalidPointer(elementParent) then goto continue end
          if isNullOrNil(nextElement) then goto continue end
          if isInvalidPointer(nextElement) then goto continue end
          if isNullOrNil(previousElement) then goto continue end
          if isInvalidPointer(previousElement) then goto continue end
          if isNullOrNil(nameAddr) then goto continue end
          if isInvalidPointer(nameAddr) then goto continue end
          if not isValidVariantType(variantType) then goto continue end

          local mapElement = rootLeft
          local visited = {}
          local validNames = 0
          local validValues = 0
          local walked = 0

          -- Reach the leftmost element.
          while readPointer(mapElement + GDDEFS.MAP_LELEM) ~= endmapAddr do

            if visited[mapElement] then goto continue end
            visited[mapElement] = true
            mapElement = readPointer(mapElement + GDDEFS.MAP_LELEM)

            if isNullOrNil(mapElement) then goto continue end
          end

          visited = {}

          while isNotNullOrNil(mapElement) and mapElement ~= endmapAddr and walked < mapSize do
            if visited[mapElement] then goto continue end
            visited[mapElement] = true
            walked = walked + 1

            local currentPtrBase = mapElement + alignOffset(0x4, GDDEFS.PTRSIZE)
            local currentNameAddr = readPointer(currentPtrBase + GDDEFS.PTRSIZE * 5)
            local currentName = getStringNameStr(currentNameAddr)
            local currentType = readInteger(currentPtrBase + GDDEFS.PTRSIZE * 6)
            if currentName and currentName ~= "" then validNames = validNames + 1 end
            if isValidVariantType(currentType) then validValues = validValues + 1 end
            mapElement = readPointer(currentPtrBase + GDDEFS.PTRSIZE * 3)

          end

          if walked == 0 then goto continue end
          if validNames ~= walked then goto continue end
          if validValues ~= walked then goto continue end

          local score = 3
          score = score + math.min(validNames, 3)
          score = score + math.min(validValues, 3)

          if walked == mapSize then score = score + 2 end

          table.insert(results, makeCandidate(candidateOffset, score,
          {
            mapSize = mapSize,
            mapSizeOffset = candidateOffset + GDDEFS.PTRSIZE * 2,
            mapSizeAddress = scriptAddr + candidateOffset + GDDEFS.PTRSIZE * 2,
            rootAddr = mapAddr,
            endAddr = endmapAddr,
            firstElement = rootLeft,

            keyOffset = alignOffset(0x4, GDDEFS.PTRSIZE) + GDDEFS.PTRSIZE * 5,
            typeOffset = alignOffset(0x4, GDDEFS.PTRSIZE) + GDDEFS.PTRSIZE * 6,

            validatedElements = walked,
            validatedNames = validNames,
            validatedValues = validValues,
          }))
        end

        ::continue::
      end

      return results

    end
  -- CONST MAP END

  -- FUNC MAP START

    local function assumeFuncMapOffset(scriptAddr)
      if assumedOffsets.FUNC_MAP then return assumedOffsets.FUNC_MAP end
      local FUNC_MAP
      local found = false

      if GDDEFS.MAJOR_VER >= 4 then

        local startFrom = assumedOffsets.SCRIPT_NAME + GDDEFS.PTRSIZE*3
        local limit = 0x300

        if assumedOffsets.VARIANT_MAP then
          startFrom = assumedOffsets.VARIANT_MAP + GDDEFS.PTRSIZE*4
          limit = 0x120
        end

        if assumedOffsets.CONST_MAP and assumedOffsets.CONST_MAP < 0x400 then
          startFrom = assumedOffsets.CONST_MAP + GDDEFS.PTRSIZE*4
          limit = 0x50
        end

        for i=0, (limit/GDDEFS.PTRSIZE) do
          FUNC_MAP = startFrom + i * GDDEFS.PTRSIZE

          local mapAddr =   readPointer( scriptAddr + FUNC_MAP )
          local hashAddr =  readPointer( scriptAddr + FUNC_MAP + GDDEFS.PTRSIZE )
          local headAddr =  readPointer( scriptAddr + FUNC_MAP + GDDEFS.PTRSIZE * 2 )
          local tailAddr =  readPointer( scriptAddr + FUNC_MAP + GDDEFS.PTRSIZE * 3 )
          local capacity =  readInteger( scriptAddr + FUNC_MAP + GDDEFS.PTRSIZE * 4 )
          local mapSize =   readInteger( scriptAddr + FUNC_MAP + GDDEFS.PTRSIZE * 4 + 0x4 )
          if isNullOrNil(mapAddr) or isInvalidPointer( mapAddr ) or
            isNullOrNil(hashAddr) or isInvalidPointer( hashAddr ) or
            isNullOrNil(headAddr) or isInvalidPointer( headAddr ) or
            tailAddr == nil or -- can be 1-sized
            isNullOrNil(capacity) or 
            isNullOrNil(mapSize) or 
            mapSize > 2000 then
              goto continue
          end

          local nextAddr =     readPointer( headAddr )
          local prevAddr =     readPointer( headAddr + GDDEFS.PTRSIZE )
          local nameAddr =     readPointer( headAddr + GDDEFS.PTRSIZE * 2 )
          local funcAddr =     readPointer( headAddr + GDDEFS.PTRSIZE * 3 )
          if isNullOrNil(nextAddr) or isInvalidPointer( nextAddr ) or
            isNotNullOrNil(prevAddr) or 
            isNullOrNil(nameAddr) or isInvalidPointer( nameAddr ) or
            isNullOrNil(funcAddr) or isInvalidPointer( funcAddr ) or
            not checkIfGDFunction(funcAddr, nameAddr) then
              goto continue
          end

          FUNC_MAP = FUNC_MAP + GDDEFS.PTRSIZE * 2
          sendDebugMessage('Valid-ish Constant HashMap offset 0x' .. numtohexstr( FUNC_MAP ) )
          found = true
          break

          ::continue::
        end

      else --[[ if GDDEFS.MAJOR_VER <= 3 then ]]

        local startFrom = assumedOffsets.SCRIPT_NAME + GDDEFS.PTRSIZE*3
        local limit = 0x100

        if assumedOffsets.CONST_MAP then
          startFrom = assumedOffsets.CONST_MAP + GDDEFS.PTRSIZE*2
          limit = assumedOffsets.CONST_MAP + 0x60
        end

        if assumedOffsets.VARIANT_MAP then
          limit = assumedOffsets.VARIANT_MAP
        end

        for i=0, (limit/GDDEFS.PTRSIZE) do
          FUNC_MAP = startFrom + i * GDDEFS.PTRSIZE

          -- script field 
          local mapAddr =     readPointer( scriptAddr + FUNC_MAP )
          local endmapAddr =  readPointer( scriptAddr + FUNC_MAP + GDDEFS.PTRSIZE )
          local mapSize =     readInteger( scriptAddr + FUNC_MAP + GDDEFS.PTRSIZE * 2 )
          if isNullOrNil(mapAddr) or
            not isBSSData(endmapAddr) or 
            isNullOrNil(mapSize) or
            mapSize > 2000 then
              goto continue
          end

          -- root's
          local base = mapAddr
          local ptrBase = base + alignOffset(0x4, GDDEFS.PTRSIZE)

          local color =    readInteger( base )
          local right =    readPointer( ptrBase + GDDEFS.PTRSIZE * 0 )
          local left =     readPointer( ptrBase + GDDEFS.PTRSIZE * 1 )
          local parent =   readPointer( ptrBase + GDDEFS.PTRSIZE * 2 )
          if color ~= 1 or
            isNullOrNil( right ) or isInvalidPointer( right ) or not isBSSData( right ) or
            isNullOrNil( left ) or isInvalidPointer( left ) or
            isNullOrNil( parent ) or isInvalidPointer( parent ) or not isBSSData( parent ) then
              goto continue
          end

          local base = left
          local ptrBase = base + alignOffset(0x4, GDDEFS.PTRSIZE)

          local color =    readInteger( base )
          local right =    readPointer( ptrBase + GDDEFS.PTRSIZE * 0 )
          local left =     readPointer( ptrBase + GDDEFS.PTRSIZE * 1 )
          local parent =   readPointer( ptrBase + GDDEFS.PTRSIZE * 2 )
          local _next =    readPointer( ptrBase + GDDEFS.PTRSIZE * 3 )
          local _prev =    readPointer( ptrBase + GDDEFS.PTRSIZE * 4 )
          local sName =    readPointer( ptrBase + GDDEFS.PTRSIZE * 5 )
          local funcAddr = readPointer( ptrBase + GDDEFS.PTRSIZE * 6 )

          if color > 1 or
            isNullOrNil( right ) or isInvalidPointer( right )  or
            isNullOrNil( left ) or isInvalidPointer( left ) or
            isNullOrNil( parent ) or isInvalidPointer( parent ) or
            isNullOrNil( _next ) or isInvalidPointer( _next ) or
            isNullOrNil( _prev ) or isInvalidPointer( _prev ) or
            isNullOrNil( sName ) or isInvalidPointer( sName ) or
            isNullOrNil(funcAddr) or not checkIfGDFunction(funcAddr) then
              goto continue
          end

          -- successful case
          sendDebugMessage('Valid Func (RBT) Map offset 0x' .. numtohexstr( FUNC_MAP ) )
          found = true
          break
        
          ::continue::
        end
      end -- END VERSION

      if found then
        assumedOffsets.FUNC_MAP = FUNC_MAP
        return FUNC_MAP;
      end

    end

    local function probeFuncMapCandidates(sample)
      local results = {}
      local scriptAddr = sample.scriptAddr

      if isNullOrNil(scriptAddr) then return results end
      if not assumedOffsets.SCRIPT_NAME then return results end

      local scanStart = assumedOffsets.SCRIPT_NAME + GDDEFS.PTRSIZE * 3

      local scanEnd = 0x400

      for candidateOffset = scanStart, scanEnd, GDDEFS.PTRSIZE do
        if GDDEFS.MAJOR_VER >= 4 then

          local mapAddr = readPointer(scriptAddr + candidateOffset)
          local hashAddr = readPointer(scriptAddr + candidateOffset + GDDEFS.PTRSIZE)
          local headAddr = readPointer(scriptAddr + candidateOffset + GDDEFS.PTRSIZE * 2)
          local tailAddr = readPointer(scriptAddr + candidateOffset + GDDEFS.PTRSIZE * 3)
          local capacity = readInteger(scriptAddr + candidateOffset + GDDEFS.PTRSIZE * 4)
          local mapSize = readInteger(scriptAddr + candidateOffset + GDDEFS.PTRSIZE * 4 + 0x4)
          if isNullOrNil(mapAddr) then goto continue end
          if isInvalidPointer(mapAddr) then goto continue end
          if isNullOrNil(hashAddr) then goto continue end
          if isInvalidPointer(hashAddr) then goto continue end
          if isNullOrNil(headAddr) then goto continue end
          if isInvalidPointer(headAddr) then goto continue end
          if tailAddr == nil then goto continue end
          if isNullOrNil(capacity) then goto continue end
          if isNullOrNil(mapSize) then goto continue end
          if mapSize > 2000 then goto continue end
          if mapSize == 0 then goto continue end

          local currentElem = headAddr
          local visited = {}
          local walked = 0
          local validNames = 0
          local validFunctions = 0

          while isNotNullOrNil(currentElem) and walked < mapSize do
            if visited[currentElem] then goto continue end
            if isInvalidPointer(currentElem) then goto continue end

            visited[currentElem] = true
            walked = walked + 1

            local previousElem = readPointer(currentElem + GDDEFS.PTRSIZE)
            local nameAddr = readPointer(currentElem + GDDEFS.PTRSIZE * 2)
            local funcAddr = readPointer(currentElem + GDDEFS.PTRSIZE * 3)
            
            if walked == 1 and isNotNullOrNil(previousElem) then goto continue end
            if isNullOrNil(nameAddr) then goto continue end
            if isInvalidPointer(nameAddr) then goto continue end
            if isNullOrNil(funcAddr) then goto continue end
            if isInvalidPointer(funcAddr) then goto continue end

            local name = getStringNameStr(nameAddr)
            if name and name ~= "" then validNames = validNames + 1 end

            if checkIfGDFunction(funcAddr, nameAddr) then validFunctions = validFunctions + 1 end

            currentElem = readPointer(currentElem)
          end

          if walked == 0 then goto continue end
          if validFunctions == 0 then goto continue end
          if validNames ~= walked then goto continue end
          if validFunctions ~= walked then goto continue end

          local score = 4

          score = score + math.min(validNames, 3)
          score = score + math.min(validFunctions * 2, 6)

          if walked == mapSize then score = score + 2 end

          local reportedOffset = candidateOffset + GDDEFS.PTRSIZE * 2

          table.insert(results, makeCandidate(reportedOffset, score,
          {
            mapSize = mapSize,
            mapObjectOffset = candidateOffset,
            mapSizeOffset = candidateOffset + GDDEFS.PTRSIZE * 4 + 0x4,
            mapSizeAddress = scriptAddr + candidateOffset + GDDEFS.PTRSIZE * 4 + 0x4,

            mapAddr = mapAddr,
            hashAddr = hashAddr,
            rootAddr = headAddr,
            endAddr = tailAddr,

            keyOffset = GDDEFS.PTRSIZE * 2,
            valueOffset = GDDEFS.PTRSIZE * 3,

            validatedElements = walked,
            validatedNames = validNames,
            validatedFunctions = validFunctions,
          }))

        else
          local mapAddr = readPointer(scriptAddr + candidateOffset)
          local endmapAddr = readPointer(scriptAddr + candidateOffset + GDDEFS.PTRSIZE)
          local mapSize = readInteger(scriptAddr + candidateOffset + GDDEFS.PTRSIZE * 2)
          if isNullOrNil(mapAddr) then goto continue end
          if isInvalidPointer(mapAddr) then goto continue end
          if not isBSSData(endmapAddr) then goto continue end
          if isNullOrNil(mapSize) then goto continue end
          if mapSize > 2000 then goto continue end
          if mapSize == 0 then goto continue end

          local rootPtrBase = mapAddr + alignOffset(0x4, GDDEFS.PTRSIZE)
          local rootColor = readInteger(mapAddr)
          local rootRight = readPointer(rootPtrBase + GDDEFS.PTRSIZE * 0)
          local rootLeft = readPointer(rootPtrBase + GDDEFS.PTRSIZE * 1)
          local rootParent = readPointer(rootPtrBase + GDDEFS.PTRSIZE * 2)
          if rootColor ~= 1 then goto continue end
          if isNullOrNil(rootRight) then goto continue end
          if isInvalidPointer(rootRight) then goto continue end
          if not isBSSData(rootRight) then goto continue end
          if isNullOrNil(rootLeft) then goto continue end
          if isInvalidPointer(rootLeft) then goto continue end
          if isNullOrNil(rootParent) then goto continue end
          if isInvalidPointer(rootParent) then goto continue end
          if not isBSSData(rootParent) then goto continue end
          local mapElement = rootLeft
          local visited = {}

          while readPointer(mapElement + GDDEFS.MAP_LELEM) ~= endmapAddr do
            if visited[mapElement] then goto continue end
            if isInvalidPointer(mapElement) then goto continue end

            visited[mapElement] = true
            mapElement = readPointer(mapElement + GDDEFS.MAP_LELEM)

            if isNullOrNil(mapElement) then goto continue end
          end

          visited = {}

          local walked = 0
          local validNames = 0
          local validFunctions = 0

          while isNotNullOrNil(mapElement) and mapElement ~= endmapAddr and walked < mapSize do
            if visited[mapElement] then goto continue end
            if isInvalidPointer(mapElement) then goto continue end

            visited[mapElement] = true
            walked = walked + 1

            local elementPtrBase = mapElement + alignOffset(0x4, GDDEFS.PTRSIZE)
            local elementColor = readInteger(mapElement)
            local elementRight = readPointer(elementPtrBase + GDDEFS.PTRSIZE * 0)
            local elementLeft = readPointer(elementPtrBase + GDDEFS.PTRSIZE * 1)
            local elementParent = readPointer(elementPtrBase + GDDEFS.PTRSIZE * 2)
            local nextElement = readPointer(elementPtrBase + GDDEFS.PTRSIZE * 3)
            local previousElement = readPointer(elementPtrBase + GDDEFS.PTRSIZE * 4)
            local nameAddr = readPointer(elementPtrBase + GDDEFS.PTRSIZE * 5)
            local funcAddr = readPointer(elementPtrBase + GDDEFS.PTRSIZE * 6)
            if elementColor > 1 then goto continue end
            if isNullOrNil(elementRight) then goto continue end
            if isInvalidPointer(elementRight) then goto continue end
            if isNullOrNil(elementLeft) then goto continue end
            if isInvalidPointer(elementLeft) then goto continue end
            if isNullOrNil(elementParent) then goto continue end
            if isInvalidPointer(elementParent) then goto continue end
            if isNullOrNil(nextElement) then goto continue end
            if isInvalidPointer(nextElement) then goto continue end
            if isNullOrNil(previousElement) then goto continue end
            if isInvalidPointer(previousElement) then goto continue end
            if isNullOrNil(nameAddr) then goto continue end
            if isInvalidPointer(nameAddr) then goto continue end
            if isNullOrNil(funcAddr) then goto continue end
            if isInvalidPointer(funcAddr) then goto continue end

            local name = getStringNameStr(nameAddr)
            if name and name ~= "" then validNames = validNames + 1 end

            if checkIfGDFunction(funcAddr) then validFunctions = validFunctions + 1 end

            mapElement = nextElement
          end

          if walked == 0 then goto continue end
          if validFunctions == 0 then goto continue end
          if validNames ~= walked then goto continue end
          if validFunctions ~= walked then goto continue end

          local score = 4

          score = score + math.min(validNames, 3)
          score = score + math.min(validFunctions * 2, 6)

          if walked == mapSize then score = score + 2 end

          table.insert(results, makeCandidate(candidateOffset, score,
          {
            mapSize = mapSize,
            mapSizeOffset = candidateOffset + GDDEFS.PTRSIZE * 2,
            mapSizeAddress = scriptAddr + candidateOffset + GDDEFS.PTRSIZE * 2,

            rootAddr = mapAddr,
            endAddr = endmapAddr,
            firstElement = rootLeft,

            keyOffset = alignOffset(0x4, GDDEFS.PTRSIZE) + GDDEFS.PTRSIZE * 5,
            valueOffset = alignOffset(0x4, GDDEFS.PTRSIZE) + GDDEFS.PTRSIZE * 6,

            validatedElements = walked,
            validatedNames = validNames,
            validatedFunctions = validFunctions,
          }))
        end

        ::continue::
      end

      return results

    end

  -- FUCN MAP END

  local function assumeSampleOffsets(sample)
    local nodeAddr = sample.nodeAddr

    if not assumedOffsets.SCRIPT_INSTANCE then
      assumeScriptInstanceOffset(nodeAddr)
    end

    sample = makeNodeSample(nodeAddr)

    if isNullOrNil(sample.scriptAddr) then return end

    assumeScriptNameOffset(sample.scriptAddr)

    if not assumedOffsets.SCRIPT_NAME then return end
    if GDDEFS.MONO then return end

    if GDDEFS.MAJOR_VER >= 4 then
      assumeVariantMapOffset(sample.scriptAddr)

      if assumedOffsets.VARIANT_MAP then
        assumeVariantVector(nodeAddr)
        assumeConstMapOffset(sample.scriptAddr)
      end

      assumeFuncMapOffset(sample.scriptAddr)

      return
    end

    assumeFuncMapOffset(sample.scriptAddr)

    if not assumedOffsets.FUNC_MAP then return end
    assumeVariantMapOffset(sample.scriptAddr)
    assumeConstMapOffset(sample.scriptAddr)

    if assumedOffsets.VARIANT_MAP then
      assumeVariantVector(nodeAddr)
    end

  end

  local function assumeNodeOffsetsDeep()
    clearAssumedOffsets()

    if not assumeChildrenOffset() then
      reportFailedOffsets()
      return false
    end

    assumeObjNameOffset()

    local rootNodes = getMainNodeTable()
    local nodeSamples = collectNodeSamples(rootNodes)

    local maxPasses = 4

    for pass = 1, maxPasses do
      local before = offsetCount()

      for _, sample in ipairs(nodeSamples) do
        assumeSampleOffsets(sample)

        if allOffsetsResolved() then
          reportFailedOffsets()
          return true
        end
      end

      local after = offsetCount()

      -- No milestone was discovered during this pass.
      if after == before then break end
    end

    reportFailedOffsets()
    return allOffsetsResolved()
  end

  -- EVIDENCE ORCHESTRATION START
    -- refactored with ai

    local function recordCandidates(category, candidates, sample)
      for _, candidate in ipairs(candidates or {}) do
        recordCandidate(category, candidate, sample)
      end
    end

    local function collectUniqueScriptSamples(nodeSamples)
      local samples = {}
      local seenScripts = {}

      enrichScriptSamples(nodeSamples)

      for _, sample in ipairs(nodeSamples) do
        if isNullOrNil(sample.scriptAddr) then goto continue end
        if seenScripts[sample.scriptAddr] then goto continue end

        seenScripts[sample.scriptAddr] = true
        sample.duplicateScript = false

        table.insert(samples, sample)

        if #samples >= RESOLVER_CONFIG.maxUniqueScripts then break end

        ::continue::
      end

      return samples
    end

    local function resolveStrongNodeOffsets()
      if not assumeChildrenOffset() then return false end
      if not assumeObjNameOffset() then return false end
      return true
    end

    local function resolveStrongScriptInstanceOffsets(nodeSamples)
      for _, sample in ipairs(nodeSamples) do
        if assumeScriptInstanceOffset(sample.nodeAddr) then
          return true
        end
      end

      return false
    end

    local function validateProbedSample(sample)
      if isNullOrNil(sample.scriptAddr) then return false end
      if isNullOrNil(sample.scriptInst) then return false end

      if assumedOffsets.SCRIPT_NAME then
        local stringAddr = readPointer(sample.scriptAddr + assumedOffsets.SCRIPT_NAME)
        if isNullOrNil(stringAddr) then return false end
        if readUTFString(stringAddr, 4) ~= "res:" then return false end
      end

      if assumedOffsets.VARIANT_VECTOR then
        local vectorAddr = readPointer( sample.scriptInst + assumedOffsets.VARIANT_VECTOR )
        if isNullOrNil(vectorAddr) then return false end

        local vectorSize = readInteger( vectorAddr - assumedOffsets.VARIANT_VECTOR_SIZE )
        if isNullOrNil(vectorSize) then return false end

        if vectorSize > 2000 then return false end
        if not validateVariantStride(vectorAddr, vectorSize) then return false end
      end

      return true
    end

    local function verifyProbedOffsets(holdoutSamples)
      local passed = 0
      local tested = 0

      for _, sample in ipairs(holdoutSamples) do
        if isNullOrNil(sample.scriptAddr) then goto continue end

        tested = tested + 1

        if validateProbedSample(sample) then passed = passed + 1 end

        ::continue::
      end

      if tested == 0 then
        sendDebugMessage("[PROBE] No holdout samples available")
        return false
      end

      local ratio = passed / tested

      sendDebugMessage( ("[PROBE] Holdout verification: %d/%d, %.2f"):format( passed, tested, ratio ) )

      return ratio >= 0.75
    end

    local function probeAndCommitCategory( category, assumedName, samples, probeFunction, options )
      for _, sample in ipairs(samples) do
        if isNullOrNil(sample.scriptAddr) then goto continue end

        local candidates = probeFunction(sample)
        -- recordCandidates(category, candidates, sample)
        recordFilteredCandidates(category, candidates, sample)

        ::continue::
      end

      local best = chooseBestCandidate(category, options)

      if not best then return nil end

      assumedOffsets[assumedName] = best.offset

      sendDebugMessage( "[PROBE] " .. assumedName .. " = 0x" .. numtohexstr(best.offset) )

      return best
    end

    local function probeVariantPairCandidates(sample)
      local results = {}
      local mapCandidates = probeVariantMapCandidates(sample)

      for _, mapCandidate in ipairs(mapCandidates) do
        local vectorCandidates = probeVariantVectorCandidates(sample, mapCandidate)

        for _, vectorCandidate in ipairs(vectorCandidates) do

          table.insert(results, makeCandidate(
            mapCandidate.offset,
            (mapCandidate.score or 0) + (vectorCandidate.score or 0) + 5,
            {
              mapOffset = mapCandidate.offset,
              mapSize = mapCandidate.mapSize,
              mapSizeOffset = mapCandidate.mapSizeOffset,

              vectorOffset = vectorCandidate.offset,
              vectorSizeOffset = vectorCandidate.sizeOffset,
              vectorSize = vectorCandidate.vectorSize,
            }
          ))

        end
      end

      return results
    end

    local function probeAndCommitVariantPair(samples)
      for _, sample in ipairs(samples) do
        if isNullOrNil(sample.scriptAddr) then goto continue end
        if isNullOrNil(sample.scriptInst) then goto continue end

        local candidates = probeVariantPairCandidates(sample)
        recordCandidates("VARIANT_PAIR", candidates, sample)

        ::continue::
      end

      local best = chooseBestCandidate("VARIANT_PAIR")

      if not best then return false end

      assumedOffsets.VARIANT_MAP = best.mapOffset
      assumedOffsets.VARIANT_VECTOR = best.vectorOffset
      assumedOffsets.VARIANT_VECTOR_SIZE = best.vectorSizeOffset

      sendDebugMessage( "[PROBE] VARIANT_MAP = 0x" .. numtohexstr(best.mapOffset) .. ", VARIANT_VECTOR = 0x" .. numtohexstr(best.vectorOffset) )

      return true
    end

    local function probeNodeOffsetsMilestone()
      clearEvidence()
      clearAssumedOffsets()

      if not resolveStrongNodeOffsets() then
        reportFailedOffsets()
        return false
      end

      local rootNodes = getMainNodeTable()
      local nodeSamples = collectNodeSamples(rootNodes)

      if #nodeSamples == 0 then
        reportFailedOffsets()
        return false
      end

      if not resolveStrongScriptInstanceOffsets(nodeSamples) then
        reportFailedOffsets()
        return false
      end

      local scriptSamples = collectUniqueScriptSamples(nodeSamples)
      local trainingSamples, holdoutSamples = splitSamples(scriptSamples)

      local scriptName = probeAndCommitCategory( "SCRIPT_NAME", "SCRIPT_NAME", trainingSamples, probeScriptNameCandidates, { requiredHits=2, requiredScripts=2, requiredScore=8, } )

      if not scriptName then
        reportFailedOffsets()
        return false
      end

      if GDDEFS.MONO then
        return true
      end

      if GDDEFS.MAJOR_VER >= 4 then
        probeAndCommitVariantPair(trainingSamples)

        if assumedOffsets.VARIANT_MAP then
          probeAndCommitCategory( "CONST_MAP", "CONST_MAP", trainingSamples, probeConstMapCandidates )
        end

        probeAndCommitCategory( "FUNC_MAP", "FUNC_MAP", trainingSamples, probeFuncMapCandidates )
      else
        probeAndCommitCategory( "FUNC_MAP", "FUNC_MAP", trainingSamples, probeFuncMapCandidates )

        if assumedOffsets.FUNC_MAP then
          probeAndCommitVariantPair(trainingSamples)
        end

        if assumedOffsets.FUNC_MAP then
          probeAndCommitCategory( "CONST_MAP", "CONST_MAP", trainingSamples, probeConstMapCandidates )
        end
      end

      local verified = verifyProbedOffsets(holdoutSamples)

      reportFailedOffsets()
      return verified
    end

  -- EVIDENCE ORCHESTRATION END

    local function printAssumedOffsets()
      assumeNodeOffsetsDeep()

      printCurrentOffsets()

      return assumedOffsets
    end

    local function printProbedOffsets()
      probeNodeOffsetsMilestone()

      printCurrentOffsets()

      return assumedOffsets
    end

  return
    {
      assume = printAssumedOffsets,
      probe = printProbedOffsets,
    }
end

return Module -- exporting

--[[

4.x
hashmap/hashset: 4 pointers, capacity, size
	HashMap<StringName, MemberInfo> member_indices; // Includes member info of all base GDScript classes.
	HashSet<StringName> members; // Only members of the current class.

	// Only static variables of the current class.
	HashMap<StringName, MemberInfo> static_variables_indices;
	Vector<Variant> static_variables; // Static variable values.

	HashMap<StringName, Variant> constants;
	HashMap<StringName, GDScriptFunction *> member_functions;

	HashMap<StringName, Ref<GDScript>> subclasses;
	HashMap<StringName, MethodInfo> _signals;

	struct MemberInfo
  {
		int index = 0;
		StringName setter;
		StringName getter;
		GDScriptDataType data_type;
		PropertyInfo property_info;
	};

  class GDScriptDataType
  {
    bool has_type = false;
    Variant::Type builtin_type = Variant::NIL;
    StringName native_type;
    Script *script_type = nullptr;
    Ref<Script> script_type_ref;
  }

  struct PropertyInfo
  {
    Variant::Type type = Variant::NIL;
    String name;
    StringName class_name; // For classes
    PropertyHint hint = PROPERTY_HINT_NONE;
    String hint_string;
    uint32_t usage = PROPERTY_USAGE_DEFAULT;
  }

3.x
	Set<StringName> members; //members are just indices to the instanced script.
	
  Map<StringName, Variant> constants;
	Map<StringName, GDScriptFunction *> member_functions;
	Map<StringName, MemberInfo> member_indices; //members are just indices to the instanced script.
	
  Map<StringName, Ref<GDScript> > subclasses;
	Map<StringName, Vector<StringName> > _signals;

]]