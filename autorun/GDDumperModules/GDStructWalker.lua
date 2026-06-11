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
  -- TODO: report changed offsets
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

  if GDDEFS.MAJOR_VER >= 4 then
    if GDDEFS.MINOR_VER <= 4 then
      GDDEFS.GET_TYPE_INDX = 8
    elseif GDDEFS.MINOR_VER == 5 then
      GDDEFS.GET_TYPE_INDX = 9
    elseif GDDEFS.MINOR_VER >= 6 then
      GDDEFS.GET_TYPE_INDX = 10
    end
  else
    GDDEFS.GET_TYPE_INDX = 6
  end

  local viewport = readPointer("ptVP")
  if isNullOrNil(viewport) then 
    if tryRegSceneTree() and setSTtoVPoffset() then registerSymbol('ptVP', '[pSceneTree]+oSTtoVP', false) else
      return
    end
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
      if HMFuncSNameAddr ~= funcResStringNameAddr then return false end -- should be fine?
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

  -- HELPERS END


  local function assumeChildrenOffset()
    local CHILDREN;
    local childrenSize, childrenAddr, nodeAddr;
    local found = false

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

  local function assumeScriptInstanceOffset(nodeAddr)
    if assumedOffsets.SCRIPT_INSTANCE then return assumedOffsets.SCRIPT_INSTANCE end
    if isNullOrNil(nodeAddr) then return end

    local SCRIPT_INSTANCE, scriptInst, NODE_REF, SCRIPT_REF;
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
        SCRIPT_REF = NODE_REF + GDDEFS.PTRSIZE
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
        VARIANT_MAP = VARIANT_MAP + GDDEFS.PTRSIZE * 2
        VARIANT_MAP_SIZE = VARIANT_MAP + GDDEFS.PTRSIZE * 4 + 0x4
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

  local function assumeFuncMapOffset(scriptAddr)
    if assumedOffsets.FUNC_MAP then return assumedOffsets.FUNC_MAP end
    local FUNC_MAP
    local found = false

    if GDDEFS.MAJOR_VER >= 4 then

      local startFrom = assumedOffsets.SCRIPT_NAME + GDDEFS.PTRSIZE*3
      local limit = 0x200

      if assumedOffsets.VARIANT_MAP then
        startFrom = assumedOffsets.VARIANT_MAP + GDDEFS.PTRSIZE*4
        limit = 0x100
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

  local function assumeGDScriptOffsets(nodeAddr)
    if not assumedOffsets.SCRIPT_REF then return end

    local scriptAddr, nodeRefAddr;

    local scriptInstanceAddr = readPointer( nodeAddr + assumedOffsets.SCRIPT_INSTANCE )
    local scriptAddr = readPointer( scriptInstanceAddr + assumedOffsets.SCRIPT_REF ) -- gdscript ref is after the owner (node)

    if isNullOrNil(scriptAddr) then return end
    if not assumeScriptNameOffset(scriptAddr) then return end
    if GDDEFS.MONO then
      sendDebugMessage('Target uses mono, skipping map offsets')
      return
    end
    
    assumeFuncMapOffset(scriptAddr)
    assumeVariantMapOffset(scriptAddr) -- TODO memberInfo name 
    assumeConstMapOffset(scriptAddr)

  end

  local function assumeNodeOffsets()

    local childrennoffset = assumeChildrenOffset()
    assumeObjNameOffset()

    -- only root offsets available
    if isNullOrNil(childrennoffset) then return end

    local nodeTable = getMainNodeTable()

    for _, value in ipairs(nodeTable) do
      if not assumeScriptInstanceOffset(value) then goto continue end

      assumeGDScriptOffsets(value)

      assumeVariantVector(value)

      ::continue::
    end

    reportFailedOffsets()

  end

  local function printAssumedOffsets()
    assumeNodeOffsets()
    print
    (
      ("CHILDREN: 0x%X\nOBJ_STRING_NAME: 0x%X\nSCRIPT_INSTANCE: 0x%X\nSCRIPT_REF: 0x%X\nVARIANT_VECTOR: 0x%X\nVARIANT_VECTOR_SIZE: 0x%X\nSCRIPT_NAME: 0x%X\nFUNC_MAP: 0x%X\nCONST_MAP: 0x%X\nVARIANT_MAP: 0x%X"):format(
      (assumedOffsets.CHILDREN or 0x0),
      (assumedOffsets.OBJ_STRING_NAME or 0x0),
      (assumedOffsets.SCRIPT_INSTANCE or 0x0),
      (assumedOffsets.SCRIPT_REF or 0x0),
      (assumedOffsets.VARIANT_VECTOR or 0x0),
      (assumedOffsets.VARIANT_VECTOR_SIZE or 0x0),
      (assumedOffsets.SCRIPT_NAME or 0x0),
      (assumedOffsets.FUNC_MAP or 0x0),
      (assumedOffsets.CONST_MAP or 0x0),
      (assumedOffsets.VARIANT_MAP or 0x0)
      )
    )
  end

  return printAssumedOffsets
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