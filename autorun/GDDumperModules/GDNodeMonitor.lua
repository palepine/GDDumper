local Module = {}
-- the implementations here trade readability/SoC for a potential performance boost, find the old commented out version below

function Module.install(contextTable)

  -- todo: watch visited dictionaries/arrays?
  local readUTFString = contextTable.readUTFString
  local getGDTypeEnumFromName = contextTable.getGDTypeEnumFromName
  local getMainModuleInfo = contextTable.getMainModuleInfo
  local getSectionBounds = contextTable.getSectionBounds
  local getNodeNameFromGDScript = contextTable.getNodeNameFromGDScript

  local GDDEFS = contextTable.GDDEFS
  -- to avoid table access overhead
  local SCRIPT_INSTANCE = GDDEFS.GDSCRIPTINSTANCE
  local SCRIPTREF = GDDEFS.GDSCRIPT_REF
  local GDSCRIPTNAME = GDDEFS.GDSCRIPTNAME
  local VARIANT_VECTOR = GDDEFS.VAR_VECTOR
  local CHILDREN = GDDEFS.CHILDREN
  local CHILDREN_SIZE = GDDEFS.CHILDREN_SIZE
  local SIZE_VECTOR = GDDEFS.SIZE_VECTOR
  
  local DICT_LIST = GDDEFS.DICT_LIST
  local DICT_HEAD = GDDEFS.DICT_HEAD
  local DICTELEM_VALTYPE = GDDEFS.DICTELEM_VALTYPE
  local DICTELEM_PAIR_NEXT = GDDEFS.DICTELEM_PAIR_NEXT

  local USES_DOUBLE_T = GDDEFS.SIZE_VECTOR
  local variantSize = GDDEFS.USES_DOUBLE_REALT and 0x28 or 0x18

  local eOBJECT = getGDTypeEnumFromName('OBJECT')
  local eDICTIONARY = getGDTypeEnumFromName('DICTIONARY')
  local eARRAY = getGDTypeEnumFromName('ARRAY')
  local eCSScript = GDDEFS.SCRIPT_TYPES["CS"]

  local MONOUSED = GDDEFS.MONO
  local MAJORVER = GDDEFS.MAJOR_VER
  local MINORVER = GDDEFS.MINOR_VER
  local PTRSIZE = GDDEFS.PTRSIZE
  local GET_TYPE_OFFSET = GDDEFS.GET_TYPE_INDX * PTRSIZE

  local DICT_SIZE = GDDEFS.DICT_SIZE
  local ARRAY_TOVECTOR = GDDEFS.ARRAY_TOVECTOR

  local MAIN_MODULE_INFO = getMainModuleInfo()
  local TEXT_SECTION_INFO = getSectionBounds(".text")

  -- Node monitor helper implementations
    local function isNullOrNil(toCheck)
      return toCheck == nil or toCheck == 0
    end

    local function isNotNullOrNil(toCheck)
      return toCheck ~= nil and toCheck ~= 0
    end

    local function isInsideSectionRange(addr, sectionInfo)
      if addr == nil or addr == 0 then return false end
      if addr > sectionInfo.startAddress and sectionInfo.endAddress > addr then return true end
    end

    local function isVtable( VTAddr )
      if VTAddr == nil or VTAddr == 0 then return false end

      if MAIN_MODULE_INFO.moduleStart < VTAddr and VTAddr < MAIN_MODULE_INFO.moduleEnd then
        local pmethod = readPointer(VTAddr) -- just check the first
        if isInsideSectionRange( pmethod, TEXT_SECTION_INFO ) then return true end
        return false
      else
        return false
      end
    end

    local function getVtable(addr)
      return readPointer(addr)
    end

    local function checkChildArray( childArray, size )
      if isNullOrNil(size) then return false end -- if no children, we don't need it
      if isNullOrNil(childArray) then return false end
      local childElem = readPointer(childArray)
      if isNullOrNil(childElem) or not isVtable( getVtable(childElem) ) then return false end  -- check the 0th object for vtable
      return true
    end

    local function checkIfCSScript( scriptNameAddr )

      if isNullOrNil(scriptNameAddr) then return 0 end

      local gdScriptName = readUTFString(scriptNameAddr) -- todo: anything more efficient?
      if  (gdScriptName):sub(-3) == '.cs' then return 2 end
      return 0
    end

    local function unregisterNodes()
      if (not GD_REGISTERED_NODES) or next(GD_REGISTERED_NODES) == nil then return; end
      for _, k in ipairs(GD_REGISTERED_NODES) do unregisterSymbol(k) end
      for _, k in ipairs(GD_REGISTERED_NODES_ABS) do unregisterSymbol(k) end
      GD_REGISTERED_NODES = {}
      GD_REGISTERED_NODES_ABS = {}
    end

    local function registerDumpedNodes()
      if (not GD_DUMP_MONITOR_NODES) or next(GD_DUMP_MONITOR_NODES) == nil then return; end
      unregisterNodes() -- unregister the current & freed nodes
      for k, nodeAddr in pairs(GD_DUMP_MONITOR_NODES) do
        table.insert(GD_REGISTERED_NODES, k)
        registerSymbol(k, nodeAddr, true)
      end
      for k, nodeAddr in pairs(GD_DUMP_MONITOR_NODES_ABS) do
        table.insert(GD_REGISTERED_NODES_ABS, k)
        registerSymbol(k, nodeAddr, true)
      end
    end

    local function getRootNodeTable()
      local viewport = readPointer("ptVP")
      if isNullOrNil(viewport) then getCurrentThreadObject().terminate() end
      
      local childrenAddr = readPointer( (viewport or 0) + CHILDREN)
      if isNullOrNil(childrenAddr) then getCurrentThreadObject().terminate() end

      local childrenSize;
      if GDDEFS.MAJOR_VER >= 4 then
        childrenSize = readInteger( viewport + CHILDREN - CHILDREN_SIZE)
      else
        childrenSize = readInteger( childrenAddr - CHILDREN_SIZE )
      end

      if isNullOrNil(childrenSize) then getCurrentThreadObject().terminate() end

      local nodeTable = {}

      for i = 0, (childrenSize - 1) do
        local nodeAddr = readPointer(childrenAddr + i * PTRSIZE)
        if isNotNullOrNil(nodeAddr) then
          table.insert(nodeTable, nodeAddr)  
        end
      end
      return nodeTable
    end



  -- Node monitor helper END

  -- FORWARD DECLARATIONS START

    local processNodeForNodes
    local iterateDictionaryForNodes
    local iterateVecVarForNodes
    local nodeMonitorService

  -- FORWARD DECLARATIONS END

  -- Monitor API
    local monitor =
      {
        MonitorThread = nil,
        CD = nil,
        runCounter = nil,
        lastRunDelta = nil,
        lastNodeCount = nil,
        currNodeCount = nil,
      }

      function monitor:init()
        self.CD = 550
        self.runCounter = -1
        self.lastRunDelta = 0
        self.lastNodeCount = 0
        self.currNodeCount = 0
        self.runBudget = 45*1000
        if self.MonitorThread then return end
        self.MonitorThread = createThread(nodeMonitorService)
      end

      function monitor:setCD(newMS)
        if isNullOrNil(newMS) or type(newMS) ~= "number" or number < 0 then error('cooldown must be valid') end
        self.CD = newMS
      end

      function monitor:getCD()
        return self.CD
      end

      function monitor:profile()
        print
        (
          "Runs: " .. (self.runCounter or -1)
          ..' Delta: ' .. (self.lastRunDelta - self.CD or -1)
          .. ' ms (raw ' .. (self.lastRunDelta or -1) .. ')'
          .. ' Nodes met: ' .. (self.lastNodeCount or -1)
        )
      end

      function monitor:startRun()
        self.runCounter = self.runCounter+1
        self.currNodeCount = 0
      end

      function monitor:endRun(runDelta)
        self.lastRunDelta = runDelta
        self.lastNodeCount = self.currNodeCount
      end

      function monitor:nodeCountInc()
        self.currNodeCount = self.currNodeCount+1
      end

      function monitor:suspend()
        self.MonitorThread.suspend()
      end

      function monitor:resume()
        self.MonitorThread.resume()
      end

  -- TYPE HANDLERS

    local function handleDictionaryForNodes(dictAddr, dumpContext)
      if isNullOrNil(dictAddr) or dumpContext:shouldStop() then return end
      local dictSize = readInteger( dictAddr + DICT_SIZE)
      if isNotNullOrNil(dictSize) then
        iterateDictionaryForNodes( dictAddr, dictSize, dumpContext )
      end
    end

    local function handleArrayForNodes(arrAddr, dumpContext)
      if isNullOrNil(arrAddr) or dumpContext:shouldStop() then return end

      local arrVectorAddr = readPointer( arrAddr + ARRAY_TOVECTOR )
      if isNullOrNil(arrVectorAddr) then return; end
      iterateVecVarForNodes( arrVectorAddr, dumpContext )
    end

    local function handleObjectForNodes( objAddr, dumpContext)
      if dumpContext:shouldStop() then return end
      processNodeForNodes( objAddr, dumpContext )
    end

  -- ITERATORS

    function iterateVecVarForNodes(vector, dumpContext)
      local vectorSize = readInteger( vector - SIZE_VECTOR )
      if isNullOrNil(vectorSize) then return; end

      for variantIndex = 0, vectorSize - 1 do
        local variantType = readInteger( vector + variantSize * variantIndex )
        local offsetToValue = variantSize*variantIndex + 0x8

        if variantType == eOBJECT then
          offsetToValue = variantSize*variantIndex + 0x10
          local objAddr = readPointer( vector + offsetToValue )

          if MAJORVER <= 3 then
            -- for references
            if not isVtable( getVtable( objAddr ) ) then
              -- shift once w/o validation, check checkObjectOffset for context
              objAddr = readPointer( readPointer( vector + offsetToValue - PTRSIZE ) )
            end
          end

          if isNotNullOrNil(objAddr) then
            handleObjectForNodes( objAddr, dumpContext )
          end

        elseif variantType == eDICTIONARY then
          local dictAddr = readPointer( vector + offsetToValue )
          handleDictionaryForNodes( dictAddr, dumpContext )
        elseif variantType == eARRAY then
          local arrAddr = readPointer( vector + offsetToValue )
          handleArrayForNodes( arrAddr, dumpContext )
        end

      end
    end

    local function iterateNodeChildrenForNodes(childrenAddr, size, dumpContext)
      if dumpContext:shouldStop() then return end
      for i = 0, (size - 1) do
        local childAddr = readPointer(childrenAddr + (i * PTRSIZE))
        processNodeForNodes(childAddr, dumpContext)
      end
    end

    function processNodeForNodes(nodeAddr, dumpContext)
      if dumpContext:shouldStop() then return end
      if isNullOrNil(nodeAddr) then return false end

      -- parse node
      local ok,
            scriptInstanceAddr,
            vectorAddr,
            scriptAddr,
            gdScriptNameAddr,
            childrenAddr,
            size = dumpContext:VisitNode(nodeAddr)
      if not ok then return end

      if MONOUSED and checkIfCSScript( gdScriptNameAddr ) == eCSScript then
      elseif vectorAddr then
        iterateVecVarForNodes( vectorAddr, dumpContext )
      end

      if checkChildArray(childrenAddr, size) then
        iterateNodeChildrenForNodes(childrenAddr, size, dumpContext)
      end
    end

    function iterateDictionaryForNodes(dictAddr, dictSize, dumpContext)
      if isNullOrNil(dictAddr) or dumpContext:shouldStop() then return end

      local dictRoot = dictAddr
      if GDDEFS.MAJOR_VER <= 3 then
        dictRoot = readPointer( dictAddr + DICT_LIST)
      end

      local mapElement = readPointer( (dictRoot or 0) + DICT_HEAD)
      if isNullOrNil(mapElement) then return end

      repeat
        local variantType = readInteger( mapElement + DICTELEM_VALTYPE)
        local offsetToValue = DICTELEM_VALTYPE + 0x8

        if variantType == eOBJECT then
          offsetToValue = offsetToValue + 0x8
          local objAddr = readPointer( mapElement + offsetToValue )

          if MAJORVER <= 3 then
            -- for references
            if not isVtable( getVtable( objAddr ) ) then
              -- shift once w/o validation, check checkObjectOffset for context
              objAddr = readPointer( readPointer( mapElement + offsetToValue - PTRSIZE ) )
            end
          end

          if isNotNullOrNil(objAddr) then
            handleObjectForNodes( objAddr, dumpContext )
          end

        elseif variantType == eDICTIONARY then
          local dictAddr = readPointer( mapElement + offsetToValue )
          handleDictionaryForNodes( dictAddr, dumpContext )

        elseif variantType == eARRAY then
          local arrAddr = readPointer( mapElement + offsetToValue )
          handleArrayForNodes( arrAddr, dumpContext )
        end

        -- getDictElemPairNext
        if MAJORVER >= 4 then
          mapElement = readPointer(mapElement) or 0 -- at 0x0
        else
          mapElement = readPointer( mapElement + DICTELEM_PAIR_NEXT ) or 0
        end

      until (mapElement == 0)
    end

  -- Monitor Thread

    local function nodeMonitorThread(thr)
      thr.Name = "GD Monitor Thread"
      thr.freeOnTerminate(false) -- we do it ourselves
      local dumpContext =
        {
          startedAt = getTickCount(),
          dumped = {}, -- only nodes with GDScript
          visited = {}, -- every encountered node
          budgetMs = GDDEFS.Monitor.runBudget,
          thread = thr,
        }

      function dumpContext:VisitNode(addr)
        if isNullOrNil(addr) then return false end
        GDDEFS.Monitor:nodeCountInc() -- how many nodes we have seen
        if self.visited[addr] then return false end
        self.visited[addr] = true

        local scriptInstanceAddr = readPointer( addr + SCRIPT_INSTANCE ) or 0
        local vectorAddr = readPointer( scriptInstanceAddr + VARIANT_VECTOR )
        local scriptAddr = readPointer( scriptInstanceAddr + SCRIPTREF ) or 0
        local gdScriptNameAddr = readPointer( scriptAddr + GDSCRIPTNAME )

        local childrenAddr = readPointer( addr + CHILDREN )
        local size
        if MAJORVER >= 4 then
          size = readInteger( addr + CHILDREN - CHILDREN_SIZE )
        else
          size = readInteger( (childrenAddr or 0) - CHILDREN_SIZE ) or 0
        end

        if isNotNullOrNil(gdScriptNameAddr) then
          table.insert(self.dumped, addr)
        end

        return true, scriptInstanceAddr, vectorAddr, scriptAddr, gdScriptNameAddr, childrenAddr, size
      end

      function dumpContext:shouldStop()
        return self.thread.Terminated or (getTickCount() - self.startedAt) > self.budgetMs -- TODO: check every other time?
      end

      local function cloneArrayAsMap(tabl)
        local result = {} -- { name : addr }
        local resultAbs = {} -- { name : addr }
        for i, val in ipairs(tabl) do
          local scriptName, longName = getNodeNameFromGDScript(val, true)
          result[ scriptName or '' ] = val
          resultAbs[ longName or '' ] = val
        end
        return result, resultAbs
      end

      local mainNodeDict = getRootNodeTable() or {}

      for _, value in ipairs(mainNodeDict) do
        processNodeForNodes(value, dumpContext)
      end

      GD_DUMP_MONITOR_NODES, GD_DUMP_MONITOR_NODES_ABS = cloneArrayAsMap(dumpContext.dumped)
      registerDumpedNodes()
    end

    function nodeMonitorService(thr)
      thr.Name = "GD Node Monitor Service"
      GD_DUMP_MONITOR_NODES = {};
      GD_DUMP_MONITOR_NODES_ABS = {};
      GD_REGISTERED_NODES = {};
      GD_REGISTERED_NODES_ABS = {};

      while not thr.Terminated do
        GDDEFS.Monitor:startRun()
        local startedAt = getTickCount()
        local gd_currNodeMonitorThread = createThread(nodeMonitorThread)
        gd_currNodeMonitorThread.waitfor()
        gd_currNodeMonitorThread.terminate()
        gd_currNodeMonitorThread.destroy() -- free the thread...

        sleep( GDDEFS.Monitor:getCD() )
        GDDEFS.Monitor:endRun( getTickCount()-startedAt or 0 )

        if #enumModules() == 0 and not thr.Terminated then  -- if we aren't attached, kill this thread
          -- if gd_currNodeMonitorThread and not gd_currNodeMonitorThread.Terminated then gd_currNodeMonitorThread.terminate() end
          thr.terminate()
          return
        end

      end
    end

  return monitor
end

return Module -- exporting

-- OLD IMPLEMENTATION
--[[
  -- ///---///--///---///--///---///--///--///---///--///---///--///---///--/// VISITORS

    local NodeVisitor = {}

      function NodeVisitor.recurseDictionary(dictPtr, dumpContext)
        iterateDictionaryForNodes(dictPtr, dumpContext)
      end

      function NodeVisitor.recurseArray(arrPtr, dumpContext)
        iterateArrayForNodes(arrPtr, dumpContext)
      end

      function NodeVisitor.visitObject(objPtr, dumpContext)
        local realPtr, bShifted = checkObjectOffset(objPtr)
        local nodeAddr = readPointer(realPtr)
        processNodeForNodes(nodeAddr, dumpContext)
      end
  -- ///---///--///---///--///---///--///--///---///--///---///--///---///--/// HELPERS
    -- for node search
    local function readVectorVariantEntry(variantVector, variantIndex, variantSize)
      local variantPtr, variantType = getVariantByIndex(variantVector, variantIndex, variantSize)

      return
      {
        index = variantIndex,
        typeId = variantType,
        typeName = getGDTypeName(variantType) or "UNKNOWNTYPE",
        variantPtr = variantPtr
      }
    end

    -- for node search
    local function readArrayValueEntry(arrVectorAddr, varIndex, variantArrSize)
      local variantPtr, variantType = getVariantByIndex(arrVectorAddr, varIndex, variantArrSize)

      return
      {
        index = varIndex,
        typeId = variantType,
        typeName = getGDTypeName(variantType) or "UNKNOWNTYPE",
        variantPtr = variantPtr
      }
    end

    -- for node search
    local function readDictionaryValueEntry(mapElement)
        local valueType = readInteger( (mapElement or 0) + GDDEFS.DICTELEM_VALTYPE)
        local offsetToValue = GDDEFS.DICTELEM_VALTYPE + getVariantValueOffset(valueType)
        return
        {
          typeId = valueType,
          typeName = getGDTypeName(valueType) or "UNKNOWNTYPE",
          variantPtr = getAddress( (mapElement or 0) + offsetToValue)
        }
    end

    local function unregisterNodes()
      if (not GD_REGISTERED_NODES) or next(GD_REGISTERED_NODES) == nil then return; end
      for _, k in ipairs(GD_REGISTERED_NODES) do unregisterSymbol(k) end
      for _, k in ipairs(GD_REGISTERED_NODES_ABS) do unregisterSymbol(k) end
      GD_REGISTERED_NODES = {}
      GD_REGISTERED_NODES_ABS = {}
    end

    local function registerDumpedNodes()
      if (not GD_DUMP_MONITOR_NODES) or next(GD_DUMP_MONITOR_NODES) == nil then return; end
      unregisterNodes() -- unregister the current & freed nodes
      for k, nodeAddr in pairs(GD_DUMP_MONITOR_NODES) do
        table.insert(GD_REGISTERED_NODES, k)
        registerSymbol(k, nodeAddr, true)
      end
      -- 2 linear loops to avoid potentially expensive getName operations
      for k, nodeAddr in pairs(GD_DUMP_MONITOR_NODES_ABS) do
        table.insert(GD_REGISTERED_NODES_ABS, k)
        registerSymbol(k, nodeAddr, true)
      end
    end

    function checkForVectorVariant(nodeAddr)
      if nodeAddr == nil then return false end

      local scriptInstance = readPointer(nodeAddr + GDDEFS.GDSCRIPTINSTANCE)
      if isNullOrNil(scriptInstance) or not isVtable( getVtable(scriptInstance) ) then return false end

      local vector = readPointer(scriptInstance + GDDEFS.VAR_VECTOR)
      if isNullOrNil(vector) then return false end
      -- will sufffice
      return true
    end


  -- ///---///--///---///--///---///--///--///---///--///---///--///---///--/// VISITORS

    local NodeVisitor = {}

      function NodeVisitor.recurseDictionary(dictPtr, dumpContext)
        iterateDictionaryForNodes(dictPtr, dumpContext)
      end

      function NodeVisitor.recurseArray(arrPtr, dumpContext)
        iterateArrayForNodes(arrPtr, dumpContext)
      end

      function NodeVisitor.visitObject(objPtr, dumpContext)
        local realPtr, bShifted = checkObjectOffset(objPtr)
        local nodeAddr = readPointer(realPtr)
        processNodeForNodes(nodeAddr, dumpContext)
      end

  -- ///---///--///---///--///---///--///--///---///--///---///--///---///--/// HANDLERS
    GDHandlers.NodeDiscoveryHandlers = {}

      GDHandlers.NodeDiscoveryHandlers.DICTIONARY = function(entry, visitor, dumpContext)
        if dumpContext:shouldStop() then return end
        local dictSize = getDictionarySizeFromVariantPtr(entry.variantPtr)
        if isNotNullOrNil(dictSize) then
          visitor.recurseDictionary(readPointer(entry.variantPtr), dumpContext)
        end
      end

      GDHandlers.NodeDiscoveryHandlers.ARRAY = function(entry, visitor, dumpContext)
        if dumpContext:shouldStop() then return end
        if not isArrayEmptyFromVariantPtr(entry.variantPtr) then
          visitor.recurseArray(readPointer(entry.variantPtr), dumpContext)
        end
      end

      GDHandlers.NodeDiscoveryHandlers.OBJECT = function(entry, visitor, dumpContext)
        if dumpContext:shouldStop() then return end
        visitor.visitObject(entry.variantPtr, dumpContext)
      end

      -- GDHandlers.NodeMetaHandlers = {}

      --   GDHandlers.NodeMetaHandlers.DICTIONARY = function(entry, visitor)
      --     local dictSize = getDictionarySizeFromVariantPtr(entry.variantPtr)
      --     if isNotNullOrNil(dictSize) then
      --       visitor.recurseDictionary(readPointer(entry.variantPtr))
      --     end
      --   end

      --   GDHandlers.NodeMetaHandlers.ARRAY = function(entry, visitor)
      --     if not isArrayEmptyFromVariantPtr(entry.variantPtr) then
      --       visitor.recurseArray(readPointer(entry.variantPtr))
      --     end
      --   end

      --   GDHandlers.NodeMetaHandlers.OBJECT = function(entry, visitor)
      --     visitor.visitObject(entry.variantPtr)
      --   end

  -- ///---///--///---///--///---///--///--///---///--///---///--///---///--/// MONITOR

    local function nodeMonitorThread(thr)
      thr.Name = "GD Monitor Thread"
      thr.freeOnTerminate(false) -- we do it ourselves
      local dumpContext =
        {
          startedAt = getTickCount(),
          dumped = {}, -- only nodes with GDScript
          visited = {}, -- every encountered node
          budgetMs = GDDEFS.Monitor.runBudget,
          thread = thr,
        }

      function dumpContext:tryVisitNode(addr)
        if addr == nil then return false end
        GDDEFS.Monitor:nodeCountInc() -- how many nodes we have seen
        if self.visited[addr] then return false end
        self.visited[addr] = true
        if checkForGDScript(addr) then
          table.insert(self.dumped, addr)
          local scriptName, absScriptPath = getNodeNameFromGDScript(addr, true)
          -- will (un)register twice, but early, potentially
          registerSymbol(absScriptPath, addr, true) -- register long symbol
          registerSymbol(scriptName, addr, true) -- register short name alias (might collide)
          table.insert(GD_REGISTERED_NODES_ABS, absScriptPath)
          table.insert(GD_REGISTERED_NODES, absScriptPath)
        end
        return true
      end

      function dumpContext:shouldStop()
        return self.thread.Terminated or (getTickCount() - self.startedAt) > self.budgetMs
      end

      local function cloneArrayAsMap(tabl)
        local result = {} -- { name : addr }
        local resultAbs = {} -- { name : addr }
        for i, val in ipairs(tabl) do
          local scriptName, longName = getNodeNameFromGDScript(val, true)
          result[ scriptName or '' ] = val
          resultAbs[ longName or '' ] = val
        end
        return result, resultAbs
      end

      local mainNodeDict = getMainNodeDict() or {}

      for _, value in pairs(mainNodeDict) do
        processNodeForNodes(value.PTR, dumpContext)
      end

      GD_DUMP_MONITOR_NODES, GD_DUMP_MONITOR_NODES_ABS = cloneArrayAsMap(dumpContext.dumped)
      registerDumpedNodes()
    end

    function nodeMonitorService(thr)
      thr.Name = "GD Node Monitor Service"
      GD_DUMP_MONITOR_NODES = {};
      GD_DUMP_MONITOR_NODES_ABS = {};
      GD_REGISTERED_NODES = {};
      GD_REGISTERED_NODES_ABS = {};

      while not thr.Terminated do
        
        GDDEFS.Monitor:startRun()

        local startedAt = getTickCount()
        local gd_currNodeMonitorThread = createThread(nodeMonitorThread)
        gd_currNodeMonitorThread.waitfor()
        gd_currNodeMonitorThread.terminate()
        gd_currNodeMonitorThread.destroy() -- free the thread...

        sleep( GDDEFS.Monitor:getCD() )
        GDDEFS.Monitor:endRun( getTickCount()-startedAt or 0 )

        if #enumModules() == 0 and not thr.Terminated then  -- if we aren't attached, kill this thread
          -- if gd_currNodeMonitorThread and not gd_currNodeMonitorThread.Terminated then gd_currNodeMonitorThread.terminate() end
          thr.terminate()
          return
        end

      end
    end

    function processNodeForNodes(nodeAddr, dumpContext)
      if not dumpContext:tryVisitNode(nodeAddr) then return end

      if GDDEFS.MONO and checkScriptType(nodeAddr) == GDDEFS.SCRIPT_TYPES["CS"] then
      elseif checkForVectorVariant(nodeAddr) then -- checkForGDScript(nodeAddr)
        iterateVecVarForNodes(nodeAddr, dumpContext)
      end

      if checkIfObjectWithChildren(nodeAddr) then
        iterateNodeChildrenForNodes(nodeAddr, dumpContext)
      end
    end

    function iterateNodeChildrenForNodes(baseAddress, dumpContext)

      local childrenAddr, childrenSize = getNodeChildrenInfo(baseAddress)
      if isNullOrNil(childrenSize) then return; end

      for i = 0, (childrenSize - 1) do
        if dumpContext:shouldStop() then return end
        local childAddr = readPointer(childrenAddr + (i * GDDEFS.PTRSIZE))
        processNodeForNodes(childAddr, dumpContext)
      end
    end


    --- iterates a dictionary for nodes
    ---@param dictAddr number
    function iterateDictionaryForNodes(dictAddr, dumpContext)
      if isNullOrNil(dictAddr) or dumpContext:shouldStop() then return end -- if (not (dictAddr > 0)) then return; end

      local dictRoot = dictAddr
      if GDDEFS.MAJOR_VER <= 3 then
        dictRoot = readPointer( (dictAddr or 0) + GDDEFS.DICT_LIST) -- for 3.x it's dictList actually
      end

      local dictSize = readInteger( (dictAddr or 0) + GDDEFS.DICT_SIZE)
      if isNullOrNil(dictSize) then return; end

      local mapElement = readPointer( (dictRoot or 0) + GDDEFS.DICT_HEAD)
      if isNullOrNil(mapElement) then return end

      local visitor = NodeVisitor

      repeat
        -- if dumpContext:shouldStop() then return end
        local entry = readDictionaryValueEntry(mapElement)
        local handler = GDHandlers.NodeDiscoveryHandlers[entry.typeName]
        if handler then
          handler(entry, visitor, dumpContext)
        end
        mapElement = getDictElemPairNext(mapElement)
      until (mapElement == 0)
    end

    --- iterates an array for nodes
    ---@param arrayAddr number
    function iterateArrayForNodes(arrayAddr, dumpContext)
      if isNullOrNil(arrayAddr) or dumpContext:shouldStop() then return end

      local arrVectorAddr = readPointer( (arrayAddr or 0) + GDDEFS.ARRAY_TOVECTOR)
      if isNullOrNil(arrVectorAddr) then return; end
      local arrVectorSize = readInteger( (arrVectorAddr or 0) - GDDEFS.SIZE_VECTOR)
      if isNullOrNil(arrVectorSize) then return; end

      local variantArrSize, ok = redefineVariantSizeByVector(arrVectorAddr, arrVectorSize)
      if not ok then return; end

      local visitor = NodeVisitor

      for varIndex = 0, arrVectorSize - 1 do
        -- if dumpContext:shouldStop() then return end
        local entry = readArrayValueEntry(arrVectorAddr, varIndex, variantArrSize)

        if isNotNullOrNil(entry.variantPtr) then
          local handler = GDHandlers.NodeDiscoveryHandlers[entry.typeName]
          if handler then
            handler(entry, visitor, dumpContext)
          end
        end
      end
    end

    --- iterate nodes only
    ---@param nodeAddr number
    function iterateVecVarForNodes(nodeAddr, dumpContext)
      if isNullOrNil(nodeAddr) or dumpContext:shouldStop() then return; end
      -- if not checkForGDScript(nodeAddr) then return; end -- should be checked at this point

      local variantVector, vectorSize = getNodeVariantVector(nodeAddr)
      if isNullOrNil(vectorSize) then return; end

      local variantSize, ok = redefineVariantSizeByVector(variantVector, vectorSize)
      if not ok then return; end

      local visitor = NodeVisitor

      for variantIndex = 0, vectorSize - 1 do
        -- if dumpContext:shouldStop() then return end
        local entry = readVectorVariantEntry(variantVector, variantIndex, variantSize)
        local handler = GDHandlers.NodeDiscoveryHandlers[entry.typeName]
        if handler then
          handler(entry, visitor, dumpContext)
        end
      end
    end


]]