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
-- the implementations here trade readability/SoC for a potential performance boost (~6 times)

--[[
https://antumce.github.io/CE_LDoc/classes/MultiReadExclusiveWriteSynchronizer.html
https://antumce.github.io/CE_LDoc/classes/Event.html
https://antumce.github.io/CE_LDoc/classes/CriticalSection.html
]]

function Module.install(GDD)

  local readUTFString = GDD.Strings.readUTFString
  local getGDTypeEnumFromName = GDD.Types.getGDTypeEnumFromName
  local getMainModuleInfo = GDD.Memory.getMainModuleInfo
  local getSectionBounds = GDD.Memory.getSectionBounds
  local gd_recompileScript = GDD.API.gd_recompileScript
  local gd_revertScript = GDD.API.gd_revertScript
  local gd_getFunctionFromNode = GDD.API.gd_getFunctionFromNode
  local gd_patchFunction = GDD.API.gd_patchFunction
  local gd_nopFunction = GDD.API.gd_nopFunction
  local validatePatchOpcodes = GDD.Patching.validateOpcodes

  local GDDEFS = GDD.Config.Defs
  local RUNTIME = GDD.Runtime
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
  local DICTELEM_VALUE_VARIANT = GDDEFS.DICTELEM_VALUE_VARIANT
  local DICTELEM_PAIR_NEXT = GDDEFS.DICTELEM_PAIR_NEXT

  local variantSize = GDDEFS.USES_DOUBLE_REALT and 0x28 or 0x18
  -- GDDEFS.SIZEOF_VARIANT = variantSize

  local BUDGET_CHECK_MASK = 0x3F -- 63 to check every 64 iteration
  local VISIT_REJECTED = 1
  local VISIT_COMPLETE = 2

  local eOBJECT = getGDTypeEnumFromName('OBJECT')
  local eDICTIONARY = getGDTypeEnumFromName('DICTIONARY')
  local eARRAY = getGDTypeEnumFromName('ARRAY')
  local eCSScript = GDDEFS.SCRIPT_TYPES["CS"]

  local MONOUSED = GDDEFS.MONO
  local PTRSIZE = GDDEFS.PTRSIZE

  local DICT_SIZE = GDDEFS.DICT_SIZE
  local ARRAY_TOVECTOR = GDDEFS.ARRAY_TOVECTOR

  local MAIN_MODULE_INFO = getMainModuleInfo()
  local TEXT_SECTION_INFO = getSectionBounds(".text")
  local ATTACHED_PROCESS_ID = getOpenedProcessID()

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

    local function checkChildArray( childArray, size )
      if size == nil or size <= 0 then return false end -- if no children, we don't need it
      if childArray == nil or childArray == 0 then return false end
      local childElem = readPointer(childArray)
      if childElem == nil or childElem == 0 or not isVtable( readPointer(childElem) ) then return false end  -- check the 0th object for vtable
      return true
    end

    -- select version handlers
    local MonitorImplementations = {}

    MonitorImplementations.modernHash = function()
      return
      {
        readChildrenInfo = function(nodeAddr)
          local childrenAddr = readPointer( nodeAddr + CHILDREN )
          if childrenAddr == nil or childrenAddr == 0 then return nil, nil end
          return childrenAddr, readInteger( nodeAddr + CHILDREN - CHILDREN_SIZE )
        end,

        readVariantObject = function(valueAddr)
          return readPointer(valueAddr)
        end,

        getDictionaryHead = function(dictAddr)
          return readPointer( dictAddr + DICT_HEAD )
        end,

        getNextDictionaryElement = function(mapElement)
          return readPointer(mapElement) or 0
        end,
      }
    end

    MonitorImplementations.legacyTree = function()
      return
      {
        readChildrenInfo = function(nodeAddr)
          local childrenAddr = readPointer( nodeAddr + CHILDREN )
          if childrenAddr == nil or childrenAddr == 0 then return nil, nil end
          local size = readInteger( childrenAddr - CHILDREN_SIZE ) or 0
          return childrenAddr, size
        end,

        readVariantObject = function(valueAddr)
          local objAddr = readPointer(valueAddr)
          if objAddr == nil or objAddr == 0 or not isVtable( readPointer(objAddr) ) then
            local wrapperAddr = readPointer( valueAddr - PTRSIZE )
            objAddr = wrapperAddr and readPointer(wrapperAddr) or nil
          end
          return objAddr
        end,

        getDictionaryHead = function(dictAddr)
          local dictRoot = readPointer( dictAddr + DICT_LIST )
          return readPointer( (dictRoot or 0) + DICT_HEAD )
        end,

        getNextDictionaryElement = function(mapElement)
          return readPointer( mapElement + DICTELEM_PAIR_NEXT ) or 0
        end,
      }
    end

    local monitorFamily = RUNTIME and RUNTIME.capabilities and RUNTIME.capabilities.containerFamily
    local implementationFactory = MonitorImplementations[monitorFamily]
    assert( implementationFactory, 'node monitor implementation is unavailable for ' .. tostring(monitorFamily) )

    local monitorImplementation = implementationFactory()
    local readChildrenInfo = monitorImplementation.readChildrenInfo
    local readVariantObject = monitorImplementation.readVariantObject
    local getDictionaryHead = monitorImplementation.getDictionaryHead
    local getNextDictionaryElement = monitorImplementation.getNextDictionaryElement

    -- ownershop management
    local serviceStateKey = "GDDumper.NodeMonitor.ServiceState"
    local serviceState = package.loaded[serviceStateKey]
    if type(serviceState) ~= "table" then
      serviceState = { generation = 0, registeredSymbols = {} }
      package.loaded[serviceStateKey] = serviceState
    end
    if type(serviceState.registeredSymbols) ~= "table" then serviceState.registeredSymbols = {} end
    serviceState.generation = serviceState.generation + 1
    local MONITOR_GENERATION = serviceState.generation

    local function checkIfCSScript( scriptNameAddr )

      if scriptNameAddr == nil or scriptNameAddr == 0 then return 0 end

      local gdScriptName = readUTFString(scriptNameAddr) -- todo: anything more efficient?
      if gdScriptName and gdScriptName:sub(-3) == '.cs' then return 2 end
      return 0
    end

    local registeredSymbols = serviceState.registeredSymbols

    local function unregisterNodes()
      for symbolName in pairs(registeredSymbols) do unregisterSymbol(symbolName) end
      for symbolName in pairs(registeredSymbols) do registeredSymbols[symbolName] = nil end
      GD_REGISTERED_NODES = {}
      GD_REGISTERED_NODES_ABS = {}
    end

    local function reconcileDumpedNodes(nodes, nodesAbs)
      local desiredSymbols = {}
      local registeredNames = {}
      local registeredAbsNames = {}

      for symbolName, nodeAddr in pairs(nodes) do
        desiredSymbols[symbolName] = nodeAddr
        registeredNames[#registeredNames + 1] = symbolName
      end
      for symbolName, nodeAddr in pairs(nodesAbs) do
        desiredSymbols[symbolName] = nodeAddr
        registeredAbsNames[#registeredAbsNames + 1] = symbolName
      end

      for symbolName, oldAddr in pairs(registeredSymbols) do
        if desiredSymbols[symbolName] ~= oldAddr then
          unregisterSymbol(symbolName)
          registeredSymbols[symbolName] = nil
        end
      end

      for symbolName, nodeAddr in pairs(desiredSymbols) do
        if registeredSymbols[symbolName] ~= nodeAddr then
          registerSymbol(symbolName, nodeAddr, true)
          registeredSymbols[symbolName] = nodeAddr
        end
      end

      GD_REGISTERED_NODES = registeredNames
      GD_REGISTERED_NODES_ABS = registeredAbsNames
    end

    local function getRootChildren()
      local viewport = readPointer("pRoot")
      if viewport == nil or viewport == 0 then return nil, 0 end

      local childrenAddr, childrenSize = readChildrenInfo(viewport)
      if childrenAddr == nil or childrenAddr == 0 or childrenSize == nil or childrenSize <= 0 then
        return nil, 0
      end

      return childrenAddr, childrenSize
    end

    local function isAttachedProcessCurrent()
      local processId = getOpenedProcessID()
      return serviceState.generation == MONITOR_GENERATION
        and processId ~= nil and processId ~= 0 and processId == ATTACHED_PROCESS_ID
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
        observers = {},
        nextObserverId = 0,
      }

      function monitor:init()
        self.CD = 500 -- previously 550
        self.runCounter = -1
        self.lastRunDelta = 0
        self.lastNodeCount = 0
        self.currNodeCount = 0
        self.runBudget = 45*1000
        if self.MonitorThread then return end
        self.MonitorThread = createThread(nodeMonitorService)
      end

      -- Observer
      function monitor:onRunFinished(name ,callback)
        if type(name) ~= 'string' or name == '' then error("subscriber name expected") end
        if type(callback) ~= "function" then error("callback expected") end

        local oldId = GDDEFS.NODE_SUBS[name]
        if oldId then self:offRunFinished(oldId) end

        self.nextObserverId = self.nextObserverId + 1
        local id = self.nextObserverId

        self.observers[id] = callback
        GDDEFS.NODE_SUBS[name] = id
        GDDEFS.NODE_SUBSID[id] = name

        return id
      end

      function monitor:offRunFinished(id)
        if not id then return false end

        self.observers[id] = nil

        local name = GDDEFS.NODE_SUBSID[id]
        if name then
          GDDEFS.NODE_SUBS[name] = nil
          GDDEFS.NODE_SUBSID[id] = nil
          return true
        end
        return false
      end

      function monitor:notifyRunFinished(event)
        for id, callback in pairs(self.observers) do
          local ok, err = pcall(callback, event)
          if not ok then print(("Monitor observer id(%s) failed: %s"):format(tostring(id), tostring(err))) end
        end
      end

      function monitor:setCD(newMS)
        if newMS == nil or newMS == 0 or type(newMS) ~= "number" or newMS < 0 then error('cooldown must be valid') end
        self.CD = newMS
      end

      function monitor:getCD()
        return self.CD
      end

      function monitor:profile()
        print
        (
          "Runs: " .. (self.runCounter or -1)
          ..' Delta: ' .. (self.lastRunDelta or -1)
          .. ' ms (wait ' .. (self.CD or -1) .. ')'
          .. ' Nodes met: ' .. (self.lastNodeCount or -1)
        )
      end

      function monitor:startRun()
        self.runCounter = self.runCounter+1
        self.currNodeCount = 0
      end

      function monitor:endRun(runDelta, nodeCount)
        self.lastRunDelta = runDelta
        self.currNodeCount = nodeCount or self.currNodeCount
        self.lastNodeCount = self.currNodeCount

        self:notifyRunFinished( { nodes = GD_DUMP_MONITOR_NODES or {}, nodesAbs = GD_DUMP_MONITOR_NODES_ABS or {}, } )
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
      if dictAddr == nil or dictAddr == 0 or dumpContext:shouldStop() then return end
      if not dumpContext:visitContainer(dictAddr) then return end
      local dictSize = readInteger( dictAddr + DICT_SIZE) -- TODO: size sanity checks?
      if dictSize ~= nil and dictSize > 0 then
        iterateDictionaryForNodes( dictAddr, dictSize, dumpContext )
      end
    end

    local function handleArrayForNodes(arrAddr, dumpContext)
      if arrAddr == nil or arrAddr == 0 or dumpContext:shouldStop() then return end
      if not dumpContext:visitContainer(arrAddr) then return end

      local arrVectorAddr = readPointer( arrAddr + ARRAY_TOVECTOR )
      if arrVectorAddr == nil or arrVectorAddr == 0 then return; end
      iterateVecVarForNodes( arrVectorAddr, dumpContext )
    end

    local function handleObjectForNodes( objAddr, dumpContext)
      if dumpContext:shouldStop() then return end
      processNodeForNodes( objAddr, dumpContext, false )
    end

  -- ITERATORS

    function iterateVecVarForNodes(vector, dumpContext)
      local vectorSize = readInteger( vector - SIZE_VECTOR )
      if vectorSize == nil or vectorSize <= 0 then return; end

      for variantIndex = 0, vectorSize - 1 do
        -- if dumpContext:shouldStopPeriodic(variantIndex) then return end
        if (variantIndex & BUDGET_CHECK_MASK) == 0 and dumpContext:shouldStop(true) then return end

        local variantType = readInteger( vector + variantSize * variantIndex )
        local offsetToValue = variantSize*variantIndex + 0x8

        if variantType == eOBJECT then
          offsetToValue = variantSize*variantIndex + 0x10
          local objAddr = readVariantObject(vector + offsetToValue)

          if objAddr ~= nil and objAddr ~= 0 then 
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
        if (i & BUDGET_CHECK_MASK) == 0 and dumpContext:shouldStop(true) then return end
        local childAddr = readPointer(childrenAddr + (i * PTRSIZE))
        processNodeForNodes(childAddr, dumpContext, true)
      end
    end

    function processNodeForNodes(nodeAddr, dumpContext, isTreeNode)
      if dumpContext:shouldStop() then return end
      if nodeAddr == nil or nodeAddr == 0 then return false end

      -- parse node
      local ok,
            scriptInstanceAddr,
            vectorAddr,
            scriptAddr,
            gdScriptNameAddr,
            childrenAddr,
            size = dumpContext:VisitNode(nodeAddr, isTreeNode)
      if not ok then return end

      if MONOUSED and checkIfCSScript( gdScriptNameAddr ) == eCSScript then
      elseif vectorAddr ~= nil and vectorAddr ~= 0 then
        iterateVecVarForNodes( vectorAddr, dumpContext )
      end

      if checkChildArray(childrenAddr, size) then
        iterateNodeChildrenForNodes(childrenAddr, size, dumpContext)
      end
    end

    function iterateDictionaryForNodes(dictAddr, dictSize, dumpContext)
      if dictAddr == nil or dictAddr == 0 or dumpContext:shouldStop() then return end

      local mapElement = getDictionaryHead(dictAddr)
      if mapElement == nil or mapElement == 0 then return end

      local iteration = 0
      while mapElement ~= 0 and iteration < dictSize do
        -- if dumpContext:shouldStopPeriodic(iteration) then return end
        -- inlined
        if (iteration & BUDGET_CHECK_MASK) == 0 and dumpContext:shouldStop(true) then return end

        local variantType = readInteger( mapElement + DICTELEM_VALUE_VARIANT)
        local offsetToValue = DICTELEM_VALUE_VARIANT + 0x8

        if variantType == eOBJECT then
          offsetToValue = offsetToValue + 0x8
          local objAddr = readVariantObject(mapElement + offsetToValue)

          if objAddr ~= nil and objAddr ~= 0 then
            handleObjectForNodes( objAddr, dumpContext )
          end

        elseif variantType == eDICTIONARY then
          local dictAddr = readPointer( mapElement + offsetToValue )
          handleDictionaryForNodes( dictAddr, dumpContext )

        elseif variantType == eARRAY then
          local arrAddr = readPointer( mapElement + offsetToValue )
          handleArrayForNodes( arrAddr, dumpContext )
        end

        mapElement = getNextDictionaryElement(mapElement)
        
        iteration = iteration + 1

      end
    end

  -- Monitor Thread

    local function getScriptLookupNames(scriptNameAddr)
      local scriptPath = readUTFString(scriptNameAddr)
      if scriptPath == nil or scriptPath == '' then return nil, nil end

      local normalizedPath = scriptPath:gsub('\\', '/')
      local stablePath = normalizedPath:match('^(.-%.tscn)::') or normalizedPath
      local isSceneScript = stablePath ~= normalizedPath or stablePath:lower():match('%.tscn$') ~= nil
      local shortName = stablePath:match('([^/]+)$')
      if shortName == nil then return nil, nil end

      local resourcePath = stablePath:gsub('^res://', '')
      if not isSceneScript then
        shortName = shortName:gsub('%.[^.]+$', '')
        resourcePath = resourcePath:gsub('%.[^.]+$', '')
      end

      return shortName, resourcePath:gsub('/', '.')
    end

    local function nodeMonitorPass(thr)
      local dumpContext =
        {
          startedAt = getTickCount(),
          dumpedNodes = {}, -- only nodes with GDScript
          dumpedScriptNames = {},
          visited = {}, -- every encountered node
          visitedContainers = {},
          budgetMs = GDDEFS.Monitor.runBudget,
          thread = thr,
          budgetCheckCounter = 0,
          nodeCount = 0,
        }
      dumpContext.deadline = dumpContext.startedAt + dumpContext.budgetMs

      function dumpContext:visitContainer(addr)
        if self.visitedContainers[addr] then return false end
        self.visitedContainers[addr] = true
        return true
      end

      function dumpContext:VisitNode(addr, isTreeNode)
        if addr == nil or addr == 0 then return false end

        local visitState = self.visited[addr]
        if visitState == VISIT_COMPLETE or (visitState == VISIT_REJECTED and not isTreeNode) then return false end
        if visitState == nil then self.nodeCount = self.nodeCount + 1 end

        local childrenAddr, size
        if isTreeNode then -- scene tree roots & child array entries have to be considered regardless
          childrenAddr, size = readChildrenInfo(addr)
        end

        local scriptInstanceAddr = readPointer( addr + SCRIPT_INSTANCE )
        if scriptInstanceAddr == nil or scriptInstanceAddr == 0 then
          self.visited[addr] = isTreeNode and VISIT_COMPLETE or VISIT_REJECTED
          if isTreeNode then return true, nil, nil, nil, nil, childrenAddr, size end
          return false
        end

        local vectorAddr = readPointer( scriptInstanceAddr + VARIANT_VECTOR )
        local scriptAddr = readPointer( scriptInstanceAddr + SCRIPTREF )
        if scriptAddr == nil or scriptAddr == 0 then
          self.visited[addr] = isTreeNode and VISIT_COMPLETE or VISIT_REJECTED
          if isTreeNode then return true, scriptInstanceAddr, nil, nil, nil, childrenAddr, size end
          return false
        end

        local gdScriptNameAddr = readPointer( scriptAddr + GDSCRIPTNAME )

        if not isTreeNode then
          childrenAddr, size = readChildrenInfo(addr)
        end

        self.visited[addr] = VISIT_COMPLETE

        if gdScriptNameAddr ~= nil and gdScriptNameAddr ~= 0 then
          local index = #self.dumpedNodes + 1
          self.dumpedNodes[index] = addr
          self.dumpedScriptNames[index] = gdScriptNameAddr
        end

        return true, scriptInstanceAddr, vectorAddr, scriptAddr, gdScriptNameAddr, childrenAddr, size
      end

      function dumpContext:shouldStop(forceBudgetCheck)
        if self.thread.Terminated then return true end

        self.budgetCheckCounter = self.budgetCheckCounter + 1
        if not forceBudgetCheck and (self.budgetCheckCounter & BUDGET_CHECK_MASK) ~= 0 then
          return false
        end

        return getTickCount() > self.deadline
      end

      function dumpContext:shouldStopPeriodic(iteration)
        return (iteration & BUDGET_CHECK_MASK) == 0 and self:shouldStop(true)
      end

      local function cloneArrayAsMap(nodes, scriptNames)
        local result = {} -- { name : addr }
        local resultAbs = {} -- { name : addr }
        for i, nodeAddr in ipairs(nodes) do
          local scriptName, longName = getScriptLookupNames(scriptNames[i])
          if scriptName and scriptName ~= 'N??' and longName and longName ~= '' then
            result[scriptName] = nodeAddr
            resultAbs[longName] = nodeAddr
          end
        end
        return result, resultAbs
      end

      local rootChildren, rootChildrenSize = getRootChildren()
      if rootChildren ~= nil then
        for index = 0, rootChildrenSize - 1 do
          if (index & BUDGET_CHECK_MASK) == 0 and dumpContext:shouldStop(true) then break end
          local nodeAddr = readPointer(rootChildren + index * PTRSIZE)
          processNodeForNodes(nodeAddr, dumpContext, true)
        end
      end

      local nodes, nodesAbs = cloneArrayAsMap(dumpContext.dumpedNodes, dumpContext.dumpedScriptNames)
      return nodes, nodesAbs, dumpContext.nodeCount
    end

    local function monitorErrorHandler(err)
      return debug.traceback(tostring(err), 2)
    end

    function nodeMonitorService(thr)
      thr.Name = "GD Node Monitor Service"
      GD_DUMP_MONITOR_NODES = {};
      GD_DUMP_MONITOR_NODES_ABS = {};
      GD_REGISTERED_NODES = {};
      GD_REGISTERED_NODES_ABS = {};

      local startupCleanupOk, startupCleanupError = pcall(reconcileDumpedNodes, {}, {})
      if not startupCleanupOk then
        print( "GD Node Monitor startup cleanup failed: " .. tostring(startupCleanupError) )
      end

      while not thr.Terminated and isAttachedProcessCurrent() do

        GDDEFS.Monitor:startRun()

        local startedAt = getTickCount()
        local ok, nodes, nodesAbs, nodeCount = xpcall(nodeMonitorPass, monitorErrorHandler, thr)

        -- no publish/notify from a pass crossing detach/reattach/etc
        if thr.Terminated or not isAttachedProcessCurrent() then break end

        if ok then
          GD_DUMP_MONITOR_NODES = nodes or {}
          GD_DUMP_MONITOR_NODES_ABS = nodesAbs or {}

          local publishOk, publishError = pcall( reconcileDumpedNodes, GD_DUMP_MONITOR_NODES, GD_DUMP_MONITOR_NODES_ABS )
          if not publishOk then
            ok = false
            nodes = publishError
          end
        end

        if not ok then
          print("GD Node Monitor run failed; retrying next poll:\n" .. tostring(nodes))
          GD_DUMP_MONITOR_NODES = {}
          GD_DUMP_MONITOR_NODES_ABS = {}
          local clearOk, clearError = pcall( reconcileDumpedNodes, {}, {} )
          if not clearOk then print("GD Node Monitor symbol cleanup failed: " .. tostring(clearError)) end
          nodeCount = 0
        end

        GDDEFS.Monitor:endRun( getTickCount() - startedAt, nodeCount )

        sleep( GDDEFS.Monitor:getCD() )
      end

      -- service no longer owns symbol cleanup
      if serviceState.generation == MONITOR_GENERATION then
        GD_DUMP_MONITOR_NODES = {}
        GD_DUMP_MONITOR_NODES_ABS = {}
        local cleanupOk, cleanupError = pcall(unregisterNodes)
        if not cleanupOk then print( "GD Node Monitor final cleanup failed: " .. tostring(cleanupError) ) end
        if monitor.MonitorThread == thr then monitor.MonitorThread = nil end
      end
    end

  GDDEFS.Monitor = monitor

  function gd_run_subscribe(callbackName, callback)
    return GDDEFS.Monitor:onRunFinished( callbackName, callback ) -- returns an id
  end

  function gd_run_unsubscribe(subID)
    return GDDEFS.Monitor:offRunFinished(subID) -- returns true on success
  end

  function gd_run_getSubscriberID(subName)
    return GDDEFS.NODE_SUBS[subName]
  end

  local function getStableScriptLookupKeys(scriptName)
    local normalizedName = scriptName:gsub('\\', '/')
    local stableName = normalizedName:match('^(.-%.tscn)::') or normalizedName
    local isEmbeddedSceneScript = stableName ~= normalizedName
    local resourceName = stableName:gsub('^res://', '')
    local shortName = resourceName:match('([^/]+)$') or resourceName

    if not isEmbeddedSceneScript and not shortName:lower():match('%.tscn$') then
      shortName = shortName:gsub('%.[^.]+$', '')
      resourceName = resourceName:gsub('%.[^.]+$', '')
    end

    return shortName, resourceName:gsub('/', '.')
  end

  local function findNodeByScriptName(event, scriptName)
    local nodeAddr = event.nodesAbs[scriptName]
    if nodeAddr == nil or nodeAddr == 0 then nodeAddr = event.nodes[scriptName] end
    if nodeAddr ~= nil and nodeAddr ~= 0 then return nodeAddr end

    local shortName, resourcePath = getStableScriptLookupKeys(scriptName)
    nodeAddr = event.nodesAbs[resourcePath]
    if nodeAddr ~= nil and nodeAddr ~= 0 then return nodeAddr end

    return event.nodes[shortName]
  end

  function gd_run_subscribeRegisterNode(nodeName, memrec)
    if type(nodeName) ~= 'string' or nodeName == '' then error("node name expected") end

    local subName = 'mr_' .. nodeName
    local subId

    subId = GDDEFS.Monitor:onRunFinished(subName, function(event)
      local nodeAddr = event.nodesAbs[nodeName]
      if isNullOrNil(nodeAddr) then
        nodeAddr = event.nodes[nodeName]
      end

      if nodeAddr then
        gd_registerNodeOffsets(nodeName)

        if memrec ~= nil and memrec.getClassName and memrec.getClassName() == 'TMemoryRecord' then
          synchronize(function()
            if memrec.IsAddressGroupHeader then memrec.Address = string.format('%X', nodeAddr) end
            memrec.Active = true
          end)
        end

        GDDEFS.Monitor:offRunFinished(subId)
      end
    end)

    return subId
  end

  function gd_run_subscribeRegisterNodeSelectively(nodeName, variantNameTable, memrec)
    if type(nodeName) ~= 'string' or nodeName == '' then error("node name expected") end

    local subName = 'mr_' .. nodeName
    local subId

    subId = GDDEFS.Monitor:onRunFinished(subName, function(event)
      local nodeAddr = event.nodes[nodeName]

      if nodeAddr then
        gd_node_registerVariantsSelectively(nodeName, variantNameTable)

        if memrec ~= nil and memrec.getClassName and memrec.getClassName() == 'TMemoryRecord' then
          synchronize(function()
            memrec.Address = string.format('%X', nodeAddr)
            memrec.Active = true
          end)
        end

        GDDEFS.Monitor:offRunFinished(subId)
      end
    end)

    return subId
  end

  function gd_run_subscribeRecompileScript(gdScriptName, fileName, memrec)
    if type(gdScriptName) ~= 'string' or gdScriptName == '' then error('gdscript name expected') end
    if type(fileName) ~= 'string' or fileName == '' then error('script file name expected') end

    local subName = 'reload_' .. gdScriptName
    local subId

    subId = GDDEFS.Monitor:onRunFinished(subName, function(event)
      local nodeAddr = findNodeByScriptName(event, gdScriptName)
      if nodeAddr == nil or nodeAddr == 0 then return end

      gd_recompileScript(nodeAddr, fileName)

      if memrec ~= nil and memrec.getClassName and memrec.getClassName() == 'TMemoryRecord' then
        synchronize(function()
          if memrec.IsAddressGroupHeader then memrec.Address = string.format('%X', nodeAddr) end
          memrec.Active = true
        end)
      end

      GDDEFS.Monitor:offRunFinished(subId)
    end)

    return subId
  end

  function gd_run_subscribeRevertScript(gdScriptName, memrec)
    if type(gdScriptName) ~= 'string' or gdScriptName == '' then error('gdscript name expected') end

    local subName = 'revert_' .. gdScriptName
    local subId

    subId = GDDEFS.Monitor:onRunFinished(subName, function(event)
      local nodeAddr = findNodeByScriptName(event, gdScriptName)
      if nodeAddr == nil or nodeAddr == 0 then return end

      gd_revertScript(nodeAddr)

      if memrec ~= nil and memrec.getClassName and memrec.getClassName() == 'TMemoryRecord' then
        synchronize(function()
          if memrec.IsAddressGroupHeader then memrec.Address = string.format('%X', nodeAddr) end
          memrec.Active = true
        end)
      end

      GDDEFS.Monitor:offRunFinished(subId)
    end)

    return subId
  end

  local function subscribeFunctionPatch(gdScriptName, funcName, patcher, memrec)
    if type(gdScriptName) ~= 'string' or gdScriptName == '' then error('gdscript name expected') end
    if type(funcName) ~= 'string' or funcName == '' then error('function name expected') end
    if type(patcher) ~= 'function' then error('function patcher expected') end

    local subName = 'patch_' .. gdScriptName .. ':' .. funcName
    local subId
    local state =
      {
        subscriberId = nil,
        completed = false,
        nodeAddress = nil,
        functionAddress = nil,
        patch = nil,
      }

    subId = GDDEFS.Monitor:onRunFinished( subName,
      function(event)
        local nodeAddr = findNodeByScriptName( event, gdScriptName )
        if nodeAddr == nil or nodeAddr == 0 then return end

        local funcAddr = gd_getFunctionFromNode( nodeAddr, funcName )
        if funcAddr == nil or funcAddr == 0 then return end

        local patch = patcher(funcAddr)
        state.nodeAddress = nodeAddr
        state.functionAddress = funcAddr
        state.patch = patch
        state.completed = true

        -- remove observer
        GDDEFS.Monitor:offRunFinished( subId )

        if memrec ~= nil and memrec.getClassName and memrec.getClassName() == 'TMemoryRecord' then
          synchronize(
            function()
              if memrec.IsAddressGroupHeader then memrec.Address = string.format('%X', funcAddr) end
              memrec.Active = true
            end
          )
        end
      end
    )

    state.subscriberId = subId
    return subId, state
  end

  function gd_run_subscribePatchFunction(gdScriptName, funcName, patchOpcodes, startPos, memrec)
    local validatedOpcodes = validatePatchOpcodes(patchOpcodes)
    if startPos ~= nil and (type(startPos) ~= 'number' or startPos % 1 ~= 0 or startPos < 0) then
      error('Patch offset must be a non-negative opcode index')
    end

    return subscribeFunctionPatch(gdScriptName, funcName,
      function(funcAddr)
        return gd_patchFunction(funcAddr, validatedOpcodes, startPos)
      end, memrec
    )
  end

  function gd_run_subscribeNopFunction(gdScriptName, funcName, memrec)
    return subscribeFunctionPatch(gdScriptName, funcName, gd_nopFunction, memrec)
  end

  return
    {
      ok = true
    }
end

return Module -- exporting
