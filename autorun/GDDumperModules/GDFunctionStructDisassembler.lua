local Module = {}

local GD_FUNC_DISASM_COLOR = 0x451630 --0x808040

local function numtohexstr(num) return ("%X"):format(num or -1) end

function Module.install(contextTable)
  local GDDEFS = contextTable.GDDEFS
  local addStructureElem = contextTable.addStructureElem
  local addLayoutStructElem = contextTable.addLayoutStructElem
  local getGDTypeName = contextTable.getGDTypeName
  local sendDebugMessage = contextTable.sendDebugMessage

  local formatDisassembledAddress = function(addrInt)
    local addrIndex = addrInt & (GDF.EADDRESS['ADDR_MASK']) -- lower 24 bits are indices
    local addrType = (addrInt >> GDF.EADDRESS['ADDR_BITS']) -- the higher 8 would be types: shift to the beginning and mask

    if addrType == 0 and (addrIndex >= 0 and addrIndex <= 2) then
      if addrIndex == GDF.EFIXEDADDRESSES['ADDR_STACK_SELF'] then   return "stack(self)" end
      if addrIndex == GDF.EFIXEDADDRESSES['ADDR_STACK_CLASS'] then  return "stack(class)" end
      if addrIndex == GDF.EFIXEDADDRESSES['ADDR_STACK_NIL'] then    return "stack(nil)" end
                                                                    return 'stack[' .. tostring(addrIndex) .. ']'
    end

    if (addrType == GDF.EADDRESS['ADDR_TYPE_STACK']) then         return ("stack[%d]"):format(addrIndex)
    elseif (addrType == GDF.EADDRESS['ADDR_TYPE_CONSTANT']) then  return ("Constants[%d]"):format(addrIndex)
    elseif (addrType == GDF.EADDRESS['ADDR_TYPE_MEMBER']) then    return ("Variants[%d]"):format(addrIndex) -- for clarity ("member[%d]"):format(addrIndex)
    else                                                          return ("addr?(0x%08X)"):format(addrInt)
    end
  end

  local GDF = {}
    local function defineGDFunctionEnums()

      local function buildReverseTable(tab)
        local reversedTable = {}
        for i, v in ipairs(tab) do
          reversedTable[v] = i - 1
        end
        return reversedTable
      end

      local function cloneArray(tabl)
        local result = {}
        for i, val in ipairs(tabl) do
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
        local spec = GDF.ProfileSpecs[version]
        if not spec then
          error("Unknown version: " .. tostring(version))
        end

        bVisited = bVisited or {}
        if bVisited[version] then
          error("Circular profile inheritance for version: " .. tostring(version))
        end
        bVisited[version] = true

        local resolvedProfileSpec =
        {
          version = version,
          decoderName = spec.decoderName,
          orderedOpcodes = nil
        }

        if spec.base then
          local parent = prepareProfileSpec(spec.base, bVisited)
          resolvedProfileSpec.orderedOpcodes = cloneArray(parent.orderedOpcodes)

          if spec.patches then
            for _, patch in ipairs(spec.patches) do
              applyPatchOnList(resolvedProfileSpec.orderedOpcodes, patch)
            end
          end
        else
          resolvedProfileSpec.orderedOpcodes = cloneArray(spec.orderedOpcodes or {})
        end

        return resolvedProfileSpec
      end

      local function createProfileFromVersion(version)
        local resolvedProfileSpec = prepareProfileSpec(version)
        local decoder = GDF.Decoders[resolvedProfileSpec.decoderName]

        if not decoder then
          error("Unknown decoder: " .. tostring(resolvedProfileSpec.decoderName))
        end

        local profile =
        {
          version = version,
          decoder = decoder,
          orderedOpcodes = cloneArray(resolvedProfileSpec.orderedOpcodes),
          OPHandlerDefFromOPEnum = {},
          OPEnumFromInternalOPID = {},
          opNameFromOPEnum = {}
        }

        for i, internalOpcodeID in ipairs(profile.orderedOpcodes) do
          local opcodeEnum = i - 1
          local disasmHandlerDef = GDF.DisasmHandlers[internalOpcodeID]

          if not disasmHandlerDef then
            error("Missing DisasmHandlers entry for internalOpcodeID: " .. tostring(internalOpcodeID))
          end

          profile.OPHandlerDefFromOPEnum[opcodeEnum] = disasmHandlerDef
          profile.OPEnumFromInternalOPID[internalOpcodeID] = opcodeEnum
          profile.opNameFromOPEnum[opcodeEnum] = disasmHandlerDef.name
        end

        return profile
      end

      function GDF.createDisassemblerFromVersion(version)
        local profile = GDF.CompiledProfiles[version]
        if not profile then
          error("Unsupported version: " .. tostring(version))
        end

        local newDisassembler = {}
        newDisassembler.version = version
        newDisassembler.profile = profile

        function newDisassembler:getOPNameFromOPEnum(opcodeEnum)
          local handlerDef = self.profile.OPHandlerDefFromOPEnum[opcodeEnum]
          return handlerDef and handlerDef.name or nil
        end

        function newDisassembler:getOPEnumFromInternalOPID(internalOpcodeID)
          return self.profile.OPEnumFromInternalOPID[internalOpcodeID]
        end

        function newDisassembler:disassembleBytecode(codeInts, codeStructElement, instrPointer)
          local disasmContext =
          {
            opcodeName = '',
            codeStructElement = codeStructElement,
            instrPointer = 1,
            codeInts = codeInts,
            opcodeEnumRaw = nil,
            profile = self.profile
          }

          while disasmContext.instrPointer <= #disasmContext.codeInts do

            disasmContext.opcodeEnumRaw = disasmContext.codeInts[disasmContext.instrPointer]
            if disasmContext.opcodeEnumRaw == nil then
              break
            end

            local opcodeHandlerDef = self.profile.decoder.resolveOPHandlerDefFromProfile(self.profile, disasmContext.opcodeEnumRaw)
              if not opcodeHandlerDef then
                sendDebugMessage('handler not retrieved opcode: ' .. (disasmContext.opcodeEnumRaw or -1) .. (" | hex: %x"):format(disasmContext.opcodeEnumRaw or -1))
              end
              sendDebugMessage(("\topcode: %-4d\thex: %-4x\tname: %s"):format( (disasmContext.opcodeEnumRaw or -1), (disasmContext.opcodeEnumRaw or -1), (opcodeHandlerDef.name or "??")))
              disasmContext.opcodeName = opcodeHandlerDef.name
              local nextInstrPointer = opcodeHandlerDef.handler(disasmContext)
              if nextInstrPointer == nil then
                error( "Opcode handler returned nil for opcode: " .. disasmContext.opcodeName .. " at InstrPtr " .. disasmContext.instrPointer)
              end
              disasmContext.instrPointer = nextInstrPointer
          end

          return
        end

        return newDisassembler
      end

      if GDDEFS.MAJOR_VER >= 4 then
        GDF.OP =
          {
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

          GDF.DisasmHandlers[GDF.OP.OPCODE_OPERATOR] =
            {
              name = "OPCODE_OPERATOR",
              handler = function(contextTable)
                local _pointer_size = GDDEFS.PTRSIZE / 0x4

                local operation = contextTable.codeInts[contextTable.instrPointer + 4] -- operator is 4*0x4 after
                addStructureElem(contextTable.codeStructElement, 'Operator: ', (contextTable.instrPointer - 1 + 4) * 0x4, vtDword)

                local operationName = GDF.OPERATOR_NAME[operation + 1] or 'UNKNOWN_OPERATOR'
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)
                local operand3 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 3]) -- where to store
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand3 .. ' = ' .. operand1 .. ' ' .. operationName .. ' ' .. operand2
                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 7 + _pointer_size -- incr += 5; in 4.0
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_OPERATOR_VALIDATED] =
            {
              name = "OPCODE_OPERATOR_VALIDATED",
              handler = function(contextTable)

                local operation = contextTable.codeInts[contextTable.instrPointer + 4] -- operator is 4*0x4 after
                addStructureElem(contextTable.codeStructElement, 'Operator: ', (contextTable.instrPointer - 1 + 4) * 0x4, vtDword)

                local operationName = GDF.OPERATOR_NAME[operation + 1] or 'UNKNOWN_OPERATOR'
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)
                local operand3 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 3]) -- where to store
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3) * 0x4, vtDword)
                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand3 .. ' = ' .. operand1 .. ' ' .. operationName .. ' ' .. operand2
                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 5
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_TEST_BUILTIN] =
            {
              name = "OPCODE_TYPE_TEST_BUILTIN",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)
                local operand3 = getGDTypeName(contextTable.codeInts[contextTable.instrPointer + 3])
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3) * 0x4, vtDword)
                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand1 .. ' = ' .. operand2 .. ' is ' .. operand3
                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)
                return contextTable.instrPointer + 4
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_TEST_ARRAY] =
            {
              name = "OPCODE_TYPE_TEST_ARRAY",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)

                local operand3 = getGDTypeName(contextTable.codeInts[contextTable.instrPointer + 4])
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
                addStructureElem(contextTable.codeStructElement, 'script_type', (contextTable.instrPointer - 1 + 3) * 0x4, vtDword)
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 4) * 0x4, vtDword)
                addStructureElem(contextTable.codeStructElement, 'native_type', (contextTable.instrPointer - 1 + 5) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand1 .. ' = ' .. operand2 .. ' is Dictionary[' .. operand3 .. ']'
                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 6
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_TEST_DICTIONARY] =
            {
              name = "OPCODE_TYPE_TEST_DICTIONARY",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)

                local operand5 = getGDTypeName(contextTable.codeInts[contextTable.instrPointer + 5])
                local operand7 = getGDTypeName(contextTable.codeInts[contextTable.instrPointer + 7])
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

                addStructureElem(contextTable.codeStructElement, 'key_script_type', (contextTable.instrPointer - 1 + 3) * 0x4, vtDword)
                addStructureElem(contextTable.codeStructElement, operand5, (contextTable.instrPointer - 1 + 5) * 0x4, vtDword)
                addStructureElem(contextTable.codeStructElement, 'value_script_type', (contextTable.instrPointer - 1 + 4) * 0x4, vtDword)
                addStructureElem(contextTable.codeStructElement, operand7, (contextTable.instrPointer - 1 + 7) * 0x4, vtDword)
                addStructureElem(contextTable.codeStructElement, 'value_native_type', (contextTable.instrPointer - 1 + 8) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand1 .. ' = ' .. operand2 .. ' is Dictionary[' .. operand5 .. ']' .. ', ' .. operand7 .. ']'
                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)
                return contextTable.instrPointer + 9

              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_TEST_NATIVE] =
            {
              name = "OPCODE_TYPE_TEST_NATIVE",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)

                local operand3 = 'get_global_name(' .. (contextTable.codeInts[contextTable.instrPointer + 3]) .. ')'
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand1 .. ' = ' .. operand2 .. ' is ' .. operand3

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)
                return contextTable.instrPointer + 4
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_TEST_SCRIPT] =
            {
              name = "OPCODE_TYPE_TEST_SCRIPT",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword) -- dest
                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword) -- value
                local operand3 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 3])
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3) * 0x4, vtDword)
                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand1 .. ' = ' .. operand2 .. ' is ' .. operand3
                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)
                return contextTable.instrPointer + 4

              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_SET_KEYED] = 
            {
              name = "OPCODE_SET_KEYED",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)
                local operand3 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 3])
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3) * 0x4, vtDword)
                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand1 .. '[' .. operand2 .. '] = ' .. operand3
                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)
                return contextTable.instrPointer + 4
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_SET_KEYED_VALIDATED] = 
            {
              name = "OPCODE_SET_KEYED_VALIDATED",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)
                local operand3 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 3])
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand1 .. '[' .. operand2 .. '] = ' .. operand3

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)
                return contextTable.instrPointer + 5
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_SET_INDEXED_VALIDATED] = 
            {
              name = "OPCODE_SET_INDEXED_VALIDATED",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)
                local operand3 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 3])
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand1 .. '[' .. operand2 .. '] = ' .. operand3

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)
                return contextTable.instrPointer + 5
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_GET_KEYED] = 
            {
              name = "OPCODE_GET_KEYED",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)
                local operand3 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 3])
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand3 .. '[' .. operand1 .. '] = ' .. operand2

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 4
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_GET_KEYED_VALIDATED] = 
            {
              name = "OPCODE_GET_KEYED_VALIDATED",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)
                local operand3 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 3])
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand3 .. '[' .. operand1 .. '] = ' .. operand2

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 5
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_GET_INDEXED_VALIDATED] = 
            {
              name = "OPCODE_GET_INDEXED_VALIDATED",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)
                local operand3 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 3])
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand3 .. '[' .. operand1 .. '] = ' .. operand2

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 5
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_SET_NAMED] = 
            {
              name = "OPCODE_SET_NAMED",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)
                local operand3 = 'Globals[' .. contextTable.codeInts[contextTable.instrPointer + 3] .. ']'
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand1 .. '["' .. operand3 .. '"] = ' .. operand2

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 4
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_SET_NAMED_VALIDATED] = 
            {
              name = "OPCODE_SET_NAMED_VALIDATED",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)
                local operand3 = 'setter_names[' .. (contextTable.codeInts[contextTable.instrPointer + 3]) .. ']'
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3) * 0x4, vtDword)

                contextTable.opcodeName =
                    contextTable.opcodeName .. ' ' .. operand1 .. '["' .. operand3 .. '"] = ' .. operand2

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 4
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_GET_NAMED] = 
            {
              name = "OPCODE_GET_NAMED",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)
                local operand3 = 'Globals[' .. contextTable.codeInts[contextTable.instrPointer + 3] .. ']'
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand2 .. ' = ' .. operand1 .. '["' .. operand3 .. '"]'

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 4
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_GET_NAMED_VALIDATED] = 
            {
              name = "OPCODE_GET_NAMED_VALIDATED",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)
                local operand3 = 'getter_names[operand3]' -- TODO
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand2 .. ' = ' .. operand1 .. '["' .. operand3 .. '"]'

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 4
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_SET_MEMBER] = 
            {
              name = "OPCODE_SET_MEMBER",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                local operand2 = 'Globals[' .. contextTable.codeInts[contextTable.instrPointer + 2] .. ']'
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. '["' .. operand2 .. '"] = ' .. operand1

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 3
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_GET_MEMBER] = 
            {
              name = "OPCODE_GET_MEMBER",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                local operand2 = 'Globals[' .. contextTable.codeInts[contextTable.instrPointer + 2] .. ']'
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand1 .. ' = ["' .. operand2 .. '"]'

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 3
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_SET_STATIC_VARIABLE] = 
            {
              name = "OPCODE_SET_STATIC_VARIABLE",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                local operand2 = 'gdscript'
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)
                local operand3 = 'debug_get_static_var_by_index(operand3)'
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' script(scriptname)[' .. operand3 .. '] = ' .. operand1

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 4
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_GET_STATIC_VARIABLE] = 
            {
              name = "OPCODE_GET_STATIC_VARIABLE",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                local operand2 = 'gdscript'
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)
                local operand3 = 'debug_get_static_var_by_index(operand3)'
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand1 .. ' = script(scriptname)[' .. operand3 .. ']'

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 4
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ASSIGN] = 
            {
              name = "OPCODE_ASSIGN",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand1 .. ' = ' .. operand2

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 3
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ASSIGN_NULL] = 
            {
              name = "OPCODE_ASSIGN_NULL",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand1 .. ' = NULL'

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 2
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ASSIGN_TRUE] = 
            {
              name = "OPCODE_ASSIGN_TRUE",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand1 .. ' = TRUE'

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 2
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ASSIGN_FALSE] = 
            {
              name = "OPCODE_ASSIGN_FALSE",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand1 .. ' = FALSE'

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 2
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ASSIGN_TYPED_BUILTIN] = 
            {
              name = "OPCODE_ASSIGN_TYPED_BUILTIN",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)
                local operand3 = getGDTypeName(contextTable.codeInts[contextTable.instrPointer + 3])
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' (' .. operand3 .. ') ' .. operand1 .. ' = ' .. operand2

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 4
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ASSIGN_TYPED_ARRAY] = 
            {
              name = "OPCODE_ASSIGN_TYPED_ARRAY",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand1 .. ' = ' .. operand2

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 6
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ASSIGN_TYPED_DICTIONARY] = 
            {
              name = "OPCODE_ASSIGN_TYPED_DICTIONARY",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand1 .. ' = ' .. operand2

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 9
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ASSIGN_TYPED_NATIVE] = 
            {
              name = "OPCODE_ASSIGN_TYPED_NATIVE",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)
                local operand3 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 3])
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' (' .. operand3 .. ')' .. operand1 .. ' = ' .. operand2

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 4
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ASSIGN_TYPED_SCRIPT] = 
            {
              name = "OPCODE_ASSIGN_TYPED_SCRIPT",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)
                local operand3 = 'debug_get_script_name(get_constant(operand3))'
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' (' .. operand3 .. ') ' .. operand1 .. ' = ' .. operand2

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 4
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CAST_TO_BUILTIN] = 
            {
              name = "OPCODE_CAST_TO_BUILTIN",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)
                local operand1_n = getGDTypeName(contextTable.codeInts[contextTable.instrPointer + 1])

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand2 .. ' = ' .. operand1 .. ' as ' .. operand1_n

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 4
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CAST_TO_NATIVE] = 
            {
              name = "OPCODE_CAST_TO_NATIVE",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)
                local operand3 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 3])
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand2 .. ' = ' .. operand1 .. ' as ' .. operand3

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 4
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CAST_TO_SCRIPT] = 
            {
              name = "OPCODE_CAST_TO_SCRIPT",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)
                local operand3 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 3])
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand2 .. ' = ' .. operand1 .. ' as ' .. operand3

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 4
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CONSTRUCT] = 
            {
              name = "OPCODE_CONSTRUCT",
              handler = function(contextTable)
                contextTable.instrPointer = contextTable.instrPointer + 1
                local instr_var_args = contextTable.codeInts[contextTable.instrPointer]
                addStructureElem(contextTable.codeStructElement, 'instr_var_args:', (contextTable.instrPointer - 1) * 0x4, vtDword)

                local typeName = getGDTypeName(contextTable.codeInts[contextTable.instrPointer + 3 + instr_var_args])
                addStructureElem(contextTable.codeStructElement, typeName, (contextTable.instrPointer - 1 + 3 + instr_var_args) * 0x4, vtDword)
                local argc = contextTable.codeInts[contextTable.instrPointer + 1 + instr_var_args]
                addStructureElem(contextTable.codeStructElement, 'argc:', (contextTable.instrPointer - 1 + 1 + instr_var_args) * 0x4, vtDword)

                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1 + argc])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1 + argc) * 0x4, vtDword)
                local operandArg = '';

                for i = 0, argc - 1 do
                  if i > 0 then
                    operandArg = operandArg .. ', '
                  end
                  operandArg = operandArg .. formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + i + 1])
                  addStructureElem(contextTable.codeStructElement, 'arg: ' .. formatDisassembledAddress(contextTable.codeInts[i + 1]), (contextTable.instrPointer - 1 + i + 1) * 0x4, vtDword)
                end

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand1 .. ' = ' .. typeName .. '(' .. operandArg .. ')'

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1 - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 3 + instr_var_args

              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CONSTRUCT_VALIDATED] = 
            {
              name = "OPCODE_CONSTRUCT_VALIDATED",
              handler = function(contextTable)
                contextTable.instrPointer = contextTable.instrPointer + 1
                local instr_var_args = contextTable.codeInts[contextTable.instrPointer]
                addStructureElem(contextTable.codeStructElement, 'instr_var_args:', (contextTable.instrPointer - 1) * 0x4, vtDword)
                local argc = contextTable.codeInts[contextTable.instrPointer + 1 + instr_var_args]
                addStructureElem(contextTable.codeStructElement, 'argc:', (contextTable.instrPointer - 1 + 1 + instr_var_args) * 0x4, vtDword)

                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1 + argc])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1 + argc) * 0x4, vtDword)
                local operandArg = '';
                local operand3 = 'constructors_names[' .. (contextTable.codeInts[contextTable.instrPointer + 3 + argc]) .. ']'
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3 + argc) * 0x4, vtDword)

                for i = 0, argc - 1 do
                  if i > 0 then
                    operandArg = operandArg .. ', '
                  end
                  operandArg = operandArg .. formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + i + 1] )
                  addStructureElem(contextTable.codeStructElement, 'arg: ' .. formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + i + 1]), (contextTable.instrPointer - 1 + i + 1) * 0x4, vtDword)
                end

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand1 .. ' = ' .. operand3 .. '(' .. operandArg .. ')'

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1 - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 3 + instr_var_args

              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CONSTRUCT_ARRAY] = 
            {
              name = "OPCODE_CONSTRUCT_ARRAY",
              handler = function(contextTable)
                contextTable.instrPointer = contextTable.instrPointer + 1
                local instr_var_args = contextTable.codeInts[contextTable.instrPointer]
                addStructureElem(contextTable.codeStructElement, 'instr_var_args:', (contextTable.instrPointer - 1) * 0x4, vtDword) -- offset to argc (hops over args and dest)
                local argc = contextTable.codeInts[contextTable.instrPointer + 1 + instr_var_args]
                addStructureElem(contextTable.codeStructElement, 'argc:', (contextTable.instrPointer - 1 + 1 + instr_var_args) * 0x4, vtDword)

                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1 + argc])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1 + argc) * 0x4, vtDword) -- dest
                local operandArg = '';

                for i = 0, argc - 1 do
                  if i > 0 then
                    operandArg = operandArg .. ', '
                  end
                  operandArg = operandArg .. formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + i + 1])
                  addStructureElem(contextTable.codeStructElement, 'arg: ' .. formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + i + 1]), (contextTable.instrPointer - 1 + i + 1) * 0x4, vtDword)
                end

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand1 .. ' = ' .. '[' .. operandArg .. ']'

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1 - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 3 + argc
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CONSTRUCT_TYPED_ARRAY] = 
            {
              name = "OPCODE_CONSTRUCT_TYPED_ARRAY",
              handler = function(contextTable)
                contextTable.instrPointer = contextTable.instrPointer + 1
                local instr_var_args = contextTable.codeInts[contextTable.instrPointer]
                addStructureElem(contextTable.codeStructElement, 'instr_var_args:', (contextTable.instrPointer - 1) * 0x4, vtDword)
                local argc = contextTable.codeInts[contextTable.instrPointer + 1 + instr_var_args]
                addStructureElem(contextTable.codeStructElement, 'argc:', (contextTable.instrPointer - 1 + 1 + instr_var_args) * 0x4, vtDword)

                local operand2 = 'get_constant(' .. (contextTable.codeInts[contextTable.instrPointer + argc + 2] & GDF.EADDRESS["ADDR_MASK"]) .. ')'
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + argc + 2) * 0x4, vtDword)
                local operand4 = getGDTypeName(contextTable.codeInts[contextTable.instrPointer + argc + 4])
                addStructureElem(contextTable.codeStructElement, operand4, (contextTable.instrPointer - 1 + argc + 4) * 0x4, vtDword)
                local operand5 = 'get_global_name(' .. (contextTable.codeInts[contextTable.instrPointer + argc + 5]) .. ')'
                addStructureElem(contextTable.codeStructElement, operand5, (contextTable.instrPointer - 1 + argc + 5) * 0x4, vtDword)

                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1 + argc])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1 + argc) * 0x4, vtDword)
                local operandArg = '';

                for i = 0, argc - 1 do
                  if i > 0 then
                    operandArg = operandArg .. ', '
                  end
                  operandArg = operandArg .. formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + i + 1])
                  addStructureElem(contextTable.codeStructElement, 'arg: ' .. formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + i + 1]), (contextTable.instrPointer - 1 + i + 1) * 0x4, vtDword)
                end

                contextTable.opcodeName = contextTable.opcodeName .. ' (' .. operand4 .. ') ' .. operand1 .. ' = ' .. '[' .. operandArg .. ']'

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1 - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 6 + argc
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CONSTRUCT_DICTIONARY] = 
            {
              name = "OPCODE_CONSTRUCT_DICTIONARY",
              handler = function(contextTable)
                contextTable.instrPointer = contextTable.instrPointer + 1
                local instr_var_args = contextTable.codeInts[contextTable.instrPointer]
                addStructureElem(contextTable.codeStructElement, 'instr_var_args:', (contextTable.instrPointer - 1) * 0x4, vtDword)
                local argc = contextTable.codeInts[contextTable.instrPointer + 1 + instr_var_args]
                addStructureElem(contextTable.codeStructElement, 'argc:', (contextTable.instrPointer - 1 + 1 + instr_var_args) * 0x4, vtDword)

                local operand3 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1 + argc * 2])
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 1 + argc * 2) * 0x4, vtDword)

                local operandArg = '';

                for i = 0, argc - 1 do
                  if i > 0 then
                    operandArg = operandArg .. ', '
                  end
                  operandArg = operandArg .. formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1 + i * 2 + 0])
                  addStructureElem(contextTable.codeStructElement, 'argK: ' .. formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1 + i * 2 + 0]), (contextTable.instrPointer - 1 + 1 + i * 2 + 0) * 0x4, vtDword)
                  operandArg = operandArg .. ': ' .. formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1 + i * 2 + 1])
                  addStructureElem(contextTable.codeStructElement, 'argV: ' .. formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1 + i * 2 + 1]), (contextTable.instrPointer - 1 + 1 + i * 2 + 1) * 0x4, vtDword)
                end

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand3 .. ' =  {' .. operandArg .. '  }'

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1 - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 3 + argc * 2

              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CONSTRUCT_TYPED_DICTIONARY] = 
            {
              name = "OPCODE_CONSTRUCT_TYPED_DICTIONARY",
              handler = function(contextTable)
                contextTable.instrPointer = contextTable.instrPointer + 1
                local instr_var_args = contextTable.codeInts[contextTable.instrPointer]
                addStructureElem(contextTable.codeStructElement, 'instr_var_args:', (contextTable.instrPointer - 1) * 0x4, vtDword)
                local argc = contextTable.codeInts[contextTable.instrPointer + 1 + instr_var_args]
                addStructureElem(contextTable.codeStructElement, 'argc:', (contextTable.instrPointer - 1 + 1 + instr_var_args) * 0x4, vtDword)

                local operand2_2 = 'get_constant(' .. (contextTable.codeInts[contextTable.instrPointer + argc * 2 + 2] & GDF.EADDRESS["ADDR_MASK"]) .. ')'
                addStructureElem(contextTable.codeStructElement, operand2_2, (contextTable.instrPointer - 1 + argc * 2 + 2) * 0x4, vtDword)
                local operand2_5 = getGDTypeName(contextTable.codeInts[contextTable.instrPointer + argc * 2 + 5])
                addStructureElem(contextTable.codeStructElement, operand2_5, (contextTable.instrPointer - 1 + argc * 2 + 5) * 0x4, vtDword)
                local operand2_6 = 'get_global_name(' .. (contextTable.codeInts[contextTable.instrPointer + argc * 2 + 6]) .. ')'
                addStructureElem(contextTable.codeStructElement, operand2_6, (contextTable.instrPointer - 1 + argc * 2 + 6) * 0x4, vtDword)

                local operand2_3 = 'get_constant(' .. (contextTable.codeInts[contextTable.instrPointer + argc * 2 + 3] & GDF.EADDRESS["ADDR_MASK"]) .. ')'
                addStructureElem(contextTable.codeStructElement, operand2_3, (contextTable.instrPointer - 1 + argc * 2 + 3) * 0x4, vtDword)
                local operand2_7 = getGDTypeName(contextTable.codeInts[contextTable.instrPointer + argc * 2 + 7])
                addStructureElem(contextTable.codeStructElement, operand2_7, (contextTable.instrPointer - 1 + argc * 2 + 7) * 0x4, vtDword)
                local operand2_8 = 'get_global_name(' .. (contextTable.codeInts[contextTable.instrPointer + argc * 2 + 8]) .. ')'
                addStructureElem(contextTable.codeStructElement, operand2_8, (contextTable.instrPointer - 1 + argc * 2 + 8) * 0x4, vtDword)

                local operand2 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1 + argc * 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 1 + argc * 2) * 0x4, vtDword)

                local operandArg = '';

                for i = 0, argc - 1 do
                  if i > 0 then
                    operandArg = operandArg .. ', '
                  end
                    operandArg = operandArg .. formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1 + i * 2 + 0])
                    addStructureElem(contextTable.codeStructElement, 'argK: ' .. formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1 + i * 2 + 0]), (contextTable.instrPointer - 1 + 1 + i * 2 + 0) * 0x4, vtDword)
                    operandArg = operandArg .. ': ' .. formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1 + i * 2 + 1])
                    addStructureElem(contextTable.codeStructElement, 'argV: ' .. formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1 + i * 2 + 1]), (contextTable.instrPointer - 1 + 1 + i * 2 + 1) * 0x4, vtDword)
                end

                contextTable.opcodeName = contextTable.opcodeName .. ' (' .. operand2_5 .. ', ' .. operand2_7 .. ') ' .. operand2 .. ' =  {' .. operandArg .. '  }'

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1 - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 9 + argc * 2
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL] = 
            {
              name = "OPCODE_CALL",
              handler = function(contextTable)
                local ret = contextTable.codeInts[contextTable.instrPointer] == GDF.CurrentDisassembler:getOPEnumFromInternalOPID(GDF.OP.OPCODE_CALL_RETURN)
                local async = contextTable.codeInts[contextTable.instrPointer] == GDF.CurrentDisassembler:getOPEnumFromInternalOPID(GDF.OP.OPCODE_CALL_ASYNC)

                contextTable.instrPointer = contextTable.instrPointer + 1
                local instr_var_args = contextTable.codeInts[contextTable.instrPointer]
                addStructureElem(contextTable.codeStructElement, 'instr_var_args:', (contextTable.instrPointer - 1) * 0x4, vtDword)

                local operand2 = '';
                local argc = contextTable.codeInts[contextTable.instrPointer + 1 + instr_var_args]
                addStructureElem(contextTable.codeStructElement, 'argc:', (contextTable.instrPointer - 1 + 1 + instr_var_args) * 0x4, vtDword)

                if (ret or async) then
                  operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + argc + 2])
                  addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + argc + 2) * 0x4, vtDword)
                  operand2 = operand2 .. ' = '
                end

                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1 + argc])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1 + argc) * 0x4, vtDword)
                operand1 = operand1 .. '.'

                local operandArg = '';

                for i = 0, argc - 1 do
                  if i > 0 then
                    operandArg = operandArg .. ', '
                  end
                  operandArg = operandArg .. formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + i + 1])
                  addStructureElem(contextTable.codeStructElement, 'arg: ' .. formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + i + 1]), (contextTable.instrPointer - 1 + i + 1) * 0x4, vtDword)
                end

                local operand3 = 'Globals[' .. (contextTable.codeInts[contextTable.instrPointer + instr_var_args + 2]) .. ']'
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + instr_var_args + 2) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand2 .. operand1 .. operand3 .. ']' .. '(' .. operandArg .. ')' -- original representation 'GlobalNames[FuncCode['..(contextTable.instrPointer-1 + instr_var_args+2)..']]'

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1 - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 5 + argc
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_RETURN] = 
            {
              name = "OPCODE_CALL_RETURN",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_ASYNC] = 
            {
              name = "OPCODE_CALL_ASYNC",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_UTILITY] = 
            {
              name = "OPCODE_CALL_UTILITY",
              handler = function(contextTable)
                contextTable.instrPointer = contextTable.instrPointer + 1
                local instr_var_args = contextTable.codeInts[contextTable.instrPointer]
                addStructureElem(contextTable.codeStructElement, 'instr_var_args:', (contextTable.instrPointer - 1) * 0x4, vtDword)
                local argc = contextTable.codeInts[contextTable.instrPointer + 1 + instr_var_args]
                addStructureElem(contextTable.codeStructElement, 'argc:', (contextTable.instrPointer - 1 + 1 + instr_var_args) * 0x4, vtDword)

                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1 + argc])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1 + argc) * 0x4, vtDword)

                local operandArg = '';

                for i = 0, argc - 1 do
                  if i > 0 then
                    operandArg = operandArg .. ', '
                  end
                  operandArg = operandArg .. formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + i + 1])
                  addStructureElem(contextTable.codeStructElement, 'arg: ' .. formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + i + 1]), (contextTable.instrPointer - 1 + i + 1) * 0x4, vtDword)
                end

                local operand2 = 'Globals[' .. contextTable.codeInts[contextTable.instrPointer + 2 + instr_var_args] .. ']'
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2 + instr_var_args) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand1 .. ' = ' .. operand2 .. '(' .. operandArg .. ')'

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1 - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 4 + argc

              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_UTILITY_VALIDATED] = 
            {
              name = "OPCODE_CALL_UTILITY_VALIDATED",
              handler = function(contextTable)
                contextTable.instrPointer = contextTable.instrPointer + 1
                local instr_var_args = contextTable.codeInts[contextTable.instrPointer]
                addStructureElem(contextTable.codeStructElement, 'instr_var_args:', (contextTable.instrPointer - 1) * 0x4, vtDword)
                local argc = contextTable.codeInts[contextTable.instrPointer + 1 + instr_var_args]
                addStructureElem(contextTable.codeStructElement, 'argc:', (contextTable.instrPointer - 1 + 1 + instr_var_args) * 0x4, vtDword)

                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1 + argc])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1 + argc) * 0x4, vtDword)

                local operandArg = '';

                for i = 0, argc - 1 do
                  if i > 0 then
                    operandArg = operandArg .. ', '
                  end
                  operandArg = operandArg .. formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + i + 1])
                  addStructureElem(contextTable.codeStructElement, 'arg: ' .. formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + i + 1]), (contextTable.instrPointer - 1 + i + 1) * 0x4, vtDword)
                end

                local operand3 = 'utilities_names[' .. contextTable.codeInts[contextTable.instrPointer + 3 + argc] .. ']'
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3 + argc) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand1 .. ' = ' .. operand3 .. '(' .. operandArg .. ')'

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1 - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 4 + argc
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_GDSCRIPT_UTILITY] = 
            {
              name = "OPCODE_CALL_GDSCRIPT_UTILITY",
              handler = function(contextTable)
                contextTable.instrPointer = contextTable.instrPointer + 1
                local instr_var_args = contextTable.codeInts[contextTable.instrPointer]
                addStructureElem(contextTable.codeStructElement, 'instr_var_args:', (contextTable.instrPointer - 1) * 0x4, vtDword)
                local argc = contextTable.codeInts[contextTable.instrPointer + 1 + instr_var_args]
                addStructureElem(contextTable.codeStructElement, 'argc:', (contextTable.instrPointer - 1 + 1 + instr_var_args) * 0x4, vtDword)
                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1 + argc])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1 + argc) * 0x4, vtDword)

                local operandArg = '';

                for i = 0, argc - 1 do
                  if i > 0 then
                    operandArg = operandArg .. ', '
                  end
                  operandArg = operandArg .. formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + i + 1])
                  addStructureElem(contextTable.codeStructElement, 'arg: ' .. formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + i + 1]), (contextTable.instrPointer - 1 + i + 1) * 0x4, vtDword)
                end

                local operand3 = 'gds_utilities_names[' .. contextTable.codeInts[contextTable.instrPointer + 3 + argc] .. ']'
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3 + argc) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand1 .. ' = ' .. operand3 .. '(' .. operandArg .. ')'
                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1 - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 4 + argc
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_BUILTIN_TYPE_VALIDATED] = 
            {
              name = "OPCODE_CALL_BUILTIN_TYPE_VALIDATED",
              handler = function(contextTable)
                contextTable.instrPointer = contextTable.instrPointer + 1
                local instr_var_args = contextTable.codeInts[contextTable.instrPointer]
                addStructureElem(contextTable.codeStructElement, 'instr_var_args:', (contextTable.instrPointer - 1) * 0x4, vtDword)
                local argc = contextTable.codeInts[contextTable.instrPointer + 1 + instr_var_args]
                addStructureElem(contextTable.codeStructElement, 'argc:', (contextTable.instrPointer - 1 + 1 + instr_var_args) * 0x4, vtDword)

                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                local operand2 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 2 + argc])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2 + argc) * 0x4, vtDword)

                local operandArg = '';

                for i = 0, argc - 1 do
                  if i > 0 then
                    operandArg = operandArg .. ', '
                  end
                  operandArg = operandArg .. formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + i + 1])
                  addStructureElem(contextTable.codeStructElement, 'arg: ' .. formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + i + 1]), (contextTable.instrPointer - 1 + i + 1) * 0x4, vtDword)
                end

                local operand4 = 'builtin_methods_names[' .. (contextTable.codeInts[contextTable.instrPointer + 4 + argc]) .. ']'
                addStructureElem(contextTable.codeStructElement, operand4, (contextTable.instrPointer - 1 + 4 + argc) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand2 .. ' = ' .. operand1 .. '.' .. operand4 .. '(' .. operandArg .. ')'

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1 - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 5 + argc
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_SELF_BASE] = 
            {
              name = "OPCODE_CALL_SELF_BASE",
              handler = function(contextTable)
                contextTable.instrPointer = contextTable.instrPointer + 1
                local instr_var_args = contextTable.codeInts[contextTable.instrPointer]
                addStructureElem(contextTable.codeStructElement, 'instr_var_args:', (contextTable.instrPointer - 1) * 0x4, vtDword)
                local argc = contextTable.codeInts[contextTable.instrPointer + 1 + instr_var_args]
                addStructureElem(contextTable.codeStructElement, 'argc:', (contextTable.instrPointer - 1 + 1 + instr_var_args) * 0x4, vtDword)
                local operand2 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 2 + argc])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2 + argc) * 0x4, vtDword)

                local operandArg = '';

                for i = 0, argc - 1 do
                  if i > 0 then
                    operandArg = operandArg .. ', '
                  end
                  operandArg = operandArg .. formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + i + 1])
                  addStructureElem(contextTable.codeStructElement, 'arg: ' .. formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + i + 1]), (contextTable.instrPointer - 1 + i + 1) * 0x4, vtDword)
                end

                local operand3 = 'Globals[' .. contextTable.codeInts[contextTable.instrPointer + 2 + instr_var_args] .. ']'
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 2 + instr_var_args) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand2 .. ' = ' .. operand3 .. '(' .. operandArg .. ')'
                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1 - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 4 + argc
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_METHOD_BIND] = 
            {
              name = "OPCODE_CALL_METHOD_BIND",
              handler = function(contextTable)
                local ret = contextTable.codeInts[contextTable.instrPointer] == GDF.CurrentDisassembler:getOPEnumFromInternalOPID(GDF.OP.OPCODE_CALL_METHOD_BIND_RET)
                contextTable.instrPointer = contextTable.instrPointer + 1
                local instr_var_args = contextTable.codeInts[contextTable.instrPointer]
                addStructureElem(contextTable.codeStructElement, 'instr_var_args:', (contextTable.instrPointer - 1) * 0x4, vtDword)
                local operand2 = '';
                local argc = contextTable.codeInts[contextTable.instrPointer + 1 + instr_var_args]
                addStructureElem(contextTable.codeStructElement, 'argc:', (contextTable.instrPointer - 1 + 1 + instr_var_args) * 0x4, vtDword)

                if (ret) then
                  operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + argc + 2])
                  addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + argc + 2) * 0x4, vtDword)
                  operand2 = operand2 .. ' = '
                end

                local operand3 = '_methods_ptr[' .. contextTable.codeInts[contextTable.instrPointer + 2 + instr_var_args] .. ']'
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 2 + instr_var_args) * 0x4, vtDword)

                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1 + argc])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1 + argc) * 0x4, vtDword)
                operand1 = operand1 .. '.'
                operand1 = operand1 .. operand3 .. '->get_name()'
                local operandArg = '';

                for i = 0, argc - 1 do
                  if i > 0 then
                    operandArg = operandArg .. ', '
                  end
                  operandArg = operandArg .. formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + i + 1])
                  addStructureElem(contextTable.codeStructElement, 'arg: ' .. formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + i + 1]),     (contextTable.instrPointer - 1 + i + 1) * 0x4, vtDword)
                end

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand2 .. operand1 .. '(' .. operandArg .. ')'
                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1 - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 5 + argc
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_METHOD_BIND_RET] = 
            {
              name = "OPCODE_CALL_METHOD_BIND_RET",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_METHOD_BIND].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_BUILTIN_STATIC] = 
            {
              name = "OPCODE_CALL_BUILTIN_STATIC",
              handler = function(contextTable)
                contextTable.instrPointer = contextTable.instrPointer + 1
                local instr_var_args = contextTable.codeInts[contextTable.instrPointer]
                addStructureElem(contextTable.codeStructElement, 'instr_var_args:', (contextTable.instrPointer - 1) * 0x4, vtDword)
                local typeName = getGDTypeName(contextTable.codeInts[contextTable.instrPointer + 1 + instr_var_args])
                addStructureElem(contextTable.codeStructElement, 'typeName:', (contextTable.instrPointer - 1 + 3 + instr_var_args) * 0x4, vtDword)

                local argc = contextTable.codeInts[contextTable.instrPointer + 1 + instr_var_args]
                addStructureElem(contextTable.codeStructElement, 'argc:', (contextTable.instrPointer - 1 + 1 + instr_var_args) * 0x4, vtDword)

                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1 + argc])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1 + argc) * 0x4, vtDword)
                local operandArg = '';

                for i = 0, argc - 1 do
                  if i > 0 then
                    operandArg = operandArg .. ', '
                  end
                  operandArg = operandArg .. formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + i + 1])
                  addStructureElem(contextTable.codeStructElement, 'arg: ' .. formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + i + 1]), (contextTable.instrPointer - 1 + i + 1) * 0x4, vtDword)
                end

                local operand2 = 'Globals[' .. contextTable.codeInts[contextTable.instrPointer + 2 + instr_var_args] .. ']'
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2 + instr_var_args) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand1 .. ' = ' .. typeName .. '.' .. operand2 .. '.operator String()' .. '(' .. operandArg .. ')'

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1 - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 5 + argc
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_NATIVE_STATIC] = 
            {
              name = "OPCODE_CALL_NATIVE_STATIC",
              handler = function(contextTable)
                contextTable.instrPointer = contextTable.instrPointer + 1
                local instr_var_args = contextTable.codeInts[contextTable.instrPointer]
                addStructureElem(contextTable.codeStructElement, 'instr_var_args:', (contextTable.instrPointer - 1) * 0x4, vtDword)
                local argc = contextTable.codeInts[contextTable.instrPointer + 2 + instr_var_args]
                addStructureElem(contextTable.codeStructElement, 'argc:', (contextTable.instrPointer - 1 + 2 + instr_var_args) * 0x4, vtDword)

                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1 + argc])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1 + argc) * 0x4, vtDword)
                local operandArg = '';

                for i = 0, argc - 1 do
                  if i > 0 then
                    operandArg = operandArg .. ', '
                  end
                  operandArg = operandArg .. formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + i + 1])
                  addStructureElem(contextTable.codeStructElement, 'arg: ' .. formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + i + 1]), (contextTable.instrPointer - 1 + i + 1) * 0x4, vtDword)
                end

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand1 .. ' = ' .. 'method->get_instance_class()' .. '.' .. 'method->get_name()' .. '(' .. operandArg .. ')'

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1 - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 4 + argc
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_NATIVE_STATIC_VALIDATED_RETURN] = 
            {
              name = "OPCODE_CALL_NATIVE_STATIC_VALIDATED_RETURN",
              handler = function(contextTable)
                contextTable.instrPointer = contextTable.instrPointer + 1
                local instr_var_args = contextTable.codeInts[contextTable.instrPointer]
                addStructureElem(contextTable.codeStructElement, 'instr_var_args:', (contextTable.instrPointer - 1) * 0x4, vtDword)
                local argc = contextTable.codeInts[contextTable.instrPointer + 1 + instr_var_args]
                addStructureElem(contextTable.codeStructElement, 'argc:', (contextTable.instrPointer - 1 + 1 + instr_var_args) * 0x4, vtDword)

                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1 + argc])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1 + argc) * 0x4, vtDword)
                local operandArg = '';

                for i = 0, argc - 1 do
                  if i > 0 then
                    operandArg = operandArg .. ', '
                  end
                  operandArg = operandArg .. formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + i + 1])
                  addStructureElem(contextTable.codeStructElement, 'arg: ' .. formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + i + 1]), (contextTable.instrPointer - 1 + i + 1) * 0x4, vtDword)
                end

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand1 .. ' = ' .. 'method->get_instance_class()' .. '.' .. 'method->get_name()' .. '(' .. operandArg .. ')'

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1 - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 4 + argc

              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_NATIVE_STATIC_VALIDATED_NO_RETURN] = 
            {
              name = "OPCODE_CALL_NATIVE_STATIC_VALIDATED_NO_RETURN",
              handler = function(contextTable)
                contextTable.instrPointer = contextTable.instrPointer + 1
                local instr_var_args = contextTable.codeInts[contextTable.instrPointer]
                addStructureElem(contextTable.codeStructElement, 'instr_var_args:', (contextTable.instrPointer - 1) * 0x4, vtDword)
                local argc = contextTable.codeInts[contextTable.instrPointer + 1 + instr_var_args]
                addStructureElem(contextTable.codeStructElement, 'argc:', (contextTable.instrPointer - 1 + 1 + instr_var_args) * 0x4, vtDword)

                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1 + argc])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1 + argc) * 0x4, vtDword)
                local operandArg = '';

                for i = 0, argc - 1 do
                  if i > 0 then
                    operandArg = operandArg .. ', '
                  end
                  operandArg = operandArg .. formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + i + 1])
                  addStructureElem(contextTable.codeStructElement, 'arg: ' .. formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + i + 1]), (contextTable.instrPointer - 1 + i + 1) * 0x4, vtDword)
                end

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand1 .. ' = ' .. 'method->get_instance_class()' .. '.' .. 'method->get_name()' .. '(' .. operandArg .. ')'

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1 - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 4 + argc
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_METHOD_BIND_VALIDATED_RETURN] = 
            {
              name = "OPCODE_CALL_METHOD_BIND_VALIDATED_RETURN",
              handler = function(contextTable)
                contextTable.instrPointer = contextTable.instrPointer + 1
                local instr_var_args = contextTable.codeInts[contextTable.instrPointer]
                addStructureElem(contextTable.codeStructElement, 'instr_var_args:', (contextTable.instrPointer - 1) * 0x4, vtDword)
                local argc = contextTable.codeInts[contextTable.instrPointer + 1 + instr_var_args]
                addStructureElem(contextTable.codeStructElement, 'argc:', (contextTable.instrPointer - 1 + 1 + instr_var_args) * 0x4, vtDword)

                local operand2 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 2 + argc])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2 + argc) * 0x4, vtDword)

                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1 + argc])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1 + argc) * 0x4, vtDword)
                local operandArg = '';

                for i = 0, argc - 1 do
                  if i > 0 then
                    operandArg = operandArg .. ', '
                  end
                  operandArg = operandArg .. formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + i + 1])
                  addStructureElem(contextTable.codeStructElement, 'arg: ' .. formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + i + 1]), (contextTable.instrPointer - 1 + i + 1) * 0x4, vtDword)
                end

                local operand3 = '_methods_ptr[' .. contextTable.codeInts[contextTable.instrPointer + 2 + instr_var_args] .. ']'
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 2 + instr_var_args) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand2 .. ' = ' .. operand1 .. '.' .. operand3 .. '->get_name()' .. '(' .. operandArg .. ')'

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1 - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 5 + argc
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_METHOD_BIND_VALIDATED_NO_RETURN] = 
            {
              name = "OPCODE_CALL_METHOD_BIND_VALIDATED_NO_RETURN",
              handler = function(contextTable)
                contextTable.instrPointer = contextTable.instrPointer + 1
                local instr_var_args = contextTable.codeInts[contextTable.instrPointer]
                addStructureElem(contextTable.codeStructElement, 'instr_var_args:', (contextTable.instrPointer - 1) * 0x4, vtDword)
                local argc = contextTable.codeInts[contextTable.instrPointer + 1 + instr_var_args]
                addStructureElem(contextTable.codeStructElement, 'argc:', (contextTable.instrPointer - 1 + 1 + instr_var_args) * 0x4, vtDword)

                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1 + argc])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1 + argc) * 0x4, vtDword)
                local operandArg = '';

                for i = 0, argc - 1 do
                  if i > 0 then
                    operandArg = operandArg .. ', '
                  end
                  operandArg = operandArg .. formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + i + 1])
                  addStructureElem(contextTable.codeStructElement, 'arg: ' .. formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + i + 1]), (contextTable.instrPointer - 1 + i + 1) * 0x4, vtDword)
                end

                local operand3 = '_methods_ptr[' .. contextTable.codeInts[contextTable.instrPointer + 2 + instr_var_args] .. ']'
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 2 + instr_var_args) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand1 .. '.' .. operand3 .. '->get_name()' .. '(' .. operandArg .. ')'

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1 - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 5 + argc
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_AWAIT] = 
            {
              name = "OPCODE_AWAIT",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand1

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)
                return contextTable.instrPointer + 2
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_AWAIT_RESUME] = 
            {
              name = "OPCODE_AWAIT_RESUME",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_AWAIT].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CREATE_LAMBDA] = 
            {
              name = "OPCODE_CREATE_LAMBDA",
              handler = function(contextTable)
                contextTable.instrPointer = contextTable.instrPointer + 1
                local instr_var_args = contextTable.codeInts[contextTable.instrPointer]
                addStructureElem(contextTable.codeStructElement, 'instr_var_args:', (contextTable.instrPointer - 1) * 0x4, vtDword)

                local operand2 = '_lambdas_ptr[' .. (contextTable.codeInts[contextTable.instrPointer + 2 + instr_var_args]) .. ']'
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2 + instr_var_args) * 0x4, vtDword)
                local captures_count = contextTable.codeInts[contextTable.instrPointer + 1 + instr_var_args]
                addStructureElem(contextTable.codeStructElement, 'argc:', (contextTable.instrPointer - 1 + 1 + instr_var_args) * 0x4, vtDword)
                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1 + captures_count])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1 + captures_count) * 0x4, vtDword)

                local operandArg = '';

                for i = 0, captures_count - 1 do
                  if i > 0 then
                    operandArg = operandArg .. ', '
                  end
                  operandArg = operandArg .. formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + i + 1])
                  addStructureElem(contextTable.codeStructElement, 'captures_count: ' .. formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + i + 1]), (contextTable.instrPointer - 1 + i + 1) * 0x4, vtDword)
                end

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand1 .. ' create lambda from ' .. operand2 .. '->name.operator String()' .. ' function, captures (' .. operandArg .. ')'
                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1 - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 4 + captures_count
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CREATE_SELF_LAMBDA] = 
            {
              name = "OPCODE_CREATE_SELF_LAMBDA",
              handler = function(contextTable)
                contextTable.instrPointer = contextTable.instrPointer + 1
                local instr_var_args = contextTable.codeInts[contextTable.instrPointer]
                addStructureElem(contextTable.codeStructElement, 'instr_var_args:', (contextTable.instrPointer - 1) * 0x4, vtDword)
                local operand2 = '_lambdas_ptr[' .. (contextTable.codeInts[contextTable.instrPointer + 2 + instr_var_args]) .. ']'
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2 + instr_var_args) * 0x4, vtDword)
                local captures_count = contextTable.codeInts[contextTable.instrPointer + 1 + instr_var_args]
                addStructureElem(contextTable.codeStructElement, 'argc:', (contextTable.instrPointer - 1 + 1 + instr_var_args) * 0x4, vtDword)
                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1 + captures_count])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1 + captures_count) * 0x4, vtDword)

                local operandArg = '';

                for i = 0, captures_count - 1 do
                  if i > 0 then
                    operandArg = operandArg .. ', '
                  end
                  operandArg = operandArg .. formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + i + 1])
                  addStructureElem(contextTable.codeStructElement, 'captures_count: ' .. formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + i + 1]),     (contextTable.instrPointer - 1 + i + 1) * 0x4, vtDword)
                end

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand1 .. ' create lambda from ' .. operand2 .. '->name.operator String()' .. ' function, captures (' .. operandArg .. ')'
                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1 - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 4 + captures_count

              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_JUMP] = 
            {
              name = "OPCODE_JUMP",
              handler = function(contextTable)
                local operand1 = numtohexstr(contextTable.codeInts[contextTable.instrPointer + 1] * 0x4) -- where to jump in hex representation, 4byte step
                local elem = addStructureElem(contextTable.codeStructElement, "JUMP to " .. operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                elem.DisplayMethod = 'dtHexadecimal'
                elem.ShowAsHex = true
                contextTable.opcodeName = contextTable.opcodeName .. ' -> ' .. operand1

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 2
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_JUMP_IF] = 
            {
              name = "OPCODE_JUMP_IF",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)

                local operand2 = numtohexstr(contextTable.codeInts[contextTable.instrPointer + 2] * 0x4) -- where to jump
                local elem = addStructureElem(contextTable.codeStructElement, "JUMP to " .. operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)
                elem.DisplayMethod = 'dtHexadecimal'
                elem.ShowAsHex = true
                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand1 .. ' -> ' .. operand2

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 3
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_JUMP_IF_NOT] = 
            {
              name = "OPCODE_JUMP_IF_NOT",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_JUMP_IF].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_JUMP_TO_DEF_ARGUMENT] = 
            {
              name = "OPCODE_JUMP_TO_DEF_ARGUMENT",
              handler = function(contextTable)
                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)
                return contextTable.instrPointer + 1
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_JUMP_IF_SHARED] = 
            {
              name = "OPCODE_JUMP_IF_SHARED",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_JUMP_IF].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_RETURN] = 
            {
              name = "OPCODE_RETURN",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand1
                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 2
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_RETURN_TYPED_BUILTIN] = 
            {
              name = "OPCODE_RETURN_TYPED_BUILTIN",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                local operand2 = getGDTypeName(contextTable.codeInts[contextTable.instrPointer + 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' (' .. operand2 .. ')' .. ' ' .. operand1
                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 3
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_RETURN_TYPED_ARRAY] = 
            {
              name = "OPCODE_RETURN_TYPED_ARRAY",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand1
                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 5
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_RETURN_TYPED_DICTIONARY] = 
            {
              name = "OPCODE_RETURN_TYPED_DICTIONARY",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand1
                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 8
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_RETURN_TYPED_NATIVE] = 
            {
              name = "OPCODE_RETURN_TYPED_NATIVE",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' (' .. operand2 .. ') ' .. operand1
                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 3

              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_RETURN_TYPED_SCRIPT] = 
            {
              name = "OPCODE_RETURN_TYPED_SCRIPT",
              handler = function(contextTable)
                local operand2 = 'get_constant(' .. (contextTable.codeInts[contextTable.instrPointer + 2] & GDF.EADDRESS["ADDR_MASK"]) .. ')'
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)

                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' (' .. 'GDScript::debug_get_script_name(' .. operand2 .. ')' .. ') ' .. operand1
                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 3
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN] = 
            {
              name = "OPCODE_ITERATE_BEGIN",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)
                local operand3 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 3])
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3) * 0x4, vtDword)
                addStructureElem(contextTable.codeStructElement, 'end: ', (contextTable.instrPointer - 1 + 4) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' for-init ' .. operand3 .. ' in ' .. operand2 .. ' counter ' .. operand1 .. ' end ' .. tostring(contextTable.codeInts[contextTable.instrPointer + 4])
                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 5
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_INT] = 
            {
              name = "OPCODE_ITERATE_BEGIN_INT",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)
                local operand3 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 3])
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3) * 0x4, vtDword)
                addStructureElem(contextTable.codeStructElement, 'end: ', (contextTable.instrPointer - 1 + 4) * 0x4, vtDword)

                local opcodeType = contextTable.opcodeName:gsub('OPCODE_ITERATE_BEGIN_', '')
                contextTable.opcodeName = contextTable.opcodeName .. ' for-init (typed ' .. opcodeType .. ') ' .. operand3 .. ' in ' .. operand2 .. ' counter ' .. operand1 .. ' end ' .. tostring(contextTable.codeInts[contextTable.instrPointer + 4])
                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 5
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_FLOAT] = 
            {
              name = "OPCODE_ITERATE_BEGIN_FLOAT",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_INT].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_VECTOR2] = 
            {
              name = "OPCODE_ITERATE_BEGIN_VECTOR2",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_INT].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_VECTOR2I] = 
            {
              name = "OPCODE_ITERATE_BEGIN_VECTOR2I",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_INT].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_VECTOR3] = 
            {
              name = "OPCODE_ITERATE_BEGIN_VECTOR3",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_INT].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_VECTOR3I] = 
            {
              name = "OPCODE_ITERATE_BEGIN_VECTOR3I",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_INT].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_STRING] = 
            {
              name = "OPCODE_ITERATE_BEGIN_STRING",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_INT].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_DICTIONARY] = 
            {
              name = "OPCODE_ITERATE_BEGIN_DICTIONARY",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_INT].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_ARRAY] = 
            {
              name = "OPCODE_ITERATE_BEGIN_ARRAY",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_INT].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_PACKED_BYTE_ARRAY] = 
            {
              name = "OPCODE_ITERATE_BEGIN_PACKED_BYTE_ARRAY",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_INT].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_PACKED_INT32_ARRAY] = 
            {
              name = "OPCODE_ITERATE_BEGIN_PACKED_INT32_ARRAY",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_INT].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_PACKED_INT64_ARRAY] = 
            {
              name = "OPCODE_ITERATE_BEGIN_PACKED_INT64_ARRAY",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_INT].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_PACKED_FLOAT32_ARRAY] = 
            {
              name = "OPCODE_ITERATE_BEGIN_PACKED_FLOAT32_ARRAY",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_INT].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_PACKED_FLOAT64_ARRAY] = 
            {
              name = "OPCODE_ITERATE_BEGIN_PACKED_FLOAT64_ARRAY",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_INT].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_PACKED_STRING_ARRAY] = 
            {
              name = "OPCODE_ITERATE_BEGIN_PACKED_STRING_ARRAY",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_INT].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_PACKED_VECTOR2_ARRAY] = 
            {
              name = "OPCODE_ITERATE_BEGIN_PACKED_VECTOR2_ARRAY",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_INT].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_PACKED_VECTOR3_ARRAY] = 
            {
              name = "OPCODE_ITERATE_BEGIN_PACKED_VECTOR3_ARRAY",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_INT].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_PACKED_COLOR_ARRAY] = 
            {
              name = "OPCODE_ITERATE_BEGIN_PACKED_COLOR_ARRAY",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_INT].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_PACKED_VECTOR4_ARRAY] = 
            {
              name = "OPCODE_ITERATE_BEGIN_PACKED_VECTOR4_ARRAY",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_INT].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_OBJECT] = 
            {
              name = "OPCODE_ITERATE_BEGIN_OBJECT",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_INT].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN_RANGE] =
            {
              name = "OPCODE_ITERATE_BEGIN_RANGE",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)

                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)

                local operand3 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 3])
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3) * 0x4, vtDword)

                local operand4 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 4])
                addStructureElem(contextTable.codeStructElement, operand4, (contextTable.instrPointer - 1 + 4) * 0x4, vtDword)

                local operand5 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 5])
                addStructureElem(contextTable.codeStructElement, operand5, (contextTable.instrPointer - 1 + 5) * 0x4, vtDword)

                addStructureElem(contextTable.codeStructElement, 'end: ', (contextTable.instrPointer - 1 + 4) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' for-init ' .. operand5 .. ' in range from ' .. operand2 .. ' to ' .. operand3 .. ' step ' .. operand4 .. ' counter ' .. operand1 .. ' end ' .. tostring(contextTable.codeInts[contextTable.instrPointer + 4])
                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 7

              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE] =
            {
              name = "OPCODE_ITERATE",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)
                local operand3 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 3])
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3) * 0x4, vtDword)
                addStructureElem(contextTable.codeStructElement, 'end: ', (contextTable.instrPointer - 1 + 4) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' for-loop ' .. operand2 .. ' in ' .. operand2 .. ' counter ' .. operand1 .. ' end ' .. tostring(contextTable.codeInts[contextTable.instrPointer + 4])
                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 5
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_INT] =
            {
              name = "OPCODE_ITERATE_INT",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)
                local operand3 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 3])
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3) * 0x4, vtDword)
                addStructureElem(contextTable.codeStructElement, 'end: ', (contextTable.instrPointer - 1 + 4) * 0x4, vtDword)

                local opcodeType = contextTable.opcodeName:gsub('OPCODE_ITERATE_', '')
                contextTable.opcodeName = contextTable.opcodeName .. ' for-init (typed ' .. opcodeType .. ') ' .. operand3 .. ' in ' .. operand2 .. ' counter ' .. operand1 .. ' end ' .. tostring(contextTable.codeInts[contextTable.instrPointer + 4])
                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 5
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_FLOAT] = 
            {
              name = "OPCODE_ITERATE_FLOAT",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_INT].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_VECTOR2] = 
            {
              name = "OPCODE_ITERATE_VECTOR2",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_INT].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_VECTOR2I] = 
            {
              name = "OPCODE_ITERATE_VECTOR2I",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_INT].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_VECTOR3] = 
            {
              name = "OPCODE_ITERATE_VECTOR3",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_INT].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_VECTOR3I] = 
            {
              name = "OPCODE_ITERATE_VECTOR3I",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_INT].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_STRING] = 
            {
              name = "OPCODE_ITERATE_STRING",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_INT].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_DICTIONARY] = 
            {
              name = "OPCODE_ITERATE_DICTIONARY",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_INT].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_ARRAY] = 
            {
              name = "OPCODE_ITERATE_ARRAY",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_INT].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_PACKED_BYTE_ARRAY] = 
            {
              name = "OPCODE_ITERATE_PACKED_BYTE_ARRAY",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_INT].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_PACKED_INT32_ARRAY] = 
            {
              name = "OPCODE_ITERATE_PACKED_INT32_ARRAY",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_INT].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_PACKED_INT64_ARRAY] = 
            {
              name = "OPCODE_ITERATE_PACKED_INT64_ARRAY",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_INT].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_PACKED_FLOAT32_ARRAY] = 
            {
              name = "OPCODE_ITERATE_PACKED_FLOAT32_ARRAY",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_INT].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_PACKED_FLOAT64_ARRAY] = 
            {
              name = "OPCODE_ITERATE_PACKED_FLOAT64_ARRAY",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_INT].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_PACKED_STRING_ARRAY] = 
            {
              name = "OPCODE_ITERATE_PACKED_STRING_ARRAY",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_INT].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_PACKED_VECTOR2_ARRAY] = 
            {
              name = "OPCODE_ITERATE_PACKED_VECTOR2_ARRAY",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_INT].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_PACKED_VECTOR3_ARRAY] = 
            {
              name = "OPCODE_ITERATE_PACKED_VECTOR3_ARRAY",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_INT].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_PACKED_COLOR_ARRAY] = 
            {
              name = "OPCODE_ITERATE_PACKED_COLOR_ARRAY",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_INT].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_PACKED_VECTOR4_ARRAY] = 
            {
              name = "OPCODE_ITERATE_PACKED_VECTOR4_ARRAY",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_INT].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_OBJECT] = 
            {
              name = "OPCODE_ITERATE_OBJECT",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_INT].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_RANGE] =
            {
              name = "OPCODE_ITERATE_RANGE",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)

                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)

                local operand3 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 3])
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3) * 0x4, vtDword)

                local operand4 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 4])
                addStructureElem(contextTable.codeStructElement, operand4, (contextTable.instrPointer - 1 + 4) * 0x4, vtDword)

                addStructureElem(contextTable.codeStructElement, 'end: ', (contextTable.instrPointer - 1 + 4) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' for-loop ' .. operand4 .. ' in range to ' .. operand2 .. ' step ' .. operand3 .. ' counter ' .. operand1 .. ' end ' .. tostring(contextTable.codeInts[contextTable.instrPointer + 4])
                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 6
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_STORE_GLOBAL] =
            {
              name = "OPCODE_STORE_GLOBAL",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)

                local operand2 = (contextTable.codeInts[contextTable.instrPointer + 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)
                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand1 .. ' = ' .. operand2
                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 3

              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_STORE_NAMED_GLOBAL] =
            {
              name = "OPCODE_STORE_NAMED_GLOBAL",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                local operand2 = 'Globals[' .. contextTable.codeInts[contextTable.instrPointer + 2] .. ']'
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)
                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand1 .. ' = ' .. operand2
                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)
                return contextTable.instrPointer + 3
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL] =
            {
              name = "OPCODE_TYPE_ADJUST_BOOL",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                local opcodeType = contextTable.opcodeName:gsub('OPCODE_TYPE_ADJUST_', '')
                contextTable.opcodeName = contextTable.opcodeName .. ' (' .. opcodeType .. ') ' .. operand1
                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)
                return contextTable.instrPointer + 2

              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_INT] = 
            {
              name = "OPCODE_TYPE_ADJUST_INT",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_FLOAT] = 
            {
              name = "OPCODE_TYPE_ADJUST_FLOAT",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_STRING] = 
            {
              name = "OPCODE_TYPE_ADJUST_STRING",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_VECTOR2] = 
            {
              name = "OPCODE_TYPE_ADJUST_VECTOR2",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_VECTOR2I] = 
            {
              name = "OPCODE_TYPE_ADJUST_VECTOR2I",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_RECT2] = 
            {
              name = "OPCODE_TYPE_ADJUST_RECT2",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_RECT2I] = 
            {
              name = "OPCODE_TYPE_ADJUST_RECT2I",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_VECTOR3] = 
            {
              name = "OPCODE_TYPE_ADJUST_VECTOR3",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_VECTOR3I] = 
            {
              name = "OPCODE_TYPE_ADJUST_VECTOR3I",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_TRANSFORM2D] = 
            {
              name = "OPCODE_TYPE_ADJUST_TRANSFORM2D",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_VECTOR4] = 
            {
              name = "OPCODE_TYPE_ADJUST_VECTOR4",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_VECTOR4I] = 
            {
              name = "OPCODE_TYPE_ADJUST_VECTOR4I",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_PLANE] = 
            {
              name = "OPCODE_TYPE_ADJUST_PLANE",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_QUATERNION] = 
            {
              name = "OPCODE_TYPE_ADJUST_QUATERNION",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_AABB] = 
            {
              name = "OPCODE_TYPE_ADJUST_AABB",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BASIS] = 
            {
              name = "OPCODE_TYPE_ADJUST_BASIS",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_TRANSFORM3D] = 
            {
              name = "OPCODE_TYPE_ADJUST_TRANSFORM3D",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_PROJECTION] = 
            {
              name = "OPCODE_TYPE_ADJUST_PROJECTION",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_COLOR] = 
            {
              name = "OPCODE_TYPE_ADJUST_COLOR",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_STRING_NAME] = 
            {
              name = "OPCODE_TYPE_ADJUST_STRING_NAME",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_NODE_PATH] = 
            {
              name = "OPCODE_TYPE_ADJUST_NODE_PATH",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_RID] = 
            {
              name = "OPCODE_TYPE_ADJUST_RID",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_OBJECT] = 
            {
              name = "OPCODE_TYPE_ADJUST_OBJECT",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_CALLABLE] = 
            {
              name = "OPCODE_TYPE_ADJUST_CALLABLE",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_SIGNAL] = 
            {
              name = "OPCODE_TYPE_ADJUST_SIGNAL",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_DICTIONARY] = 
            {
              name = "OPCODE_TYPE_ADJUST_DICTIONARY",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_ARRAY] = 
            {
              name = "OPCODE_TYPE_ADJUST_ARRAY",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_PACKED_BYTE_ARRAY] = 
            {
              name = "OPCODE_TYPE_ADJUST_PACKED_BYTE_ARRAY",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_PACKED_INT32_ARRAY] = 
            {
              name = "OPCODE_TYPE_ADJUST_PACKED_INT32_ARRAY",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_PACKED_INT64_ARRAY] = 
            {
              name = "OPCODE_TYPE_ADJUST_PACKED_INT64_ARRAY",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_PACKED_FLOAT32_ARRAY] = 
            {
              name = "OPCODE_TYPE_ADJUST_PACKED_FLOAT32_ARRAY",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_PACKED_FLOAT64_ARRAY] = 
            {
              name = "OPCODE_TYPE_ADJUST_PACKED_FLOAT64_ARRAY",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_PACKED_STRING_ARRAY] = 
            {
              name = "OPCODE_TYPE_ADJUST_PACKED_STRING_ARRAY",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_PACKED_VECTOR2_ARRAY] = 
            {
              name = "OPCODE_TYPE_ADJUST_PACKED_VECTOR2_ARRAY",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_PACKED_VECTOR3_ARRAY] = 
            {
              name = "OPCODE_TYPE_ADJUST_PACKED_VECTOR3_ARRAY",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_PACKED_COLOR_ARRAY] = 
            {
              name = "OPCODE_TYPE_ADJUST_PACKED_COLOR_ARRAY",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_PACKED_VECTOR4_ARRAY] = 
            {
              name = "OPCODE_TYPE_ADJUST_PACKED_VECTOR4_ARRAY",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_TYPE_ADJUST_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_ASSERT] =
            {
              name = "OPCODE_ASSERT",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' (' .. operand1 .. ', ' .. operand2 .. ')'

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)
                return contextTable.instrPointer + 3
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_BREAKPOINT] =
            {
              name = "OPCODE_BREAKPOINT",
              handler = function(contextTable)
                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)
                return contextTable.instrPointer + 1
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_LINE] =
            {
              name = "OPCODE_LINE",
              handler = function(contextTable)
                local line = contextTable.codeInts[contextTable.instrPointer + 1] - 1
                if line > 0 --[[and line < p_code_lines.size()]] then
                  contextTable.opcodeName = contextTable.opcodeName .. ' ' .. tostring(line + 1) .. ': '
                else
                  contextTable.opcodeName = ''
                end
                addStructureElem(contextTable.codeStructElement, 'line: ', (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)
                return contextTable.instrPointer + 2
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_END] =
            {
              name = "OPCODE_END",
              handler = function(contextTable)
                addLayoutStructElem(contextTable.codeStructElement, '>>>END.', GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)
                return contextTable.instrPointer + 1
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_NO_RETURN] =
            {
              name = "OPCODE_CALL_PTRCALL_NO_RETURN",
              handler = function(contextTable)

                contextTable.instrPointer = contextTable.instrPointer + 1
                local instr_var_args = contextTable.codeInts[contextTable.instrPointer]
                addStructureElem(contextTable.codeStructElement, 'instr_var_args:', (contextTable.instrPointer - 1) * 0x4, vtDword)
                local argc = contextTable.codeInts[contextTable.instrPointer + 1 + instr_var_args]
                addStructureElem(contextTable.codeStructElement, 'argc:', (contextTable.instrPointer - 1 + 1 + instr_var_args) * 0x4, vtDword)

                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1 + argc])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1 + argc) * 0x4, vtDword)
                operand1 = operand1 .. '.'

                local operandArg = '';

                for i = 0, argc - 1 do
                  if i > 0 then
                    operandArg = operandArg .. ', '
                  end
                  operandArg = operandArg .. formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + i + 1])
                  addStructureElem(contextTable.codeStructElement, 'arg: ' .. formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + i + 1]), (contextTable.instrPointer - 1 + i + 1) * 0x4, vtDword)
                end

                local operand3 = '_methods_ptr[' .. contextTable.codeInts[contextTable.instrPointer + 2 + instr_var_args] .. ']'
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 2 + instr_var_args) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand1 .. operand3 .. '->getname()' .. '(' .. operandArg .. ')'

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1 - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 5 + argc

              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL] =
            {
              name = "OPCODE_CALL_PTRCALL_BOOL",
              handler = function(contextTable)

                contextTable.instrPointer = contextTable.instrPointer + 1
                local instr_var_args = contextTable.codeInts[contextTable.instrPointer]
                addStructureElem(contextTable.codeStructElement, 'instr_var_args:', (contextTable.instrPointer - 1) * 0x4, vtDword)

                local argc = contextTable.codeInts[contextTable.instrPointer + 1 + instr_var_args]
                addStructureElem(contextTable.codeStructElement, 'argc:', (contextTable.instrPointer - 1 + 1 + instr_var_args) * 0x4, vtDword)

                local operand2 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 2 + argc])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)

                local operand1 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 1 + argc])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1 + argc) * 0x4, vtDword)
                operand1 = operand1 .. '.'

                local operandArg = '';

                for i = 0, argc - 1 do
                  if i > 0 then
                    operandArg = operandArg .. ', '
                  end
                  operandArg = operandArg .. formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + i + 1])
                  addStructureElem(contextTable.codeStructElement, 'arg: ' .. formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + i + 1]), (contextTable.instrPointer - 1 + i + 1) * 0x4, vtDword)
                end

                local operand3 = '_methods_ptr[' .. contextTable.codeInts[contextTable.instrPointer + 2 + instr_var_args] .. ']'
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 2 + instr_var_args) * 0x4, vtDword)

                local opcodeType = contextTable.opcodeName:gsub('OPCODE_TYPE_ADJUST_', '')
                contextTable.opcodeName = contextTable.opcodeName .. '(return ' .. opcodeType .. ') ' .. operand2 .. ' = ' .. operand1 .. operand3 .. '->getname()' .. '(' .. operandArg .. ')'
                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1 - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 5 + argc
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_INT] = 
            {
              name = "OPCODE_CALL_PTRCALL_INT",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_FLOAT] = 
            {
              name = "OPCODE_CALL_PTRCALL_FLOAT",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_STRING] = 
            {
              name = "OPCODE_CALL_PTRCALL_STRING",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_VECTOR2] = 
            {
              name = "OPCODE_CALL_PTRCALL_VECTOR2",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_VECTOR2I] = 
            {
              name = "OPCODE_CALL_PTRCALL_VECTOR2I",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_RECT2] = 
            {
              name = "OPCODE_CALL_PTRCALL_RECT2",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_RECT2I] = 
            {
              name = "OPCODE_CALL_PTRCALL_RECT2I",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_VECTOR3] = 
            {
              name = "OPCODE_CALL_PTRCALL_VECTOR3",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_VECTOR3I] = 
            {
              name = "OPCODE_CALL_PTRCALL_VECTOR3I",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_TRANSFORM2D] = 
            {
              name = "OPCODE_CALL_PTRCALL_TRANSFORM2D",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_VECTOR4] = 
            {
              name = "OPCODE_CALL_PTRCALL_VECTOR4",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_VECTOR4I] = 
            {
              name = "OPCODE_CALL_PTRCALL_VECTOR4I",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_PLANE] = 
            {
              name = "OPCODE_CALL_PTRCALL_PLANE",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_QUATERNION] = 
            {
              name = "OPCODE_CALL_PTRCALL_QUATERNION",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_AABB] = 
            {
              name = "OPCODE_CALL_PTRCALL_AABB",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BASIS] = 
            {
              name = "OPCODE_CALL_PTRCALL_BASIS",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_TRANSFORM3D] = 
            {
              name = "OPCODE_CALL_PTRCALL_TRANSFORM3D",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_PROJECTION] = 
            {
              name = "OPCODE_CALL_PTRCALL_PROJECTION",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_COLOR] = 
            {
              name = "OPCODE_CALL_PTRCALL_COLOR",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_STRING_NAME] = 
            {
              name = "OPCODE_CALL_PTRCALL_STRING_NAME",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_NODE_PATH] = 
            {
              name = "OPCODE_CALL_PTRCALL_NODE_PATH",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_RID] = 
            {
              name = "OPCODE_CALL_PTRCALL_RID",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_OBJECT] = 
            {
              name = "OPCODE_CALL_PTRCALL_OBJECT",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_CALLABLE] = 
            {
              name = "OPCODE_CALL_PTRCALL_CALLABLE",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_SIGNAL] = 
            {
              name = "OPCODE_CALL_PTRCALL_SIGNAL",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_DICTIONARY] = 
            {
              name = "OPCODE_CALL_PTRCALL_DICTIONARY",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_ARRAY] = 
            {
              name = "OPCODE_CALL_PTRCALL_ARRAY",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_PACKED_BYTE_ARRAY] = 
            {
              name = "OPCODE_CALL_PTRCALL_PACKED_BYTE_ARRAY",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_PACKED_INT32_ARRAY] = 
            {
              name = "OPCODE_CALL_PTRCALL_PACKED_INT32_ARRAY",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_PACKED_INT64_ARRAY] = 
            {
              name = "OPCODE_CALL_PTRCALL_PACKED_INT64_ARRAY",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_PACKED_FLOAT32_ARRAY] = 
            {
              name = "OPCODE_CALL_PTRCALL_PACKED_FLOAT32_ARRAY",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_PACKED_FLOAT64_ARRAY] = 
            {
              name = "OPCODE_CALL_PTRCALL_PACKED_FLOAT64_ARRAY",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_PACKED_STRING_ARRAY] = 
            {
              name = "OPCODE_CALL_PTRCALL_PACKED_STRING_ARRAY",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_PACKED_VECTOR2_ARRAY] = 
            {
              name = "OPCODE_CALL_PTRCALL_PACKED_VECTOR2_ARRAY",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_PACKED_VECTOR3_ARRAY] = 
            {
              name = "OPCODE_CALL_PTRCALL_PACKED_VECTOR3_ARRAY",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_PACKED_COLOR_ARRAY] = 
            {
              name = "OPCODE_CALL_PTRCALL_PACKED_COLOR_ARRAY",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_PTRCALL_BOOL].handler
            }

        GDF.Decoders = {}

          GDF.Decoders.BytecodeV0 =
            {
              name = "BytecodeV0",
              resolveOPHandlerDefFromProfile = function(profile, opcodeEnum)
                if profile.OPEnumFromInternalOPID[GDF.OP.OPCODE_OPERATOR] == opcodeEnum then
                if profile.OPEnumFromInternalOPID[GDF.OP.OPCODE_OPERATOR] == opcodeEnum then
                  local base = profile.OPHandlerDefFromOPEnum[opcodeEnum]
                  profile.OPHandlerDefFromOPEnum[opcodeEnum] = {
                    name = base.name,
                    handler = function(contextTable)
                      local _pointer_size = GDDEFS.PTRSIZE / 0x4
                      local operation = contextTable.codeInts[contextTable.instrPointer + 4] -- operator is 4*0x4 after
                      addStructureElem(contextTable.codeStructElement, 'Operator: ', (contextTable.instrPointer - 1 + 4) * 0x4, vtDword)
                      local operationName = GDF.OPERATOR_NAME[operation + 1] or 'UNKNOWN_OPERATOR'
                      local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                      addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                      local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2])
                      addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)
                      local operand3 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 3]) -- where to store
                      addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3) * 0x4, vtDword)
                      contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand3 .. ' = ' .. operand1 .. ' ' .. operationName .. ' ' .. operand2
                      addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)
                      return contextTable.instrPointer + 5
                    end
                  }
                end
                end
                return profile.OPHandlerDefFromOPEnum[opcodeEnum]
              end
            }
          GDF.Decoders.BytecodeV1 =
            {
              name = "BytecodeV1",
              resolveOPHandlerDefFromProfile = function(profile, opcodeEnum)
                if profile.OPEnumFromInternalOPID[GDF.OP.OPCODE_OPERATOR] == opcodeEnum then
                  local base = profile.OPHandlerDefFromOPEnum[opcodeEnum]
                  profile.OPHandlerDefFromOPEnum[opcodeEnum] = {
                    name = base.name,
                    handler = function(contextTable)
                      local _pointer_size = GDDEFS.PTRSIZE / 0x4
                      local operation = contextTable.codeInts[contextTable.instrPointer + 4] -- operator is 4*0x4 after
                      addStructureElem(contextTable.codeStructElement, 'Operator: ', (contextTable.instrPointer - 1 + 4) * 0x4, vtDword)
                      local operationName = GDF.OPERATOR_NAME[operation + 1] or 'UNKNOWN_OPERATOR'
                      local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                      addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                      local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2])
                      addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)
                      local operand3 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 3]) -- where to store
                      addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3) * 0x4, vtDword)
                      contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand3 .. ' = ' .. operand1 .. ' ' .. operationName .. ' ' .. operand2
                      addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)
                      return contextTable.instrPointer + 7 + _pointer_size
                    end
                  }
                end

                return profile.OPHandlerDefFromOPEnum[opcodeEnum]
              end
            }

        GDF.ProfileSpecs =
          {
            ["4.0"] =
              {
                decoderName = "BytecodeV0",
                orderedOpcodes =
                {
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

            ["4.1"] =
              {
                base = "4.0",
                decoderName = "BytecodeV0",
                patches = 
                {
                  {
                    kind = "insertValueAfter",
                    anchor = GDF.OP.OPCODE_GET_MEMBER,
                    value = GDF.OP.OPCODE_SET_STATIC_VARIABLE
                  },
                  {
                    kind = "insertValueAfter",
                    anchor = GDF.OP.OPCODE_SET_STATIC_VARIABLE,
                    value = GDF.OP.OPCODE_GET_STATIC_VARIABLE
                  }
                }
              },

            ["4.2"] =
              {
                base = "4.1",
                decoderName = "BytecodeV1",
                patches =
                {
                  {
                    kind = "insertValueAfter",
                    anchor = GDF.OP.OPCODE_CALL_NATIVE_STATIC,
                    value = GDF.OP.OPCODE_CALL_METHOD_BIND_VALIDATED_RETURN
                  },
                  {
                    kind = "insertValueAfter",
                    anchor = GDF.OP.OPCODE_CALL_METHOD_BIND_VALIDATED_RETURN,
                    value = GDF.OP.OPCODE_CALL_METHOD_BIND_VALIDATED_NO_RETURN
                  },
                  {
                    kind = "removeValue",
                    value = GDF.OP.OPCODE_CALL_PTRCALL_NO_RETURN
                  },
                  {
                    kind = "removeValue",
                    value = GDF.OP.OPCODE_CALL_PTRCALL_BOOL
                  },
                  {
                    kind = "removeValue",
                    value = GDF.OP.OPCODE_CALL_PTRCALL_INT
                  },
                  {
                    kind = "removeValue",
                    value = GDF.OP.OPCODE_CALL_PTRCALL_FLOAT
                  },
                  {
                    kind = "removeValue",
                    value = GDF.OP.OPCODE_CALL_PTRCALL_STRING
                  },
                  {
                    kind = "removeValue",
                    value = GDF.OP.OPCODE_CALL_PTRCALL_VECTOR2
                  },
                  {
                    kind = "removeValue",
                    value = GDF.OP.OPCODE_CALL_PTRCALL_VECTOR2I
                  },
                  {
                    kind = "removeValue",
                    value = GDF.OP.OPCODE_CALL_PTRCALL_RECT2
                  },
                  {
                    kind = "removeValue",
                    value = GDF.OP.OPCODE_CALL_PTRCALL_RECT2I
                  },
                  {
                    kind = "removeValue",
                    value = GDF.OP.OPCODE_CALL_PTRCALL_VECTOR3
                  },
                  {
                    kind = "removeValue",
                    value = GDF.OP.OPCODE_CALL_PTRCALL_VECTOR3I
                  },
                  {
                    kind = "removeValue",
                    value = GDF.OP.OPCODE_CALL_PTRCALL_TRANSFORM2D
                  },
                  {
                    kind = "removeValue",
                    value = GDF.OP.OPCODE_CALL_PTRCALL_VECTOR4
                  },
                  {
                    kind = "removeValue",
                    value = GDF.OP.OPCODE_CALL_PTRCALL_VECTOR4I
                  },
                  {
                    kind = "removeValue",
                    value = GDF.OP.OPCODE_CALL_PTRCALL_PLANE
                  },
                  {
                    kind = "removeValue",
                    value = GDF.OP.OPCODE_CALL_PTRCALL_QUATERNION
                  },
                  {
                    kind = "removeValue",
                    value = GDF.OP.OPCODE_CALL_PTRCALL_AABB
                  },
                  {
                    kind = "removeValue",
                    value = GDF.OP.OPCODE_CALL_PTRCALL_BASIS
                  },
                  {
                    kind = "removeValue",
                    value = GDF.OP.OPCODE_CALL_PTRCALL_TRANSFORM3D
                  },
                  {
                    kind = "removeValue",
                    value = GDF.OP.OPCODE_CALL_PTRCALL_PROJECTION
                  },
                  {
                    kind = "removeValue",
                    value = GDF.OP.OPCODE_CALL_PTRCALL_COLOR
                  },
                  {
                    kind = "removeValue",
                    value = GDF.OP.OPCODE_CALL_PTRCALL_STRING_NAME
                  },
                  {
                    kind = "removeValue",
                    value = GDF.OP.OPCODE_CALL_PTRCALL_NODE_PATH
                  },
                  {
                    kind = "removeValue",
                    value = GDF.OP.OPCODE_CALL_PTRCALL_RID
                  },
                  {
                    kind = "removeValue",
                    value = GDF.OP.OPCODE_CALL_PTRCALL_OBJECT
                  },
                  {
                    kind = "removeValue",
                    value = GDF.OP.OPCODE_CALL_PTRCALL_CALLABLE
                  },
                  {
                    kind = "removeValue",
                    value = GDF.OP.OPCODE_CALL_PTRCALL_SIGNAL
                  },
                  {
                    kind = "removeValue",
                    value = GDF.OP.OPCODE_CALL_PTRCALL_DICTIONARY
                  },
                  {
                    kind = "removeValue",
                    value = GDF.OP.OPCODE_CALL_PTRCALL_ARRAY
                  },
                  {
                    kind = "removeValue",
                    value = GDF.OP.OPCODE_CALL_PTRCALL_PACKED_BYTE_ARRAY
                  },
                  {
                    kind = "removeValue",
                    value = GDF.OP.OPCODE_CALL_PTRCALL_PACKED_INT32_ARRAY
                  },
                  {
                    kind = "removeValue",
                    value = GDF.OP.OPCODE_CALL_PTRCALL_PACKED_INT64_ARRAY
                  },
                  {
                    kind = "removeValue",
                    value = GDF.OP.OPCODE_CALL_PTRCALL_PACKED_FLOAT32_ARRAY
                  },
                  {
                    kind = "removeValue",
                    value = GDF.OP.OPCODE_CALL_PTRCALL_PACKED_FLOAT64_ARRAY
                  },
                  {
                    kind = "removeValue",
                    value = GDF.OP.OPCODE_CALL_PTRCALL_PACKED_STRING_ARRAY
                  },
                  {
                    kind = "removeValue",
                    value = GDF.OP.OPCODE_CALL_PTRCALL_PACKED_VECTOR2_ARRAY
                  },
                  {
                    kind = "removeValue",
                    value = GDF.OP.OPCODE_CALL_PTRCALL_PACKED_VECTOR3_ARRAY
                  },
                  {
                    kind = "removeValue",
                    value = GDF.OP.OPCODE_CALL_PTRCALL_PACKED_COLOR_ARRAY
                
                  }
                }
              },

            ["4.3"] =
              {
                base = "4.2",
                decoderName = "BytecodeV1",
                patches =
                {
                  {
                    kind = "insertValueAfter",
                    anchor = GDF.OP.OPCODE_ASSIGN,
                    value = GDF.OP.OPCODE_ASSIGN_NULL
                  },
                  {
                    kind = "insertValueAfter",
                    anchor = GDF.OP.OPCODE_CALL_NATIVE_STATIC,
                    value = GDF.OP.OPCODE_CALL_NATIVE_STATIC_VALIDATED_RETURN
                  },
                  {
                    kind = "insertValueAfter",
                    anchor = GDF.OP.OPCODE_CALL_NATIVE_STATIC_VALIDATED_RETURN,
                    value = GDF.OP.OPCODE_CALL_NATIVE_STATIC_VALIDATED_NO_RETURN
                  },
                  {
                    kind = "insertValueAfter",
                    anchor = GDF.OP.OPCODE_ITERATE_BEGIN_PACKED_COLOR_ARRAY,
                    value = GDF.OP.OPCODE_ITERATE_BEGIN_PACKED_VECTOR4_ARRAY
                  },
                  {
                    kind = "insertValueAfter",
                    anchor = GDF.OP.OPCODE_ITERATE_PACKED_COLOR_ARRAY,
                    value = GDF.OP.OPCODE_ITERATE_PACKED_VECTOR4_ARRAY
                  },
                  {
                    kind = "insertValueAfter",
                    anchor = GDF.OP.OPCODE_TYPE_ADJUST_PACKED_COLOR_ARRAY,
                    value = GDF.OP.OPCODE_TYPE_ADJUST_PACKED_VECTOR4_ARRAY
                  }
                }
              },

            ["4.4"] =
              {
                base = "4.3",
                decoderName = "BytecodeV1",
                patches =
                {
                  {
                    kind = "insertValueAfter",
                    anchor = GDF.OP.OPCODE_TYPE_TEST_ARRAY,
                    value = GDF.OP.OPCODE_TYPE_TEST_DICTIONARY
                  },
                  {
                    kind = "insertValueAfter",
                    anchor = GDF.OP.OPCODE_ASSIGN_TYPED_ARRAY,
                    value = GDF.OP.OPCODE_ASSIGN_TYPED_DICTIONARY
                  },
                  {
                    kind = "insertValueAfter",
                    anchor = GDF.OP.OPCODE_CONSTRUCT_DICTIONARY,
                    value = GDF.OP.OPCODE_CONSTRUCT_TYPED_DICTIONARY
                  },
                  {
                    kind = "insertValueAfter",
                    anchor = GDF.OP.OPCODE_RETURN_TYPED_ARRAY,
                    value = GDF.OP.OPCODE_RETURN_TYPED_DICTIONARY
                  }
                }
              },

            ["4.5"] =
              {
                base = "4.4",
                decoderName = "BytecodeV1",
                patches =
                {
                  {
                    kind = "insertValueAfter",
                    anchor = GDF.OP.OPCODE_ITERATE_BEGIN_OBJECT,
                    value = GDF.OP.OPCODE_ITERATE_BEGIN_RANGE
                  },
                  {
                    kind = "insertValueAfter",
                    anchor = GDF.OP.OPCODE_ITERATE_OBJECT,
                    value = GDF.OP.OPCODE_ITERATE_RANGE
                  }
                }
              },

            ["4.6"] =
              {
                base = "4.5",
                decoderName = "BytecodeV1",
                patches = {}
              },
            ["4.7"] =
              {
                base = "4.6",
                decoderName = "BytecodeV1",
                patches = {}
              },
            ["4.8"] =
              {
                base = "4.7",
                decoderName = "BytecodeV1",
                patches = {}
              }
          }
        GDF.CompiledProfiles = {}
        GDF.EADDRESS =
          {
            ['ADDR_BITS'] = 24,
            ['ADDR_MASK'] = ((1 << 24) - 1), -- ((1 << ADDR_BITS) - 1)
            ['ADDR_TYPE_MASK'] = ~((1 << 24) - 1),
            ['ADDR_TYPE_STACK'] = 0,
            ['ADDR_TYPE_CONSTANT'] = 1,
            ['ADDR_TYPE_MEMBER'] = 2,
            ['ADDR_TYPE_MAX'] = 3
          }
        GDF.EFIXEDADDRESSES =
          {
            ['ADDR_STACK_SELF'] = 0,
            ['ADDR_STACK_CLASS'] = 1,
            ['ADDR_STACK_NIL'] = 2,
            ['FIXED_ADDRESSES_MAX'] = 3,
            ['ADDR_SELF'] = 0 | GDF.EADDRESS['ADDR_TYPE_STACK'] << GDF.EADDRESS['ADDR_BITS'],
            ['ADDR_CLASS'] = 1 | GDF.EADDRESS['ADDR_TYPE_STACK'] << GDF.EADDRESS['ADDR_BITS'],
            ['ADDR_NIL'] = 2 | GDF.EADDRESS['ADDR_TYPE_STACK'] << GDF.EADDRESS['ADDR_BITS']
          }
        GDF.OPERATOR_NAME =
          {
            -- comparison
            "OP_EQUAL",
            "OP_NOT_EQUAL",
            "OP_LESS",
            "OP_LESS_EQUAL",
            "OP_GREATER",
            "OP_GREATER_EQUAL",
            -- mathematic
            "OP_ADD",
            "OP_SUBTRACT",
            "OP_MULTIPLY",
            "OP_DIVIDE",
            "OP_NEGATE",
            "OP_POSITIVE", 
            "OP_MODULE",
            "OP_POWER",
            -- bitwise
            "OP_SHIFT_LEFT",
            "OP_SHIFT_RIGHT",
            "OP_BIT_AND",
            "OP_BIT_OR",
            "OP_BIT_XOR",
            "OP_BIT_NEGATE",
            -- logic
            "OP_AND",
            "OP_OR",
            "OP_XOR",
            "OP_NOT",
            -- containment
            "OP_IN",
            "OP_MAX" -- 25
          }

        for version, _ in pairs(GDF.ProfileSpecs) do
          GDF.CompiledProfiles[version] = createProfileFromVersion(version)
        end

        if GDDEFS.VERSION_STRING then
          GDF.CurrentDisassembler = GDF.createDisassemblerFromVersion(GDDEFS.VERSION_STRING)
        end

      else--if GDDEFS.MAJOR_VER <= 3 then

        formatDisassembledAddress = function(addrInt) -- redefined for 3.x
          local addrIndex = addrInt & (GDF.EADDRESS['ADDR_MASK']) -- address, lower 24 bits are indices
          local addrType = ( (addrInt & GDF.EADDRESS['ADDR_TYPE_MASK']) >> GDF.EADDRESS['ADDR_BITS']) -- the higher 8 would be types: shift to the beginning and mask

          if addrType == 0 and (addrIndex >= 0 and addrIndex <= 3) then
            if addrIndex == GDF.EADDRESS['ADDR_TYPE_SELF'] then    return "stack(self)" end -- return &self;
            if addrIndex == GDF.EADDRESS['ADDR_TYPE_CLASS'] then   return "stack(class)" end -- &static_ref;
            if addrIndex == GDF.EADDRESS['ADDR_TYPE_NIL'] then     return "stack(nil)" end -- return &nil
                                                                    return 'stack[' .. tostring(addrIndex) .. ']'
          end

          if (addrType == GDF.EADDRESS['ADDR_TYPE_STACK']) then               return ("stack[%d]"):format(addrIndex) -- return &p_stack[address];
          elseif (addrType == GDF.EADDRESS['ADDR_TYPE_STACK_VARIABLE']) then  return ("stack[%d]"):format(addrIndex) -- return &p_stack[address];
          elseif (addrType == GDF.EADDRESS['ADDR_TYPE_CLASS_CONSTANT']) then  return ("Node Constants[%d]"):format(addrIndex) -- Map<StringName, Variant>::Element *E = o->constants.find(*sn); return &E->get();
          elseif (addrType == GDF.EADDRESS['ADDR_TYPE_LOCAL_CONSTANT']) then  return ("Constants[%d]"):format(addrIndex) -- return &_constants_ptr[address];
          elseif (addrType == GDF.EADDRESS['ADDR_TYPE_GLOBAL']) then          return ("ScriptLang::GlobArray[%d]"):format(addrIndex) -- return &GDScriptLanguage::get_singleton()->get_global_array()[address];
          elseif (addrType == GDF.EADDRESS['ADDR_TYPE_MEMBER']) then          return ("Variants[%d]"):format(addrIndex) -- for clarity ("member[%d]"):format(addrIndex)
          else                                                                return ("addr?(0x%08X)"):format(addrInt)
          end
        end

        GDF.OP =
          {
            OPCODE_OPERATOR = "OPCODE_OPERATOR", -- 0
            OPCODE_EXTENDS_TEST = "OPCODE_EXTENDS_TEST", -- 1
            OPCODE_IS_BUILTIN = "OPCODE_IS_BUILTIN", -- 2
            OPCODE_SET = "OPCODE_SET", -- 3
            OPCODE_GET = "OPCODE_GET", -- 4
            OPCODE_SET_NAMED = "OPCODE_SET_NAMED", -- 5
            OPCODE_GET_NAMED = "OPCODE_GET_NAMED", -- 6
            OPCODE_SET_MEMBER = "OPCODE_SET_MEMBER", -- 7
            OPCODE_GET_MEMBER = "OPCODE_GET_MEMBER", -- 8
            OPCODE_ASSIGN = "OPCODE_ASSIGN", -- 9
            OPCODE_ASSIGN_TRUE = "OPCODE_ASSIGN_TRUE", -- 10
            OPCODE_ASSIGN_FALSE = "OPCODE_ASSIGN_FALSE", -- 11
            OPCODE_ASSIGN_TYPED_BUILTIN = "OPCODE_ASSIGN_TYPED_BUILTIN", -- 12
            OPCODE_ASSIGN_TYPED_NATIVE = "OPCODE_ASSIGN_TYPED_NATIVE", -- 13
            OPCODE_ASSIGN_TYPED_SCRIPT = "OPCODE_ASSIGN_TYPED_SCRIPT", -- 14
            OPCODE_CAST_TO_BUILTIN = "OPCODE_CAST_TO_BUILTIN", -- 15
            OPCODE_CAST_TO_NATIVE = "OPCODE_CAST_TO_NATIVE", -- 16
            OPCODE_CAST_TO_SCRIPT = "OPCODE_CAST_TO_SCRIPT", -- 17
            OPCODE_CONSTRUCT = "OPCODE_CONSTRUCT", -- 18
            OPCODE_CONSTRUCT_ARRAY = "OPCODE_CONSTRUCT_ARRAY", -- 19
            OPCODE_CONSTRUCT_DICTIONARY = "OPCODE_CONSTRUCT_DICTIONARY", -- 20
            OPCODE_CALL = "OPCODE_CALL", -- 21
            OPCODE_CALL_RETURN = "OPCODE_CALL_RETURN", -- 22
            OPCODE_CALL_BUILT_IN = "OPCODE_CALL_BUILT_IN", -- 23
            OPCODE_CALL_SELF = "OPCODE_CALL_SELF", -- 24
            OPCODE_CALL_SELF_BASE = "OPCODE_CALL_SELF_BASE", -- 25
            OPCODE_YIELD = "OPCODE_YIELD", -- 26
            OPCODE_YIELD_SIGNAL = "OPCODE_YIELD_SIGNAL", -- 27
            OPCODE_YIELD_RESUME = "OPCODE_YIELD_RESUME", -- 28
            OPCODE_JUMP = "OPCODE_JUMP", -- 29
            OPCODE_JUMP_IF = "OPCODE_JUMP_IF", -- 30
            OPCODE_JUMP_IF_NOT = "OPCODE_JUMP_IF_NOT", -- 31
            OPCODE_JUMP_TO_DEF_ARGUMENT = "OPCODE_JUMP_TO_DEF_ARGUMENT", -- 32
            OPCODE_RETURN = "OPCODE_RETURN", -- 33
            OPCODE_ITERATE_BEGIN = "OPCODE_ITERATE_BEGIN", -- 34
            OPCODE_ITERATE = "OPCODE_ITERATE", -- 35
            OPCODE_ASSERT = "OPCODE_ASSERT", -- 36
            OPCODE_BREAKPOINT = "OPCODE_BREAKPOINT", -- 37
            OPCODE_LINE = "OPCODE_LINE", -- 38
            OPCODE_END = "OPCODE_END" -- 39 (enum)
          }
        
        GDF.DisasmHandlers = {}

          GDF.DisasmHandlers[GDF.OP.OPCODE_OPERATOR] =
            {

              name = "OPCODE_OPERATOR",
              handler = function(contextTable)

                local operation = contextTable.codeInts[contextTable.instrPointer + 1] -- operator is 4*0x4 after
                addStructureElem(contextTable.codeStructElement, 'Operator: ', (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)

                local operationName = GDF.OPERATOR_NAME[operation + 1] or 'UNKNOWN_OPERATOR'
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2]) -- a
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)
                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 3]) -- b
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 3) * 0x4, vtDword)
                local operand3 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 4]) -- dest
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 4) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand3 .. ' = ' .. operand1 .. ' ' .. operationName .. ' ' .. operand2
                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 5
              end
            }

          GDF.DisasmHandlers[GDF.OP.OPCODE_EXTENDS_TEST] =
            {

              name = "OPCODE_EXTENDS_TEST",
              handler = function(contextTable)

                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)
                local operand3 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 3]) -- dest
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand3 .. ' = ' .. operand1 .. ' extends' .. ' ' .. operand2 .. ' ?'
                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 4
              end
            }

          GDF.DisasmHandlers[GDF.OP.OPCODE_IS_BUILTIN] =
            {

              name = "OPCODE_IS_BUILTIN",
              handler = function(contextTable)

                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1]) -- value
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                local operand2 = getGDTypeName(contextTable.codeInts[contextTable.instrPointer + 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)
                local operand3 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 3]) -- dest
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand3 .. ' = ' .. operand1 .. ' is built-in type ' .. ' ' .. operand2 .. ' ?'
                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 4
              end
            }

          GDF.DisasmHandlers[GDF.OP.OPCODE_SET] = 
            {
              name = "OPCODE_SET",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1]) -- dest
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2]) -- index
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)
                local operand3 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 3]) -- value
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3) * 0x4, vtDword)
                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand1 .. '[' .. operand2 .. '] = ' .. operand3
                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)
                return contextTable.instrPointer + 4
              end
            }


          GDF.DisasmHandlers[GDF.OP.OPCODE_GET] = 
            {
              name = "OPCODE_GET",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1]) -- src
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2]) -- index
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)
                local operand3 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 3]) -- dest
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand3 .. ' = ' .. operand1 .. '[' .. operand2 .. ']'

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 4
              end
            }

          GDF.DisasmHandlers[GDF.OP.OPCODE_SET_NAMED] = 
            {
              name = "OPCODE_SET_NAMED",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1]) -- dest
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                local operand2 = 'Globals[' .. contextTable.codeInts[contextTable.instrPointer + 2] .. ']' -- globals index
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)
                local operand3 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 3]) -- value
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand1 .. '= ["' .. operand2 .. '"] = ' .. operand3

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 4
              end
            }

          GDF.DisasmHandlers[GDF.OP.OPCODE_GET_NAMED] = 
            {
              name = "OPCODE_GET_NAMED",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1]) -- source
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                local operand2 = 'Globals[' .. contextTable.codeInts[contextTable.instrPointer + 2] .. ']' -- globals index
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)
                local operand3 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 3]) -- dest
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand3 .. ' = ' .. operand1 .. '["' .. operand2 .. '"]'

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 4
              end
            }

          GDF.DisasmHandlers[GDF.OP.OPCODE_SET_MEMBER] = 
            {
              name = "OPCODE_SET_MEMBER",
              handler = function(contextTable)
                
                local operand1 = 'Globals[' .. contextTable.codeInts[contextTable.instrPointer + 1] .. ']' -- index
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2]) -- src
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. '["' .. operand1 .. '"] = ' .. operand2

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 3
              end
            }

          GDF.DisasmHandlers[GDF.OP.OPCODE_GET_MEMBER] = 
            {
              name = "OPCODE_GET_MEMBER",
              handler = function(contextTable)
                local operand1 = 'Globals[' .. contextTable.codeInts[contextTable.instrPointer + 1] .. ']' -- index
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2]) -- dest
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand2 .. ' = ["' .. operand1 .. '"]'

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 3
              end
            }

          GDF.DisasmHandlers[GDF.OP.OPCODE_ASSIGN] = 
            {
              name = "OPCODE_ASSIGN",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1]) -- dest
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2]) -- src
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand1 .. ' = ' .. operand2

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 3
              end
            }

          GDF.DisasmHandlers[GDF.OP.OPCODE_ASSIGN_TRUE] = 
            {
              name = "OPCODE_ASSIGN_TRUE",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand1 .. ' = TRUE'
                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)
                return contextTable.instrPointer + 2
              end
            }

          GDF.DisasmHandlers[GDF.OP.OPCODE_ASSIGN_FALSE] = 
            {
              name = "OPCODE_ASSIGN_FALSE",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand1 .. ' = FALSE'

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 2
              end
            }

            GDF.DisasmHandlers[GDF.OP.OPCODE_ASSIGN_TYPED_BUILTIN] = 
              {
                name = "OPCODE_ASSIGN_TYPED_BUILTIN",
                handler = function(contextTable)
                  local operand1 = getGDTypeName(contextTable.codeInts[contextTable.instrPointer + 1])
                  addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword) -- type
                  local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2])
                  addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)  -- dest
                  local operand3 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 3])
                  addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3) * 0x4, vtDword) -- src

                  contextTable.opcodeName = contextTable.opcodeName .. ' (' .. operand1 .. ') ' .. operand2 .. ' = ' .. operand3

                  addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                  return contextTable.instrPointer + 4
                end
              }

          GDF.DisasmHandlers[GDF.OP.OPCODE_ASSIGN_TYPED_NATIVE] = 
            {
              name = "OPCODE_ASSIGN_TYPED_NATIVE",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword) -- type
                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword) -- dest
                local operand3 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 3])
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3) * 0x4, vtDword) -- src

                contextTable.opcodeName = contextTable.opcodeName .. ' (' .. operand1 .. ')' .. operand2 .. ' = ' .. operand3

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 4
              end
            }

          GDF.DisasmHandlers[GDF.OP.OPCODE_ASSIGN_TYPED_SCRIPT] = 
            {
              name = "OPCODE_ASSIGN_TYPED_SCRIPT",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword) -- script type
                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword) -- dest
                local operand3 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 3])
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3) * 0x4, vtDword) -- src

                contextTable.opcodeName = contextTable.opcodeName .. ' (' .. operand1 .. ') ' .. operand2 .. ' = ' .. operand3

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 4
              end
            }

          GDF.DisasmHandlers[GDF.OP.OPCODE_CAST_TO_BUILTIN] = 
            {
              name = "OPCODE_CAST_TO_BUILTIN",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword) -- to_type
                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword) -- src
                local operand3 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 3])
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3) * 0x4, vtDword) -- dest

                local operand1_n = getGDTypeName(contextTable.codeInts[contextTable.instrPointer + 1])

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand3 .. ' = ' .. operand2 .. ' as ' .. operand1_n

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 4
              end
            }

          GDF.DisasmHandlers[GDF.OP.OPCODE_CAST_TO_NATIVE] = 
            {
              name = "OPCODE_CAST_TO_NATIVE",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword) -- to_type
                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword) -- src
                local operand3 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 3])
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3) * 0x4, vtDword) -- dest

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand3 .. ' = ' .. operand2 .. ' as GDScriptNativeClass ' .. operand1

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 4
              end
            }

          GDF.DisasmHandlers[GDF.OP.OPCODE_CAST_TO_SCRIPT] = 
            {
              name = "OPCODE_CAST_TO_SCRIPT",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword) -- to_type
                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword) -- src
                local operand3 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 3])
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3) * 0x4, vtDword) -- dest

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand3 .. ' = ' .. operand2 .. ' as Script ' .. operand1

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 4
              end
            }

          GDF.DisasmHandlers[GDF.OP.OPCODE_CONSTRUCT] = 
            {
              name = "OPCODE_CONSTRUCT",
              handler = function(contextTable)
                
                local typeName = getGDTypeName(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, typeName, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword) -- Variant::Type

                local argc = contextTable.codeInts[contextTable.instrPointer + 2]
                addStructureElem(contextTable.codeStructElement, 'argc:', (contextTable.instrPointer - 1 + 2) * 0x4, vtDword) -- argc

                local operand3 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 3 + argc])
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3 + argc) * 0x4, vtDword) -- dest
                local operandArg = '';

                for i = 0, argc - 1 do
                  if i > 0 then
                    operandArg = operandArg .. ', '
                  end
                  operandArg = operandArg .. formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 3 + i]) -- argptrs[i] = Arg;
                  addStructureElem(contextTable.codeStructElement, 'arg: ' .. formatDisassembledAddress(contextTable.codeInts[3 + i]), (contextTable.instrPointer - 1 + 3 + i) * 0x4, vtDword)
                end

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand3 .. ' = ' .. typeName .. '(' .. operandArg .. ')'

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 4 + argc
              end
            }

          GDF.DisasmHandlers[GDF.OP.OPCODE_CONSTRUCT_ARRAY] = 
            {
              name = "OPCODE_CONSTRUCT_ARRAY",
              handler = function(contextTable)

                local argc = contextTable.codeInts[contextTable.instrPointer + 1]
                addStructureElem(contextTable.codeStructElement, 'argc:', (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)

                local operandArg = '';

                for i = 0, argc - 1 do
                  if i > 0 then
                    operandArg = operandArg .. ', '
                  end
                  operandArg = operandArg .. formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 2 + i])
                  addStructureElem(contextTable.codeStructElement, 'arg: ' .. formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2 + i]), (contextTable.instrPointer - 1 + 2 + i) * 0x4, vtDword)
                end

                local operand2 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 2 + argc])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2 + argc) * 0x4, vtDword) -- dest

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand2 .. ' = ' .. '[' .. operandArg .. ']'

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 3 + argc
              end
            }

          GDF.DisasmHandlers[GDF.OP.OPCODE_CONSTRUCT_DICTIONARY] = 
            {
              name = "OPCODE_CONSTRUCT_DICTIONARY",
              handler = function(contextTable)
                -- contextTable.instrPointer = contextTable.instrPointer + 1
                
                local argc = contextTable.codeInts[contextTable.instrPointer + 1]
                addStructureElem(contextTable.codeStructElement, 'argc:', (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)

                local operand2 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + argc * 2 + 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + argc * 2 + 2) * 0x4, vtDword)

                local operandArg = '';

                for i = 0, argc - 1 do
                  if i > 0 then
                    operandArg = operandArg .. ', '
                  end
                  operandArg = operandArg .. formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 2 + i * 2 + 0])
                  addStructureElem(contextTable.codeStructElement, 'argK: ' .. formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2 + i * 2 + 0]), (contextTable.instrPointer - 1 + 2 + i * 2 + 0) * 0x4, vtDword)
                  operandArg = operandArg .. ': ' .. formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + 2 + i * 2 + 1])
                  addStructureElem(contextTable.codeStructElement, 'argV: ' .. formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2 + i * 2 + 1]), (contextTable.instrPointer - 1 + 2 + i * 2 + 1) * 0x4, vtDword)
                end

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand2 .. ' =  {' .. operandArg .. '  }'

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 3 + argc * 2

              end
            }

          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL] = 
            {
              name = "OPCODE_CALL",
              handler = function(contextTable)

                local ret = contextTable.codeInts[contextTable.instrPointer] == GDF.CurrentDisassembler:getOPEnumFromInternalOPID(GDF.OP.OPCODE_CALL_RETURN)

                local argc = contextTable.codeInts[contextTable.instrPointer + 1]
                addStructureElem(contextTable.codeStructElement, 'argc:', (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)

                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword) -- base

                local operand3 = 'Globals[' .. (contextTable.codeInts[contextTable.instrPointer + 3]) .. ']'
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3) * 0x4, vtDword) -- nameg then *methodname

                contextTable.instrPointer = contextTable.instrPointer + 4

                local operandArg = '';
                for i = 0, argc - 1 do
                  if i > 0 then
                    operandArg = operandArg .. ', '
                  end
                  operandArg = operandArg .. formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + i])
                  addStructureElem(contextTable.codeStructElement, 'arg: ' .. formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + i]), (contextTable.instrPointer - 1 + i) * 0x4, vtDword)
                end

                local operand_arg = ''
                if (ret) then
                  operand_arg = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + argc])
                  addStructureElem(contextTable.codeStructElement, operand_arg, (contextTable.instrPointer - 1 + argc) * 0x4, vtDword)
                  operand_arg = operand_arg .. ' = '
                end

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand_arg .. operand2 .. '.' .. '[' .. operand3 .. ']' .. '(' .. operandArg .. ')' -- base->call_ptr(*methodname, (const Variant **)argptrs, argc, nullptr, err);
                
                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1 - 4) * 0x4, vtDword) -- decrementing to get the original instruction
                
                return contextTable.instrPointer + argc + 1
              end
            }
          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_RETURN] =
            {
              name = "OPCODE_CALL_RETURN",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_CALL].handler
            }

          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_BUILT_IN] = 
            {
              name = "OPCODE_CALL_BUILT_IN",
              handler = function(contextTable)

                local operand1 = contextTable.codeInts[contextTable.instrPointer + 1]
                operand1 = "GDScriptFunctions::Function(" .. operand1 .. ")"
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword) -- func   GDScriptFunctions::Function func = GDScriptFunctions::Function(_code_ptr[ip + 1]);

                local argc = contextTable.codeInts[contextTable.instrPointer + 2]
                addStructureElem(contextTable.codeStructElement, 'argc:', (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)

                contextTable.instrPointer = contextTable.instrPointer + 3

                local operand_argc = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + argc])
                addStructureElem(contextTable.codeStructElement, operand_argc, (contextTable.instrPointer - 1 + argc) * 0x4, vtDword) -- dest

                local operandArg = '';

                for i = 0, argc - 1 do
                  if i > 0 then
                    operandArg = operandArg .. ', '
                  end
                  operandArg = operandArg .. formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + i])
                  addStructureElem(contextTable.codeStructElement, 'arg: ' .. formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + i]), (contextTable.instrPointer - 1 + i) * 0x4, vtDword)
                end

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand_argc .. ' = ' .. "builtin_methods_names[" .. operand1 .. "]" .. '(' .. operandArg .. ')' -- GDScriptFunctions::call(func, (const Variant **)argptrs, argc, *dst, err);
                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1 - 3) * 0x4, vtDword) -- decrement what's been incremented

                return contextTable.instrPointer + argc + 1
              end
            }

          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_SELF] = 
            {
              name = "OPCODE_CALL_SELF",
              handler = function(contextTable)
                -- nothing, should break?
                return contextTable.instrPointer -- + 1
              end
            }

          GDF.DisasmHandlers[GDF.OP.OPCODE_CALL_SELF_BASE] = 
            {
              name = "OPCODE_CALL_SELF_BASE",
              handler = function(contextTable)

                local operand1 = 'Globals[' .. contextTable.codeInts[contextTable.instrPointer + 1] .. ']'
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword) -- self_fun then *methodname which is then used to look up member_functions or MethodBind *mb = ClassDB::get_method(gds->native->get_name(), *methodname);

                local argc = contextTable.codeInts[contextTable.instrPointer + 2]
                addStructureElem(contextTable.codeStructElement, 'argc:', (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)

                local operandArg = '';
                for i = 0, argc - 1 do
                  if i > 0 then
                    operandArg = operandArg .. ', '
                  end
                  operandArg = operandArg .. formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + i + 3])
                  addStructureElem(contextTable.codeStructElement, 'arg: ' .. formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + i + 3]), (contextTable.instrPointer - 1 + i + 3) * 0x4, vtDword)
                end

                local operand3 = formatDisassembledAddress( contextTable.codeInts[contextTable.instrPointer + argc + 3])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + argc + 3) * 0x4, vtDword) -- dest

                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand3 .. ' = ' .. operand1 .. '(' .. operandArg .. ')'
                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 4 + argc
              end
            }

          GDF.DisasmHandlers[GDF.OP.OPCODE_YIELD] = 
            {
              name = "OPCODE_YIELD",
              handler = function(contextTable)

                local operand1 = ''
                local operand2 = ''
                local ipofs = 1
                local signal = contextTable.codeInts[contextTable.instrPointer] == GDF.CurrentDisassembler:getOPEnumFromInternalOPID(GDF.OP.OPCODE_YIELD_SIGNAL)
                if signal then
                  ipofs = ipofs+2
                  local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                  operand1 = "argobj " .. operand1
                  addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)

                  local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2])
                  operand2 = "argname " .. operand2
                  addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)
                  -- obj->connect(signal, gdfs.ptr(), "_signal_callback", varray(gdfs), Object::CONNECT_ONESHOT);
                end
                -- 2 + 2 if signal; 2 otherwise
        
                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand1 .. ' ' .. operand2
                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 1 + ipofs -- opcode + whatever offset, though it's yielded
              end
            }

          GDF.DisasmHandlers[GDF.OP.OPCODE_YIELD_SIGNAL] = 
            {
              name = "OPCODE_YIELD_SIGNAL",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_YIELD].handler
            }

          GDF.DisasmHandlers[GDF.OP.OPCODE_YIELD_RESUME] = 
            {
              name = "OPCODE_YIELD_RESUME",
              handler = function(contextTable)

                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword) -- self_fun then *methodname which is then used to look up member_functions or MethodBind *mb = ClassDB::get_method(gds->native->get_name(), *methodname);
        
                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. 'result' .. operand1
                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 2
              end
            }

          GDF.DisasmHandlers[GDF.OP.OPCODE_JUMP] = 
            {
              name = "OPCODE_JUMP",
              handler = function(contextTable)
                local operand1 = numtohexstr(contextTable.codeInts[contextTable.instrPointer + 1] * 0x4) -- where to jump in hex representation, 4byte step
                local elem = addStructureElem(contextTable.codeStructElement, "JUMP to " .. operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                elem.DisplayMethod = 'dtHexadecimal'
                elem.ShowAsHex = true
                contextTable.opcodeName = contextTable.opcodeName .. ' -> ' .. operand1

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 2
              end
            }

          GDF.DisasmHandlers[GDF.OP.OPCODE_JUMP_IF] = 
            {
              name = "OPCODE_JUMP_IF",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1]) -- test, boolenized
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)

                local operand2 = numtohexstr(contextTable.codeInts[contextTable.instrPointer + 2] * 0x4) -- where to jump
                local elem = addStructureElem(contextTable.codeStructElement, "JUMP to " .. operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword)
                elem.DisplayMethod = 'dtHexadecimal'
                elem.ShowAsHex = true
                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand1 .. ' -> ' .. operand2

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 3
              end
            }

          GDF.DisasmHandlers[GDF.OP.OPCODE_JUMP_IF_NOT] = 
            {
              name = "OPCODE_JUMP_IF_NOT",
              handler = GDF.DisasmHandlers[GDF.OP.OPCODE_JUMP_IF].handler
            }

          GDF.DisasmHandlers[GDF.OP.OPCODE_JUMP_TO_DEF_ARGUMENT] = 
            {
              name = "OPCODE_JUMP_TO_DEF_ARGUMENT",
              handler = function(contextTable)
                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)
                return contextTable.instrPointer + 1
              end
            }

          GDF.DisasmHandlers[GDF.OP.OPCODE_RETURN] = 
            {
              name = "OPCODE_RETURN",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword) -- retvalue
                contextTable.opcodeName = contextTable.opcodeName .. ' ' .. operand1
                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 2
              end
            }

          GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE_BEGIN] = 
            {
              name = "OPCODE_ITERATE_BEGIN",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword) -- counter
                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword) -- container
                local operand3 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 3])
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3) * 0x4, vtDword) -- jumpto
                local operand4 = tostring(contextTable.codeInts[contextTable.instrPointer + 4])
                addStructureElem(contextTable.codeStructElement, 'end: ', (contextTable.instrPointer - 1 + 4) * 0x4, vtDword) -- iterator

                contextTable.opcodeName = contextTable.opcodeName .. ' for-init ' .. operand3 .. ' in ' .. operand2 .. ' counter ' .. operand1 .. ' end: ' .. operand4
                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 5
              end
            }

          GDF.DisasmHandlers[GDF.OP.OPCODE_ITERATE] =
            {
              name = "OPCODE_ITERATE",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword) -- counter
                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword) -- container
                local operand3 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 3])
                addStructureElem(contextTable.codeStructElement, operand3, (contextTable.instrPointer - 1 + 3) * 0x4, vtDword) -- jumpto
                local operand4 = tostring(contextTable.codeInts[contextTable.instrPointer + 4])
                addStructureElem(contextTable.codeStructElement, 'end: ', (contextTable.instrPointer - 1 + 4) * 0x4, vtDword)

                contextTable.opcodeName = contextTable.opcodeName .. ' for-loop ' .. operand2 .. ' in ' .. operand2 .. ' counter ' .. operand1 .. ' end: ' .. operand4
                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)

                return contextTable.instrPointer + 5
              end
            }

          GDF.DisasmHandlers[GDF.OP.OPCODE_ASSERT] =
            {
              name = "OPCODE_ASSERT",
              handler = function(contextTable)
                local operand1 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 1])
                addStructureElem(contextTable.codeStructElement, operand1, (contextTable.instrPointer - 1 + 1) * 0x4, vtDword) -- test
                local operand2 = formatDisassembledAddress(contextTable.codeInts[contextTable.instrPointer + 2])
                addStructureElem(contextTable.codeStructElement, operand2, (contextTable.instrPointer - 1 + 2) * 0x4, vtDword) -- message

                contextTable.opcodeName = contextTable.opcodeName .. ' (' .. operand1 .. ', ' .. operand2 .. ')'

                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)
                return contextTable.instrPointer + 3
              end
            }

          GDF.DisasmHandlers[GDF.OP.OPCODE_BREAKPOINT] =
            {
              name = "OPCODE_BREAKPOINT",
              handler = function(contextTable)
                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)
                return contextTable.instrPointer + 1
              end
            }

          GDF.DisasmHandlers[GDF.OP.OPCODE_LINE] =
            {
              name = "OPCODE_LINE",
              handler = function(contextTable)
                local line = contextTable.codeInts[contextTable.instrPointer + 1] - 1
                if line > 0 --[[and line < p_code_lines.size()]] then
                  contextTable.opcodeName = contextTable.opcodeName .. ' ' .. tostring(line + 1) .. ': '
                else
                  contextTable.opcodeName = ''
                end
                addStructureElem(contextTable.codeStructElement, 'line: ', (contextTable.instrPointer - 1 + 1) * 0x4, vtDword)
                addLayoutStructElem(contextTable.codeStructElement, contextTable.opcodeName, GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)
                return contextTable.instrPointer + 2
              end
            }

          GDF.DisasmHandlers[GDF.OP.OPCODE_END] =
            {
              name = "OPCODE_END",
              handler = function(contextTable)
                addLayoutStructElem(contextTable.codeStructElement, '>>>END.', GD_FUNC_DISASM_COLOR, (contextTable.instrPointer - 1) * 0x4, vtDword)
                return contextTable.instrPointer + 1
              end
            }

        GDF.Decoders = {}
          GDF.Decoders.BytecodeV0 =
            {
              name = "BytecodeV0",
              resolveOPHandlerDefFromProfile = function(profile, opcodeEnum)
                return profile.OPHandlerDefFromOPEnum[opcodeEnum]
              end
            }
          GDF.Decoders.BytecodeV1 =
            {
              name = "BytecodeV1",
              resolveOPHandlerDefFromProfile = function(profile, opcodeEnum)
                -- for other versions redefine the handler on the fly
                return profile.OPHandlerDefFromOPEnum[opcodeEnum]
              end
            }

        
        GDF.ProfileSpecs =
          {
            ["2.0"] =
              {
                decoderName = "BytecodeV0",
                orderedOpcodes =
                  {
                    GDF.OP.OPCODE_OPERATOR,
                    GDF.OP.OPCODE_EXTENDS_TEST,
                    GDF.OP.OPCODE_SET,
                    GDF.OP.OPCODE_GET,
                    GDF.OP.OPCODE_SET_NAMED,
                    GDF.OP.OPCODE_GET_NAMED,
                    -- GDF.OP.OPCODE_SET_MEMBER,
                    -- GDF.OP.OPCODE_GET_MEMBER,
                    GDF.OP.OPCODE_ASSIGN,
                    GDF.OP.OPCODE_ASSIGN_TRUE,
                    GDF.OP.OPCODE_ASSIGN_FALSE,
                    GDF.OP.OPCODE_CONSTRUCT,
                    GDF.OP.OPCODE_CONSTRUCT_ARRAY,
                    GDF.OP.OPCODE_CONSTRUCT_DICTIONARY,
                    GDF.OP.OPCODE_CALL,
                    GDF.OP.OPCODE_CALL_RETURN,
                    GDF.OP.OPCODE_CALL_BUILT_IN,
                    GDF.OP.OPCODE_CALL_SELF,
                    GDF.OP.OPCODE_CALL_SELF_BASE,
                    GDF.OP.OPCODE_YIELD,
                    GDF.OP.OPCODE_YIELD_SIGNAL,
                    GDF.OP.OPCODE_YIELD_RESUME,
                    GDF.OP.OPCODE_JUMP,
                    GDF.OP.OPCODE_JUMP_IF,
                    GDF.OP.OPCODE_JUMP_IF_NOT,
                    GDF.OP.OPCODE_JUMP_TO_DEF_ARGUMENT,
                    GDF.OP.OPCODE_RETURN,
                    GDF.OP.OPCODE_ITERATE_BEGIN,
                    GDF.OP.OPCODE_ITERATE,
                    GDF.OP.OPCODE_ASSERT,
                    GDF.OP.OPCODE_BREAKPOINT,
                    GDF.OP.OPCODE_LINE,
                    GDF.OP.OPCODE_END
                  }
              },

            ["2.1"] =
              {
                base = "2.0",
                decoderName = "BytecodeV0",
                patches =  { }
              },

            ["3.0"] =
              {
                base = "2.1",
                decoderName = "BytecodeV0",
                patches = 
                {
                  {
                    kind = "insertValueAfter",
                    anchor = GDF.OP.OPCODE_GET_NAMED,
                    value = GDF.OP.OPCODE_SET_MEMBER
                  },
                  {
                    kind = "insertValueAfter",
                    anchor = GDF.OP.OPCODE_SET_MEMBER,
                    value = GDF.OP.OPCODE_GET_MEMBER
                  },
                }
              },

            ["3.1"] =
              {
                base = "3.0",
                decoderName = "BytecodeV0",
                patches =
                {
                  {
                    kind = "insertValueAfter",
                    anchor = GDF.OP.OPCODE_EXTENDS_TEST,
                    value = GDF.OP.OPCODE_IS_BUILTIN
                  },
                  {
                    kind = "insertValueAfter",
                    anchor = GDF.OP.OPCODE_ASSIGN_FALSE,
                    value = GDF.OP.OPCODE_ASSIGN_TYPED_BUILTIN
                  },
                  {
                    kind = "insertValueAfter",
                    anchor = GDF.OP.OPCODE_ASSIGN_TYPED_BUILTIN,
                    value = GDF.OP.OPCODE_ASSIGN_TYPED_NATIVE
                  },
                  {
                    kind = "insertValueAfter",
                    anchor = GDF.OP.OPCODE_ASSIGN_TYPED_NATIVE,
                    value = GDF.OP.OPCODE_ASSIGN_TYPED_SCRIPT
                  },
                  {
                    kind = "insertValueAfter",
                    anchor = GDF.OP.OPCODE_ASSIGN_TYPED_SCRIPT,
                    value = GDF.OP.OPCODE_CAST_TO_BUILTIN
                  },
                  {
                    kind = "insertValueAfter",
                    anchor = GDF.OP.OPCODE_CAST_TO_BUILTIN,
                    value = GDF.OP.OPCODE_CAST_TO_NATIVE
                  },
                  {
                    kind = "insertValueAfter",
                    anchor = GDF.OP.OPCODE_CAST_TO_NATIVE,
                    value = GDF.OP.OPCODE_CAST_TO_SCRIPT
                  },
                }
              },

            ["3.2"] =
              {
                base = "3.1",
                decoderName = "BytecodeV0",
                patches = {}
              },

            ["3.3"] =
              {
                base = "3.2",
                decoderName = "BytecodeV0",
                patches = {}
              },

            ["3.4"] =
              {
                base = "3.3",
                decoderName = "BytecodeV0",
                patches = {}
              },

            ["3.5"] =
              {
                base = "3.4",
                decoderName = "BytecodeV0",
                patches = {}
              },

            ["3.6"] =
              {
                base = "3.5",
                decoderName = "BytecodeV0",
                patches = {}
              }
          }
        GDF.CompiledProfiles = {}
        GDF.EADDRESS =
          {
            ['ADDR_BITS'] = 24,
            ['ADDR_MASK'] = ((1 << 24) - 1), -- ((1 << ADDR_BITS) - 1)
            ['ADDR_TYPE_MASK'] = ~((1 << 24) - 1),
            ['ADDR_TYPE_SELF'] = 0,
            ['ADDR_TYPE_CLASS'] = 1,
            ['ADDR_TYPE_MEMBER'] = 2,
            ['ADDR_TYPE_CLASS_CONSTANT'] = 3,
            ['ADDR_TYPE_LOCAL_CONSTANT'] = 4,
            ['ADDR_TYPE_STACK'] = 5,
            ['ADDR_TYPE_STACK_VARIABLE'] = 6,
            ['ADDR_TYPE_GLOBAL'] = 7,
            ['ADDR_TYPE_NIL'] = 8
            --ADDR_TYPE_NAMED_GLOBAL on tools enabled
          }

        GDF.OPERATOR_NAME =
          {
            -- comparison
            "OP_EQUAL",
            "OP_NOT_EQUAL",
            "OP_LESS",
            "OP_LESS_EQUAL",
            "OP_GREATER",
            "OP_GREATER_EQUAL",
            -- mathematic
            "OP_ADD",
            "OP_SUBTRACT",
            "OP_MULTIPLY",
            "OP_DIVIDE",
            "OP_NEGATE",
            "OP_POSITIVE", -- doesnt exist in 2.1/2.0
            "OP_MODULE",
            "OP_STRING_CONCAT",
            -- bitwise
            "OP_SHIFT_LEFT",
            "OP_SHIFT_RIGHT",
            "OP_BIT_AND",
            "OP_BIT_OR",
            "OP_BIT_XOR",
            "OP_BIT_NEGATE",
            -- logic
            "OP_AND",
            "OP_OR",
            "OP_XOR",
            "OP_NOT",
            -- containment
            "OP_IN",
            "OP_MAX" -- 25
          }
          if GDDEFS.MAJOR_VER == 2 then table.remove(GDF.OPERATOR_NAME, 12) end -- lazy but whatever; removing "OP_POSITIVE"

        for version, _ in pairs(GDF.ProfileSpecs) do
          GDF.CompiledProfiles[version] = createProfileFromVersion(version)
        end

        if GDDEFS.VERSION_STRING then
          GDF.CurrentDisassembler = GDF.createDisassemblerFromVersion(GDDEFS.VERSION_STRING)
        end

      end
    end



  return
    {
      defineGDFunctionEnums = defineGDFunctionEnums,
      GDF = GDF,
    }
end

return Module -- exporting