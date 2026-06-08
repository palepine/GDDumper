local Module = {}

function Module.install(contextTable)

  local SceneTreeAOB = {}
    table.insert(SceneTreeAOB, { sig = "48 39 1D ? ? ? ? 75 07 4C 89 35 ? ? ? ? 66 0F 6F 05 ? ? ? ? 4?", toRel = 3 } )
    table.insert(SceneTreeAOB, { sig = "48 83 3D ? ? ? ? 00 0F 84 ? ? ? ? 0F 28 05 ? ? ? ? 4?", toRel = 3 } )
    table.insert(SceneTreeAOB, { sig = "4C 39 ? ? ? ? ? 75 07 ? 89 35 ? ? ? ? 66 0F 6F 05", toRel = 3 } )    
    table.insert(SceneTreeAOB, { sig = "48 83 3D ? ? ? ? 00 48 C7 86 ? ? ? ? 00 00 00 00", toRel = 3 } )
    table.insert(SceneTreeAOB, { sig = "48 8B 15 ? ? ? ? 48 85 D2 74 ? 48 8B 37 4?", toRel = 3 } )
    table.insert(SceneTreeAOB, { sig = "48 83 3D ? ? ? ? 00 75 07 4C 89 35 ? ? ? ? 0F 28 05", toRel = 3 } )
    table.insert(SceneTreeAOB, { sig = "48 8B 15 ? ? ? ? 48 85 D2 74 ? 4C 8B 26", toRel = 3 } )
    table.insert(SceneTreeAOB, { sig = "48 C7 05 ? ? ? ? 00 00 00 00 E9 ? ? ? ? 85 C0", toRel = 3 } )
    table.insert(SceneTreeAOB, { sig = "48 8B 05 ? ? ? ? 48 85 C0 0F 11 85 ? ? ? ? 49 0F ? ? 48 89 05", toRel = 3 } ) -- 4.3
    table.insert(SceneTreeAOB, { sig = "48 8B 05 ? ? ? ? 48 8D 8F ? ? ? ? 48 3B C7 49 0F 44 C7 48 8B 05", toRel = 3 } )
    table.insert(SceneTreeAOB, { sig = "48 8B 05 ? ? ? ? 48 85 C0 74 0D 80 B8 ? ? ? ? 00 0F", toRel = 3 } )
    table.insert(SceneTreeAOB, { sig = "48 89 05 ? ? ? ? 0F 11 85 ? ? 00 00 E8 ? ? ? ? 48 8D", toRel = 3 } ) -- 4.1

    table.insert(SceneTreeAOB, { sig = "39 0D ? ? ? ? 75 06 89 35 ? ? ? ? 0F 28 05", toRel = 2 } ) -- 32 4.6
    table.insert(SceneTreeAOB, { sig = "48 8B 15 ? ? ? ? 48 85 D2 74 ? 4D 8B 24 24", toRel = 3 } )
    table.insert(SceneTreeAOB, { sig = "48 8B 0D ? ? ? ? E8 ? ? ? ? 90 48 8B 4C 24 ? 48 85 C9 74 ? F0 0F C1 59 ? 83 FB", toRel = 3 } )
    table.insert(SceneTreeAOB, { sig = "48 8B 15 ? ? ? ? 48 85 D2 74 3D", toRel = 3 } )
    table.insert(SceneTreeAOB, { sig = "48 8B 15 ? ? ? ? 48 85 D2 74 3D 4C 8B 2B", toRel = 3 } )
    table.insert(SceneTreeAOB, { sig = "48 8B 15 ? ? ? ? 48 85 D2 74 3D 48 8B 36", toRel = 3 } )
    table.insert(SceneTreeAOB, { sig = "4C 8B 0D ? ? ? ? 4C 89 B4 24", toRel = 3 } )
    table.insert(SceneTreeAOB, { sig = "48 8B 15 ? ? ? ? 48 85 D2 74 ? 4C 8B 2B", toRel = 3 } )
    table.insert(SceneTreeAOB, { sig = "48 83 3D ? ? ? ? 00  49 C7 85 ? ? ? ? 00 00 00 00 49 89 9D", toRel = 3 } )
    table.insert(SceneTreeAOB, { sig = "A1 ? ? ? ? 85 C0 74 ? 8B 35 ? ? ? ? 8B", toRel = 1 } ) -- 3.5 32
    table.insert(SceneTreeAOB, { sig = "C7 05 ? ? ? ? 00 00 00 00 85 C0 0F 84 ? ? ? ? B9", toRel = 2 } ) -- 3.5 32
    table.insert(SceneTreeAOB, { sig = "48 8B 0D ? ? ? ? 48 85 C9 74 ? 48 8D 55 ? E8", toRel = 3 } ) -- 3.2
    table.insert(SceneTreeAOB, { sig = "48 8B 0D ? ? ? ? 48 83 C4 ?   5?", toRel = 3 } ) -- 3.0
    
    table.insert(SceneTreeAOB, { sig = "48 89 35 ? ? ? ? 66 44 89 A6 ? ? ? ? 66 44 89 A6", toRel = 3 } ) -- 2.1
    table.insert(SceneTreeAOB, { sig = "48 89 35 ? ? ? ? 0F 11 45 ? 66 44 89 BE ? ? ? ? C6 86 ? ? 00 00 01 E8", toRel = 3 } ) -- 2.1

  local RootAOB = {}
    table.insert(RootAOB, "48 8B 9? ? ? ? ? 4? 8D 8F ? ? ? ? 45 33 C0 E8")
    table.insert(RootAOB, "48 8B 9? ? ? ? ? 4? 31 C0 48 89 E9 E8 ? ? ? ? 80 3D ? ? ? ? 00")
    table.insert(RootAOB, "48 8B B0 ? ? ? ? 80 BB")
    table.insert(RootAOB, "48 8B 88 ? ? ? ? E8 ? ? ? ? 84 C0 74 ? 48 8B 03")
    table.insert(RootAOB, "48 8B B9 ? ? ? ? 89 DA")
    table.insert(RootAOB, "48 8B B0 ? ? ? ? 48 8B 8E")
    table.insert(RootAOB, "48 8B BF ? ? ? ? 74") -- might be too short
    table.insert(RootAOB, "48 8B 80 ? ? ? ? 40 38 B8 ? ? ? ? 0F 85")
    table.insert(RootAOB, "48 8B B0 ? ? ? ? 48 39 BE")
    table.insert(RootAOB, "48 8B 80 ? ? ? ? 80 B8 ? ? ? ? ? 0F 85 ? ? ? ? 48 8B 03")
    table.insert(RootAOB, "48 8B 89 ? ? ? ? E9 ? ? ? ? 0F 1F 80 ? ? ? ? 81 FA")
    table.insert(RootAOB, "48 8B B0 ? ? ? ? 48 8B 8E ? ? ? ? 48 85 C9 74")
    table.insert(RootAOB, "48 8B 88 ? ? ? ? E8 ? ? ? ? 84 C0 0F 85 ? ? ? ? 48 8B 03")
    table.insert(RootAOB, "48 8B B0 ? ? ? ? 48 8B 8E ? ? ? ? 48 85 C9 0F 84")
    table.insert(RootAOB, "48 8B 8? ? ? ? ? E8 ? ? ? ? 48 8B 5C 24 ? 48 83 C4 ? 5F C3 90")
    table.insert(RootAOB, "48 8B 8B ? ? ? ? BA ? ? ? ? 48 83 C4 ? 5B 5E 5F E9 ? ? ? ? 0F 1F 80")
    table.insert(RootAOB, "48 8B 8B ? ? ? ? 48 83 C4 ? 5B 5E 5F E9 ? ? ? ? 0F 1F 44 00 ? 48 8B 05")
    table.insert(RootAOB, "48 8B 8B ? ? ? ? 45 31 C0 48 89 F2 48 89 B3")
    table.insert(RootAOB, "48 8B 8B ? ? ? ? 45 31 C0 4C 89 E2 4C 89 A3")
    table.insert(RootAOB, "48 8B 8B ? ? ? ? 48 83 C4 ? 5B 41 5C 41 5D 41 5E")

    table.insert(RootAOB, "48 3B 90 ? ? ? ? 0F 84 ? ? ? ? 48 8B 83")
    table.insert(RootAOB, "48 39 82 ? ? ? ? 74 ? 48 8B 83")
    table.insert(RootAOB, "48 39 86 ? ? ? ? 74 ? C7 44 24")
    table.insert(RootAOB, "48 8B 8B ? ? ? ? 48 83 C4 ? 5B 5E 5F 5D 41 5C E9 ? ? ? ? 66 2E 0F 1F 84 00")
    table.insert(RootAOB, "48 8B 8B ? ? ? ? BA ? ? ? ? 48 83 C4 ? 5B 5E 5F 5D 41 5C E9 ? ? ? ? 0F 1F 40")

  local GDExtensionAOB = {}
    table.insert(GDExtensionAOB, "53 48 83 EC ? 45 31 C0 48 89 CA 48 8D 4C 24 ? E8 ? ? ? ? 48 8D 4C 24 ? E8" ) -- 4.6
    table.insert(GDExtensionAOB, "40 53 48 83 EC ? 48 8B D1 45 33 C0 48 8D ? 24 ? E8 ? ? ? ? 48 8D ? 24 ? E8" ) -- 4.6, 4.3 4.1, just a swapped encoding
    table.insert(GDExtensionAOB, "56 53 48 83 EC ? 45 31 C0 48 8D ? 24 ? 48 89 CA 48 89 F1 E8 ? ? ? ? 48 89 F1 E8" ) -- 4.5 4.4

    table.insert(GDExtensionAOB, "41 57 41 56 41 55 41 54 55 57 56 53 48 81 EC ? ? ? ? 45 31 C0 48 8D 44 24 ? 48 89 CA 48 89 C1" ) -- 4.3

    table.insert(GDExtensionAOB, "41 57 41 56 41 55 41 54 55 57 56 53 48 83 EC ? 4? 8D ? 24 ? 48 89 CA ? 89 ? E8" ) -- merged 4.1 4.2
    table.insert(GDExtensionAOB, "41 57 41 56 41 55 41 54 55 57 56 53 48 83 EC ? 4? 8D ? 24 ? 48 89 CA ? 89 ? 48 89 44 24 ? E8 ? ? ? ? 4C 8B 05 ? ? ? ? 48 8B 6C 24 ? 4D 8B 70 ? 4D 85 F6 OF" ) -- merged 4.3 / 4.1

  local GDNativeAOB = {}
    table.insert(GDNativeAOB, "48 8D 3D ? ? ? ? 66 48 0F 6E C0 66 48 0F 6E C9" )
    table.insert(GDNativeAOB, "4C 8D 15 ? ? ? ? 48 89 84 24 ? ? ? ? 48 8D 05" )

  local GDVMCallAOB = {}
    table.insert(GDVMCallAOB, { isheavy = true,  sig = "4C 89 ? 24 28 89 44 24 20 4C 8B 8C 24 ? ? ? ? 48 89 F9 49 89 E8 E8", sigsize = 24 }) -- 4.6 ret 64<
    table.insert(GDVMCallAOB, { isheavy = false, sig = "48 89 44 24 ? 89 44 24 68 48 8D 44 24 ? 48 89 44 24 28 C7 44 24 20 ? ? ? ? E8", sigsize = 28 }) -- 4.6 ret 64>
    table.insert(GDVMCallAOB, { isheavy = false, sig = "48 8B 84 24 ? ? ? ?     48 C7 44 24 30 00 00 00 00    48 89 44 24 28 8B 84 24 ? ? ? ? 89 44 24 20 E8", sigsize = 34 }) -- 4.5
    table.insert(GDVMCallAOB, { isheavy = true,  sig = "4C 89 7C 24 28 89 44 24 20 48 89 ? >48 89 ? >48 89 ? E8", sigsize = 19 }) -- 4.5 ret 64<
    table.insert(GDVMCallAOB, { isheavy = true, sig = "4C 89 74 24 28 89 44 24 20 48 89 D9 49 89 F9 49 89 F0 E8", sigsize = 19 }) -- 4.4
    table.insert(GDVMCallAOB, { isheavy = false, sig = "4C 89 64 24 28 89 44 24 20 48 89 D9 49 89 F9 49 89 F0 E8", sigsize = 19 }) -- 4.3
    table.insert(GDVMCallAOB, { isheavy = true, sig = "4C 89 64 24 28 89 44 24 20 4C 8B 8C 24 ? ? 00 00 48 89 D9 49 89 F0 E8", sigsize = 22 }) -- 4.3
    table.insert(GDVMCallAOB, { isheavy = false, sig = "4C 89 64 24 30      48 8B D6 48 89 44 24 28 8B 84 24 ? ? ? ? 89 44 24 20 E8", sigsize = 25 }) -- 4.3 ret 64<
    table.insert(GDVMCallAOB, { isheavy = false, sig = "4C 89 ? 24 28 89 44 24 20 48 89 D9 49 89 F9 49 89 F0 E8", sigsize = 19 }) -- 4.4-4.3
    table.insert(GDVMCallAOB, { isheavy = false, sig = "4C 89 ? 24 28 89 44 24 20 48 89 D9 49 89 F9 49 89 F0 E8", sigsize = 19 }) -- 4.3

    table.insert(GDVMCallAOB, { isheavy = false, sig = "4C 89 ? 24 28 89 44 24 20 48 89 F1 49 89 D8 E8", sigsize = 16 }) -- 4.2
    table.insert(GDVMCallAOB, { isheavy = true,  sig = "4C 89 74 24 28 89 44 24 20 49 89 D8 49 89 E9 E8", sigsize = 16 }) -- 4.2 Godot Engine v4.2.2.stable.official.15073afe3

    table.insert(GDVMCallAOB, { isheavy = false, sig = "4C 89 ? 24 28 44 89 6C 24 20 4D 8B CC 4C 8B C5 48 8B D6 48 8B 49 ? E8", sigsize = 24 }) -- 4.1
    table.insert(GDVMCallAOB, { isheavy = false, sig = "48 89 44 24 28 8B 84 24 ? ? ? ? 48 8B 8C 24 ? ? ? ? 89 44 24 20 E8 ? ? ? ? EB", sigsize = 30 }) -- 4.1
    table.insert(GDVMCallAOB, { isheavy = false, sig = "48 89 7C 24 28 49 89 F0 48 89 D9 48 C7 44 24 30 ? 00 00 00 8B 84 24 ? ? 00 00 89 44 24 20 E8", sigsize = 32 }) -- 3.6
    table.insert(GDVMCallAOB, { isheavy = false, sig = "4C 89 7C 24 30 48 8D 44 24 ?     48 89 44 24 28 44 89 74 24 20 4C 8B CD 4C 8B C6 48 8D 54 24 ? 48 8B 49 ? E8", sigsize = 36 }) -- 3.5
    table.insert(GDVMCallAOB, { isheavy = true, sig = "48 C7 44 24 30 ? 00 00 00   48 89 44 24 28 8B 44 24 ? 89 44 24 20 E8", sigsize = 23 }) -- 3.3 - 3.4 - 3.5
    table.insert(GDVMCallAOB, { isheavy = true,  sig = "4C 89 6C 24 28 44 89 64 24 20 49 89 F0 48 89 F9 E8", sigsize = 17 }) -- 3.0 prefixed by 48 C7 44 24 30 ? 000000

  local GDGetMonoObjAOB = {}
    table.insert(GDGetMonoObjAOB, "41 55 41 54 56 53 48 83 EC ? 49 89 CD 48 85 C9 0F 84 ? ? ? ? 48 8B 49 ? 48 85 C9 74" ) -- 3.5
    table.insert(GDGetMonoObjAOB, "55 57 56 53 48 83 EC ? 48 89 CB 48 85 C9 0F 84 ? ? ? ? 48 8B 49 ? 48 85 C9 74 ?" )  -- 3.6

  local GDSigs =
    {
      SceneTree = SceneTreeAOB,
      Root = RootAOB,
      GDExtension = GDExtensionAOB,
      GDNative = GDNativeAOB,
      VMCall = GDVMCallAOB,
      MonoGetObj = GDGetMonoObjAOB
    }

  return GDSigs
end

return Module -- exporting