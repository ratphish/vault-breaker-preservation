using System.IO;
using System.Buffers.Binary;
using Tiger.Schema;
using System.Runtime.Loader;
using Tiger;
using Tiger.Schema.Strings;
var dir=Environment.GetEnvironmentVariable("MIDA_DIR") ?? throw new Exception("Set MIDA_DIR to the MIDA distribution directory");
AssemblyLoadContext.Default.Resolving += (ctx,name) => { var p=Path.Combine(dir,name.Name+".dll"); return File.Exists(p) ? ctx.LoadFromAssemblyPath(p) : null; };
Directory.SetCurrentDirectory(dir);
Strategy.AddNewStrategy(TigerStrategy.MARATHON, Environment.GetEnvironmentVariable("MARATHON_PACKAGES") ?? throw new Exception("Set MARATHON_PACKAGES to the snapshot packages directory"), true);
SchemaDeserializer.Setup(); FileResourcer.Setup(); PackageResourcer.Setup(); Hash64Map.Setup();
if (args.Length == 1 && args[0] == "find-row7-service-tag-sources")
{
    var resources = PackageResourcer.Get();
    var packages = resources.PackagePathsCache.GetAllPackagesMap().Where(pair =>
        Path.GetFileName(pair.Value).Contains("startup_globals", StringComparison.OrdinalIgnoreCase) ||
        Path.GetFileName(pair.Value).Contains("investment_globals", StringComparison.OrdinalIgnoreCase));
    foreach (var pair in packages.OrderBy(pair => pair.Key))
    {
        var package = resources.GetPackage(pair.Key);
        foreach (var entry in package.GetAllFileMetadata())
        {
            if (entry.Type != 8 && entry.Type != 16 || entry.Size < 4 || entry.Size > 67108864)
                continue;
            var bytes = package.GetFileSpan(entry.FileIndex);
            foreach (uint target in new[] { 0x80A6A004u, 0x80AA2163u })
            {
                var needle = BitConverter.GetBytes(target);
                for (int start = 0; start <= bytes.Length - needle.Length;)
                {
                    int match = bytes[start..].IndexOf(needle);
                    if (match < 0)
                        break;
                    int offset = start + match;
                    Console.WriteLine(System.Text.Json.JsonSerializer.Serialize(new
                    {
                        tag = entry.Hash.ToString(), reference = entry.Reference.ToString(),
                        package = Path.GetFileName(pair.Value), offset, target = target.ToString("X8")
                    }));
                    start = offset + 1;
                }
            }
        }
    }
    return;
}
if (args.Length == 1 && args[0] == "find-row7-service-tables")
{
    var resources = PackageResourcer.Get();
    var packages = resources.PackagePathsCache.GetAllPackagesMap().OrderBy(pair => pair.Key).ToList();
    int examined = 0, errors = 0, oversized = 0, matches = 0;
    foreach (var pair in packages)
    {
        var package = resources.GetPackage(pair.Key);
        foreach (var entry in package.GetAllFileMetadata())
        {
            if (entry.Type != 8 && entry.Type != 16 || entry.Size < 0x70)
                continue;
            if (entry.Size > 67108864)
            {
                oversized++;
                continue;
            }
            try
            {
                var bytes = package.GetFileSpan(entry.FileIndex);
                examined++;
                var count = BinaryPrimitives.ReadInt32LittleEndian(bytes[0x18..]);
                var displacement = BinaryPrimitives.ReadInt64LittleEndian(bytes[0x20..]);
                if (count < 2 || displacement <= 0 || displacement > bytes.Length - 0x30L - 32L * count)
                    continue;
                int offset = 0x30 + (int)displacement;
                uint firstKey = BinaryPrimitives.ReadUInt32LittleEndian(bytes[(offset + 8)..]);
                uint previous = firstKey;
                bool sorted = true;
                int enumRange = 0;
                for (int index = 0; index < count; index++)
                {
                    int row = offset + 32 * index;
                    uint key = BinaryPrimitives.ReadUInt32LittleEndian(bytes[(row + 8)..]);
                    if (key < previous)
                    {
                        sorted = false;
                        break;
                    }
                    previous = key;
                    if (bytes[row + 0x1c] <= 54)
                        enumRange++;
                }
                if (!sorted)
                    continue;
                matches++;
                Console.WriteLine(System.Text.Json.JsonSerializer.Serialize(new
                {
                    tag = entry.Hash.ToString(), reference = entry.Reference.ToString(),
                    package = Path.GetFileName(pair.Value), size = bytes.Length, count, offset,
                    firstKey = firstKey.ToString("X8"), lastKey = previous.ToString("X8"), enumRange
                }));
            }
            catch (Exception ex)
            {
                errors++;
                if (errors <= 10)
                    Console.Error.WriteLine($"FAILED {entry.Hash} {ex.GetType().Name}");
            }
        }
    }
    Console.Error.WriteLine($"TOTAL packages={packages.Count} examined={examined} errors={errors} oversized={oversized} matches={matches}");
    return;
}
if(args.Length==2 && args[0]=="inspect-localized-table") {
 var table=new LocalizedStrings(new FileHash(args[1]));foreach(var x in table.GetAllStringViews())Console.WriteLine(System.Text.Json.JsonSerializer.Serialize(new{hash=x.StringHash.ToString(),index=x.StringIndex,text=x.RawString,data=x.DataFileHash.ToString()}));return;
}
if(args.Length==3 && args[0]=="extract-selection-tags") {
 var output=Path.GetFullPath(args[1]);Directory.CreateDirectory(output);
 foreach(var value in args[2].Split(',')){var h=new FileHash(value);var m=h.GetFileMetadata();if(m.Size>67108864)throw new Exception("bounded extraction limit");var b=PackageResourcer.Get().GetFileData(h);var path=Path.Combine(output,h.ToString()+".bin");using(var f=new FileStream(path,FileMode.CreateNew,FileAccess.Write))f.Write(b);Console.WriteLine(System.Text.Json.JsonSerializer.Serialize(new{tag=h.ToString(),reference=m.Reference.ToString(),size=b.Length,sha256=Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(b))}));}return;
}
if(args.Length>0 && args[0]=="find-vault-handler-fnv-all") {
 var words=Enumerable.Range(1,7).Select(i=>$"sc_vault_{i}_objectives_d_execute_impl").Concat(new[]{"spawn_initial_keys","main_d_execute_impl","il_player_spawned_handle_incident_impl","il_kill_handle_incident_impl","il_pre_exfil_handle_incident_impl"}).ToArray();
 uint Fnv1(string s){uint h=0x811c9dc5;foreach(byte c in System.Text.Encoding.ASCII.GetBytes(s))h=unchecked(h*0x01000193)^c;return h;}
 var targets=words.Select(w=>BitConverter.GetBytes(Fnv1(w))).ToArray();var map=PackageResourcer.Get().PackagePathsCache.GetAllPackagesMap().OrderBy(x=>x.Key).ToList();int seen=0,err=0,over=0,matches=0;
 foreach(var pair in map){var pkg=PackageResourcer.Get().GetPackage(pair.Key);foreach(var e in pkg.GetAllFileMetadata()){
  if(!(e.Type==8 || e.Type==16))continue;if(e.Size>67108864){over++;continue;}
  try {var b=pkg.GetFileSpan(e.FileIndex);seen++;for(int i=0;i<targets.Length;i++){int pos=b.IndexOf(targets[i]);if(pos>=0){matches++;Console.WriteLine(System.Text.Json.JsonSerializer.Serialize(new{tag=e.Hash.ToString(),reference=e.Reference.ToString(),type=e.Type,size=e.Size,package=Path.GetFileName(pair.Value),name=words[i],fnv1=Fnv1(words[i]).ToString("X8"),first_offset=pos}));}}}
  catch(Exception ex){err++;if(err<=10)Console.Error.WriteLine($"FAILED {e.Hash} {ex.GetType().Name}");}
 }Console.Error.WriteLine($"package={pair.Key:X4} examined={seen} errors={err} matches={matches}");}
 Console.Error.WriteLine($"TOTAL packages={map.Count} examined={seen} errors={err} oversized={over} matches={matches}");return;
}
if(args.Length>0 && (args[0]=="find-script" || args[0]=="find-script-all" || args[0]=="find-impl-all" || args[0]=="find-activity-state-all" || args[0]=="find-cryo-selection-all" || args[0]=="find-cryo-activity-strings-all")) {var targets=(args[0]=="find-cryo-activity-strings-all" ? new[]{"activity_exp.cryo.vault_breaker_server","vb_solo_synced","activity_exp.cryo.standard_server","rated_synced"} : args[0]=="find-cryo-selection-all" ? new[]{"Vault Breaker","VaultBreaker","vault_breaker","Cryo Archive","cryo_archive"} : args[0]=="find-activity-state-all" ? new[]{"activity_script_state","bs_compiler_generated"} : args[0]=="find-impl-all" ? new[]{"sc_vault_1_objectives_d_execute_impl","spawn_initial_keys"} : new[]{"activity_vault_breaker.es","pf_vault_breaker_key_pedestal.es"}).Select(x=>System.Text.Encoding.ASCII.GetBytes(x)).ToArray(); var map=PackageResourcer.Get().PackagePathsCache.GetAllPackagesMap().Where(x=>(args[0]=="find-cryo-activity-strings-all" || args[0]=="find-cryo-selection-all" || args[0]=="find-script-all" || args[0]=="find-impl-all" || args[0]=="find-activity-state-all") || x.Value.Contains("marathon_deck_001",StringComparison.OrdinalIgnoreCase)).OrderBy(x=>x.Key).ToList();int seen=0,err=0,over=0;foreach(var pair in map){var pkg=PackageResourcer.Get().GetPackage(pair.Key);foreach(var e in pkg.GetAllFileMetadata()){if((args[0]=="find-cryo-activity-strings-all" || args[0]=="find-cryo-selection-all" || args[0]=="find-script-all" || args[0]=="find-impl-all" || args[0]=="find-activity-state-all") && !(e.Type==8 || e.Type==16))continue;if(e.Size>67108864){over++;continue;} try{var b=pkg.GetFileSpan(e.FileIndex);seen++;for(int n=0;n<targets.Length;n++){int off=b.IndexOf(targets[n]);if(off>=0)Console.WriteLine(System.Text.Json.JsonSerializer.Serialize(new{tag=e.Hash.ToString(),reference=e.Reference.ToString(),type=e.Type,subtype=e.SubType,size=e.Size,package=Path.GetFileName(pair.Value),needle=System.Text.Encoding.ASCII.GetString(targets[n]),offset=off}));}}catch(Exception ex){err++;if(err<=10)Console.Error.WriteLine($"FAILED {e.Hash} {ex.GetType().Name}");}}}Console.Error.WriteLine($"TOTAL packages={map.Count} examined={seen} errors={err} oversized={over}");return;}

if(args.Length>0 && (args[0]=="find-vault-tag-refs-all" || args[0]=="find-cryo-mode-keys-all" || args[0]=="find-cryo-fields-all" || args[0]=="find-cryo-server-hashes-all")) {var targets=args[0]=="find-cryo-server-hashes-all" ? new uint[]{0x3F0B32C2,0xD1FDE482,0x11B3D549} : args[0]=="find-cryo-fields-all" ? new uint[]{0x716E3AF5,0xCD9F6F19,0xA137AAB3,0xE44E8EB2} : args[0]=="find-cryo-mode-keys-all" ? new uint[]{0xBBD96908,0xAB661274,0x905BBCFF} : new uint[]{0x80B37C7E,0x80B37FED,0x80B38561,0x80B38555};var map=PackageResourcer.Get().PackagePathsCache.GetAllPackagesMap().OrderBy(x=>x.Key).ToList();int seen=0,err=0,over=0,matches=0;foreach(var pair in map){var pkg=PackageResourcer.Get().GetPackage(pair.Key);foreach(var e in pkg.GetAllFileMetadata()){if(!(e.Type==8 || e.Type==16))continue;if(e.Size>67108864){over++;continue;}try{var b=pkg.GetFileSpan(e.FileIndex);seen++;foreach(var t in targets){var needle=BitConverter.GetBytes(t);var offsets=new List<int>();var pos=0;while(pos<b.Length){var found=b.Slice(pos).IndexOf(needle);if(found<0)break;offsets.Add(pos+found);pos+=found+1;if(offsets.Count==64)break;}if(offsets.Count>0){matches++;Console.WriteLine(System.Text.Json.JsonSerializer.Serialize(new{tag=e.Hash.ToString(),reference=e.Reference.ToString(),type=e.Type,subtype=e.SubType,size=e.Size,package=Path.GetFileName(pair.Value),target=t.ToString("X8"),offsets=offsets.ToArray(),truncated=offsets.Count==64}));}}}catch(Exception ex){err++;if(err<=10)Console.Error.WriteLine($"FAILED {e.Hash} {ex.GetType().Name}");}}}Console.Error.WriteLine($"TOTAL packages={map.Count} examined={seen} errors={err} oversized={over} matches={matches}");return;}

if(args.Length>0 && args[0]=="find-listener-targets-all") {var targets=new uint[]{0x80B3B7F2,0x80B3B81C,0x8080A244,0x8080BAE0};var map=PackageResourcer.Get().PackagePathsCache.GetAllPackagesMap().OrderBy(x=>x.Key).ToList();int seen=0,err=0,over=0,matches=0;foreach(var pair in map){var pkg=PackageResourcer.Get().GetPackage(pair.Key);foreach(var e in pkg.GetAllFileMetadata()){if(!(e.Type==8 || e.Type==16))continue;if(e.Size>67108864){over++;continue;}try{var b=pkg.GetFileSpan(e.FileIndex);seen++;foreach(var t in targets){var needle=BitConverter.GetBytes(t);var offsets=new List<int>();var pos=0;while(pos<b.Length){var found=b.Slice(pos).IndexOf(needle);if(found<0)break;offsets.Add(pos+found);pos+=found+1;if(offsets.Count==64)break;}if(offsets.Count>0){matches++;Console.WriteLine(System.Text.Json.JsonSerializer.Serialize(new{tag=e.Hash.ToString(),reference=e.Reference.ToString(),type=e.Type,subtype=e.SubType,size=e.Size,package=Path.GetFileName(pair.Value),target=t.ToString("X8"),offsets=offsets.ToArray(),truncated=offsets.Count==64}));}}}catch(Exception ex){err++;if(err<=10)Console.Error.WriteLine($"FAILED {e.Hash} {ex.GetType().Name}");}}}Console.Error.WriteLine($"TOTAL packages={map.Count} examined={seen} errors={err} oversized={over} matches={matches}");return;}

if(args.Length>0 && args[0]=="entry-type-census") {var map=PackageResourcer.Get().PackagePathsCache.GetAllPackagesMap().OrderBy(x=>x.Key).ToList();var counts=new SortedDictionary<int,(long entries,long bytes,long oversized)>();foreach(var pair in map){var pkg=PackageResourcer.Get().GetPackage(pair.Key);foreach(var e in pkg.GetAllFileMetadata()){int k=e.Type;counts.TryGetValue(k,out var v);counts[k]=(v.entries+1,v.bytes+e.Size,v.oversized+(e.Size>67108864?1:0));}}foreach(var v in counts)Console.WriteLine(System.Text.Json.JsonSerializer.Serialize(new{type=v.Key,entries=v.Value.entries,bytes=v.Value.bytes,oversized=v.Value.oversized}));Console.Error.WriteLine($"packages={map.Count}");return;}

if(args.Length>0 && args[0]=="find-vault-other-types") {var targets=new (string label,byte[] bytes)[]{("80B37C7E",BitConverter.GetBytes(0x80B37C7Eu)),("80B37FED",BitConverter.GetBytes(0x80B37FEDu)),("80B38561",BitConverter.GetBytes(0x80B38561u)),("80B38555",BitConverter.GetBytes(0x80B38555u)),("activity_vault_breaker.es",System.Text.Encoding.ASCII.GetBytes("activity_vault_breaker.es")),("pf_vault_breaker_key_pedestal.es",System.Text.Encoding.ASCII.GetBytes("pf_vault_breaker_key_pedestal.es")),("spawn_initial_keys",System.Text.Encoding.ASCII.GetBytes("spawn_initial_keys")),("sc_vault_1_objectives_d_execute_impl",System.Text.Encoding.ASCII.GetBytes("sc_vault_1_objectives_d_execute_impl"))};var map=PackageResourcer.Get().PackagePathsCache.GetAllPackagesMap().OrderBy(x=>x.Key).ToList();int seen=0,err=0,over=0,matches=0;long bytes=0;foreach(var pair in map){var pkg=PackageResourcer.Get().GetPackage(pair.Key);foreach(var e in pkg.GetAllFileMetadata()){if(e.Type==0 || e.Type==8 || e.Type==16)continue;if(e.Size>67108864){over++;continue;}try{var b=pkg.GetFileSpan(e.FileIndex);seen++;bytes+=b.Length;if(seen%10000==0)Console.Error.WriteLine($"progress entries={seen} bytes={bytes} errors={err} matches={matches}");foreach(var t in targets){var offsets=new List<int>();var pos=0;while(pos<b.Length){var found=b.Slice(pos).IndexOf(t.bytes);if(found<0)break;offsets.Add(pos+found);pos+=found+1;if(offsets.Count==64)break;}if(offsets.Count>0){matches++;Console.WriteLine(System.Text.Json.JsonSerializer.Serialize(new{tag=e.Hash.ToString(),reference=e.Reference.ToString(),type=e.Type,subtype=e.SubType,size=e.Size,package=Path.GetFileName(pair.Value),target=t.label,offsets=offsets.ToArray(),truncated=offsets.Count==64}));}}}catch(Exception ex){err++;if(err<=10)Console.Error.WriteLine($"FAILED {e.Hash} {ex.GetType().Name}");}}}Console.Error.WriteLine($"TOTAL packages={map.Count} examined={seen} bytes={bytes} errors={err} oversized={over} matches={matches}");return;}

if(args.Length>0 && args[0]=="oversized-entry-list") {var map=PackageResourcer.Get().PackagePathsCache.GetAllPackagesMap().OrderBy(x=>x.Key).ToList();foreach(var pair in map){var pkg=PackageResourcer.Get().GetPackage(pair.Key);foreach(var e in pkg.GetAllFileMetadata())if(e.Size>67108864)Console.WriteLine(System.Text.Json.JsonSerializer.Serialize(new{tag=e.Hash.ToString(),type=e.Type,size=e.Size,package=Path.GetFileName(pair.Value)}));}return;}

if(args.Length==2 && args[0]=="scan-one-oversized") {var h=new FileHash(args[1]);var m=h.GetFileMetadata();if(m.Type!=27 || m.Size<=67108864 || m.Size>1000000000)throw new Exception("entry outside bounded video scope");var b=PackageResourcer.Get().GetFileData(h);var terms=new (string label,byte[] bytes)[]{("80B37C7E",BitConverter.GetBytes(0x80B37C7Eu)),("80B37FED",BitConverter.GetBytes(0x80B37FEDu)),("80B38561",BitConverter.GetBytes(0x80B38561u)),("80B38555",BitConverter.GetBytes(0x80B38555u)),("activity_vault_breaker.es",System.Text.Encoding.ASCII.GetBytes("activity_vault_breaker.es")),("pf_vault_breaker_key_pedestal.es",System.Text.Encoding.ASCII.GetBytes("pf_vault_breaker_key_pedestal.es")),("spawn_initial_keys",System.Text.Encoding.ASCII.GetBytes("spawn_initial_keys")),("sc_vault_1_objectives_d_execute_impl",System.Text.Encoding.ASCII.GetBytes("sc_vault_1_objectives_d_execute_impl"))};var matches=new List<object>();foreach(var t in terms){var offsets=new List<int>();var pos=0;while(pos<b.Length){var found=b.AsSpan(pos).IndexOf(t.bytes);if(found<0)break;offsets.Add(pos+found);pos+=found+1;if(offsets.Count==64)break;}if(offsets.Count>0)matches.Add(new{target=t.label,offsets=offsets.ToArray(),truncated=offsets.Count==64});}Console.WriteLine(System.Text.Json.JsonSerializer.Serialize(new{tag=h.ToString(),type=m.Type,size=b.Length,matches}));return;}

if(args.Length>0 && args[0]=="find-vault-impl-names-all") {var words=Enumerable.Range(1,7).Select(i=>$"sc_vault_{i}_objectives_d_execute_impl").Concat(new[]{"spawn_initial_keys","submit_analytics_for_vault_objective_assignment"}).ToArray();var targets=words.Select(System.Text.Encoding.ASCII.GetBytes).ToArray();var map=PackageResourcer.Get().PackagePathsCache.GetAllPackagesMap().OrderBy(x=>x.Key).ToList();int seen=0,err=0,over=0,matches=0;foreach(var pair in map){var pkg=PackageResourcer.Get().GetPackage(pair.Key);foreach(var e in pkg.GetAllFileMetadata()){if(!(e.Type==8 || e.Type==16))continue;if(e.Size>67108864){over++;continue;}try{var b=pkg.GetFileSpan(e.FileIndex);seen++;for(int i=0;i<targets.Length;i++){int pos=b.IndexOf(targets[i]);if(pos>=0){matches++;Console.WriteLine(System.Text.Json.JsonSerializer.Serialize(new{tag=e.Hash.ToString(),reference=e.Reference.ToString(),type=e.Type,subtype=e.SubType,size=e.Size,package=Path.GetFileName(pair.Value),target=words[i],offset=pos}));}}}catch(Exception ex){err++;if(err<=10)Console.Error.WriteLine($"FAILED {e.Hash} {ex.GetType().Name}");}}}Console.Error.WriteLine($"TOTAL packages={map.Count} examined={seen} errors={err} oversized={over} matches={matches}");return;}
