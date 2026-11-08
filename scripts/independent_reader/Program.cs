using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Tiger;
if (args.Length != 3) throw new ArgumentException("Usage: package.pkg comma-separated-entry-indices oodle-dll");
Oodle.Initialize(Path.GetFullPath(args[2]));
var pkg = new TigerPackage(Path.GetFullPath(args[0]));
try {
 foreach (var part in args[1].Split(',')) {
  int index=int.Parse(part); var entry=pkg.Entries[index]; byte[] data=pkg.ReadEntry(index);
  var needle=Encoding.ASCII.GetBytes("content\\prefabs\\activities\\objects\\pf_vault_breaker_key_pedestal.es");
  var targets = new uint[]{0x80B38C23, 0x80B38BEC, 0x80B38569, 0x80B38567, 0x80B37FEE, 0x80B37FED};
  var references = targets.Select(t => new { target=t.ToString("X8"), offsets=Enumerable.Range(0, Math.Max(0, data.Length-3)).Where(i => BitConverter.ToUInt32(data, i)==t).ToArray() }).Where(x=>x.offsets.Length>0).ToArray();
  var activityNeedle=Encoding.ASCII.GetBytes("activity_vault_breaker.es");
  Console.WriteLine(JsonSerializer.Serialize(new { activityPathOffset=data.AsSpan().IndexOf(activityNeedle), references, tag=pkg.TagHash(index).ToString("X8"), reference=entry.Reference.ToString("X8"), entry.FileType, entry.FileSubType, length=data.Length, sha256=Convert.ToHexString(SHA256.HashData(data)), pathOffset=data.AsSpan().IndexOf(needle), pkg.PkgId, pkg.PatchId }));
 }
} finally {pkg.CloseStreams();}
