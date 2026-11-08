import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import java.nio.file.Files;
import java.nio.file.Path;

public class BatchBoundedFunctions extends GhidraScript {
 public void run() throws Exception {
  String[] args=getScriptArgs();
  if(args.length!=1)throw new IllegalArgumentException("expected range file");
  DecompInterface d=new DecompInterface();
  try {
   if(!d.openProgram(currentProgram))throw new IllegalStateException("decompiler unavailable");
   int n=0;
   for(String line:Files.readAllLines(Path.of(args[0]))) {
    if(monitor.isCancelled() || n++>=15000)break;
    String[] parts=line.trim().split("\\s+");
    if(parts.length!=2)throw new IllegalArgumentException("invalid range");
    Address start=toAddr(parts[0]), end=toAddr(parts[1]);
    if(start==null || end==null || start.compareTo(end)>0 || end.subtract(start)>0x100000 || !currentProgram.getMemory().contains(start) || !currentProgram.getMemory().contains(end))throw new IllegalArgumentException("unsafe range");
    AddressSet range=new AddressSet(start,end);
    boolean decoded=new DisassembleCommand(start,range,true).applyTo(currentProgram,monitor);
    boolean created=new CreateFunctionCmd("candidate_"+start,start,range,SourceType.USER_DEFINED).applyTo(currentProgram,monitor);
    Function f=getFunctionAt(start);
    println("BATCH_FUNCTION start="+start+" end="+end+" disassembled="+decoded+" created="+created+" function="+f);
    if(f==null)continue;
    DecompileResults r=d.decompileFunction(f,2,monitor);
    println("BATCH_RESULT start="+start+" completed="+r.decompileCompleted()+" error="+r.getErrorMessage());
    if(r.getDecompiledFunction()!=null)println(r.getDecompiledFunction().getC());
   }
  } finally {d.dispose();}
 }
}



