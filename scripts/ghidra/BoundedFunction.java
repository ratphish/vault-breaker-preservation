import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;

public class BoundedFunction extends GhidraScript {
    @Override public void run() throws Exception {
        String[] args=getScriptArgs();
        if(args.length!=2)throw new IllegalArgumentException("expected inclusive start and end VAs");
        Address start=toAddr(args[0]), end=toAddr(args[1]);
        if(start==null || end==null || start.compareTo(end)>0 || end.subtract(start)>0x10000)throw new IllegalArgumentException("invalid bounded range");
        AddressSet range=new AddressSet(start,end);
        boolean decoded=new DisassembleCommand(start,range,true).applyTo(currentProgram,monitor);
        println("BOUNDED_FUNCTION disassembled="+decoded+" range="+range);
        boolean created=new CreateFunctionCmd("bounded_candidate",start,range,SourceType.USER_DEFINED).applyTo(currentProgram,monitor);
        Function function=getFunctionAt(start);
        println("BOUNDED_FUNCTION created="+created+" function="+function);
        if(function==null)return;
        DecompInterface d=new DecompInterface();
        try {
            if(!d.openProgram(currentProgram)){println("BOUNDED_FUNCTION decompiler_open_failed");return;}
            DecompileResults r=d.decompileFunction(function,60,monitor);
            println("BOUNDED_FUNCTION completed="+r.decompileCompleted()+" error="+r.getErrorMessage());
            if(r.getDecompiledFunction()!=null)println(r.getDecompiledFunction().getC());
        } finally {d.dispose();}
    }
}
