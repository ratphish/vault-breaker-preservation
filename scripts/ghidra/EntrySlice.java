import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;

public class EntrySlice extends GhidraScript {
    @Override public void run() throws Exception {
        Address start=toAddr("0x15a14e2b8"), end=toAddr("0x15a14e2d0");
        AddressSet range=new AddressSet(start,end);
        boolean decoded=new DisassembleCommand(start,range,false).applyTo(currentProgram,monitor);
        println("ENTRY_SLICE disassembled="+decoded+" range="+range);
        boolean created=new CreateFunctionCmd("entry_slice",start,range,SourceType.USER_DEFINED).applyTo(currentProgram,monitor);
        Function function=getFunctionAt(start);
        println("ENTRY_SLICE created="+created+" function="+function);
        if(function==null)return;
        DecompInterface decompiler=new DecompInterface();
        try {
            if(!decompiler.openProgram(currentProgram)){println("ENTRY_SLICE decompiler_open_failed");return;}
            DecompileResults result=decompiler.decompileFunction(function,60,monitor);
            println("ENTRY_SLICE completed="+result.decompileCompleted()+" error="+result.getErrorMessage());
            if(result.getDecompiledFunction()!=null)println(result.getDecompiledFunction().getC());
        } finally {decompiler.dispose();}
    }
}
