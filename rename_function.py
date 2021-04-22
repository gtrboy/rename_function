# coding=utf-8
try:
    from ghidra_builtins import *
except:
    pass
from ghidra.program.model.symbol.SourceType import USER_DEFINED
from ghidra.app.decompiler import DecompInterface, DecompileOptions, DecompileResults
from ghidra.program.model.pcode import HighParam, PcodeOp, PcodeOpAST
from ghidra.program.model.address import GenericAddress
import sys

#log_func_name = 'PrintfImpl'
log_func_addr = 0x109570  # change me
param_idx = 4             # change me

UNKNOWN_FUNC_Pfx = 'FUN_'

class FunctionAnalyzer(object):

    def __init__(self, function, timeout = 30):
        self.function = function
        self.timeout = timeout
        #self.hfunction = None
        self.call_pcodes = {}
        self.hfunction = self.get_hfunction()
        self.func_pcode = self.get_function_pcode()
        self.get_all_call_pcode()

    def get_hfunction(self):
        decomplib = DecompInterface()
        decomplib.openProgram(currentProgram)
        timeout = self.timeout
        dRes = decomplib.decompileFunction(self.function, timeout, getMonitor())
        hfunction = dRes.getHighFunction()
        return hfunction

    def get_function_pcode(self):
        if self.hfunction:
            try:
                ops = self.hfunction.getPcodeOps()
            except:
                return None
            return ops

    def get_all_call_pcode(self):
        ops = self.get_function_pcode()
        if not ops:
            print('no ops found!')
            return

        while ops.hasNext():
            pcodeOpAST = ops.next()
            opcode = pcodeOpAST.getOpcode()
            if opcode in [PcodeOp.CALL, PcodeOp.CALLIND]:
                op_call_addr = pcodeOpAST.getInput(0).getPCAddress()
                self.call_pcodes[op_call_addr] = pcodeOpAST
        #print(self.call_pcodes)

    def get_constant_value(self, varnode):
        if varnode.isConstant():
            val = varnode.getAddress().getOffset()
            return val
        else:
            return -1

    def get_func_name_from_param(self, idx, address):
        if address in self.call_pcodes:
            pcodeOpAST = self.call_pcodes[address]
            varnode = pcodeOpAST.getInput(idx)
            if varnode and varnode.isUnique():
                #print('Unique')
                def_pcode = varnode.getDef()
                opcode = def_pcode.getOpcode()
                if opcode == PcodeOp.COPY:
                    #print(def_pcode.getInput(1))
                    str_addr = self.get_constant_value(def_pcode.getInput(0))
                    #print(str_addr)
                    data = getDataAt(toAddr(str_addr))
                    if data.hasStringValue:
                        func_str = data.getValue()
                        #print(func_str)
                        return func_str
                

    def print_pcodes(self):
        print('enter print pcodes')
        ops = self.get_function_pcode()
        while ops.hasNext():
            pcodeOpAST = ops.next()
            print(pcodeOpAST)
            opcode = pcodeOpAST.getOpcode()
            print("Opcode: {}".format(opcode))
            if opcode == PcodeOp.CALL:
                op_call_addr = pcodeOpAST.getInput(0).getPCAddress()
                print('PCAddress: {}'.format(op_call_addr))
                #print("We found Call at 0x{}".format(pcodeOpAST.getInput(0).PCAddress))
                #call_addr = pcodeOpAST.getInput(0).getAddress()
                #print("Calling {}(0x{}) ".format(getFunctionAt(call_addr), call_addr))
                #inputs = pcodeOpAST.getInputs()
                #for i in range(len(inputs)):
                #    parm = inputs[i]
                #    print("parm{}: {}".format(i, parm))


if __name__ == '__main__':
    #printf_function = getFunction(log_func_name)
    printf_function = getFunctionAt(toAddr(log_func_addr))
    if not printf_function:
        print('No {} function.'.format(log_func_name))
        sys.exit()
    
    printf_entry_point = printf_function.entryPoint
    printf_refs = getReferencesTo(printf_entry_point)
    for ref in printf_refs:
        if ref.getReferenceType().isCall():
            ref_from_address = ref.getFromAddress()
            #print("ref_from_address: {}".format(ref_from_address))
            ref_from_function = getFunctionContaining(ref_from_address)
            #print('ref_from_function: {}'.format(ref_from_function))
            if ref_from_function:
                if ref_from_function.name.startswith(UNKNOWN_FUNC_Pfx):
                    #print(ref_from_function.name)
                    #print(ref_from_address)
                    analyzer = FunctionAnalyzer(function=ref_from_function)
                    func_name = analyzer.get_func_name_from_param(param_idx, ref_from_address)
                    print('Rename func_name: {}, at {}'.format(func_name,ref_from_function.name))
                    ref_from_function.setName(func_name, USER_DEFINED)
