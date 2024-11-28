# coding=utf-8

"""
Script Prerequisites:
- Labeling of the operator.new function(s)
- Locating the base TypedParam constructor
- Disassemble everything in the .text section, otherwise, Ghidra will be too slow to update
"""

import json
import os
import struct

import ghidra.program.model.data as Data
import ghidra.program.model.data.DataUtilities as DataUtils
import ghidra.program.model.symbol as Symbol
import ghidra.app.util.NamespaceUtils as NameUtils

# Utilities

class VtableIter:
    def __init__(self, start, end):
        self.start = start
        self.end = end
        self.current = start

    def __iter__(self):
        return self
    
    def next(self):
        if self.current.getUnsignedOffset() > self.end.getUnsignedOffset():
            raise StopIteration
        addr = self.current
        self.current = addr.add(8)
        return addr
    
    def reset(self):
        self.current = self.start

class FunctionIter:
    def __init__(self, addr, reversed=False):
        self.func = getFunctionContaining(addr)
        self.current = addr
        self.reversed = reversed

    def __iter__(self):
        return self
    
    def __reversed__(self):
        self.reversed = True
        return self
    
    def set(self, addr):
        self.current = addr
        self.func = getFunctionContaining(addr)

    def reverse(self):
        if not self.reversed:
            self.current = self.current.subtract(4)
        self.reversed = True

    def unreverse(self):
        if self.reversed:
            self.current = self.current.add(4)
        self.reversed = False

    def next(self):
        if not self.func.getBody().contains(self.current):
            raise StopIteration
        addr = self.current
        self.current = self.current.subtract(4) if self.reversed else self.current.add(4)
        return addr

    def reset(self):
        self.current = self.func.getEntryPoint()

    def is_end(self, addr):
        return addr.getUnsignedOffset() >= self.func.getBody().getMaxAddress().getUnsignedOffset() & 0xfffffffffffffffc
    
    def is_start(self, addr):
        return addr.getUnsignedOffset() == self.func.getEntryPoint().getUnsignedOffset()

# Data

prop_accessor_vtable = [
    "checkDerivedRuntimeTypeInfo",
    "getRuntimeTypeInfo",
    "d",
    "d",
    "setValueFromBgyml",
    "setValueFromParent",
    "formatProp",
    "clearValue",
    "setValue",
    "getValueAddress",
    "getValueAddress",
    "getValueSize",
    "",
    "getValueAddressVirtual",
    "getValueAddressVirtual",
    ""
]

composite_vtable = [
    "checkDerivedRuntimeTypeInfo",
    "getRuntimeTypeInfo",
    "d",
    "d",
    "loadBgyml",
    "initDefaults",
    "resolveParent",
    "finalize",
    "findComposite",
    "formatComposite",
    "format",
    ""
]

typed_param_vtable = composite_vtable + [
    "getClassName",
    "getNameMurmur32",
    "getClassSize",
    "",
    "loopComposites",
    "loopEmbeds",
    "loopProps",
    "formatProps",
    "formatComposites",
    "getNameMurmur64",
    "isParamPresent"
]

typed_param_map_vtable = composite_vtable + [
    "",
    "",
    "",
    "getClassNameHash",
    "createTypedParam"
]

typed_param_buffer_vtable = composite_vtable + [
    "getClassNameHash",
    "createTypedParam"
]

prop_map_vtable = composite_vtable + [
    "getProp",
    "",
    "",
    "",
    ""
]

prop_buffer_vtable = composite_vtable + [
    "",
    "",
    "",
    "getProp",
    "getCount",
    "",
    "setValueFromBgyml",
    "setValueDefault",
    "setCount",
    "allocBuffer"
]

curve_types = {
    0 : "Linear",
    1 : "Hermit",
    2 : "Step",
    3 : "Sin",
    4 : "Cos",
    5 : "SinPow2",
    6 : "Linear2D",
    7 : "Hermit2D",
    8 : "Step2D",
    9 : "NonuniformSpline",
    10 : "Hermit2DSmooth"
}

# not an actual enum
cPropMap = 0
cPropEnumMap = 1
cPropBuffer = 2
cTypedParamMap = 3
cTypedParamEnumMap = 4
cTypedParamBuffer = 5
cTypedParam = 6

# Ghidra stuff

text = getMemoryBlock(".text")
data = getMemoryBlock(".data")
rodata = getMemoryBlock(".rodata.1")
plt = getMemoryBlock(".plt")
got = getMemoryBlock(".got")
init_array = getMemoryBlock(".init_array")
mem = currentProgram.getMemory()
syms = currentProgram.getSymbolTable()

assert text is not None, "Missing .text block"
assert data is not None, "Missing .data block"
assert rodata is not None, "Missing .rodata.1 block"
assert plt is not None, "Missing .plt block"
assert got is not None, "Missing .got block"
assert init_array is not None, "Missing init_array"

# Data Storage

sead_type_info = {} # Address: Name
inheritance_map = {} # This: Base
prop_accessors = {} # Address: Type
composites = {} # Address: (Type, ResolveType)
typed_param_locations = {} # Address: Address
typed_param_classes = {} # Address: Everything Else

# Useful Functions

# this is required for relative paths when running through Ghidra
def format_path(path):
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), path)

def align_up(value, align):
    return (value + align - 1) & -align

def to_namespace(classname):
    return NameUtils.createNamespaceHierarchy(classname.replace("__", "::"), None, currentProgram, Symbol.SourceType.USER_DEFINED)

def get_classname(classname):
    pos = classname.find("<")
    if pos == -1:
        return classname.split("__")[-1]
    else:
        return classname[:pos].split("__")[-1]

def clear_and_create_label(addr, name, namespace):
    if isinstance(namespace, str):
        namespace = to_namespace(namespace)
    old = syms.getSymbols(addr)
    for sym in old:
        sym.delete()
    createLabel(addr, name, namespace, True, Symbol.SourceType.USER_DEFINED)

def register_rtti(addr, namespace):
    if isinstance(namespace, str):
        namespace = to_namespace(namespace)
    clear_and_create_label(addr, "sTypeInfo", namespace)
    sead_type_info[int(addr.getUnsignedOffset())] = namespace.getName(True)

# labels a vtable function + type info if applicable
def label_func(func, name, classname):
    namespace = to_namespace(classname)
    if name == "d":
        name = "~" + get_classname(classname)
    if name == "getRuntimeTypeInfo":
        static_func = func
        if func.isThunk():
            thunk = func.getThunkedFunction(False)
            func.setThunkedFunction(None)
            thunk.setParentNamespace(namespace)
            thunk.setName("getRuntimeTypeInfoStatic", Symbol.SourceType.USER_DEFINED)
            static_func = thunk
        # manual thunk check (if ghidra missed it or the user already unthunked it)
        elif getInstructionAt(func.getEntryPoint()).getMnemonicString() == "b":
            thunk = getFunctionAt(getInstructionAt(func.getEntryPoint()).getOpObjects(0)[0])
            func.setThunkedFunction(None)
            thunk.setParentNamespace(namespace)
            thunk.setName("getRuntimeTypeInfoStatic", Symbol.SourceType.USER_DEFINED)
            static_func = thunk
        iter = FunctionIter(static_func.getEntryPoint())
        ret_addr = None
        for addr in iter:
            inst = getInstructionAt(addr)
            if inst.getMnemonicString() == "ret":
                ret_addr = addr
                break
        iter.set(ret_addr)
        for addr in reversed(iter):
            inst = getInstructionAt(addr)
            if inst.getMnemonicString() in ["ldr", "add"] and inst.getRegister(0).getName() == "x0":
                type_info_ptr = inst.getOperandReferences(0)[0].getToAddress()
                register_rtti(type_info_ptr, namespace)
            elif inst.getMnemonicString() == "ldp":
                if inst.getRegister(0).getName() == "x0":
                    type_info_ptr = inst.getOperandReferences(0)[0].getToAddress()
                    register_rtti(type_info_ptr, namespace)
                elif inst.getRegister(1).getName() == "x0":
                    type_info_ptr = inst.getOperandReferences(1)[0].getToAddress()
                    register_rtti(type_info_ptr, namespace)
    func.setParentNamespace(namespace)
    func.setName(name, Symbol.SourceType.USER_DEFINED)

def create_func(addr, name=None):
    assert text.contains(addr), "Can only create functions in text"
    diasm_res = disassemble(addr)
    if not diasm_res:
        return None
    return createFunction(addr, name)

def create_data(addr, dt):
    return DataUtils.createData(currentProgram, addr, dt, -1, DataUtils.ClearDataMode.CLEAR_ALL_CONFLICT_DATA)

def create_pointer(addr):
    assert data.contains(addr), "Can only create pointer in data"
    val = mem.getLong(addr)
    if val >> 0x20 != 0x71:
        return None
    ptr = create_data(addr, Data.PointerDataType.dataType)
    return None if ptr is None else ptr.getValue()

def create_string(addr):
    assert data.contains(addr) or rodata.contains(addr), "Can only create string in data/rodata"
    string = create_data(addr, Data.StringUTF8DataType.dataType)
    return "" if string is None else string.getValue()

def get_func(addr, name=None):
    assert text.contains(addr) or plt.contains(addr), "Func not in text or plt"
    func = getFunctionAt(addr)
    if func is not None:
        return func
    return create_func(addr, name)

def get_pointer(addr):
    assert data.contains(addr) or got.contains(addr), "Can only get pointer in data or GOT"
    val = mem.getLong(addr)
    if val >> 0x20 != 0x71:
        return None
    ptr = getDataAt(addr)
    if ptr is None or not ptr.isPointer():
        return create_pointer(addr)
    return ptr.getValue()

def get_string(addr, force_create=False):
    assert data.contains(addr) or rodata.contains(addr), "Strings must be in .data or .rodata.1"
    string = getDataAt(addr)
    if force_create or string is None or not string.hasStringValue():
        return create_string(addr)
    return string.getValue()

def is_vtable_ptr(addr):
    return data.contains(addr)

def is_func_ptr(addr):
    return text.contains(addr)

def is_init_array_func(func):
    for ref in getReferencesTo(func.getEntryPoint()):
        if init_array.contains(ref.getFromAddress()):
            return True
    return False

# gets the function at a specific address in the vtable
def get_vtable_func(addr):
    assert data.contains(addr), "Invalid vtable address"
    ptr = get_pointer(addr)
    if ptr is None:
        return None
    return get_func(ptr)

# takes in an arbitrary entry in the vtable
def get_vtable_start(addr):
    assert data.contains(addr), "Not a valid vtable location"
    while True:
        ptr = get_pointer(addr)
        if ptr is None or not is_func_ptr(ptr):
            return addr.add(8)
        addr = addr.subtract(8)
        if not data.contains(addr):
            return addr.add(8)

# takes in an arbitrary entry in the vtable
def get_vtable_end(addr):
    assert data.contains(addr), "Not a valid vtable location"
    while True:
        ptr = get_pointer(addr)
        if ptr is None or not is_func_ptr(ptr):
            return addr.subtract(8)
        addr = addr.add(8)
        if not data.contains(addr):
            return addr.subtract(8)
        
# takes in an arbitrary entry in the vtable
def create_vtable(addr):
    assert data.contains(addr), "Not a valid vtable location"
    for address in VtableIter(get_vtable_start(addr), get_vtable_end(addr)):
        func_ptr = get_pointer(address)
        assert func_ptr is not None and is_func_ptr(func_ptr), "Found non function pointer in vtable"
        create_func(func_ptr)

def clear_vtable(addr):
    assert data.contains(addr), "Not a valid vtable location"
    for address in VtableIter(get_vtable_start(addr), get_vtable_end(addr)):
        func = get_vtable_func(address)
        if func is None:
            continue
        old = syms.getSymbols(func.getEntryPoint())
        for sym in old:
            if not sym.isPrimary():
                sym.delete()
        func.setParentNamespace(currentProgram.getGlobalNamespace())
        func.setName(None, Symbol.SourceType.ANALYSIS)


def label_vtable(addr, classname, names, clear_existing=False):
    assert data.contains(addr), "Not a valid vtable location"
    if clear_existing:
        clear_vtable(addr)
    for name, address in zip(names, VtableIter(get_vtable_start(addr), get_vtable_end(addr))):
        func = get_vtable_func(address)
        if func is None or func.getName() == name or func.getName() == "__cxa_pure_virtual" or "~" in func.getName():
            continue
        if not func.isGlobal() and name == "":
            continue
        label_func(func, name, classname)

def skip_prologue(addr):
    assert text.contains(addr), "Not a valid function address"
    func = get_func(addr)
    frame_size = 0
    if func is None:
        return addr, frame_size
    for address in FunctionIter(addr):
        inst = getInstructionAt(address)
        if inst is None:
            return address, frame_size
        if inst.getMnemonicString() not in ["stp", "add", "str", "sub", "mov"]:
            return address, frame_size
        if inst.getMnemonicString() == "stp":
            if inst.getOpObjects(2)[0].getName() != "sp":
                return address, frame_size
        if inst.getMnemonicString() in ["add", "sub", "mov", "str"]:
            if inst.getMnemonicString() == "add":
                if inst.getRegister(0).getName() == "x29" and inst.getRegister(1).getName() == "sp":
                    frame_size = inst.getScalar(2).getUnsignedValue()
            if inst.getOpObjects(1)[0].getName() != "sp":
                return address, frame_size

# the assumption is the first add/ldr after the adrp will be for the string
# also assuming ghidra correctly recognizes the string reference
def get_adrp_string(addr):
    assert text.contains(addr), "Not a valid function address"
    register = None
    check_str = False
    for address in FunctionIter(addr):
        inst = getInstructionAt(address)
        if register is None and inst.getMnemonicString() == "adrp":
            register = inst.getOpObjects(0)[0]
        elif register is None:
            continue
        elif inst.getMnemonicString() == "add" and inst.getRegister(1) == register:
            if len(inst.getOperandReferences(0)) > 0:
                ref_addr = inst.getOperandReferences(0)[0].getToAddress()
                return get_string(ref_addr)
        elif inst.getMnemonicString() == "ldr" and inst.getRegister(1) == register:
            if len(inst.getOperandReferences(1)) > 0:
                ref_addr = inst.getOperandReferences(1)[0].getToAddress()
                return get_string(ref_addr)
        elif inst.getMnemonicString() == "mov" and inst.getRegister(1) == register:
            if len(inst.getOperandReferences(0)) > 0:
                ref_addr = inst.getOperandReferences(0)[0].getToAddress()
                return get_string(ref_addr)
        elif inst.getMnemonicString() == "csel" and (inst.getRegister(1) == register or inst.getRegister(2) == register):
            register = inst.getRegister(0)
            check_str = True
        elif check_str and inst.getMnemonicString() == "str" and inst.getRegister(0) == register:
            if len(inst.getOperandReferences(0)) > 0:
                ref_addr = inst.getOperandReferences(0)[0].getToAddress()
                return get_string(ref_addr)
    return None

# for getting a pointer to static data passed to a function
def get_adrp_ptr(addr, register):
    assert text.contains(addr), "Not a valid function address"
    for address in FunctionIter(addr, True):
        inst = getInstructionAt(address)
        if inst.getMnemonicString() == "add" and inst.getRegister(0).getName() == register:
            if len(inst.getOperandReferences(0)) > 0:
                return inst.getOperandReferences(0)[0].getToAddress()
        
    return None

# for getting an immediate value passed to a function
def get_immediate(addr, register):
    assert text.contains(addr), "Not a valid function address"
    val = 0
    for address in FunctionIter(addr, True):
        inst = getInstructionAt(address)
        if inst.getMnemonicString() == "mov" and inst.getRegister(0).getName() == register:
            if inst.getScalar(1) is not None:
                return val | int(inst.getScalar(1).getValue())
            else:
                register = inst.getRegister(1).getName()
        elif inst.getMnemonicString() == "movk" and inst.getRegister(0).getName() == register:
            i = inst.getDefaultOperandRepresentation(1).find("LSL #")
            shift = int(inst.getDefaultOperandRepresentation(1)[i+5:])
            val |= inst.getOpObjects(1)[0].getValue() << shift
        elif inst.getMnemonicString() == "fmov" and inst.getRegister(0).getName() == register:
            if inst.getScalar(1) is not None:
                return struct.unpack("!f", hex(int(inst.getScalar(1).getValue()))[2:].decode("hex"))[0]
    return None

def get_type_info(addr):
    assert text.contains(addr), "Not a valid function address"
    for address in FunctionIter(addr):
        inst = getInstructionAt(address)
        if inst.getMnemonicString() == "bl" and getFunctionAt(inst.getOpObjects(0)[0]).getName() == "__cxa_guard_acquire":
            add_inst = getInstructionAt(address.subtract(4))
            assert add_inst.getMnemonicString() == "add", address
            return inst.getOperandReferences(0)[0].getToAddress().subtract(8)

# returns (this type, base type), takes in the address to checkDerivedRuntimeTypeInfo
def get_base_type(addr):
    assert text.contains(addr), "Not a valid function address"
    func = get_func(addr)
    if func.isThunk():
        func = func.getThunkedFunction(False)
    this = None
    base = None
    iter = FunctionIter(func.getEntryPoint())
    for address in iter:
        inst = getInstructionAt(address)
        if inst.getMnemonicString() == "b" and not iter.is_end(address):
            iter.set(inst.getOpObjects(0)[0])
        elif inst.getMnemonicString() == "tbz":
            iter.set(inst.getOpObjects(2)[0])
        elif inst.getMnemonicString() == "bl":
            if getFunctionAt(inst.getOpObjects(0)[0]).getName() == "__cxa_guard_acquire":
                add_inst = getInstructionAt(address.subtract(4))
                if add_inst.getMnemonicString() not in ["add", "ldr", "mov"]:
                    add_inst = getInstructionAt(address.subtract(8))
                assert add_inst.getMnemonicString() in ["add", "ldr", "mov"], addr
                if this is None:
                    # yes, really
                    # ghidra is just slow sometimes, disassemble the entire .text section beforehand to avoid having to do this
                    while True:
                        try:
                            this = add_inst.getOperandReferences(0)[0].getToAddress().subtract(8)
                            break
                        except:
                            pass
                else:
                    base = add_inst.getOperandReferences(0)[0].getToAddress().subtract(8)
            elif getFunctionAt(inst.getOpObjects(0)[0]).getName() != "__cxa_guard_release":
                if this is None:
                    this = get_base_type(inst.getOpObjects(0)[0])[0]
                else:
                    base = get_base_type(inst.getOpObjects(0)[0])[0]
        elif iter.is_end(address) and inst.getMnemonicString() == "b":
            func = getFunctionAt(inst.getOpObjects(0)[0])
            if func is None:
                iter.set(inst.getOpObjects(0)[0])
                continue
            if func.getName().startswith("__cxa_guard_"):
                continue
            if this is None:
                this = get_base_type(inst.getOpObjects(0)[0])[0]
            else:
                base = get_base_type(inst.getOpObjects(0)[0])[0]
        if base is not None and this is not None:
            break
    return (this, base)

# takes in the addr to the start of the vtable
def get_name_from_vtable(addr):
    assert data.contains(addr), "Invalid vtable address"
    addr = get_vtable_start(addr).add(0x60)
    func = get_vtable_func(addr)
    if func is None:
        raise Exception("Failed to get name function")
    return get_adrp_string(func.getEntryPoint())

def find_inst(iter, mnemonic):
    for addr in iter:
        inst = getInstructionAt(addr)
        if inst.getMnemonicString() == mnemonic:
            return addr
    return None

# skips inlined sead::Heap::tryAlloc()
# returns address post-skip and the name of the register with the pointer
def skip_create(addr):
    assert text.contains(addr), "Invalid function address"
    addr, _size = skip_prologue(addr)
    iter = FunctionIter(addr)
    bl_iter = FunctionIter(addr)
    for address in bl_iter:
        inst = getInstructionAt(address)
        if inst.getMnemonicString() == "bl":
            func = getFunctionAt(inst.getOpObjects(0)[0])
            if func.getName() == "operator.new":
                inst = getInstructionAt(bl_iter.current)
                if inst.getMnemonicString() == "mov" and inst.getRegister(1).getName() == "x0":
                    return bl_iter.current.add(4), inst.getRegister(0).getName()
                return bl_iter.current, "x0"
    bl_iter.reset()
    bl_addr = find_inst(bl_iter, "bl")
    inst = getInstructionAt(iter.current)
    if bl_addr is None or getFunctionAt(getInstructionAt(bl_addr).getOpObjects(0)[0]).getName(True) != "nn::os::GetTlsValue":
        if inst.getMnemonicString() == "mov" and inst.getRegister(1).getName() == "x0":
            return iter.current.add(4), inst.getRegister(0).getName()
        return iter.current, "x0"
    if inst.getMnemonicString() != "adrp":
        if inst.getMnemonicString() == "mov" and inst.getRegister(1).getName() == "x0":
            return iter.current.add(4), inst.getRegister(0).getName()
        return iter.get_address(), "x0"
    elif addr == getFunctionContaining(addr).getEntryPoint():
        if inst.getMnemonicString() == "mov" and inst.getRegister(1).getName() == "x0":
            return iter.current.add(4), inst.getRegister(0).getName()
        return iter.current, "x0"
    branch = 0
    for address in iter:
        inst = getInstructionAt(address)
        if branch == 0 and inst.getMnemonicString() == "cbz" and inst.getRegister(0).getName() == "x19":
            iter.set(inst.getOpObjects(1)[0])
            branch = 1
        elif branch == 1 and inst.getMnemonicString() == "b":
            iter.set(inst.getOpObjects(0)[0])
            branch = 2
        elif branch == 2:
            if inst.getMnemonicString() == "mov" and inst.getRegister(1).getName() == "x0":
                return iter.current.add(4), inst.getRegister(0).getName()
            inst = getInstructionAt(iter.current.subtract(4))
            if inst.getMnemonicString() == "mov" and inst.getRegister(1).getName() == "x0":
                return iter.current, inst.getRegister(0).getName()
            return iter.current, "x0"
    return iter.current, "x0"

def get_inst_array(addr, count):
    assert text.contains(addr) or plt.contains(addr), "Invalid function address"
    insts = []
    func = getFunctionContaining(addr)
    for i in range(count):
        if func != getFunctionContaining(addr):
            break
        insts.append(getInstructionAt(addr))
        addr = addr.add(4)
    return insts

# checks if a function is the function that returns PropBuffer info stuff
def check_prop_buf_info_func(addr):
    assert text.contains(addr) or plt.contains(addr), "Invalid function address"
    instructions = get_inst_array(addr, 6)
    if len(instructions) != 6:
        return False
    return [i.getMnemonicString() for i in instructions] == ["adrp", "add", "add", "cmp", "csel", "ret"]

# get the pointer to the PropBuffer info from the function
# value is the value of x0
# this determines how PropBuffer parent resolution works
def parse_prop_info_func(addr, value):
    assert text.contains(addr), "Invalid function address"
    instructions = get_inst_array(addr, 6)
    adrp_base = toAddr(instructions[0].getOpObjects(1)[0].getValue())
    adrp_base = adrp_base.add(instructions[1].getScalar(2).getValue())
    return adrp_base.add(value * 8)

def check_orr(addr, register):
    assert text.contains(addr), "Invalid function address"
    iter = FunctionIter(addr, True)
    orr_addr = find_inst(iter, "orr")
    if orr_addr is None:
        return False
    orr = getInstructionAt(orr_addr)
    assert orr.getMnemonicString() == "orr", orr_addr
    if orr.getRegister(0) != register or orr.getOpObjects(1)[0].getName() != "xzr":
        return False
    return True

# returns a pointer value found in relative to x0
# used for finding what a field in a struct is initialized to in the ctor
# assumes no complex branching
def get_ptr_relative(addr, offset, check_branches=True, return_reg=False):
    assert text.contains(addr), "Invalid function address"
    registers = { "x0" : 0x0 } # keep track of the current offset
    addr, new_reg = skip_create(addr)
    registers[new_reg] = 0x0
    extra_refs = {}
    iter = FunctionIter(addr)
    for address in iter:
        inst = getInstructionAt(address)
        if inst.getMnemonicString() == "ret":
            return None
        if inst.getMnemonicString() == "mov" and len(inst.getOpObjects(1)) > 0 and type(inst.getOpObjects(1)[0]) == ghidra.program.model.lang.Register:
            if inst.getRegister(0).getName() in extra_refs:
                del extra_refs[inst.getRegister(0).getName()]
            if inst.getRegister(1) is not None and inst.getRegister(1).getName() in registers:
                registers[inst.getRegister(0).getName()] = registers[inst.getRegister(1).getName()]
        elif inst.getMnemonicString() == "add":
            if inst.getRegister(1) is not None and inst.getRegister(1).getName() in registers:
                registers[inst.getRegister(0).getName()] = registers[inst.getRegister(1).getName()] + inst.getScalar(2).getValue()
        elif check_branches and inst.getMnemonicString() == "bl":
            if check_prop_buf_info_func(inst.getOpObjects(0)[0]):
                if "x0" in registers:
                    del registers["x0"]
                val = get_immediate(address, "x0")
                if val is None:
                    val = get_immediate(address, "w0")
                extra_refs["x0"] = parse_prop_info_func(inst.getOpObjects(0)[0], val)
            else:
                relative_offset = offset - registers["x0"]
                if text.contains(inst.getOpObjects(0)[0]):
                    if relative_offset >= 0:
                        value = get_ptr_relative(inst.getOpObjects(0)[0], relative_offset, return_reg=return_reg)
                        if value is None:
                            continue
                        alternate = get_ptr_relative(getFunctionContaining(addr).getEntryPoint(), offset, False, return_reg=return_reg)
                        if alternate is None:
                            alternate = value
                        if isinstance(alternate, tuple):
                            alternate = list(alternate)
                            alternate[1] = address
                            alternate = tuple(alternate)
                        return alternate
        elif inst.getMnemonicString() in ["str", "strh", "strb", "stur"]:
            off = 0
            if len(inst.getOpObjects(1)) > 1:
                off = inst.getOpObjects(1)[1].getValue()
            if inst.getOpObjects(1)[0].getName() in registers:
                if (off + registers[inst.getOpObjects(1)[0].getName()]) == offset:
                    target = inst.getOpObjects(0)[0]
                    if target.getName() in ["xzr", "wzr"]:
                        return 0
                    param = inst.getOperandReferences(0)
                    if param is not None and len(param) > 0:
                        return param[0].getToAddress()
                    if inst.getRegister(0).getName() in extra_refs:
                        return extra_refs[inst.getRegister(0).getName()]
                    if check_orr(address, inst.getRegister(0)):
                        return 0
                    value = get_immediate(address, target.getName())
                    if value is not None:
                        return value
                    if return_reg:
                        return (target, address)
                if inst.getDefaultOperandRepresentation(1)[-1] == "!":
                    registers[inst.getOpObjects(1)[0].getName()] += inst.getOpObjects(1)[1].getValue()
        elif inst.getMnemonicString() == "stp":
            off = 0
            if len(inst.getOpObjects(2)) > 1:
                off = inst.getOpObjects(2)[1].getValue()
            add = 0x4 if inst.getOpObjects(0)[0].getName().startswith("w") else 0x8
            if inst.getOpObjects(2)[0].getName() in registers and (off + registers[inst.getOpObjects(2)[0].getName()]) == offset:
                target = inst.getOpObjects(0)[0]
                if target.getName() in ["xzr", "wzr"]:
                    return 0
                param = inst.getOperandReferences(0)
                if param is not None and len(param) > 0:
                    return param[0].getToAddress()
                if inst.getRegister(0).getName() in extra_refs:
                    return extra_refs[inst.getRegister(0).getName()]
                if check_orr(address, inst.getRegister(0)):
                    return 0
                value = get_immediate(address, target.getName())
                if value is not None:
                    return value
                if return_reg:
                    return (target, address)
            elif inst.getOpObjects(2)[0].getName() in registers and (off + add + registers[inst.getOpObjects(2)[0].getName()]) == offset:
                target = inst.getOpObjects(1)[0]
                if target.getName() in ["xzr", "wzr"]:
                    return 0
                param = inst.getOperandReferences(1)
                if param is not None and len(param) > 0:
                    return param[0].getToAddress()
                if inst.getRegister(1).getName() in extra_refs:
                    return extra_refs[inst.getRegister(1).getName()]
                if check_orr(address, inst.getRegister(1)):
                    return 0
                value = get_immediate(address, target.getName())
                if value is not None:
                    return value
                if return_reg:
                    return (target, address)
    val = 0
    for address in reversed(iter):
        inst = getInstructionAt(address)
        if inst.getMnemonicString() == "mov" and inst.getRegister(0) == target:
            val |= inst.getScalar(1).getValue()
            return val
        elif inst.getMnemonicString() == "movk" and inst.getRegister(0) == target:
            i = inst.getDefaultOperandRepresentation(1).find("LSL #")
            shift = int(inst.getDefaultOperandRepresentation(1)[i+5:])
            val |= inst.getOpObjects(1)[0].getValue() << shift
    return None

def get_vptr_from_ctor(addr):
    assert text.contains(addr), "Invalid function address"
    return get_ptr_relative(addr, 0x0)

# find offset in stack a given register is stored into
def get_stack_offset(addr, register):
    assert text.contains(addr), "Invalid function address"
    for address in FunctionIter(addr, True):
        inst = getInstructionAt(address)
        if inst is None or inst.getMnemonicString() == "ret":
            return None
        if inst.getMnemonicString() == "add":
            if inst.getRegister(0).getName() == register:
                if inst.getScalar(2) != None:
                    return inst.getScalar(2).getUnsignedValue()
                else:
                    return 0
        if inst.getMnemonicString() == "mov" and inst.getRegister(0).getName() == register and inst.getRegister(1) is not None:
            if inst.getRegister(1).getName() == "sp":
                return 0
    return 0

def get_stack_param(addr, offset, base):
    register = None
    iter = FunctionIter(addr, True)
    for address in iter:
        inst = getInstructionAt(address)
        if inst is None or inst.getMnemonicString() == "ret":
            return None
        if inst.getMnemonicString() == "str":
            stack_offset = 0
            if len(inst.getOpObjects(1)) > 1:
                stack_offset = inst.getOpObjects(1)[1].getUnsignedValue()
            if inst.getOpObjects(1)[0].getName() == "sp" and (stack_offset - base) == offset:
                param = inst.getOperandReferences(0)
                if param is not None and len(param) > 0:
                    return param[0].getToAddress()
                register = inst.getRegister(0)
        if inst.getMnemonicString() == "stp":
            stack_offset = 0
            if len(inst.getOpObjects(2)) > 1:
                stack_offset = inst.getOpObjects(2)[1].getUnsignedValue()
            if inst.getOpObjects(2)[0].getName() == "sp" and (stack_offset - base) == offset:
                param = inst.getOperandReferences(0)
                if param is not None and len(param) > 0:
                    return param[0].getToAddress()
                register = inst.getRegister(0)
                break
            if inst.getOpObjects(2)[0].getName() == "sp" and (stack_offset - base + 0x8) == offset:
                param = inst.getOperandReferences(1)
                if param is not None and len(param) > 0:
                    return param[0].getToAddress()
                register = inst.getRegister(1)
                break
    if register is None:
        raise Exception("Failed to get stack param", iter.current)
    found = False
    for address in iter:
        inst = getInstructionAt(address)
        if not found and inst.getMnemonicString() == "mov" and inst.getRegister(0) == register and inst.getRegister(1).getName() == "x0":
            found = True
        if found and inst.getMnemonicString() == "bl":
            return get_adrp_string(inst.getOpObjects(0)[0])
                
def get_stack_param_immediate(addr, offset, base):
    register = None
    for address in FunctionIter(addr, True):
        inst = getInstructionAt(address)
        if inst is None or inst.getMnemonicString() == "ret":
            return 0
        if inst.getMnemonicString() == "str":
            stack_offset = 0
            if len(inst.getOpObjects(1)) > 1:
                stack_offset = inst.getOpObjects(1)[1].getUnsignedValue()
            if inst.getOpObjects(1)[0].getName() == "sp" and (stack_offset - base) == offset:
                register = inst.getRegister(0)
        if inst.getMnemonicString() == "stp":
            stack_offset = 0
            if len(inst.getOpObjects(2)) > 1:
                stack_offset = inst.getOpObjects(2)[1].getUnsignedValue()
            if inst.getOpObjects(2)[0].getName() == "sp" and (stack_offset - base) == offset:
                register = inst.getRegister(0)
            if inst.getOpObjects(2)[0].getName() == "sp" and (stack_offset - base + 0x8) == offset:
                register = inst.getRegister(1)
        if register is not None and inst.getMnemonicString() == "mov" and inst.getRegister(0) == register:
            return inst.getScalar(1).getValue()
    return 0
        
def get_stack_param_offset(addr, offset, base, frame_size):
    register = None
    for address in FunctionIter(addr, True):
        inst = getInstructionAt(address)
        if inst is None or inst.getMnemonicString() == "ret":
            return None
        if inst.getMnemonicString() == "str":
            stack_offset = 0
            if len(inst.getOpObjects(1)) > 1:
                stack_offset = inst.getOpObjects(1)[1].getUnsignedValue()
            if inst.getOpObjects(1)[0].getName() == "sp" and (stack_offset - base) == offset:
                register = inst.getRegister(0)
            if inst.getOpObjects(1)[0].getName() == "x29" and (stack_offset - base + frame_size) == offset:
                register = inst.getRegister(0)
        if inst.getMnemonicString() == "stp":
            stack_offset = 0
            if len(inst.getOpObjects(2)) > 1:
                stack_offset = inst.getOpObjects(2)[1].getUnsignedValue()
            if inst.getOpObjects(2)[0].getName() == "sp" and (stack_offset - base) == offset:
                register = inst.getRegister(0)
            if inst.getOpObjects(2)[0].getName() == "sp" and (stack_offset - base + 0x8) == offset:
                register = inst.getRegister(1)
            if inst.getOpObjects(2)[0].getName() == "x29" and (stack_offset - base + frame_size) == offset:
                register = inst.getRegister(0)
            if inst.getOpObjects(2)[0].getName() == "x29" and (stack_offset - base + 0x8 + frame_size) == offset:
                register = inst.getRegister(1)
        if register is not None and inst.getMnemonicString() == "add" and inst.getRegister(0) == register and inst.getRegister(1).getName() in ["x20", "x0"]:
            return inst.getScalar(2).getValue()
        if register is not None and inst.getMnemonicString() == "ldr" and inst.getRegister(0) == register and inst.getOpObjects(1)[0].getName() in ["x20", "x0"]:
            return inst.getOpObjects(1)[1].getValue()

def get_last_vtable(addr):
    guard = False
    for address in FunctionIter(addr, True):
        inst = getInstructionAt(address)
        if inst is None or inst.getMnemonicString() == "ret":
            return None
        if inst.getMnemonicString() == 'bl':
            function = getFunctionContaining(inst.getOpObjects(0)[0])
            if function is not None and function.getName() == "__cxa_guard_release":
                guard = True
            elif function is not None and function.getName() == "__cxa_guard_acquire":
                guard = False
        if guard:
            continue
        if inst.getMnemonicString() == "str":
            param = inst.getOperandReferences(0)
            if param is not None and len(param) > 0 and data.contains(param[0].getToAddress()):
                vtable = param[0].getToAddress()
                if text.contains(toAddr(getLong(vtable))):
                    return vtable
        if inst.getMnemonicString() == "stp":
            param = inst.getOperandReferences(0)
            if param is not None and len(param) > 0 and data.contains(param[0].getToAddress()):
                vtable = param[0].getToAddress()
                if text.contains(toAddr(getLong(vtable))):
                    return vtable
            param = inst.getOperandReferences(1)
            if param is not None and len(param) > 0 and data.contains(param[0].getToAddress()):
                vtable = param[0].getToAddress()
                if text.contains(toAddr(getLong(vtable))):
                    return vtable
    return None

# find first PropAccessor vtable in loopProps or formatProps
def find_first_vtable(addr):
    assert text.contains(addr), "Invalid function address"
    addr, _size = skip_prologue(addr)
    iter = FunctionIter(addr)

    guard = 0
    for address in iter:
        inst = getInstructionAt(address)
        if inst.getMnemonicString() == "bl":
            function = getFunctionContaining(inst.getOpObjects(0)[0])
            if function is not None and function.getName() == "__cxa_guard_acquire":
                guard += 1
            elif function is not None and function.getName() == "__cxa_guard_release":
                guard -= 1
            continue

        if guard > 0:
            continue
        if inst.getMnemonicString() != "blr":
            continue

        return get_last_vtable(iter.current)

def parse_byml_node_type(value, conv_func):
    if value > 0xff:
        value = value >> 0x20
    if value == 0xd0:
        return "bool"
    elif value == 0xd1:
        return "s32"
    elif value == 0xd2:
        if getInstructionAt(conv_func.getEntryPoint()).getMnemonicString() != "ret":
            # probably fake
            # just a float angle that can be in degrees or radians
            return "sead::Angle"
        return "f32"
    elif value == 0xd3:
        return "u32"
    elif value == 0xd4:
        return "s64"
    elif value == 0xd5:
        return "u64"
    elif value == 0xd6:
        return "f64"
    elif value == 0xa0:
        if getInstructionAt(conv_func.getEntryPoint()).getMnemonicString() != "ret":
            return "sead::Hash"
        return "sead::SafeString"
    return "other"

# Takes in a vtable address, tries to guess PropAccessor type
def guess_type(addr):
    addr = get_vtable_start(addr)
    if addr in prop_accessors:
        return prop_accessors[addr]
    create_vtable(addr)
    set_func = get_vtable_func(addr.add(0x20))
    format_func = get_vtable_func(addr.add(0x30))
    conv_func = get_vtable_func(addr.add(0x78))

    a, _size = skip_prologue(set_func.getEntryPoint())
    set_iter = FunctionIter(a)
    prop_type = ""
    value = 0
    register = None
    for address in set_iter:
        inst = getInstructionAt(address)
        if inst.getMnemonicString() == "bl":
            set_func = getFunctionAt(inst.getOpObjects(0)[0])
            a, _size = skip_prologue(set_func.getEntryPoint())
            set_iter.set(a)
            continue
        if not set_iter.reversed and inst.getMnemonicString() != "cmp":
            continue
        if set_iter.reversed and register is not None and inst.getMnemonicString() == "mov":
            if inst.getOpObjects(0)[0] == register:
                value = inst.getOpObjects(1)[0].getUnsignedValue()
                prop_type = parse_byml_node_type(value, conv_func)
                break
        node_type = inst.getOpObjects(1)[0]
        if isinstance(node_type, ghidra.program.model.lang.Register):
            set_iter.reverse()
            register = inst.getOpObjects(1)[0]
        elif isinstance(node_type, ghidra.program.model.scalar.Scalar):
            value = inst.getOpObjects(1)[0].getUnsignedValue()
            prop_type = parse_byml_node_type(value, conv_func)
            break
    
    if prop_type not in ["sead::SafeString", "other"]:
        prop_accessors[addr] = prop_type
        return prop_type

    if prop_type == "sead::SafeString":
        current = format_func.getEntryPoint()
        current, a = skip_prologue(current)
        iter = FunctionIter(current)
        count = 0
        current = find_inst(iter, "cmp")
        if current is None:
            prop_accessors[addr] = prop_type
            return prop_type

        offset = 0
        register = getInstructionAt(current).getRegister(0)
        # some enums are adjusted before being indexed
        if getInstructionAt(current.subtract(4)).getMnemonicString() in ["add", "sub"]:
            if getInstructionAt(current.subtract(4)).getRegister(0) == register:
                offset = getInstructionAt(current.subtract(4)).getScalar(2).getValue()
                if getInstructionAt(current.subtract(4)).getMnemonicString() == "sub":
                    offset = -offset
        if getInstructionAt(current.add(4)).getMnemonicString() in ["b.hi", "b.gt"]:
            count = getInstructionAt(current).getOpObjects(1)[0].getUnsignedValue() + 1
        elif getInstructionAt(current.add(4)).getMnemonicString() in ["b.ls", "b.le"]:
            count = getInstructionAt(current).getOpObjects(1)[0].getUnsignedValue() + 1
        elif getInstructionAt(current.add(4)).getMnemonicString() == "csel":
            # in the rare case the enum only has one value
            current = current.subtract(4)
            iter = FunctionIter(current, True)
            current = find_inst(iter, "adrp")
            prop_type = []
            inst = getInstructionAt(current)
            adrp_offset = inst.getScalar(1).getUnsignedValue()
            adrp_offset += getInstructionAt(current.add(4)).getScalar(2).getUnsignedValue()
            string = get_string(toAddr(adrp_offset))
            if string is None:
                raise Exception("Could not resolve string")
            prop_type.append(string)
            prop_accessors[addr] = prop_type
            return prop_type
        else:
            raise Exception(getInstructionAt(current.add(4)).getMnemonicString(), current)
        current = current.add(4)
        ptr = None
        register = None

        for address in FunctionIter(current):
            inst = getInstructionAt(address)
            if inst.getMnemonicString() == "adrp":
                ptr = inst.getOpObjects(1)[0].getValue()
                register = inst.getOpObjects(0)[0]
                continue
            if inst.getMnemonicString() == "add" and ptr is not None and register is not None:
                if inst.getOpObjects(0)[0] == register:
                    ptr += inst.getOpObjects(2)[0].getUnsignedValue()
                    continue
            if inst.getMnemonicString() == "ldr" and ptr is not None:
                if inst.getOpObjects(0)[0].getName() == "x10":
                    ptr += inst.getOpObjects(1)[1].getUnsignedValue() if len(inst.getOpObjects(1)) > 1 else 0
                if get_pointer(toAddr(ptr)) is None:
                    ptr += inst.getOpObjects(1)[1].getUnsignedValue()
                    break
                if inst.getOpObjects(0)[0].getName() == "x9":
                    try:
                        ptr = getDataAt(toAddr(ptr)).getValue().getUnsignedOffset() + (inst.getOpObjects(1)[1].getUnsignedValue() if len(inst.getOpObjects(1)) > 1 else 0)
                    except:
                        raise Exception(current)
                    break
        
        prop_type = []
        ptr = toAddr(ptr)

        for i in range(count):
            string_addr = get_pointer(ptr)
            string = get_string(string_addr)
            prop_type.append(str(string))
            ptr = ptr.add(8)
        
        if offset != 0:
            prop_type.append(offset) # append the adjustment to the end for later
        
        prop_accessors[addr] = prop_type
        return prop_type
    elif prop_type == "other":
        current = format_func.getEntryPoint()
        current, a = skip_prologue(current)
        iter = FunctionIter(current)
        current = find_inst(iter, "adrp")
        
        format_str = get_adrp_string(current)
        while format_str is None:
            current = find_inst(iter, "adrp")
            if current is None:
                raise Exception(addr)
            format_str = get_adrp_string(current)
        if format_str is None:
            raise Exception(addr)
        if format_str == r"%d, %d":
            prop_type = "sead::Vector2i"
        elif format_str == r"%d, %d, %d":
            prop_type = "sead::Vector3i"
        elif format_str == r"%f, %f":
            prop_type = "sead::Vector2f"
        elif format_str == r"%f, %f, %f":
            prop_type = "sead::Vector3f"
        elif format_str == r"%f, %f, %f, %f":
            prop_type = "sead::Color4f"
        elif format_str == r"%f [rad]":
            # idk what to call this I just made it up lol
            # it's just a sead::Vector3f that stores three angles either as deg or rad
            prop_type = "sead::Rotation"
        elif format_str == r"%llu":
            prop_type = "u64"
        elif format_str == r"%lld":
            prop_type = "s64"
        else:
            prop_type = "sead::hostio::Curve"
        prop_accessors[addr] = prop_type
        return prop_type

# get default value for sead::hostio::Curve props
def get_curve_properties(addr):
    refs = getReferencesTo(addr)
    for ref in refs:
        if ref.getReferenceType().isWrite():
            ref_addr = ref.getFromAddress()
            break
    iter = FunctionIter(ref_addr, True)

    curve = {"Type": None, "MaxX": None, "Floats": None}
    count = None
    floats = None

    inst = getInstructionAt(iter.current)
    assert inst.getMnemonicString() in ["str", "stp"], iter.current
    if inst.getMnemonicString() != "str": # curve constructor is inlined
        type_max_refs = getReferencesTo(addr.add(8))
        for ref in type_max_refs:
            if ref.getReferenceType().isWrite():
                ref_addr = ref.getFromAddress()
                break
        inst = getInstructionAt(ref_addr)
        register = inst.getRegister(1)
        value = 0
        for address in FunctionIter(ref_addr, True):
            inst = getInstructionAt(address)
            if inst.getMnemonicString() == "movk" and inst.getRegister(0) == register:
                i = inst.getDefaultOperandRepresentation(1).find("LSL #")
                shift = int(inst.getDefaultOperandRepresentation(1)[i+5:])
                value |= inst.getOpObjects(1)[0].getValue() << shift
            if inst.getMnemonicString() == "mov" and inst.getRegister(0) == register:
                value |= inst.getOpObjects(1)[0].getValue()
                break
        curve["Type"] = curve_types[value & 0xffffffff]
        curve["MaxX"] = struct.unpack("<f", struct.pack("<i", (value >> 0x20) & 0xffffffff))[0]
        count_refs = getReferencesTo(addr.add(0x10))
        for ref in count_refs:
            if ref.getReferenceType().isWrite():
                ref_addr = ref.getFromAddress()
                break
        iter = FunctionIter(ref_addr, True)
        register = getInstructionAt(iter.current).getRegister(0)
        for address in iter:
            inst = getInstructionAt(iter.current)
            if inst.getMnemonicString() == "mov" and inst.getRegister(0) == register:
                count = inst.getScalar(1).getValue()
                break
        float_refs = getReferencesTo(addr.add(0x18))
        for ref in float_refs:
            if ref.getReferenceType().isWrite():
                ref_addr = ref.getFromAddress()
                break
        inst = getInstructionAt(ref_addr)
        param = inst.getOperandReferences(0)
        if param is not None and len(param) > 0:
            floats = param[0].getToAddress()
        else:
            raise Exception("Did not find curve float data", iter.current)
        curve["Floats"] = []
        for i in range(count):
            curve["Floats"].append(getFloat(floats.add(4 * i)))
        return curve

    max_register = None
    for address in iter:
        inst = getInstructionAt(address)
        if inst is None or inst.getMnemonicString() == "ret":
            return None
        if inst.getMnemonicString() == 'bl':
            function = getFunctionContaining(inst.getOpObjects(0)[0])
            if function is not None and function.getName() == "__cxa_guard_acquire":
               return curve
        if inst.getMnemonicString() == "mov":
            if inst.getRegister(0).getName() in ["w1", "x1"]:
                if inst.getRegister(1) is not None:
                    if inst.getRegister(1).getName() in ["wzr", "xzr"]:
                        curve["Type"] = curve_types[0]
                else:
                    curve["Type"] = curve_types[inst.getScalar(1).getUnsignedValue()]
                continue
            if inst.getRegister(0).getName() in ["w2", "x2"]:
                count = inst.getScalar(1).getUnsignedValue()
                continue
            if inst.getRegister(0) == max_register:
                curve["MaxX"] = struct.unpack("<f", struct.pack("<i", inst.getScalar(1).getValue()))[0]
                continue
        if inst.getMnemonicString() == "fmov" and inst.getRegister(0).getName() in ["s0", "d0"]:
            if inst.getScalar(1) is not None:
                curve["MaxX"] = struct.unpack("<f", struct.pack("<i", inst.getScalar(1).getValue()))[0]
            else:
                max_register = inst.getRegister(1)
            continue
        if inst.getRegister(0) is not None and inst.getRegister(0).getName() == "x3" and inst.getMnemonicString() == "add":
            floats = get_adrp_ptr(address, "x3")
            continue
        if floats is not None and count is not None:
            curve["Floats"] = []
            for i in range(count):
                curve["Floats"].append(getFloat(floats.add(4 * i)))
            continue
        if curve["Type"] is not None and count is not None and curve["Floats"] is not None and curve["MaxX"] is not None:
            return curve
    return curve

# get default value for enums using SEAD_ENUM_EX
def get_enum_ex(addr):
    ref_addr = None
    wonky = False
    is_reverse = False
    for ref in getReferencesTo(addr):
        inst = getInstructionAt(ref.getFromAddress())
        if inst.getRegister(ref.getOperandIndex()) is not None and inst.getRegister(ref.getOperandIndex()).getName() == "x0":
            ref_addr = ref.getFromAddress()
            valid = ["x1", "w1"]
            break
        elif inst.getRegister(0).getName() in ["w0", "x0"]:
            ref_addr = ref.getFromAddress()
            valid = ["x0", "w0"]
            is_reverse = True
            break
    if ref_addr is None:
        for ref in getReferencesTo(addr):
            inst = getInstructionAt(ref.getFromAddress())
            if inst.getRegister(0).getName() in ["w8", "x8"]:
                ref_addr = ref.getFromAddress()
                valid = ["x0", "w0"]
                wonky = True
                break
    target = None
    branch = 0
    guard = 0
    branch_addr = None
    values = {}
    register_values = {}
    iter = FunctionIter(ref_addr, is_reverse)
    for address in iter:
        inst = getInstructionAt(address)
        if wonky and branch == 0 and inst.getMnemonicString() != "bl":
            continue
        if iter.reversed and inst.getMnemonicString() not in ["bl", "mov"]:
            continue
        if branch == 0 and inst.getMnemonicString() == "mov" and inst.getRegister(0).getName() in valid:
            target = inst.getScalar(1).getValue()
            iter.unreverse()
        if (target is not None or wonky) and branch == 0 and inst.getMnemonicString() == "bl" and "__cxa" not in getFunctionAt(inst.getOpObjects(0)[0]).getName():
            iter.set(inst.getOpObjects(0)[0])
            branch = 1
            branch_addr = iter.current
            continue
        if branch == 1 and inst.getMnemonicString() == "bl" and "__cxa" not in getFunctionAt(inst.getOpObjects(0)[0]).getName():
            iter.set(inst.getOpObjects(0)[0])
            branch = 2
            continue
        if branch == 2 and inst.getMnemonicString() == "bl" and getFunctionAt(inst.getOpObjects(0)[0]).getName() == "__cxa_guard_acquire":
            guard += 1
        if branch == 2 and inst.getMnemonicString() == "bl" and getFunctionAt(inst.getOpObjects(0)[0]).getName() == "__cxa_guard_release":
            guard -= 1
            break
        if guard > 0:
            if inst.getMnemonicString() == "mov":
                if "x" in inst.getRegister(0).getName():
                    if inst.getScalar(1).getUnsignedValue() > 0xffffffff:
                        register_values[inst.getRegister(0).getName()] = [inst.getScalar(1).getUnsignedValue() & 0xffffffff, 
                                                                        inst.getScalar(1).getUnsignedValue() >> 0x20]
                    else:
                        register_values[inst.getRegister(0).getName()] = [inst.getScalar(1).getUnsignedValue()]
                else:
                    if len(register_values[inst.getRegister(0).getName().replace("w", "x")]) == 0:
                        register_values[inst.getRegister(0).getName().replace("w", "x")].append(inst.getScalar(1).getUnsignedValue())
                    else:
                        register_values[inst.getRegister(0).getName().replace("w", "x")][0] = inst.getScalar(1).getUnsignedValue()
            elif inst.getMnemonicString() == "movk":
                if len(register_values[inst.getRegister(0).getName()]) == 1:
                    register_values[inst.getRegister(0).getName()].append(inst.getOpObjects(1)[0].getUnsignedValue())
                else:
                    register_values[inst.getRegister(0).getName()][1] = inst.getOpObjects(1)[0].getUnsignedValue()
            if inst.getMnemonicString() == "stp":
                reg0 = inst.getRegister(0).getName()
                reg0 = reg0.replace("w", "x")
                reg1 = inst.getRegister(1).getName()
                reg1 = reg1.replace("w", "x")
                offset = int(inst.getOpObjects(2)[1].getValue() / 4) if len(inst.getOpObjects(2)) > 1 else 0
                if register_values[reg0][0] not in values:
                    values[register_values[reg0][0]] = offset
                if register_values[reg0][1] not in values:
                    values[register_values[reg0][1]] = offset + 1
                if register_values[reg1][0] not in values:
                    values[register_values[reg1][0]] = offset + 2
                if len(register_values[reg1]) > 1 and register_values[reg1][1] not in values:
                    values[register_values[reg1][1]] = offset + 3
                elif len(register_values[reg1]) == 1 and 0 not in values:
                    values[0] = offset + 3
                register_values[reg0] = []
                register_values[reg1] = []
            elif inst.getMnemonicString() == "str":
                reg = inst.getRegister(0).getName()
                reg = reg.replace("w", "x")
                offset = int(inst.getOpObjects(1)[1].getValue() / 4) if len(inst.getOpObjects(1)) > 1 else 0
                if register_values[reg][0] not in values:
                    values[register_values[reg][0]] = offset
                if len(register_values[reg]) > 1 and register_values[reg][1] not in values:
                    values[register_values[reg][1]] = offset + 1
                elif len(register_values[reg]) == 1 and 0 not in values:
                    values[0] = offset + 1
                register_values[reg] = []
    if wonky:
        cmp_count = 0
        for address in FunctionIter(branch_addr):
            inst = getInstructionAt(address)
            if inst.getMnemonicString() == "cmp":
                cmp_count += 1
                if cmp_count == 2:
                    target = inst.getScalar(1).getValue()
                    break
    return values[target]

def get_props(addr, classname, allow_overwrite=True):
    assert text.contains(addr), "Invalid function address"
    addr, frame_size = skip_prologue(addr)
    iter = FunctionIter(addr)

    props = {}

    guard = 0
    for address in iter:
        inst = getInstructionAt(address)
        if inst.getMnemonicString() == "bl":
            function = getFunctionContaining(inst.getOpObjects(0)[0])
            if function is not None and function.getName() == "__cxa_guard_acquire":
                guard += 1
                continue
            elif function is not None and function.getName() == "__cxa_guard_release":
                guard -= 1
                continue
            elif guard > 0:
                continue
            props.update(get_props(inst.getOpObjects(0)[0], classname, False))
            continue

        if guard > 0:
            continue
        if inst.getMnemonicString() != "blr":
            continue

        stack_offset = get_stack_offset(address, "x1")
        string_addr = get_stack_param(address, 0x0, stack_offset)
        name = get_string(string_addr)
        default = get_stack_param(address, 0x30, stack_offset)
        if allow_overwrite:
            namespace = to_namespace(classname)
            sym = getSymbolAt(default)
            if sym.getParentNamespace() != namespace:
                sym.delete()
                createLabel(default, "c" + name, namespace, True, Symbol.SourceType.USER_DEFINED)
            elif sym.isGlobal():
                createLabel(default, "c" + name, namespace, True, Symbol.SourceType.USER_DEFINED)
        index = get_stack_param_immediate(address, 0x18, stack_offset)
        offset = get_stack_param_offset(address, 0x40, stack_offset, frame_size)
        if offset is None:
            offset = get_stack_param_offset(address, -0x10, stack_offset, frame_size) # lazy fix
        assert offset is not None, address
        vtable = get_last_vtable(address)
        prop_type = prop_accessors[vtable]
        if isinstance(prop_type, str) or isinstance(prop_type, unicode):
            datatype = prop_type
        else:
            datatype = classname.replace("__", "::") + "::" + name

        if prop_type == "bool":
            props[name] = {"Type": "bool", "Value": True if getByte(default) == 1 else False}
        elif prop_type == "u8":
            props[name] = {"Type": "u8", "Value": getByte(default)}
        elif prop_type == "u32":
            props[name] = {"Type": "u32", "Value": getInt(default) & 0xffffffff}
        elif prop_type == "s32":
            props[name] = {"Type": "s32", "Value": getInt(default)}
        elif prop_type == "u64":
            props[name] = {"Type": "u64", "Value": getLong(default) & 0xffffffffffffffff}
        elif prop_type == "s64":
            props[name] = {"Type": "s64", "Value": getLong(default)}
        elif prop_type == "f32":
            props[name] = {"Type": "f32", "Value": getFloat(default)}
        elif prop_type == "sead::Angle":
            props[name] = {"Type": "sead::Angle", "Value": getFloat(default)}
        elif prop_type == "sead::SafeString":
            props[name] = {"Type": "sead::SafeString", "Value": get_string(get_pointer(default))}
        elif prop_type == "sead::Hash":
            props[name] = {"Type": "sead::Hash", "Value": get_string(get_pointer(default))}
        elif prop_type == "sead::Vector3f":
            props[name] = {"Type": "sead::Vector3f", "Value": [getFloat(default), getFloat(default.add(4)), getFloat(default.add(8))]}
        elif prop_type == "sead::Rotation":
            props[name] = {"Type": "sead::Rotation", "Value": [getFloat(default), getFloat(default.add(4)), getFloat(default.add(8))]}
        elif prop_type == "sead::Color4f":
            props[name] = {"Type": "sead::Color4f", "Value": [getFloat(default), getFloat(default.add(4)), getFloat(default.add(8)), getFloat(default.add(0xc))]}
        elif prop_type == "sead::Vector2f":
            props[name] = {"Type": "sead::Vector2f", "Value": [getFloat(default), getFloat(default.add(4))]}
        elif prop_type == "sead::Vector2i":
            props[name] = {"Type": "sead::Vector2i", "Value": [getInt(default), getInt(default.add(4))]}
        elif prop_type == "sead::Vector3i":
            props[name] = {"Type": "sead::Vector3i", "Value": [getInt(default), getInt(default.add(4)), getInt(default.add(8))]}
        elif prop_type == "f64":
            props[name] = {"Type": "f64", "Value": getDouble(default)}
        elif prop_type == "sead::hostio::Curve":
            props[name] = {"Type": "sead::hostio::Curve", "Value": get_curve_properties(default)}
        else:
            if type(prop_type[-1]) not in [str, unicode]:
                props[name] = {"Type": prop_type, "Value": prop_type[getInt(default) + prop_type[-1]]}
            else:
                try:
                    props[name] = {"Type": prop_type, "Value": prop_type[getInt(default)]}
                except:
                    props[name] = {"Type": prop_type, "Value": prop_type[get_enum_ex(default)]}
        props[name]["Index"] = index
        props[name]["Offset"] = offset
    
    return props

def get_embeds(addr):
    assert text.contains(addr), "Invalid function address"
    addr, frame_size = skip_prologue(addr)

    embeds = {}

    guard = 0
    for address in FunctionIter(addr):
        inst = getInstructionAt(address)
        if inst.getMnemonicString() == "bl":
            function = getFunctionContaining(inst.getOpObjects(0)[0])
            if function is not None and function.getName() == "__cxa_guard_acquire":
                guard += 1
                continue
            elif function is not None and function.getName() == "__cxa_guard_release":
                guard -= 1
                continue
            elif guard > 0:
                continue
            embeds.update(get_embeds(inst.getOpObjects(0)[0]))
            continue

        if guard > 0:
            continue
        if inst.getMnemonicString() != "blr":
            continue

        stack_offset = get_stack_offset(address, "x1")
        string_addr = get_stack_param(address, 0x0, stack_offset)
        name = get_string(string_addr)
        offset = get_stack_param_offset(address, 0x38, stack_offset, frame_size)
        index = get_stack_param_immediate(address, 0x18, stack_offset)
        typed_param_addr = get_stack_param(address, 0x28, stack_offset)
        if isinstance(typed_param_addr, str) or isinstance(typed_param_addr, unicode):
            typed_param = typed_param_addr
        else:
            typed_param = get_string(typed_param_addr)
        embeds[name] = {"Offset": offset, "Index": index, "Type": typed_param}
    return embeds

def get_composites(addr):
    assert text.contains(addr), "Invalid function address"
    addr, frame_size = skip_prologue(addr)

    comps = {}

    guard = 0
    for address in FunctionIter(addr):
        inst = getInstructionAt(address)
        if inst.getMnemonicString() == "bl":
            function = getFunctionContaining(inst.getOpObjects(0)[0])
            if function is not None and function.getName() == "__cxa_guard_acquire":
                guard += 1
                continue
            elif function is not None and function.getName() == "__cxa_guard_release":
                guard -= 1
                continue
            elif guard > 0:
                continue
            comps.update(get_composites(inst.getOpObjects(0)[0]))
            continue

        if guard > 0:
            continue
        if inst.getMnemonicString() != "blr":
            continue

        stack_offset = get_stack_offset(address, "x1")
        string_addr = get_stack_param(address, 0x0, stack_offset)
        name = get_string(string_addr)
        offset = get_stack_param_offset(address, 0x28, stack_offset, frame_size)
        index = get_stack_param_immediate(address, 0x18, stack_offset)
        comps[name] = {"Offset": offset, "Index": index}
    return comps

# find ctor and create funcs
def resolve_ctor(addr):
    assert data.contains(addr), "Not a valid vtable address"
    ctor = None
    create = None
    factory = None
    for ref in getReferencesTo(addr):
        ctor_addr = ref.getFromAddress()
        ctor = getFunctionContaining(ctor_addr)
        if ctor is None:
            continue
        ia_xref = find_ia_ref(ctor.getEntryPoint())
        if ia_xref is None:
            for ctor_ref in getReferencesTo(ctor.getEntryPoint()):
                create_addr = ctor_ref.getFromAddress()
                create = getFunctionContaining(create_addr)
                if create is None:
                    continue
                ia_xref = find_ia_ref(create.getEntryPoint())
                if ia_xref is not None:
                    factory = create
                    create = ctor
                    return ctor, create, factory
                for create_ref in getReferencesTo(create.getEntryPoint()):
                    factory_addr = create_ref.getFromAddress()
                    factory = getFunctionContaining(factory_addr)
                    if factory is None:
                        continue
                    ia_xref = find_ia_ref(factory.getEntryPoint())
                    if ia_xref is not None:
                        return ctor, create, factory
                    factory = None
            continue
        else:
            factory = ctor
            create = ctor
            break
    return ctor, create, factory

# returns address in .init_array
# used on the factory register func
def find_ia_ref(addr):
    for ref in getReferencesTo(addr):
        func = getFunctionContaining(ref.getFromAddress())
        if func is None:
            continue
        for ia_ref in getReferencesTo(func.getEntryPoint()):
            if init_array.contains(ia_ref.getFromAddress()):
                return ia_ref.getFromAddress()
    return None

def get_type_string(addr):
    assert text.contains(addr), "Not a valid function address"
    exists_type = False
    for address in FunctionIter(addr):
        string = get_adrp_string(address)
        if string == "ppPropEnumMap.h":
            return cPropEnumMap
        elif string == "ppPropMap.h":
            return cPropMap
        elif string in ["ppPropBuffer.h", "ppPropBuffer.cpp"]:
            return cPropBuffer
        # TypedParamMap also has $type but it's always after ppTypedParamMap.cpp
        elif string  == "ppTypedParamEnumMap.h":
            return cTypedParamEnumMap
        elif string in ["ppTypedParamMap.h", "ppTypedParamMap.cpp"]:
            return cTypedParamMap
        elif string in ["ppTypedParamBuffer.h", "ppTypedParamBuffer.cpp"]:
            return cTypedParamBuffer
        # exists in TypedParamMap and TypedParamEnumMap
        # TypedParamEnumMap is missing the actual source path string usually
        elif string == "$type":
            exists_type = True
    return cTypedParamEnumMap if exists_type else None

# takes in a vtable address
def get_composite_type(addr):
    assert data.contains(addr), "Not a valid vtable address"
    create_vtable(addr)
    func = get_vtable_func(addr.add(0x20))
    func_addr = func.getEntryPoint()
    if func is None:
        return None
    type_str = get_type_string(func_addr)
    if type_str is not None:
        return type_str
    func_addr = get_vtable_func(addr.add(0x68)).getEntryPoint()
    type_str = get_type_string(func_addr)
    if type_str is not None:
        return type_str
    func_addr = get_vtable_func(addr.add(0x80)).getEntryPoint()
    type_str = get_type_string(func_addr)
    if type_str is not None:
        return type_str
    if get_vtable_func(addr.add(0x90)) is None:
        func_addr = get_vtable_func(addr.add(0x50)).getEntryPoint()
        if get_prop_enum(func_addr) != []:
            return cPropEnumMap
        else:
            return cPropMap
    func_addr = get_vtable_func(addr.add(0x90)).getEntryPoint()
    type_str = get_type_string(func_addr)
    if type_str is not None:
        return type_str
    raise Exception(addr)

# I forgot what these did but I'm too done with this to rewrite them
def get_adrp_type_info(addr, register="x0"):
    offset = 0
    for address in FunctionIter(addr):
        inst = getInstructionAt(address)
        if inst.getMnemonicString() not in ["adrp", "add", "ldr"]:
            continue
        if inst.getMnemonicString() == "adrp" and inst.getOpObjects(0)[0].getName() == register:
            offset += inst.getOpObjects(1)[0].getUnsignedValue()
        elif inst.getMnemonicString() == "add" and inst.getOpObjects(1)[0].getName() == register:
            offset += inst.getOpObjects(2)[0].getUnsignedValue()
            return toAddr(offset)
        elif inst.getMnemonicString() == "ldr" and inst.getOpObjects(0)[0].getName() == register:
            if len(inst.getOpObjects(1)) > 1:
                offset += inst.getOpObjects(1)[1].getUnsignedValue()
            return toAddr(offset)
    return None

# See above
# Ok I remembered actually but I'm still too lazy to redo it
# If it ain't broke don't fix
def get_adrp_value(addr):
    iter = FunctionIter(addr)
    offset = 0
    register = None
    found_branch = False
    count = 0
    for address in iter:
        inst = getInstructionAt(address)
        if inst.getMnemonicString() not in ["b.hi", "adrp", "add", "ldr", "csel"]:
            continue
        if register is None and inst.getMnemonicString() == "adrp":
            offset += inst.getOpObjects(1)[0].getUnsignedValue()
            register = inst.getRegister(0)
        elif inst.getMnemonicString() == "csel":
            found_branch = True
            count = 1
            register = inst.getRegister(1)
            iter.reverse()
            for address in iter:
                inst = getInstructionAt(address)
                if inst.getMnemonicString() == "adrp" and inst.getRegister(0) == register:
                    break
            return get_adrp_type_info(address, register.getName()), count
        elif inst.getMnemonicString() == "b.hi":
            found_branch = True
            count = getInstructionAt(address.subtract(4)).getScalar(1).getUnsignedValue() + 1
        elif found_branch and inst.getMnemonicString() == "add":
            register = inst.getRegister(0)
        elif register is not None:
            if inst.getMnemonicString() == "add" and inst.getOpObjects(1)[0] == register:
                if not found_branch:
                    offset += inst.getOpObjects(2)[0].getUnsignedValue()
            if inst.getMnemonicString() == "ldr" and inst.getOpObjects(1)[0] == register:
                if len(inst.getOpObjects(1)) > 1:
                    offset += inst.getOpObjects(1)[1].getUnsignedValue()
                if found_branch:
                    param = inst.getOperandReferences(1)
                    if param is not None:
                        return param[0].getToAddress(), count
    return toAddr(offset), count

def get_prop_type(addr):
    assert data.contains(addr), "Not a valid vtable address"
    func = get_vtable_func(addr.add(0x50))
    func_addr = func.getEntryPoint()
    if func is None:
        raise Exception("No format function")
    for address in FunctionIter(func_addr):
        string = get_adrp_string(address)
        if string == "":
            pass
        elif string in ["true", "false"]:
            return "bool"
        elif string == r"%d":
            return "s32"
        elif string == r"%u":
            return "u32"
        elif string == r"%f":
            return "f32"
        elif string == r"%lld":
            return "s64"
        elif string == r"%llu":
            return "u64"
        elif string == r"%lf":
            return "f64"
        elif string == r"%f, %f, %f":
            return "sead::Vector3f"
        elif string == r"%f, %f":
            return "sead::Vector2f"
        elif string == r"%d, %d, %d":
            return "sead::Vector3i"
        elif string == r"%d, %d":
            return "sead::Vector2i"
        elif string == r"%f, %f, %f, %f":
            return "sead::Color4f"
    iter = FunctionIter(func_addr)
    for address in iter:
        inst = getInstructionAt(address)
        if inst.getMnemonicString() == "cbnz":
            iter.set(inst.getOpObjects(1)[0])
            break
    if iter.is_end(iter.current):
        prop_type = get_prop_enum(func_addr, True)
        if prop_type == []:
            return "sead::SafeString"
        return prop_type
    param, count = get_adrp_value(iter.current)
    # all of this is for ppPropEnumMap bc I don't want to figure out how to properly do those
    if param.getUnsignedOffset() == 0:
        return "sead::SafeString"
    if getDataAt(param) is None:
        return "sead::SafeString"
    if getDataAt(param).isPointer():
        data_addr = getDataAt(param).getValue()
        func = getFunctionAt(data_addr)
        if func is not None:
            return guess_type(param)
        ptr = param
    else:
        return [get_string(param)]
    prop_type = []
    for i in range(count):
        string_addr = get_pointer(ptr)
        string = get_string(string_addr)
        prop_type.append(str(string))
        ptr = ptr.add(8)
    return prop_type

def get_typed_param_class(addr, is_buffer):
    if is_buffer:
        func = get_vtable_func(addr.add(0x68))
    else:
        func = get_vtable_func(addr.add(0x80))
    if func is None:
        raise Exception("Vtable mismatch")
    iter = FunctionIter(func.getEntryPoint())
    iter.set(find_inst(iter, "ret"))
    iter.reverse()
    register = None
    for address in iter:
        inst = getInstructionAt(address)
        if inst.getMnemonicString() == "mov" and inst.getRegister(0).getName() == "x0":
            register = inst.getRegister(1)
            break
    if register is None:
        raise Exception("Did not find register")
    new_reg = False
    for address in iter:
        inst = getInstructionAt(address)
        if iter.reversed and inst.getMnemonicString() == "bl":
            if getFunctionAt(inst.getOpObjects(0)[0]).getName() != "memset":
                iter.set(inst.getOpObjects(0)[0])
                iter.unreverse()
                continue
        if not iter.reversed and not new_reg and inst.getMnemonicString() == "mov" and inst.getRegister(1) is not None and inst.getRegister(1).getName() == "x0":
            register = inst.getRegister(0)
            new_reg = True
        if inst.getMnemonicString() == "str" and (inst.getOpObjects(1)[0] == register or inst.getOpObjects(1)[0].getName() == "x0") and len(inst.getOpObjects(1)) == 1:
            param = inst.getOperandReferences(0)
            if param is not None:
                return param[0].getToAddress()
        if inst.getMnemonicString() == "stp" and (inst.getOpObjects(2)[0] == register or inst.getOpObjects(2)[0].getName() == "x0") and len(inst.getOpObjects(2)) == 1:
            param = inst.getOperandReferences(0)
            if param is not None:
                return param[0].getToAddress()
    raise Exception("Did not find TypedParam vtable")

def get_prop_info(addr, prop_type, is_buffer=False):
    info = {"Resolve Type": None, "Default": None}
    refs = getReferencesTo(addr)
    for ref in refs:
        if not ref.getReferenceType().isWrite():
            continue
        # find first write reference
        # the struct we're looking for for PropEnumMaps is something like
        # template <typename T>
        # struct EnumMapInfo {
        #   u32 resolve_type;
        #   T default;
        # };
        # for PropBuffers, it's something like
        # template <typename T>
        # struct PropBufferInfo {
        #   u32 resolve_type;
        #   u32 count; // if 0xffffffff, then no default value is provided
        #   T default;
        # };
        temp_addr = ref.getFromAddress()
        iter = FunctionIter(temp_addr, True)
        inst = getInstructionAt(temp_addr)
        assert inst.getMnemonicString() in ["str", "stp"], temp_addr
        register = inst.getOpObjects(0)[0]
        add = 8
        if register.getName() in ["xzr", "wzr"]:
            info["Resolve Type"] = 0
            if register.getName() == "xzr":
                if is_buffer:
                    info["Count"] = 0
                elif prop_type not in ["sead::SafeString", "sead::Hash", "u64", "s64", "f64", "sead::hostio::Curve"]:
                    if prop_type == "f32":
                        info["Default"] = 0.0
                    elif prop_type == "bool":
                        info["Default"] = False
                    else:
                        info["Default"] = 0
            elif prop_type not in ["sead::SafeString", "sead::Hash", "u64", "s64", "f64", "sead::hostio::Curve"]:
                add = 4
        else:
            # find the register where the bottom eight bytes are
            for address in iter:
                inst = getInstructionAt(address)
                if inst.getMnemonicString() == "mov" and inst.getRegister(0) == register:
                    info["Resolve Type"] = inst.getScalar(1).getValue()
                    break
            # read the value from that register
            # can be a single mov if the bottom four bytes are zero or a mov + movk
            # orr may be possible but we'll just assume it's not
            for address in FunctionIter(temp_addr, True):
                inst = getInstructionAt(address)
                if inst.getMnemonicString() == "movk" and inst.getRegister(0) == register:
                    value = inst.getScalar(1).getValue()
                    i = inst.getDefaultOperandRepresentation(1).find("LSL #")
                    shift = int(inst.getDefaultOperandRepresentation(1)[i+5:])
                    assert shift > 0x20, address
                    value = value << (shift - 0x20)
                    if is_buffer:
                        info["Count"] = value & 0xFFFFFFFF
                        if info["Count"] == -1:
                            del info["Default"]
                    else:
                        if prop_type == "f32":
                            info["Default"] = struct.unpack("<f", struct.pack("<i", value & 0xFFFFFFFF))[0]
                        elif prop_type == "bool":
                            info["Default"] = value != 0
                        else:
                            # technically incorrect but totk never uses the other types so whatever
                            info["Default"] = value & 0xFFFFFFFF
                        return info
                elif inst.getMnemonicString() == "mov" and inst.getRegister(0) == register:
                    value = inst.getScalar(1).getUnsignedValue()
                    info["Resolve Type"] = value & 0xFFFFFFFF
                    if is_buffer and value > 0xFFFFFFFF:
                        info["Count"] = value >> 0x20
                        if info["Count"] == -1:
                            del info["Default"]
                        break
                    if prop_type not in ["sead::SafeString", "sead::Hash", "u64", "s64", "f64", "sead::hostio::Curve"] and value > 0xFFFFFFFF:
                        value = value >> 0x20
                        if prop_type == "f32":
                            info["Default"] = struct.unpack("<f", struct.pack("<i", value & 0xFFFFFFFF))[0]
                        elif prop_type == "bool":
                            info["Default"] = value != 0
                        else:
                            # technically incorrect but totk never uses the other types so whatever
                            info["Default"] = value & 0xFFFFFFFF
                        return info
                    else:
                        break
            if not is_buffer and prop_type not in ["sead::SafeString", "sead::Hash", "u64", "s64", "f64", "sead::hostio::Curve"]:
                return info
        # vectors never appear here I believe so I'll just ignore that case
        value_addr = addr.add(add)
        value_refs = getReferencesTo(value_addr)
        for value_ref in value_refs:
            if not value_ref.getReferenceType().isWrite():
                continue
            temp_addr = value_ref.getFromAddress()
            inst = getInstructionAt(temp_addr)
            if prop_type in ["sead::SafeString", "sead::Hash"]:
                if inst.getMnemonicString() == "str":
                    param = inst.getOperandReferences(0)
                elif inst.getMnemonicString() == "stp":
                    param = inst.getOperandReferences(1)
                if len(param) > 0:
                    info["Default"] = getDataAt(param[0].getToAddress()).getValue()
                    return info
            else:
                if inst.getMnemonicString() in ["str", "strb", "stur", "strh"]:
                    reg = inst.getOpObjects(0)[0]
                elif inst.getMnemonicString() == "stp":
                    reg = inst.getOpObjects(1)[0]
                else:
                    raise Exception(temp_addr)
                if reg.getName() in ["xzr", "wzr"]:
                    if prop_type in ["f32", "f64"]:
                        info["Default"] = 0.0
                    elif prop_type == "bool":
                        info["Default"] = False
                    else:
                        info["Default"] = 0
                    return info
                else:
                    for address in FunctionIter(temp_addr, True):
                        inst = getInstructionAt(address)
                        if inst.getMnemonicString() == "mov" and inst.getRegister(0) == reg:
                            if inst.getScalar(1) is not None:
                                if prop_type == "bool":
                                    info["Default"] = inst.getScalar(1).getValue() != 0
                                elif prop_type == "f32":
                                    info["Default"] = struct.unpack("<f", struct.pack("<i", inst.getScalar(1).getValue() & 0xFFFFFFFF))[0]
                                else:
                                    if prop_type in ["u32", "u64"]:
                                        info["Default"] = inst.getScalar(1).getValue()
                                    else:
                                        # I don't think 64-bit types ever show up like this in totk so I'm just gonna be lazy
                                        info["Default"] = struct.unpack("<i", struct.pack("<I", inst.getScalar(1).getValue() & 0xFFFFFFFF))[0]
                                assert info["Default"] is not None, address
                                return info
                            else:
                                reg = inst.getRegister(1)
                        if inst.getMnemonicString() == "fmov" and inst.getRegister(0) == reg:
                            info["Default"] = struct.unpack("<f", struct.pack("<i", inst.getScalar(1).getValue() & 0xFFFFFFFF))[0]
        assert info["Default"] is not None, addr
        return info
    # if no write refs, then it must be constant
    # there is never a default value for these and it's only for PropBuffers
    info["Resolve Type"] = getInt(addr)
    info["Count"] = getInt(addr.add(0x4)) # always -1
    if info["Count"] == -1:
        del info["Default"]
    # default but since count is -1 it's irrelevant
    return info

def track_prop_info(addr):
    iter = FunctionIter(addr, True)
    bl_addr = find_inst(iter, "bl")
    bl_inst = getInstructionAt(bl_addr)
    assert bl_inst.getMnemonicString() == "bl", bl_addr
    iter.set(bl_inst.getOpObjects(0)[0])
    iter.unreverse()
    iter.set(find_inst(iter, "bl"))
    inst = getInstructionAt(iter.current)
    assert getFunctionAt(inst.getOpObjects(0)[0]).getName() == "__cxa_guard_acquire", addr
    ldr_inst = getInstructionAt(iter.current.subtract(4))
    assert ldr_inst.getMnemonicString() == "ldr", addr
    return ldr_inst.getOperandReferences(0)[0].getToAddress().subtract(0x10)

def get_prop_enum(addr, no_loop_check=False):
    assert text.contains(addr), "Invalid function address"
    register = None
    count = 0
    enum_ptr = None
    enum = []
    iter = FunctionIter(addr)
    for address in iter:
        inst = getInstructionAt(address)
        if register is None and inst.getMnemonicString() == "add":
            if "LSL" in inst.getDefaultOperandRepresentation(2):
                register = inst.getRegister(0)
        elif register is not None and inst.getMnemonicString() == "ldr" and inst.getOpObjects(1)[0] == register:
            enum_ptr = inst.getOperandReferences(1)[0].getToAddress()
            for address1 in FunctionIter(address, True):
                if not no_loop_check and len(getReferencesTo(address1)) > 0:
                    for ref in getReferencesTo(address1):
                        inst1 = getInstructionAt(ref.getFromAddress().subtract(0x4))
                        if inst1.getMnemonicString() == "cmp":
                            count = inst1.getScalar(1).getValue()
                            break
                    break
                elif no_loop_check and getInstructionAt(address1).getMnemonicString() == "cmp":
                    if getInstructionAt(address1.add(4)).getMnemonicString() in ["b.hi", "b.gt"]:
                        count = getInstructionAt(address1).getOpObjects(1)[0].getUnsignedValue() + 1
                    elif getInstructionAt(address1.add(4)).getMnemonicString() in ["b.ls", "b.le"]:
                        count = getInstructionAt(address1).getOpObjects(1)[0].getUnsignedValue() + 1
                    break
            break
    if not no_loop_check and (enum_ptr is None or count == 0):
        # loop is unrolled
        iter.reset()
        for address in iter:
            inst = getInstructionAt(address)
            if inst.getMnemonicString() == "blr":
                if "#0x40" in getInstructionAt(address.subtract(4)).getDefaultOperandRepresentation(1):
                    offset = None
                    str_iter = FunctionIter(address, True)
                    for address1 in str_iter:
                        inst1 = getInstructionAt(address1)
                        if inst1.getMnemonicString() == "add" and inst1.getRegister(0).getName() == "x1":
                            offset = inst1.getScalar(2).getValue()
                        elif offset is not None and inst1.getMnemonicString() == "str":
                            if len(inst1.getOpObjects(1)) > 1:
                                if inst1.getOpObjects(1)[1].getValue() == offset:
                                    if len(inst1.getOperandReferences(0)) == 0:
                                        return enum
                                    enum.append(get_string(inst1.getOperandReferences(0)[0].getToAddress()))
                                    break
                        elif not str_iter.reversed and address1.equals(address):
                            break
                        elif inst1.getMnemonicString() == "bl" and not address1.equals(address):
                            str_iter.unreverse()
        return enum
    for i in range(count):
        string_addr = get_pointer(enum_ptr)
        string = get_string(string_addr)
        enum.append(str(string))
        enum_ptr = enum_ptr.add(8)
    return enum

# Resolve Types:
# 0 = resolve to default (TypedParam map types) or none (other)
# 1 = append to parent
# 2 = resolve to parent (TypedParam map types only)
def resolve_composite(addr):
    assert data.contains(addr), "Not a valid vtable address"
    if addr in composites:
        return composites[addr]
    comp_type = get_composite_type(addr)
    info = {}
    if comp_type == cTypedParam: # probably unreachable since embeds are excluded
        info["Type"] = get_name_from_vtable(addr)
    elif comp_type in [cPropMap, cPropEnumMap]:
        if comp_type == cPropEnumMap:
            info["Type"] = "PropEnumMap"
        else:
            info["Type"] = "PropMap"
        info["Prop Type"] = get_prop_type(addr)
    elif comp_type in [cTypedParamMap, cTypedParamEnumMap]:
        if comp_type == cTypedParamEnumMap:
            info["Type"] = "TypedParamEnumMap"
        else:
            info["Type"] = "TypedParamMap"
        info["TypedParam Type"] = get_name_from_vtable(get_typed_param_class(addr, False))
    elif comp_type == cPropBuffer:
        info["Type"] = "PropBuffer"
        info["Prop Type"] = get_prop_type(addr)
    elif comp_type == cTypedParamBuffer:
        info["Type"] = "TypedParamBuffer"
        info["TypedParam Type"] = get_name_from_vtable(get_typed_param_class(addr, True))
    composites[addr] = info
    return info

def parse_typed_param(addr):
    # Verify address
    assert data.contains(addr), "Not a valid vtable location"
    create_vtable(addr)
    ctor, create, factory = resolve_ctor(addr)
    if factory is None:
        return # ignore UMiiConstructor TypedParam extensions
    classname = get_name_from_vtable(addr)
    print(classname)

    # Label
    label_vtable(addr, classname, typed_param_vtable)

    # Parse properties
    typed_param = {}
    typed_param["Composites"] = get_composites(get_vtable_func(addr.add(0x80)).getEntryPoint())
    typed_param["Embeds"] = get_embeds(get_vtable_func(addr.add(0x88)).getEntryPoint())
    typed_param["Props"] = get_props(get_vtable_func(addr.add(0x90)).getEntryPoint(), classname)
    # embeds are duplicated into the list of composites (since they are a type of composite)
    typed_param["Composites"] = {k: typed_param["Composites"][k] for k in typed_param["Composites"] if k not in typed_param["Embeds"]}
    
    # Label constructor + factory
    if ctor != create:
        label_func(ctor, classname.split("__")[-1], classname)
    label_func(create, "create", classname)
    factory_name = "pp::TypedParamFactory<" + classname.replace("__", "::") + ">"
    label_func(factory, "register", factory_name)
    ia_ref = find_ia_ref(factory.getEntryPoint())
    assert ia_ref is not None, factory.getEntryPoint()
    ia_func = getFunctionContaining(getDataAt(ia_ref).getValue())
    assert ia_func is not None
    ia_func.setParentNamespace(currentProgram.getGlobalNamespace())
    ia_func.setName("IA_pp_TypedParam_" + classname, Symbol.SourceType.USER_DEFINED)

    for composite in typed_param["Composites"]:
        entry = typed_param["Composites"][composite]
        vtable = get_ptr_relative(ctor.getEntryPoint(), entry["Offset"])
        entry.update(resolve_composite(vtable))
        if entry["Type"] in ["PropMap", "TypedParamMap"]:
            entry["Resolve Type"] = get_ptr_relative(ctor.getEntryPoint(), entry["Offset"] + 0x28) & 0xFFFFFFFF
        elif entry["Type"] == "PropBuffer":
            info_ptr = get_ptr_relative(ctor.getEntryPoint(), entry["Offset"] + 0x8, return_reg=True)
            if isinstance(info_ptr, tuple):
                if info_ptr[0].getName() == "x0":
                    info_ptr = track_prop_info(info_ptr[1])
                else:
                    raise Exception(info_ptr[1])
            entry.update(get_prop_info(info_ptr, entry["Prop Type"], True))
        elif entry["Type"] == "TypedParamBuffer":
            val = get_ptr_relative(ctor.getEntryPoint(), entry["Offset"] + 0x20)
            entry["Resolve Type"] = val & 0xFFFFFFFF
            count = get_ptr_relative(ctor.getEntryPoint(), entry["Offset"] + 0x24)
            if count is None:
                count = val >> 0x20
            entry["Count"] = count
        elif entry["Type"] == "PropEnumMap":
            entry["Enum Type"] = get_prop_enum(get_vtable_func(vtable.add(0x50)).getEntryPoint())
            if entry["Prop Type"] in ["u32", "f32", "s32"]:
                size = 0x8
            elif entry["Prop Type"] == "bool":
                size = 0x2
            elif entry["Prop Type"] in ["u64", "f64", "s64", "sead::Vector3f","sead::Vector3i", "sead::SafeString", "sead::Hash", "sead::Angle"]:
                size = 0x10
            elif entry["Prop Type"] in ["sead::Vector2f", "sead::Vector2i"]:
                size = 0xc
            elif entry["Prop Type"] == "sead::Color4f":
                size = 0x14
            elif entry["Prop Type"] == "sead::hostio::Curve":
                size = 0x28
            else:
                size = 0x8
            info_ptr = get_ptr_relative(ctor.getEntryPoint(), align_up(entry["Offset"] + 0x8 + size * len(entry["Enum Type"]), 0x8), return_reg=True)
            if isinstance(info_ptr, tuple):
                info_ptr = get_adrp_ptr(info_ptr[1], info_ptr[0].getName())
            entry.update(get_prop_info(info_ptr, entry["Prop Type"]))
        elif entry["Type"] == "TypedParamEnumMap":
            resolve_type = get_ptr_relative(ctor.getEntryPoint(), entry["Offset"] + 0x28, return_reg=True)
            if isinstance(resolve_type, tuple): # TypedParamEnumMap ctor is not inlined
                count_info = get_ptr_relative(ctor.getEntryPoint(), entry["Offset"] + 0x2c, return_reg=True)
                enum_info = get_ptr_relative(ctor.getEntryPoint(), entry["Offset"] + 0x18, return_reg=True)
                assert isinstance(count_info, tuple) and isinstance(enum_info, tuple), ctor.getEntryPoint()
                enum_ptr = get_adrp_ptr(enum_info[1], enum_info[0].getName())
                count = get_immediate(count_info[1], count_info[0].getName()) & 0xFFFFFFFF
                resolve_type = get_immediate(resolve_type[1], resolve_type[0].getName()) & 0xFFFFFFFF
                assert enum_ptr is not None and count is not None and resolve_type is not None, (ctor.getEntryPoint(), enum_ptr, count, resolve_type)
                entry["Resolve Type"] = resolve_type
                entry["Enum Type"] = []
                for i in range(count):
                    string_addr = get_pointer(enum_ptr)
                    string = get_string(string_addr)
                    entry["Enum Type"].append(str(string))
                    enum_ptr = enum_ptr.add(8)
            else:
                entry["Resolve Type"] = resolve_type & 0xFFFFFFFF
                count = get_ptr_relative(ctor.getEntryPoint(), entry["Offset"] + 0x2c)
                if count is None:
                    count = resolve_type >> 0x20
                enum_ptr = get_ptr_relative(ctor.getEntryPoint(), entry["Offset"] + 0x18)
                assert enum_ptr is not None, ctor.getEntryPoint()
                entry["Enum Type"] = []
                for i in range(count):
                    string_addr = get_pointer(enum_ptr)
                    string = get_string(string_addr)
                    entry["Enum Type"].append(str(string))
                    enum_ptr = enum_ptr.add(8)

    typed_param_classes[classname] = typed_param

def parse_inheritance(this, base, count=1):
    if this == base:
        return 0
    if inheritance_map.get(this, None) is None:
        # UMii has some TypedParam extensions that should be ignored
        return None
    if inheritance_map[this] == base:
        return count
    return parse_inheritance(inheritance_map[this], base, count + 1)

def main():
    print("Starting")
    # Make sure we're at the correct location
    assert text.contains(currentAddress), "Please relocate to pp::TypedParam::TypedParam()"
    typed_param_ctor = get_func(currentAddress)
    vptr = get_vptr_from_ctor(currentAddress)
    check_name = get_name_from_vtable(vptr)
    assert check_name == "pp__TypedParam", "Please relocate to pp::TypedParam::TypedParam()"

    print("Clearing existing TypedParam labels")
    # Clear existing TypedParam class labels
    load_bgyml = get_vtable_func(vptr.add(0x20))
    accessor_vptr = None
    for ref in getReferencesTo(load_bgyml.getEntryPoint()):
        addr = ref.getFromAddress()
        clear_vtable(addr)
        if accessor_vptr is None:
            loop_props = get_vtable_func(get_vtable_start(addr).add(0x90))
            accessor_vptr = find_first_vtable(loop_props.getEntryPoint())

        # Check inheritance as well
        this, base = get_base_type(get_vtable_func(get_vtable_start(addr)).getEntryPoint())
        typed_param_locations[int(this.getUnsignedOffset())] = get_vtable_start(addr)
        assert base is not None, addr
        inheritance_map[int(this.getUnsignedOffset())] = int(base.getUnsignedOffset())

    print("Clearing existing PropAccessor labels")
    # Clear existing PropAccessor labels
    clear_vtable(accessor_vptr)
    for ref in getReferencesTo(get_vtable_func(accessor_vptr.add(0x10)).getEntryPoint()):
        addr = ref.getFromAddress()
        clear_vtable(addr)

    print("Labeling TypedParam")
    # Label pp::TypedParam
    label_func(typed_param_ctor, "TypedParam", "pp__TypedParam")
    create_vtable(vptr)
    label_vtable(vptr, "pp__TypedParam", typed_param_vtable, True)
    check_rtti = get_vtable_func(vptr) # always first in the vtable
    tp_rtti, comp_rtti = get_base_type(check_rtti.getEntryPoint())
    register_rtti(tp_rtti, "pp__TypedParam")
    register_rtti(comp_rtti, "pp__Composite")

    print("Labeling PropAccessor classes")
    # Parse PropAccessors and guess types
    _rtti, accessor_rtti = get_base_type(get_vtable_func(accessor_vptr).getEntryPoint())
    register_rtti(accessor_rtti, "pp__PropAccessor")
    # Shared PropAccessor virtual functions
    label_func(get_vtable_func(accessor_vptr.add(0x10)), "~PropAccessor", "pp__PropAccessor")
    label_func(get_vtable_func(accessor_vptr.add(0x60)), None, "pp__PropAccessor")
    label_func(get_vtable_func(accessor_vptr.add(0x68)), "getValueAddressVirtual", "pp__PropAccessor")
    label_func(get_vtable_func(accessor_vptr.add(0x70)), "getValueAddressVirtual", "pp__PropAccessor")
    label_func(get_vtable_func(accessor_vptr.add(0x78)), None, "pp__PropAccessor")
    for ref in getReferencesTo(get_vtable_func(accessor_vptr.add(0x10)).getEntryPoint()):
        addr = get_vtable_start(ref.getFromAddress())
        prop_type = guess_type(addr)
        namespace = "pp__PropAccessor<"
        if isinstance(prop_type, str):
            namespace += prop_type
        else:
            namespace += "Enum_0x%010x" % int(addr.getUnsignedOffset())
        namespace += ">"
        label_vtable(addr, namespace, prop_accessor_vtable)

    print("Handling TypedParam classes")
    # Handle TypedParams in inheritance order
    ordered_classes = []
    for type_info in inheritance_map:
        index = parse_inheritance(type_info, int(tp_rtti.getUnsignedOffset()))
        if index is None:
            continue
        if len(ordered_classes) <= index:
            ordered_classes += [[] for i in range (index - len(ordered_classes) + 1)]
        ordered_classes[index].append(type_info)
    
    for level in ordered_classes:
        for type_info in level:
            parse_typed_param(typed_param_locations[type_info])

    # Clear old Composite labels then relabel


    # Save to file
    # this one is just for reference
    # with open(format_path("pp__PropAccessors.json"), "w") as f:
    #     json.dump({k.toString(): prop_accessors[k] for k in prop_accessors}, f, indent=2)
    try:
        with open(format_path("pp__TypedParams.json"), "w") as f: # everything important is in here
            json.dump(typed_param_classes, f, indent=2)
    except Exception as e:
        with open(format_path("error.txt"), "w") as f:
            f.write(str(typed_param_classes))
        raise e

if __name__ == "__main__":
    main()