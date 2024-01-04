# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
"""A module containing a collection of plugins that produce data typically
found in Linux's /proc file system."""

import logging
from typing import List, Iterable
from volatility3.cli import text_renderer, volshell
from volatility3.framework import exceptions, renderers, constants, interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints
KPROBE_TABLE_SIZE = 64
PTR_SIZE = 8
UTF_8 = 'utf-8'
##### PROBE_LIST #####
##### FTRACE_EVENTS #####

vollog = logging.getLogger(__name__)


class kprobes(interfaces.plugins.PluginInterface):
    """Lists loaded kernel modules."""

    _required_framework_version = (2, 0, 0)
    _version = (2, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=["Intel32", "Intel64"],
            ),
        ]
    
    def readPtr(self,offset):
        ptr = self._read_data(offset,PTR_SIZE,None)
        return self.bytes_to_int(ptr)

    def _read_data(self, offset, count=128, layer_name=None):
        """Reads the bytes necessary for the display_* methods"""
        return self.context.layers[layer_name or "layer_name"].read(offset, count)
    
    def readSymbol(self,offset):
        symbol_chars = []
        while True:
            curr_char = self._read_data(offset,1, None)
            if curr_char == b"\x00":
                return b"".join(symbol_chars)
            symbol_chars.append(curr_char)
            offset += 1

    def getSymbolfromPtr(self,ptr):
        return bytes.decode(self.readSymbol(ptr),UTF_8)
    
    def bytes_to_int(self,byte_data):
        #Reversing small endian and turning to int - ptr
        return int.from_bytes(byte_data,"little")
        

    def list_kprobes(
        self,
        cls, context: interfaces.context.ContextInterface, vmlinux_module_name: str
    ) -> Iterable[interfaces.objects.ObjectInterface]:

        
        vmlinux = context.modules[vmlinux_module_name]

        #ftrace_events = vmlinux.object_from_symbol(symbol_name="ftrace_events").cast("list_head")
       # table_name = ftrace_events.vol.type_name.split(constants.BANG)[0]
       # for event in ftrace_events.to_list(table_name + constants.BANG + "ftrace_event_call", "list"):
        #    event_name= utility.pointer_to_string(event.name,10)
         #   print(event_name)
            

        kprobe_ptrs = []
        data = []
        kprobe_table = vmlinux.get_absolute_symbol_address("kprobe_table")
        offset = 0
        for i in range(KPROBE_TABLE_SIZE):
            kprobe_ptr = self.readPtr(kprobe_table + offset)
            offset +=PTR_SIZE
            if(kprobe_ptr != 0):
                kprobe_ptrs.append(kprobe_ptr)

        symbol_off = vmlinux.get_type("kprobe").relative_child_offset("symbol_name")
        pre_handler_off = vmlinux.get_type("kprobe").relative_child_offset("pre_handler")
        addr_off = vmlinux.get_type("kprobe").relative_child_offset("addr")
        for kprobe in kprobe_ptrs:
            addr_ptr = self.readPtr(kprobe + addr_off)
            symbol_ptr = self.readPtr(kprobe + symbol_off)
            symbol_name = self.getSymbolfromPtr(symbol_ptr)
            pre_handler = self.readPtr(kprobe + pre_handler_off)
            yield [addr_ptr,symbol_name,pre_handler]



    def _generator(self):
        try:
            for kprobe in self.list_kprobes(self,self.context, self.config["kernel"]):
                kprobe[0] = hex(kprobe[0])
                kprobe[2] = hex(kprobe[2])

                yield 0,(kprobe)

        except exceptions.SymbolError:
            vollog.debug(
                "The required symbol 'module' is not present in symbol table. Please check that kernel modules are enabled for the system under analysis."
            )

    def run(self):
        return renderers.TreeGrid(
            [("Addr                ", str), ("Symbol   ", str), ("pre_handler addr", str)],
            self._generator(),
        )
