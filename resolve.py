import sys
import r2pipe

'''
        GDB script to add a `symresolve` command that resolves the addresses of 
	non-debugging relative addresses in symbols to position independent 
	binaries. Uses r2pipe to gather sizing for later expansion.

	Its sucks that GDB lacks support for adding to its symbol tables,
	and so I wrote this to work on a pwnable.

	Added further additional commands to make life easier when debugging that pwnable
'''

class Syms:
	__static_symbols__ = {}
	__baseaddr__ = 0
	__heap__ = 0
	__heap_oldsz__ = 0

def getheapmap():
	maps = gdb.execute("info proc map", to_string=True).splitlines()
	for line in maps:
		if "heap" not in line:
			continue
		print("Found heap map: %s" % line)
		return line.split()
	return None

class ResolveSymbolsCommand(gdb.Command):
	"""Implements the kind of memory searching that I personally wanted in GDB."""
	__cmdline__ = "symresolve"
	__r2__ = None
	__quiet__ = False
	def __init__(self, *args, **kwargs):
		super(ResolveSymbolsCommand, self).__init__(self.__cmdline__, gdb.COMMAND_USER, gdb.COMPLETE_COMMAND)
		print("Command `symresolve` initialized.")
		return

	def initr2(self, binary, base_addr=0, silent=False, project=None):
		if self.__r2__ == None:
			self.__r2__ = r2pipe.open(binary)
		if not silent:
			print("Opening binary: {}".format(binary))
		if project:
			print("Opening project {}...".format(project))
			self.__r2__.cmd("Po {}".format(project))
		objs = self.__r2__.cmd("f~obj").splitlines()
		for obj in objs:
			rva, sz, symname = obj.split()[:3]
			symname = symname.split('.')[1]
			rva = int(rva,0)
			addr = base_addr + rva
			Syms.__static_symbols__[symname] = {
				"RVA": rva, 
				"addr": addr,
				"size":int(sz),
			}
			if not silent:
				print("Added symbol: %s @ %s" % (symname, rva))
				print("Setting ${symname} = {addr}".format(symname=symname,addr=addr))
			gdb.execute("set ${symname}={addr}".format(symname=symname,addr=addr))
		gdb.execute("set $base={base_addr}".format(base_addr=base_addr))
		return

	def invoke(self, arguments, from_tty):
		"""Load symbols from binary, and resolve to proper address. """
		maps = gdb.execute("info proc map", to_string=True).splitlines()
		filename = gdb.current_progspace().filename
		print("Program filename: {}".format(filename))
		base_map = None
		potential_maps = [_map.split() for _map in maps[4:]]
		for _map in potential_maps:
			if filename in _map[-1]:
				print("Found {}".format(_map))
				base_map = _map
				break
		if not base_map:
			print("Coudln't find base map. :(")
			return
		print("base map: {}".format(repr(base_map)))
		binary = base_map[-1]
		if not Syms.__baseaddr__:
			Syms.__baseaddr__ = int(base_map[0], 16)
		for line in maps:
			if 'heap' in line:
				Syms.__heap__ = int(line.split()[1],0)
				gdb.execute("set $heap={heap}".format(heap=Syms.__heap__))
		if not isinstance(arguments, list):
			arguments = arguments.split()
		print("Arguments:" + repr(arguments))
		silent = 'q' in arguments or '-q' in arguments
		project = None
		if '-p' in arguments:
			project = arguments[arguments.index('-p')+1]
		self.initr2(binary, Syms.__baseaddr__, silent, project)
		print("Done.")
		return

	def usage(self):
		print("Usage: symresolve")

class AddRelativeCommand(gdb.Command):
	__cmdline__ = "addrel"
	""" For help in GDB scripting. """
	def __init__(self, *args, **kwargs):
		super(AddRelativeCommand, self).__init__(self.__cmdline__, gdb.COMMAND_USER, gdb.COMPLETE_COMMAND)
		print("Command `addrel` initialized.")
		return

	def invoke(self, arguments, from_tty):
		"""Add relative symbol for binary to convenience variable."""
		arguments = arguments.split()
		symname = arguments[0]
		rva = int(arguments[1],0)
		sz = -1
		if len(arguments) > 2:
			sz = int(arguments[2],0)
		print("Adding ${} with relative adddress:{}".format(symname, hex(rva)))
		if not Syms.__baseaddr__:
			gdb.execute('symresolve')
		base = Syms.__baseaddr__ + rva
		Syms.__static_symbols__[symname] = {"RVA": rva,
				"addr":rva+Syms.__baseaddr__,
				"size": sz}
		gdb.execute("set ${symname} = {base}".format(symname=symname, base=base))
		return

class FindHeap(gdb.Command):
	__cmdline__ = "findheap"
	""" Just to find the heap and initialize it in Syms. """
	def __init__(self, *args, **kwargs):
		super(FindHeap, self).__init__(self.__cmdline__, gdb.COMMAND_USER, gdb.COMPLETE_COMMAND)
		print("Command `findheap` initialized.")
		return
	def invoke(self, arguments, from_tty):
		heap_found = False
		maps = gdb.execute("info proc map", to_string=True).splitlines()
		heap_base, heap_end, sz = 0,0,0
		for line in maps:
			if "heap" in line:
				heap_found = True
				heap_base, heap_end, sz = line.split()[:3]
				heap_base, heap_end = int(heap_base,0), int(heap_end,0)
		if not heap_found:
			print("Heap hasn't been created yet.")
			return
		if not Syms.__heap__:
			Syms.__heap__ = heap_base
			Syms.__heap_oldsz__ = sz
			gdb.execute("set $heap = {}".format(heap_base))
		return


class ExpandHeap(gdb.Command):
	__cmdline__ = "expandheap"
	"""For simulating expansion of heap without time-consuming spray."""
	def __init__(self, *args, **kwargs):
		super(ExpandHeap, self).__init__(self.__cmdline__, gdb.COMMAND_USER, gdb.COMPLETE_COMMAND)
		print("Command `expandheap` initialized.")
		return

	def invoke(self, arguments, from_tty):
		""" Call brk to expand heap. """
		arguments = arguments.split()
		print("Arguments [{}]: {}".format(len(arguments), arguments))
		sz_arg =  0x30000
		if len(arguments) > 0:
			sz_arg = int(arguments[0], 0)
		heap_found = False
		maps = gdb.execute("info proc map", to_string=True).split()
		for line in maps:
			if "heap" in line:
				heap_found = True
		
		if not heap_found:
			print("Heap hasn't been created yet.")
			return
		if not Syms.__heap__:
			print("$heap not initialized.")
			gdb.execute("findheap")
			if not Syms.__heap__:
				print("Something's not right with findheap.")
				return
		try:
			heapmap = getheapmap()
			base, end, sz = heapmap[:3]
			sz = int(sz,0) + sz_arg
			cmd = "p __brk({base}+{size})".format(base=base, size=sz)
			print("Executing:", cmd)
			gdb.execute(cmd)
		except:
			print("Bug in expanding heap.")
			print(sys.exc_info())
		return

ResolveSymbolsCommand()
AddRelativeCommand()
FindHeap()
ExpandHeap()
