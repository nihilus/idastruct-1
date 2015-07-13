import idc
import idaapi
from PySide import QtGui
from PySide import QtCore
from PySide.QtCore import Slot
		
SKELETON_OFFSET = 0
SKELETON_NAME = 1
SKELETON_TYPE = 2

EAS_EA = 0
EAS_OPNDN = 1
EAS_OFFSET = 2

data_types = {
		idaapi.FF_BYTE: 1,
		idaapi.FF_WORD: 2,
		idaapi.FF_DWRD: 4,
		idaapi.FF_DOUBLE: 8,
		idaapi.FF_QWRD: 8,
	}

dtyp = {
		0: idaapi.FF_BYTE,
		1: idaapi.FF_WORD,
		2: idaapi.FF_DWRD,
		4: idaapi.FF_DOUBLE,
		7: idaapi.FF_QWRD
	}

phrase = {
	'eax': 0,
	'ecx': 1,
	'edx': 2,
	'ebx': 3,	
	'ebp': 5,
	'esi': 6,
	'edi': 7,
}

def gen_skeleton_and_eas(reg):
	ea = idc.ScreenEA()
	start = idc.GetFunctionAttr(ea, idc.FUNCATTR_START)
	end = idc.GetFunctionAttr(ea, idc.FUNCATTR_END)
	ea = start
	eas = []
	skeleton = {}
	while ea <= end:
		if idaapi.decode_insn(ea) == 0:
			print 'error in {0}'.format(GetDisasm(ea))
		else:
			for opn in (0, 1):
				op = idaapi.cmd.Operands[opn]
				offset = 0
				if op.type == idaapi.o_idpspec3:
					continue
				if op.type in (idaapi.o_phrase, idaapi.o_displ) and op.phrase == phrase[reg]:
					skeleton[op.addr] = ('field_{0}'.format(hex(op.addr)), dtyp[op.dtyp])
					eas.append((ea, opn, offset))
		ea = idc.NextHead(ea)
	skeleton = [(elem[0], elem[1][0], elem[1][1]) for elem in sorted(skeleton.items(), key = lambda x: x[0])]
	return [skeleton, eas]

def create_struc_from_skeleton(name, skeleton, default_type = idaapi.FF_DWRD):
	sorted_data_types = sorted(data_types.items(), key = lambda x: x[1], reverse = True)
	sid = idc.GetStrucIdByName(name)
	if sid != idaapi.BADADDR:
		idc.DelStruc(sid)
	idx = idc.AddStrucEx(idaapi.BADADDR, name, False)
	i = 0
	size = skeleton[-1][SKELETON_OFFSET] + data_types[skeleton[-1][SKELETON_TYPE]]
	while i < size:
		if i < skeleton[0][SKELETON_OFFSET]:
			if i + data_types[default_type] <= skeleton[0][SKELETON_OFFSET]:
				idc.AddStrucMember(idx, 'field_{0}'.format(hex(i)), i, default_type | idaapi.FF_DATA, -1, data_types[default_type])
				i += data_types[default_type]
			else:
				for data_type in sorted_data_types:
					if skeleton[0][SKELETON_OFFSET] - i >= data_type[1]:
						idc.AddStrucMember(idx, 'field_{0}'.format(hex(i)), i, data_type[0] | idaapi.FF_DATA, -1, data_type[1])				
						i += data_type[1]
						break
		elif i == skeleton[0][SKELETON_OFFSET]:
			idc.AddStrucMember(idx, skeleton[0][SKELETON_NAME], skeleton[0][SKELETON_OFFSET], 
				skeleton[0][SKELETON_TYPE] | idaapi.FF_DATA, -1, data_types[skeleton[0][SKELETON_TYPE]])
			i += data_types[skeleton[0][SKELETON_TYPE]]
			skeleton.pop(0)
		else:
			skeleton.pop(0)

def create_struc(name, size, default_type = idaapi.FF_DWRD):
	sid = idc.GetStrucIdByName(name)
	if sid != idaapi.BADADDR:
		idc.DelStruc(sid)
	idx = idc.AddStrucEx(idaapi.BADADDR, name, False)
	i = 0
	while i < size:
		idc.AddStrucMember(idx, 'field_{0}'.format(hex(i)), i, default_type | idaapi.FF_DATA, -1, data_types[default_type])
		i += data_types[default_type]
	

def set_struc_offset(eas, sid):
	for elem in eas:
		OpStroffEx(elem[EAS_EA], elem[EAS_OPNDN], sid, elem[EAS_OFFSET])

def get_struc_offset(ea, opn):
	path = idaapi.tid_array(1)
	delta = idaapi.sval_pointer()
	idaapi.get_stroff_path(ea, opn, path.cast(), delta.cast())
	struct = path[0]
	if idaapi.decode_insn(ea) == 0:
		print 'error in {0}'.format(GetDisasm(ea))
	else:
		op = idaapi.cmd.Operands[opn]
		offset = op.value
		result = []
		idaapi.get_stroff_path(ea, opn, path.cast(), delta.cast())
		struct = path[0]	
		while offset:
			member_id = idc.GetMemberId(struct, offset)
			member_name = idc.GetMemberName(member_id)
			field_struct_id = idc.GetMemberStrId(struct, offset)
			if field_struct_id != idc.BADADDR:
				result.append([field_struct_id, idc.GetStrucName(field_struct_id)])
			else:
				result.append([member_name, idc.GetMemberFlag(struct, offset)])
				return result
			offset -= idc.GetMemberOffset(member_name)

class StructuresGui(QtGui.QDialog):
	def __init__(self):
		super(StructuresGui, self).__init__()
		self.setWindowTitle("Structures Helper")
		self.setModal(True)
		self.layout = QtGui.QVBoxLayout()
		self.reg = QtGui.QComboBox(self)
		self.reg.addItems(phrase.keys())
		self.layout.addWidget(self.reg)
		self.name = QtGui.QLineEdit(self)
		self.wordlist = []
		self.completer = QtGui.QCompleter(self.wordlist, self)
		self.layout.addWidget(self.name)
		self.size = QtGui.QLineEdit(self)
		self.layout.addWidget(self.size)		
		self.name.setCompleter(self.completer)
		self.button = QtGui.QPushButton('Create', self)
		self.button.clicked.connect(self.create_struc)
		self.layout.addWidget(self.button)
		self.setLayout(self.layout)
		self.show()

	
	@Slot()
	def create_struc(self):
					
		self.wordlist.append(self.name.text())
		self.completer = QtGui.QCompleter(self.wordlist, self)
		self.name.setCompleter(self.completer)
		if self.size.text():
			size = int(self.size.text(), base = 16)
			create_struc(str(self.name.text()), size)
		else:
			create_struc_from_skeleton(str(self.name.text()), gen_skeleton_and_eas(phrase.keys()[self.reg.currentIndex()])[0])

	
def run_structs():
	global gui
	gui = StructuresGui()

idaapi.CompileLine('static key_2() {RunPythonStatement("run_structs()");}')
idc.AddHotkey("2", "key_2")

#gui.show()
#create_struc_from_skeleton('DXGDEVICE', gen_skeleton_and_eas('esi')[0])
#print get_struc_offset(ScreenEA(), 1)

#def copy_struc_members(src, dest, src_offset, dest_offset, size):
#	# TODO structure with member as structures
#	src_sid = idc.GetStrucIdByName(src)
#	dest_sid = idc.GetStrucIdByName(dest)
#	while src_offset != idc.BADADDR and src_offset < src_offset + size:
#		name = idc.GetMemberName(src_sid, src_offset)
#		flag = idc.GetMemberFlag(src_sid, src_offset)
#		idc.SetMemberName(dest_sid, dest_offset, name)
#		idc.SetMemberType(dest_sid, dest_offset, flag, -1, 1)
#		src_offset = idc.GetStrucNextOff(src_sid, src_offset)
#		dest_offset = idc.GetStrucNextOff(dest_sid, dest_offset)
#		print src_offset, dest_offset, flag
#
#copy_struc_members('DRIVER_INITIALIZATION_DATA', 'DRIVER_OBJECT_EXTENSION', 0, 0x50, 0x11C)
