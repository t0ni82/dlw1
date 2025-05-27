import tkinter as tk
from tkinter import ttk, messagebox

class DLW1:
    def __init__(self):
        self.reset()

    def reset(self):
        self.reg = [0] * 4  # A, B, C, D
        self.ram = [0] * 32  # 32 bytes de RAM
        self.pc = 0
        self.program = []

    def load_program(self, program_bytes):
        self.ram[:len(program_bytes)] = program_bytes
        self.program = program_bytes
        self.pc = 0

    def fetch(self):
        if self.pc + 1 >= len(self.ram):
            return None
        instr = (self.ram[self.pc] << 8) | self.ram[self.pc + 1]
        self.pc += 2
        return instr

    def decode_execute(self, instr):
        mode = (instr >> 15) & 0b1

        if mode == 0:
            opcode = (instr >> 12) & 0b111
            src1 = (instr >> 10) & 0b11
            src2 = (instr >> 8) & 0b11
            dest = (instr >> 6) & 0b11

            if opcode == 0b000:  # ADD
                self.reg[dest] = (self.reg[src1] + self.reg[src2]) & 0xFF
            elif opcode == 0b001:  # SUB
                self.reg[dest] = (self.reg[src1] - self.reg[src2]) & 0xFF
            elif opcode == 0b011:  # LOAD desde dirección contenida en src1
                addr = self.reg[src1]
                if 0 <= addr < len(self.ram):
                    self.reg[dest] = self.ram[addr]
                else:
                    self.reg[dest] = 0

        else:
            opcode = (instr >> 12) & 0b111

            if opcode == 0b000:  # ADD inmediato
                src = (instr >> 10) & 0b11
                dest = (instr >> 8) & 0b11
                imm_val = instr & 0xFF
                self.reg[dest] = (self.reg[src] + imm_val) & 0xFF

            elif opcode == 0b001:  # SUB inmediato
                src = (instr >> 10) & 0b11
                dest = (instr >> 8) & 0b11
                imm_val = instr & 0xFF
                self.reg[dest] = (self.reg[src] - imm_val) & 0xFF

            elif opcode == 0b010:  # LOAD inmediato desde RAM
                dest = (instr >> 8) & 0b11
                addr = instr & 0xFF
                if 0 <= addr < len(self.ram):
                    self.reg[dest] = self.ram[addr]
                else:
                    self.reg[dest] = 0

            elif opcode == 0b100:  # STORE inmediato en RAM
                src = (instr >> 10) & 0b11
                addr = instr & 0xFF
                if 0 <= addr < len(self.ram):
                    self.ram[addr] = self.reg[src]

            elif opcode == 0b110:  # NOP
                pass

            elif opcode == 0b111:  # HLT
                self.pc -= 2
                raise StopIteration("Ejecución detenida por HLT")

class DLWGUI:
    def __init__(self, root):
        self.cpu = DLW1()
        self.root = root
        root.title("DLW-1 Emulator")
        self.setup_widgets()

    def setup_widgets(self):
        main_frame = ttk.Frame(self.root)
        main_frame.pack(padx=10, pady=10, fill="both", expand=True)

        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(0, weight=1)

        left_frame = ttk.Frame(main_frame)
        left_frame.grid(row=0, column=0, sticky="n")

        ttk.Label(left_frame, text="REGISTROS").pack()
        self.reg_labels = []
        for name in ["A", "B", "C", "D"]:
            label = ttk.Label(left_frame, text=f"{name}: 0")
            label.pack(anchor="w")
            self.reg_labels.append(label)

        center_frame = ttk.Frame(main_frame)
        center_frame.grid(row=0, column=1, sticky="nsew", padx=10)
        center_frame.columnconfigure(0, weight=1)
        center_frame.rowconfigure(1, weight=1)

        ttk.Label(center_frame, text="CÓDIGO ENSAMBLADOR").grid(row=0, column=0, sticky="w")
        self.asm_text = tk.Text(center_frame, wrap="none")
        self.asm_text.grid(row=1, column=0, sticky="nsew")

        button_frame = ttk.Frame(center_frame)
        button_frame.grid(row=2, column=0, pady=5, sticky="w")

        ttk.Button(button_frame, text="Cargar programa", command=self.load_program).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Paso a paso", command=self.step).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Reiniciar", command=self.reset).pack(side="left", padx=5)

        self.opcode_label = ttk.Label(center_frame, text="Instrucción actual (bin): --")
        self.opcode_label.grid(row=3, column=0, sticky="w", pady=5)

        self.pc_label = ttk.Label(center_frame, text="PC: 0x00")
        self.pc_label.grid(row=4, column=0, sticky="w")

        self.ir_label = ttk.Label(center_frame, text="IR: --")
        self.ir_label.grid(row=5, column=0, sticky="w")

        right_frame = ttk.Frame(main_frame)
        right_frame.grid(row=0, column=2, sticky="n")

        ttk.Label(right_frame, text="RAM (dirección 0x)").pack()
        self.ram_entries = []
        for row in range(4):
            row_frame = ttk.Frame(right_frame)
            row_frame.pack()
            for col in range(8):
                addr = row * 8 + col
                frame = ttk.Frame(row_frame)
                frame.pack(side="left", padx=1)
                addr_label = ttk.Label(frame, text=f"0x{addr:02X}", width=5)
                addr_label.pack()
                entry = ttk.Entry(frame, width=4, justify="center")
                entry.insert(0, "00")
                entry.pack()
                self.ram_entries.append(entry)

    def update_gui(self):
        for i, val in enumerate(self.cpu.reg):
            self.reg_labels[i].config(text=f"{chr(65+i)}: {val}")

        for i in range(32):
            self.ram_entries[i].delete(0, tk.END)
            self.ram_entries[i].insert(0, f"{self.cpu.ram[i]:02X}")

    def reset(self):
        self.cpu.reset()
        self.opcode_label.config(text="Instrucción actual (bin): --")
        self.pc_label.config(text="PC: 0x00")
        self.ir_label.config(text="IR: --")
        self.update_gui()

    def update_ram_from_table(self):
        for i in range(32):
            entry = self.ram_entries[i]
            try:
                val = int(entry.get(), 16)
                self.cpu.ram[i] = val & 0xFF
            except ValueError:
                continue

    def step(self):
        self.update_ram_from_table()
        pc_before = self.cpu.pc
        self.asm_text.tag_remove("current_instr", "1.0", tk.END)
        instr = self.cpu.fetch()
        if instr is None:
            self.opcode_label.config(text="Instrucción actual (bin): --")
            self.pc_label.config(text="PC: --")
            self.ir_label.config(text="IR: --")
            return
        try:
            self.cpu.decode_execute(instr)
            line_number = self.cpu.pc // 2
            self.asm_text.tag_add("current_instr", f"{line_number + 1}.0", f"{line_number + 1}.end")
            self.asm_text.tag_config("current_instr", background="lightyellow")

        except StopIteration as e:
            messagebox.showinfo("HLT", str(e))
            return

        bin_str = f"{(instr >> 8) & 0xFF:08b} {(instr & 0xFF):08b}"
        self.opcode_label.config(text=f"Instrucción actual (bin): {bin_str}")
        self.pc_label.config(text=f"PC: 0x{pc_before:02X}")
        self.ir_label.config(text=f"IR: 0x{instr:04X}")
        self.update_gui()

    def load_program(self):
        asm_code = self.asm_text.get("1.0", tk.END).strip()
        lines = []
        for raw_line in asm_code.splitlines():
            line = raw_line.split(';')[0].strip()
            if line:
                lines.append(line)

        bin_program = []
        try:
            for line in lines:
                instr = self.assemble_instruction(line)
                bin_program.append((instr >> 8) & 0xFF)
                bin_program.append(instr & 0xFF)
            self.cpu.load_program(bin_program)
            self.update_gui()
        except Exception as e:
            messagebox.showerror("Error", f"Error al ensamblar: {e}")

    def assemble_instruction(self, line):
        parts = line.lower().split()
        if len(parts) < 1:
            raise ValueError("Instrucción vacía")

        op = parts[0]
        reg_map = {'a': 0, 'b': 1, 'c': 2, 'd': 3}

        def is_num(s):
            try:
                int(s)
                return True
            except:
                return False

        if op == "load":
            if len(parts) != 3:
                raise ValueError("Formato: load #addr reg  o  load reg_src reg_dest")

            src_token = parts[1]
            dest_token = parts[2]

            if dest_token not in reg_map:
                raise ValueError("Registro destino inválido")

            dest = reg_map[dest_token]

            if src_token.startswith("#"):
                addr = int(src_token[1:], 16) & 0xFF
                opcode_imm = 0b010
                instr = (1 << 15) | (opcode_imm << 12) | (0 << 10) | (dest << 8) | addr
                return instr
            else:
                if src_token not in reg_map:
                    raise ValueError("Registro fuente inválido")
                src = reg_map[src_token]
                opcode_reg = 0b011
                instr = (0 << 15) | (opcode_reg << 12) | (src << 10) | (0 << 8) | (dest << 6)
                return instr

        elif op in ["add", "sub"]:
            if len(parts) != 4:
                raise ValueError("Formato: add a b c  /  add c 8 a / add 5 a c")

            if op == "add":
                opcode_reg = 0b000
                opcode_imm = 0b000
            else:
                opcode_reg = 0b001
                opcode_imm = 0b001

            p1, p2, p3 = parts[1], parts[2], parts[3]

            if is_num(p2):
                if p1 not in reg_map or p3 not in reg_map:
                    raise ValueError("Registro inválido")
                src = reg_map[p1]
                imm = int(p2) & 0xFF
                dest = reg_map[p3]
                instr = (1 << 15) | (opcode_imm << 12) | (src << 10) | (dest << 8) | imm

            elif is_num(p1):
                if p2 not in reg_map or p3 not in reg_map:
                    raise ValueError("Registro inválido")
                imm = int(p1) & 0xFF
                src = reg_map[p2]
                dest = reg_map[p3]
                instr = (1 << 15) | (opcode_imm << 12) | (src << 10) | (dest << 8) | imm

            else:
                if p1 not in reg_map or p2 not in reg_map or p3 not in reg_map:
                    raise ValueError("Registro inválido")
                src1 = reg_map[p1]
                src2 = reg_map[p2]
                dest = reg_map[p3]
                instr = (0 << 15) | (opcode_reg << 12) | (src1 << 10) | (src2 << 8) | (dest << 6)

            return instr

        elif op == "store":
            if len(parts) != 3:
                raise ValueError("Formato: store reg #addr")

            src_token = parts[1]
            addr_token = parts[2]

            if not addr_token.startswith("#"):
                raise ValueError("Dirección inmediata debe empezar con '#'")

            if src_token not in reg_map:
                raise ValueError("Registro fuente inválido")

            src = reg_map[src_token]
            addr = int(addr_token[1:], 16) & 0xFF
            opcode_imm = 0b100
            instr = (1 << 15) | (opcode_imm << 12) | (src << 10) | addr
            return instr

        elif op == "nop":
            return (1 << 15) | (0b110 << 12)

        elif op == "hlt":
            return (1 << 15) | (0b111 << 12)

        else:
            raise ValueError(f"Instrucción no reconocida: {op}")

if __name__ == "__main__":
    root = tk.Tk()
    app = DLWGUI(root)
    root.mainloop()