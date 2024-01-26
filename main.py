import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox, ttk
import pefile
from capstone import *

class DisassemblerApp:
    def __init__(self, master):
        self.master = master
        self.master.title("PinocchoDisAsm")
        self.master.configure(bg="#333333")  # Arka plan rengi
        self.create_widgets()

    def create_widgets(self):
        # Üst menü
        menubar = tk.Menu(self.master)
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Open", command=self.browse_file)
        file_menu.add_separator()
        file_menu.add_command(label="Save Assembly", command=self.save_assembly)
        file_menu.add_command(label="Exit", command=self.master.quit)
        menubar.add_cascade(label="File", menu=file_menu)
        self.master.config(menu=menubar)

        # Sol bölme
        left_frame = tk.Frame(self.master, bg="#333333")
        left_frame.pack(padx=10, pady=10, side=tk.LEFT, fill=tk.Y)  # Solda hizalanmış, Y ekseninde doldurulmuş

        # Hex kodunu gösterme bölümü
        hex_frame = tk.Frame(left_frame, bg="#333333")
        hex_frame.pack(fill=tk.BOTH, expand=True)

        hex_label = tk.Label(hex_frame, text="Hex Code", bg="#333333", fg="white")
        hex_label.pack(padx=10, pady=10, anchor=tk.W)

        self.hex_text = scrolledtext.ScrolledText(hex_frame, wrap=tk.WORD, bg="#000000", fg="white")
        self.hex_text.pack(padx=10, pady=(0, 10), fill=tk.BOTH, expand=True)

        # ASCII kodunu gösterme bölümü
        ascii_frame = tk.Frame(left_frame, bg="#333333")
        ascii_frame.pack(fill=tk.BOTH, expand=True)

        ascii_label = tk.Label(ascii_frame, text="ASCII Code", bg="#333333", fg="white")
        ascii_label.pack(padx=10, pady=10, anchor=tk.W)

        self.ascii_text = scrolledtext.ScrolledText(ascii_frame, wrap=tk.WORD, bg="#000000", fg="white")
        self.ascii_text.pack(padx=10, pady=(0, 10), fill=tk.BOTH, expand=True)

        # Aralarında çizgi
        ttk.Separator(left_frame, orient=tk.VERTICAL).pack(fill=tk.Y, padx=5, pady=5, side=tk.LEFT)

        # Sağ bölme
        right_frame = tk.Frame(self.master, bg="#333333")
        right_frame.pack(padx=10, pady=10, side=tk.LEFT, fill=tk.Y)  # Solda hizalanmış, Y ekseninde doldurulmuş

        # Assembly kodu gösterme bölümü
        assembly_frame = tk.Frame(right_frame, bg="#333333")
        assembly_frame.pack(fill=tk.BOTH, expand=True)

        assembly_label = tk.Label(assembly_frame, text="Assembly Code", bg="#333333", fg="white")
        assembly_label.pack(padx=10, pady=10, anchor=tk.W)

        self.assembly_text = scrolledtext.ScrolledText(assembly_frame, wrap=tk.WORD, bg="#F0EAD6", fg="black")
        self.assembly_text.pack(padx=10, pady=(0, 10), fill=tk.BOTH, expand=True)

    def browse_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Executable files", "*.exe")])
        if file_path:
            try:
                with open(file_path, "rb") as f:
                    hex_data = f.read().hex().upper()
                    self.display_hex(hex_data)
                    disassembled_code = self.disassemble_exe(file_path)
                    self.display_assembly(disassembled_code)
                    self.display_ascii(hex_data)
            except Exception as e:
                messagebox.showerror("Error", f"An error occurred: {str(e)}")

    def disassemble_exe(self, file_path):
        pe = pefile.PE(file_path)

        executable_sections = []
        for section in pe.sections:
            if section.IMAGE_SCN_MEM_EXECUTE:
                executable_sections.append(section)

        disassembled_code = []
        for section in executable_sections:
            cs = Cs(CS_ARCH_X86, CS_MODE_32) if pe.FILE_HEADER.Machine == 0x14c else Cs(CS_ARCH_X86, CS_MODE_64)
            code = section.get_data()
            for insn in cs.disasm(code, section.VirtualAddress):
                disassembled_code.append((hex(insn.address), insn.mnemonic, insn.op_str))

        return disassembled_code

    def display_hex(self, hex_data):
        self.hex_text.delete(1.0, tk.END)
        self.hex_text.insert(tk.END, hex_data)

    def display_assembly(self, disassembled_code):
        self.assembly_text.delete(1.0, tk.END)
        for addr, mnemonic, op_str in disassembled_code:
            self.assembly_text.insert(tk.END, f"{addr:<10}: {mnemonic:<10} {op_str}\n")

    def display_ascii(self, hex_data):
        ascii_data = "".join([chr(int(hex_data[i:i+2], 16)) for i in range(0, len(hex_data), 2) if hex_data[i:i+2]])
        self.ascii_text.delete(1.0, tk.END)
        self.ascii_text.insert(tk.END, ascii_data)

    def save_assembly(self):
        assembly_text = self.assembly_text.get(1.0, tk.END)
        if assembly_text.strip():
            file_path = filedialog.asksaveasfilename(defaultextension=".asm", filetypes=[("Assembly files", "*.asm")])
            if file_path:
                with open(file_path, "w") as f:
                    f.write(assembly_text)
                    messagebox.showinfo("Success", "Assembly code saved successfully.")
        else:
            messagebox.showwarning("Warning", "No assembly code to save.")

def main():
    root = tk.Tk()
    app = DisassemblerApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
