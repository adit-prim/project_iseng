import tkinter as tk
from tkinter import messagebox

def encode_text(text):
    tanda_baca = set(
        c for c in text if not c.isalpha() and not c.isspace() and c != '/'
    )

    hasil = []
    for kata in text.split():
        encoded_kata = []
        for char in kata:
            if char.isalpha():
                encoded_kata.append(str(ord(char.lower()) - ord('a')))
            elif char in tanda_baca:
                encoded_kata.append(char)
        if not encoded_kata:
            hasil.append('')
            continue

        gabung = encoded_kata[0]
        for e in encoded_kata[1:]:
            if e in tanda_baca:
                gabung += e
            elif gabung[-1] in tanda_baca:
                gabung += e
            else:
                gabung += '.' + e
        hasil.append(gabung)

    return '/'.join(hasil)

def decode_text(text):
    hasil = []

    for kata in text.split('/'):
        kata_hasil = ""
        buffer = ""
        for c in kata:
            if c.isdigit():
                buffer += c
            elif c == '.':
                if buffer:
                    huruf = chr(int(buffer) + ord('a'))
                    kata_hasil += huruf
                    buffer = ""
            else:  # simbol atau akhir angka
                if buffer:
                    huruf = chr(int(buffer) + ord('a'))
                    kata_hasil += huruf
                    buffer = ""
                kata_hasil += c

        if buffer:
            kata_hasil += chr(int(buffer) + ord('a'))

        hasil.append(kata_hasil)

    return ' '.join(hasil)

# === GUI Functions ===
def encode_gui():
    teks = input_text.get("1.0", tk.END).strip()
    if not teks:
        messagebox.showwarning("Peringatan", "Silakan masukkan teks terlebih dahulu.")
        return

    hasil = encode_text(teks)
    tampilkan_output(hasil)

def decode_gui():
    teks = input_text.get("1.0", tk.END).strip()
    if not teks:
        messagebox.showwarning("Peringatan", "Silakan masukkan teks terenkripsi.")
        return

    hasil = decode_text(teks)
    tampilkan_output(hasil)

def tampilkan_output(hasil):
    output_text.config(state='normal')
    output_text.delete("1.0", tk.END)
    output_text.insert(tk.END, hasil)
    output_text.config(state='disabled')

def bersihkan():
    input_text.delete("1.0", tk.END)
    output_text.config(state='normal')
    output_text.delete("1.0", tk.END)
    output_text.config(state='disabled')

def salin_ke_clipboard():
    hasil = output_text.get("1.0", tk.END).strip()
    if hasil:
        root.clipboard_clear()
        root.clipboard_append(hasil)
        root.update()
        messagebox.showinfo("Disalin", "Hasil telah disalin ke clipboard.")
    else:
        messagebox.showwarning("Kosong", "Tidak ada teks untuk disalin.")

def keluar():
    root.destroy()

# === GUI Layout ===
root = tk.Tk()
root.title("Encode/Decode Teks ke Angka")
root.geometry("650x500")

# Input
tk.Label(root, text="Masukkan Teks atau Kode:").pack(pady=5)
input_text = tk.Text(root, height=5, width=75)
input_text.pack()

# Tombol Encode/Decode
frame_buttons = tk.Frame(root)
frame_buttons.pack(pady=10)

tk.Button(frame_buttons, text="Encode", command=encode_gui, width=15).pack(side=tk.LEFT, padx=5)
tk.Button(frame_buttons, text="Decode", command=decode_gui, width=15).pack(side=tk.LEFT, padx=5)

# Output
tk.Label(root, text="Hasil:").pack(pady=5)
output_text = tk.Text(root, height=5, width=75, state='disabled')
output_text.pack()

# Tombol Copy/Bersihkan/Keluar
frame_bottom = tk.Frame(root)
frame_bottom.pack(pady=10)

tk.Button(frame_bottom, text="Copy", command=salin_ke_clipboard, width=15).pack(side=tk.LEFT, padx=5)
tk.Button(frame_bottom, text="Bersihkan", command=bersihkan, width=15).pack(side=tk.LEFT, padx=5)
tk.Button(frame_bottom, text="Keluar", command=keluar, width=15).pack(side=tk.LEFT, padx=5)

root.mainloop()
