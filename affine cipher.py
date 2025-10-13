import tkinter as tk
from tkinter import messagebox
from math import gcd

# ================= Affine Cipher Logic =================

def mod_inverse(a, m):
    # Extended Euclidean Algorithm to find inverse modulo m
    for i in range(1, m):
        if (a * i) % m == 1:
            return i
    return None

def affine_encrypt(text, a, b):
    result = ''
    for char in text:
        if char.isalpha():
            offset = ord('A') if char.isupper() else ord('a')
            x = ord(char) - offset
            enc = (a * x + b) % 26
            result += chr(enc + offset)
        else:
            result += char  # spasi, tanda baca, angka tetap
    return result

def affine_decrypt(text, a, b):
    result = ''
    a_inv = mod_inverse(a, 26)
    if a_inv is None:
        return "[Error] 'a' tidak memiliki invers mod 26"
    for char in text:
        if char.isalpha():
            offset = ord('A') if char.isupper() else ord('a')
            y = ord(char) - offset
            dec = (a_inv * (y - b)) % 26
            result += chr(dec + offset)
        else:
            result += char
    return result

# ================= GUI Functions =================

def encode_gui():
    teks = input_text.get("1.0", tk.END).strip()
    a_val = a_entry.get().strip()
    b_val = b_entry.get().strip()

    if not teks or not a_val or not b_val:
        messagebox.showwarning("Peringatan", "Isi teks dan kedua kunci (a dan b).")
        return

    try:
        a = int(a_val)
        b = int(b_val)
    except ValueError:
        messagebox.showerror("Error", "Kunci a dan b harus berupa angka.")
        return

    if gcd(a, 26) != 1:
        messagebox.showerror("Error", f"Nilai a = {a} tidak valid (harus relatif prima terhadap 26).")
        return

    hasil = affine_encrypt(teks, a, b)
    tampilkan_output(hasil)

def decode_gui():
    teks = input_text.get("1.0", tk.END).strip()
    a_val = a_entry.get().strip()
    b_val = b_entry.get().strip()

    if not teks or not a_val or not b_val:
        messagebox.showwarning("Peringatan", "Isi teks dan kedua kunci (a dan b).")
        return

    try:
        a = int(a_val)
        b = int(b_val)
    except ValueError:
        messagebox.showerror("Error", "Kunci a dan b harus berupa angka.")
        return

    if gcd(a, 26) != 1:
        messagebox.showerror("Error", f"Nilai a = {a} tidak valid (harus relatif prima terhadap 26).")
        return

    hasil = affine_decrypt(teks, a, b)
    tampilkan_output(hasil)

def tampilkan_output(hasil):
    output_text.config(state='normal')
    output_text.delete("1.0", tk.END)
    output_text.insert(tk.END, hasil)
    output_text.config(state='disabled')

def bersihkan():
    input_text.delete("1.0", tk.END)
    a_entry.delete(0, tk.END)
    b_entry.delete(0, tk.END)
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

# ================= GUI Layout =================

root = tk.Tk()
root.title("Affine Cipher - GUI")
root.geometry("650x580")

# Input teks
tk.Label(root, text="Masukkan Teks:").pack(pady=5)
input_text = tk.Text(root, height=5, width=75)
input_text.pack()

# Input kunci a dan b
tk.Label(root, text="Masukkan kunci a (relatif prima terhadap 26):").pack()
a_entry = tk.Entry(root, width=15)
a_entry.pack()

tk.Label(root, text="Masukkan kunci b:").pack()
b_entry = tk.Entry(root, width=15)
b_entry.pack()

# Tombol Encode / Decode
frame_buttons = tk.Frame(root)
frame_buttons.pack(pady=10)

tk.Button(frame_buttons, text="Encode", command=encode_gui, width=15).pack(side=tk.LEFT, padx=5)
tk.Button(frame_buttons, text="Decode", command=decode_gui, width=15).pack(side=tk.LEFT, padx=5)

# Output hasil
tk.Label(root, text="Hasil:").pack(pady=5)
output_text = tk.Text(root, height=5, width=75, state='disabled')
output_text.pack()

# Tombol Copy / Bersihkan / Keluar
frame_bottom = tk.Frame(root)
frame_bottom.pack(pady=10)

tk.Button(frame_bottom, text="Copy", command=salin_ke_clipboard, width=15).pack(side=tk.LEFT, padx=5)
tk.Button(frame_bottom, text="Bersihkan", command=bersihkan, width=15).pack(side=tk.LEFT, padx=5)
tk.Button(frame_bottom, text="Keluar", command=keluar, width=15).pack(side=tk.LEFT, padx=5)

root.mainloop()
