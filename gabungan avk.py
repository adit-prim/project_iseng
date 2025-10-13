import tkinter as tk
from tkinter import ttk, messagebox
from math import gcd

# ====================== Sandi Angka Logic ======================

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

# ====================== Vigenère Cipher Logic ======================

def vigenere_encrypt_preserve(text, key):
    key = key.upper()
    result = ''
    key_index = 0

    for char in text:
        if char.isalpha():
            offset = ord('A') if char.isupper() else ord('a')
            k = ord(key[key_index % len(key)]) - ord('A')
            c = chr((ord(char) - offset + k) % 26 + offset)
            result += c
            key_index += 1
        else:
            result += char  # spasi, tanda baca, angka tetap
    return result

def vigenere_decrypt_preserve(text, key):
    key = key.upper()
    result = ''
    key_index = 0

    for char in text:
        if char.isalpha():
            offset = ord('A') if char.isupper() else ord('a')
            k = ord(key[key_index % len(key)]) - ord('A')
            p = chr((ord(char) - offset - k) % 26 + offset)
            result += p
            key_index += 1
        else:
            result += char
    return result

# ====================== Affine Cipher Logic ======================

def mod_inverse(a, m):
    # Coba gunakan pow jika tersedia (Python 3.8+), fallback ke iterasi
    try:
        return pow(a, -1, m)
    except TypeError:
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

# ====================== Helper UI Functions ======================

def tampilkan_output(out_widget, teks):
    out_widget.config(state='normal')
    out_widget.delete("1.0", tk.END)
    out_widget.insert(tk.END, teks)
    out_widget.config(state='disabled')

def salin_ke_clipboard(widget_in_tab):
    # Ambil teks dari output pada tab terkait
    hasil = widget_in_tab.get("1.0", tk.END).strip()
    toplevel = widget_in_tab.winfo_toplevel()
    if hasil:
        toplevel.clipboard_clear()
        toplevel.clipboard_append(hasil)
        toplevel.update()
        messagebox.showinfo("Disalin", "Hasil telah disalin ke clipboard.")
    else:
        messagebox.showwarning("Kosong", "Tidak ada teks untuk disalin.")

def bersihkan_text(input_widget, output_widget, extra_entries=None):
    input_widget.delete("1.0", tk.END)
    if extra_entries:
        for e in extra_entries:
            e.delete(0, tk.END)
    output_widget.config(state='normal')
    output_widget.delete("1.0", tk.END)
    output_widget.config(state='disabled')

# ====================== Build Tabs ======================

def build_tab_sandi_angka(notebook):
    frame = ttk.Frame(notebook, padding=10)

    ttk.Label(frame, text="Masukkan Teks atau Kode (gunakan '/' antar kata untuk decode):").pack(anchor='w', pady=(0,5))
    input_text = tk.Text(frame, height=6, width=90)
    input_text.pack(fill='x')

    btn_row = ttk.Frame(frame)
    btn_row.pack(pady=10)
    output_text = tk.Text(frame, height=6, width=90, state='disabled')

    def do_encode():
        teks = input_text.get("1.0", tk.END).strip()
        if not teks:
            messagebox.showwarning("Peringatan", "Silakan masukkan teks terlebih dahulu.")
            return
        hasil = encode_text(teks)
        tampilkan_output(output_text, hasil)

    def do_decode():
        teks = input_text.get("1.0", tk.END).strip()
        if not teks:
            messagebox.showwarning("Peringatan", "Silakan masukkan teks terenkripsi.")
            return
        hasil = decode_text(teks)
        tampilkan_output(output_text, hasil)

    ttk.Button(btn_row, text="Encode", command=do_encode, width=18).pack(side='left', padx=5)
    ttk.Button(btn_row, text="Decode", command=do_decode, width=18).pack(side='left', padx=5)

    ttk.Label(frame, text="Hasil:").pack(anchor='w', pady=(5,5))
    output_text.pack(fill='x')

    bottom = ttk.Frame(frame)
    bottom.pack(pady=10)

    ttk.Button(bottom, text="Copy", command=lambda: salin_ke_clipboard(output_text), width=18).pack(side='left', padx=5)
    ttk.Button(bottom, text="Bersihkan", command=lambda: bersihkan_text(input_text, output_text), width=18).pack(side='left', padx=5)

    return frame

def build_tab_vigenere(notebook):
    frame = ttk.Frame(notebook, padding=10)

    ttk.Label(frame, text="Masukkan Teks:").pack(anchor='w', pady=(0,5))
    input_text = tk.Text(frame, height=6, width=90)
    input_text.pack(fill='x')

    ttk.Label(frame, text="Masukkan Kunci (huruf saja):").pack(anchor='w', pady=(8,5))
    key_entry = ttk.Entry(frame, width=40)
    key_entry.pack(anchor='w')

    btn_row = ttk.Frame(frame)
    btn_row.pack(pady=10)
    output_text = tk.Text(frame, height=6, width=90, state='disabled')

    def do_encode():
        teks = input_text.get("1.0", tk.END).strip()
        key = key_entry.get().strip()
        if not teks or not key:
            messagebox.showwarning("Peringatan", "Silakan masukkan teks dan kunci.")
            return
        hasil = vigenere_encrypt_preserve(teks, key)
        tampilkan_output(output_text, hasil)

    def do_decode():
        teks = input_text.get("1.0", tk.END).strip()
        key = key_entry.get().strip()
        if not teks or not key:
            messagebox.showwarning("Peringatan", "Silakan masukkan teks dan kunci.")
            return
        hasil = vigenere_decrypt_preserve(teks, key)
        tampilkan_output(output_text, hasil)

    ttk.Button(btn_row, text="Encode", command=do_encode, width=18).pack(side='left', padx=5)
    ttk.Button(btn_row, text="Decode", command=do_decode, width=18).pack(side='left', padx=5)

    ttk.Label(frame, text="Hasil:").pack(anchor='w', pady=(5,5))
    output_text.pack(fill='x')

    bottom = ttk.Frame(frame)
    bottom.pack(pady=10)

    ttk.Button(bottom, text="Copy", command=lambda: salin_ke_clipboard(output_text), width=18).pack(side='left', padx=5)
    ttk.Button(bottom, text="Bersihkan", command=lambda: bersihkan_text(input_text, output_text, [key_entry]), width=18).pack(side='left', padx=5)

    return frame

def build_tab_affine(notebook):
    frame = ttk.Frame(notebook, padding=10)

    ttk.Label(frame, text="Masukkan Teks:").pack(anchor='w', pady=(0,5))
    input_text = tk.Text(frame, height=6, width=90)
    input_text.pack(fill='x')

    keys_frame = ttk.Frame(frame)
    keys_frame.pack(anchor='w', pady=(8,5))
    ttk.Label(keys_frame, text="Kunci a (relatif prima terhadap 26):").grid(row=0, column=0, sticky='w')
    a_entry = ttk.Entry(keys_frame, width=10)
    a_entry.grid(row=0, column=1, padx=(6,20))
    ttk.Label(keys_frame, text="Kunci b:").grid(row=0, column=2, sticky='w')
    b_entry = ttk.Entry(keys_frame, width=10)
    b_entry.grid(row=0, column=3, padx=6)

    btn_row = ttk.Frame(frame)
    btn_row.pack(pady=10)
    output_text = tk.Text(frame, height=6, width=90, state='disabled')

    def do_encode():
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
        tampilkan_output(output_text, hasil)

    def do_decode():
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
        tampilkan_output(output_text, hasil)

    ttk.Button(btn_row, text="Encode", command=do_encode, width=18).pack(side='left', padx=5)
    ttk.Button(btn_row, text="Decode", command=do_decode, width=18).pack(side='left', padx=5)

    ttk.Label(frame, text="Hasil:").pack(anchor='w', pady=(5,5))
    output_text.pack(fill='x')

    bottom = ttk.Frame(frame)
    bottom.pack(pady=10)

    ttk.Button(bottom, text="Copy", command=lambda: salin_ke_clipboard(output_text), width=18).pack(side='left', padx=5)
    ttk.Button(bottom, text="Bersihkan", command=lambda: bersihkan_text(input_text, output_text, [a_entry, b_entry]), width=18).pack(side='left', padx=5)

    return frame

# ====================== Main App ======================

def main():
    root = tk.Tk()
    root.title("Kumpulan Cipher: Sandi Angka • Vigenère • Affine")
    root.geometry("820x650")

    # Gunakan ttk theme default
    try:
        style = ttk.Style()
        if "clam" in style.theme_names():
            style.theme_use("clam")
    except Exception:
        pass

    notebook = ttk.Notebook(root)
    notebook.pack(fill='both', expand=True)

    tab1 = build_tab_sandi_angka(notebook)
    tab2 = build_tab_vigenere(notebook)
    tab3 = build_tab_affine(notebook)

    notebook.add(tab1, text="Sandi Angka")
    notebook.add(tab2, text="Vigenère")
    notebook.add(tab3, text="Affine")

    # Tombol Keluar di bawah
    bottom = ttk.Frame(root, padding=10)
    bottom.pack(fill='x')
    ttk.Button(bottom, text="Keluar", command=root.destroy, width=18).pack(side='right')

    root.mainloop()

if __name__ == "__main__":
    main()