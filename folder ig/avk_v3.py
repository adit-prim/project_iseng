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

# ====================== GUI: Fitur Tunggal "Berantai" ======================

def build_tab_berantai(notebook):
    frame = ttk.Frame(notebook, padding=10)

    ttk.Label(frame, text="Input: Plaintext (Encode) atau Sandi Angka (Decode)").pack(anchor='w', pady=(0,5))
    input_text = tk.Text(frame, height=6, width=90)
    input_text.pack(fill='x')

    # Kunci Vigenère + tombol 'mata'
    ttk.Label(frame, text="Kunci Vigenère (huruf saja):").pack(anchor='w', pady=(8,5))
    key_row = ttk.Frame(frame)
    key_row.pack(anchor='w')
    key_entry = ttk.Entry(key_row, width=40, show='*')
    key_entry.pack(side='left')
    # state toggle untuk vigenere
    vigenere_hidden = {'value': True}
    def toggle_vigenere_visibility():
        if vigenere_hidden['value']:
            key_entry.config(show='')
            btn_vigenere_eye.config(text='🙈')  # sekarang terlihat, tombol untuk menyembunyikan
        else:
            key_entry.config(show='*')
            btn_vigenere_eye.config(text='👁')  # sekarang tersembunyi, tombol untuk menampilkan
        vigenere_hidden['value'] = not vigenere_hidden['value']
    btn_vigenere_eye = ttk.Button(key_row, text='👁', width=3, command=toggle_vigenere_visibility)
    btn_vigenere_eye.pack(side='left', padx=6)

    # Kunci Affine (a, b) + tombol 'mata' masing-masing
    keys_frame = ttk.Frame(frame)
    keys_frame.pack(anchor='w', pady=(8,5))

    ttk.Label(keys_frame, text="Kunci Affine a (relatif prima terhadap 26):").grid(row=0, column=0, sticky='w')
    a_entry = ttk.Entry(keys_frame, width=10, show='*')
    a_entry.grid(row=0, column=1, padx=(6,4))
    a_hidden = {'value': True}
    def toggle_a_visibility():
        if a_hidden['value']:
            a_entry.config(show='')
            btn_a_eye.config(text='🙈')
        else:
            a_entry.config(show='*')
            btn_a_eye.config(text='👁')
        a_hidden['value'] = not a_hidden['value']
    btn_a_eye = ttk.Button(keys_frame, text='👁', width=3, command=toggle_a_visibility)
    btn_a_eye.grid(row=0, column=2, padx=(4,20))

    ttk.Label(keys_frame, text="Kunci Affine b:").grid(row=0, column=3, sticky='w')
    b_entry = ttk.Entry(keys_frame, width=10, show='*')
    b_entry.grid(row=0, column=4, padx=(6,4))
    b_hidden = {'value': True}
    def toggle_b_visibility():
        if b_hidden['value']:
            b_entry.config(show='')
            btn_b_eye.config(text='🙈')
        else:
            b_entry.config(show='*')
            btn_b_eye.config(text='👁')
        b_hidden['value'] = not b_hidden['value']
    btn_b_eye = ttk.Button(keys_frame, text='👁', width=3, command=toggle_b_visibility)
    btn_b_eye.grid(row=0, column=5, padx=(4,6))

    # Tombol aksi
    btn_row = ttk.Frame(frame)
    btn_row.pack(pady=10)
    output_text = tk.Text(frame, height=8, width=90, state='disabled')

    def encode_chain():
        teks = input_text.get("1.0", tk.END).strip()
        key = key_entry.get().strip()
        a_val = a_entry.get().strip()
        b_val = b_entry.get().strip()

        if not teks or not key or not a_val or not b_val:
            messagebox.showwarning("Peringatan", "Isi teks, kunci Vigenère, dan kunci Affine (a dan b).")
            return

        if not key.isalpha():
            messagebox.showerror("Error", "Kunci Vigenère harus berupa huruf saja (A-Z).")
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

        # Berantai: Vigenère -> Affine -> Sandi Angka
        step1 = vigenere_encrypt_preserve(teks, key)
        step2 = affine_encrypt(step1, a, b)
        step3 = encode_text(step2)

        tampilkan_output(output_text, step3)

    def decode_chain():
        # Berantai balik: Sandi Angka -> Affine (decrypt) -> Vigenère (decrypt)
        teks = input_text.get("1.0", tk.END).strip()
        key = key_entry.get().strip()
        a_val = a_entry.get().strip()
        b_val = b_entry.get().strip()

        if not teks or not key or not a_val or not b_val:
            messagebox.showwarning("Peringatan", "Isi teks (Sandi Angka), kunci Vigenère, dan kunci Affine (a dan b).")
            return

        if not key.isalpha():
            messagebox.showerror("Error", "Kunci Vigenère harus berupa huruf saja (A-Z).")
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

        # Decode urut terbalik
        step1 = decode_text(teks)
        step2 = affine_decrypt(step1, a, b)
        if step2.startswith("[Error]"):
            tampilkan_output(output_text, step2)
            return
        step3 = vigenere_decrypt_preserve(step2, key)

        tampilkan_output(output_text, step3)

    ttk.Button(btn_row, text="Encode Berantai", command=encode_chain, width=18).pack(side='left', padx=5)
    ttk.Button(btn_row, text="Decode Berantai", command=decode_chain, width=18).pack(side='left', padx=5)

    ttk.Label(frame, text="Hasil:").pack(anchor='w', pady=(5,5))
    output_text.pack(fill='x')

    bottom = ttk.Frame(frame)
    bottom.pack(pady=10)

    ttk.Button(bottom, text="Copy", command=lambda: salin_ke_clipboard(output_text), width=18).pack(side='left', padx=5)
    ttk.Button(bottom, text="Bersihkan", command=lambda: bersihkan_text(input_text, output_text, [key_entry, a_entry, b_entry]), width=18).pack(side='left', padx=5)

    return frame

# ====================== Main App ======================

def main():
    root = tk.Tk()
    root.title("Cipher Berantai: Vigenère → Affine → Sandi Angka")
    root.geometry("840x560")

    try:
        style = ttk.Style()
        if "clam" in style.theme_names():
            style.theme_use("clam")
    except Exception:
        pass

    notebook = ttk.Notebook(root)
    notebook.pack(fill='both', expand=True)

    tab = build_tab_berantai(notebook)
    notebook.add(tab, text="Berantai (Vigenère → Affine → Sandi Angka)")

    bottom = ttk.Frame(root, padding=10)
    bottom.pack(fill='x')
    ttk.Button(bottom, text="Keluar", command=root.destroy, width=18).pack(side='right')

    root.mainloop()

if __name__ == "__main__":
    main()