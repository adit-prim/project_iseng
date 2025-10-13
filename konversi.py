import tkinter as tk
from tkinter import messagebox

def convert():
    number = entry.get().strip()
    from_base = input_var.get()
    to_base = output_var.get()

    try:
        # Mapping basis
        bases = {
            "Biner": 2,
            "Oktal": 8,
            "Desimal": 10,
            "Heksadesimal": 16
        }

        # Konversi input ke desimal dulu
        decimal_value = int(number, bases[from_base])

        # Konversi dari desimal ke basis tujuan
        if to_base == "Biner":
            result = bin(decimal_value)[2:]
        elif to_base == "Oktal":
            result = oct(decimal_value)[2:]
        elif to_base == "Heksadesimal":
            result = hex(decimal_value)[2:].upper()
        elif to_base == "Desimal":
            result = str(decimal_value)
        else:
            raise ValueError("Pilih basis tujuan!")

        result_label.config(text=f"Hasil ({to_base}): {result}")

    except ValueError:
        messagebox.showerror("Error", f"Input tidak valid untuk {from_base}.")
    except Exception as e:
        messagebox.showerror("Error", str(e))


# Setup GUI
root = tk.Tk()
root.title("Konversi Bilangan")
root.geometry("420x350")

# Input
tk.Label(root, text="Masukkan Bilangan:").pack(pady=5)
entry = tk.Entry(root, width=30)
entry.pack(pady=5)

# Pilih basis input
tk.Label(root, text="Basis Input:").pack(pady=5)
input_var = tk.StringVar(value="Desimal")
for base in ["Desimal", "Biner", "Oktal", "Heksadesimal"]:
    tk.Radiobutton(root, text=base, variable=input_var, value=base).pack()

# Pilih basis output
tk.Label(root, text="Konversi ke:").pack(pady=5)
output_var = tk.StringVar(value="Biner")
for base in ["Desimal", "Biner", "Oktal", "Heksadesimal"]:
    tk.Radiobutton(root, text=base, variable=output_var, value=base).pack()

# Tombol konversi
tk.Button(root, text="Konversi", command=convert).pack(pady=10)

# Label hasil
result_label = tk.Label(root, text="Hasil akan muncul di sini", font=("Arial", 12))
result_label.pack(pady=10)

root.mainloop()