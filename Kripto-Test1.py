import tkinter as tk
from tkinter import filedialog, messagebox, Scrollbar, Canvas, Frame
from Crypto.Cipher import AES
import base64, os
import PyPDF2
from io import BytesIO
from pdf2image import convert_from_bytes
from PIL import ImageTk

selected_file_path = None

def pad(data):
    pad_length = 16 - (len(data) % 16)
    return data + bytes([pad_length] * pad_length)

def unpad(data):
    pad_length = data[-1]
    return data[:-pad_length]

def caesar_cipher_ascii(text, shift):
    return ''.join(chr((ord(char) + shift) % 256) for char in text)

def caesar_decipher_ascii(text, shift):
    return ''.join(chr((ord(char) - shift) % 256) for char in text)

def encrypt_aes(data, key):
    key = key.ljust(32)[:32].encode('utf-8')
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(data))
    return base64.b64encode(iv + ciphertext).decode('utf-8')

def decrypt_aes(data, key):
    key = key.ljust(32)[:32].encode('utf-8')
    raw_data = base64.b64decode(data)
    iv, ciphertext = raw_data[:16], raw_data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext))

def select_file():
    global selected_file_path
    selected_file_path = filedialog.askopenfilename(filetypes=[("PDF or Encrypted files", "*.pdf *.enc")])
    if selected_file_path:
        messagebox.showinfo("File Selected", f"File dipilih: {selected_file_path}")
        preview_file(selected_file_path)

def encrypt_pdf():
    if not selected_file_path:
        messagebox.showerror("Error", "Pilih file terlebih dahulu!")
        return
    key = key_entry.get()
    if not key:
        messagebox.showerror("Error", "Key tidak boleh kosong!")
        return
    
    with open(selected_file_path, "rb") as f:
        pdf_data = f.read()
    
    aes_encrypted = encrypt_aes(pdf_data, key)
    caesar_key = caesar_cipher_ascii(key, 3)
    final_encrypted = caesar_cipher_ascii(aes_encrypted, 3)
    
    encrypted_file_path = selected_file_path + ".enc"
    with open(encrypted_file_path, "w", encoding='utf-8') as f:
        f.write(final_encrypted)
    
    messagebox.showinfo("Sukses", f"File terenkripsi disimpan di {encrypted_file_path}")
    preview_file(encrypted_file_path)

def decrypt_pdf():
    if not selected_file_path:
        messagebox.showerror("Error", "Pilih file terlebih dahulu!")
        return
    key = key_entry.get()
    if not key:
        messagebox.showerror("Error", "Key tidak boleh kosong!")
        return
    
    with open(selected_file_path, "r", encoding='utf-8') as f:
        encrypted_data = f.read()
    
    decrypted_caesar = caesar_decipher_ascii(encrypted_data, 3)
    try:
        decrypted_data = decrypt_aes(decrypted_caesar, key)
        decrypted_file_path = selected_file_path.replace(".enc", "_decrypted.pdf")
        with open(decrypted_file_path, "wb") as f:
            f.write(decrypted_data)
        messagebox.showinfo("Sukses", f"File didekripsi dan disimpan di {decrypted_file_path}")
        preview_file(decrypted_file_path)
    except Exception as e:
        messagebox.showerror("Error", f"Gagal mendekripsi: {e}")


def preview_file(file_path):
    for widget in pdf_preview.winfo_children():
        widget.destroy()
    
    if file_path.endswith(".pdf"):
        with open(file_path, "rb") as f:
            pdf_reader = PyPDF2.PdfReader(f)
            pdf_images = []
            for page in pdf_reader.pages:
                pdf_bytes = BytesIO()
                pdf_writer = PyPDF2.PdfWriter()
                pdf_writer.add_page(page)
                pdf_writer.write(pdf_bytes)
                images = convert_from_bytes(pdf_bytes.getvalue())
                pdf_images.extend(images)
            
            canvas = Canvas(pdf_preview, bg="#f0f0f0")
            scrollbar = Scrollbar(pdf_preview, orient="vertical", command=canvas.yview)
            scroll_frame = Frame(canvas, bg="#f0f0f0")
            
            scroll_frame.bind(
                "<Configure>", lambda e: canvas.configure(
                    scrollregion=canvas.bbox("all")
                )
            )
            
            canvas.create_window((canvas.winfo_width() // 2, 0), window=scroll_frame, anchor="n")
            canvas.configure(yscrollcommand=scrollbar.set)
            
            for img in pdf_images:
                img.thumbnail((500, 600))
                img_tk = ImageTk.PhotoImage(img)
                img_label = tk.Label(scroll_frame, image=img_tk, bg="#f0f0f0")
                img_label.image = img_tk
                img_label.pack(pady=5)

            canvas.pack(side="left", fill="both", expand=True)
            scrollbar.pack(side="right", fill="y")
    else:
        enc_label.config(text="Preview tidak tersedia untuk file terenkripsi.")

# Setup GUI
root = tk.Tk()
root.title("PDF Encryption & Decryption Tool")
root.geometry("1920x1080")
root.config(bg="#f8f9fa")

tk.Label(root, text="Masukkan Key:", font=("Arial", 12), bg="#f8f9fa").pack(pady=5)
key_entry = tk.Entry(root, show="*", width=50, font=("Arial", 10))
key_entry.pack(pady=5)

button_frame = tk.Frame(root, bg="#f8f9fa")
button_frame.pack(pady=10)

select_button = tk.Button(button_frame, text="Pilih File", command=select_file, bg="#007bff", fg="black", font=("Arial", 10), padx=10)
select_button.grid(row=0, column=0, padx=5)

encrypt_button = tk.Button(button_frame, text="Enkripsi PDF", command=encrypt_pdf, bg="#28a745", fg="black", font=("Arial", 10), padx=10)
encrypt_button.grid(row=0, column=1, padx=5)

decrypt_button = tk.Button(button_frame, text="Dekripsi PDF", command=decrypt_pdf, bg="#dc3545", fg="black", font=("Arial", 10), padx=10)
decrypt_button.grid(row=0, column=2, padx=5)

pdf_preview = tk.Frame(root, bg="#ffffff", relief="sunken", bd=2)
pdf_preview.pack(pady=5, fill="both", expand=True)

enc_label = tk.Label(root, text="", bg="#f8f9fa", font=("Arial", 10))
enc_label.pack(pady=5)

root.mainloop()