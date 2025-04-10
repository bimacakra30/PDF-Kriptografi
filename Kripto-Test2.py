import sys, os, base64
from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QPushButton, QFileDialog,
    QVBoxLayout, QHBoxLayout, QLineEdit, QMessageBox, QScrollArea, QFrame
)
from PyQt5.QtGui import QPixmap, QImage, QFont
from PyQt5.QtCore import Qt
from pdf2image import convert_from_bytes
from Crypto.Cipher import AES

selected_file_path = None

def pad(data): return data + bytes([16 - len(data) % 16] * (16 - len(data) % 16))
def unpad(data): return data[:-data[-1]]
def caesar_cipher(text, shift): return ''.join(chr((ord(c) + shift) % 256) for c in text)
def caesar_decipher(text, shift): return ''.join(chr((ord(c) - shift) % 256) for c in text)

def encrypt_aes(data, key):
    key = key.ljust(32)[:32].encode()
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return base64.b64encode(iv + cipher.encrypt(pad(data))).decode()

def decrypt_aes(data, key):
    key = key.ljust(32)[:32].encode()
    raw = base64.b64decode(data)
    cipher = AES.new(key, AES.MODE_CBC, raw[:16])
    return unpad(cipher.decrypt(raw[16:]))

class PDFEncryptor(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("🔐 PDF Encryption & Decryption Tool")
        self.setGeometry(100, 100, 1200, 800)
        self.setStyleSheet("""
            QWidget {
                background-color: #f0f2f5;
                font-family: Segoe UI, sans-serif;
                font-size: 14px;
            }
            QPushButton {
                background-color: #007bff;
                color: white;
                padding: 8px 16px;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #0056b3;
            }
            QLineEdit {
                padding: 6px;
                border: 1px solid #ccc;
                border-radius: 4px;
                background-color: white;
            }
            QLabel {
                color: #333;
            }
        """)
        self.encrypted_content = None
        self.decrypted_content = None
        self.initUI()

    def initUI(self):
        layout = QVBoxLayout()

        key_label = QLabel("Masukkan Key:")
        key_label.setFont(QFont("Segoe UI", 10, QFont.Bold))
        self.key_input = QLineEdit()
        self.key_input.setEchoMode(QLineEdit.Password)

        layout.addWidget(key_label)
        layout.addWidget(self.key_input)

        button_layout = QHBoxLayout()
        for text, func in [("📂 Pilih File", self.select_file), ("🔒 Enkripsi PDF", self.encrypt_pdf), ("🔓 Dekripsi PDF", self.decrypt_pdf)]:
            b = QPushButton(text)
            b.setFixedHeight(35)
            b.clicked.connect(func)
            button_layout.addWidget(b)
        layout.addLayout(button_layout)

        previews = QHBoxLayout()
        self.original_preview = self.create_scroll_area("📄 Preview Asli")
        self.encrypted_preview = self.create_scroll_area("🧾 Hasil Enkripsi / Dekripsi")
        previews.addWidget(self.original_preview.wrapper)
        previews.addWidget(self.encrypted_preview.wrapper)
        layout.addLayout(previews)

        self.setLayout(layout)

    def create_scroll_area(self, title):
        wrapper = QWidget()
        wrapper_layout = QVBoxLayout(wrapper)

        label = QLabel(title)
        label.setFont(QFont("Segoe UI", 10, QFont.Bold))
        wrapper_layout.addWidget(label)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.StyledPanel)

        container = QWidget()
        layout = QVBoxLayout(container)
        container.setLayout(layout)

        scroll.setWidget(container)
        scroll.container = container
        scroll.content_layout = layout

        wrapper_layout.addWidget(scroll)

        class ScrollWrapper:
            def __init__(self, scroll, wrapper):
                self.scroll = scroll
                self.wrapper = wrapper
                self.container = container
                self.content_layout = layout

        return ScrollWrapper(scroll, wrapper)

    def clear_previews(self):
        for preview in [self.original_preview, self.encrypted_preview]:
            while preview.content_layout.count():
                w = preview.content_layout.takeAt(0).widget()
                if w:
                    w.deleteLater()

    def preview_file(self, path, to_right=False):
        layout = self.encrypted_preview.content_layout if to_right else self.original_preview.content_layout
        try:
            if path.endswith(".pdf"):
                with open(path, "rb") as f:
                    for img in convert_from_bytes(f.read()):
                        img = img.convert("RGB")
                        img = img.resize((600, int(img.height * 600 / img.width)))
                        qimg = QImage(img.tobytes(), img.width, img.height, QImage.Format_RGB888)
                        lbl = QLabel()
                        lbl.setPixmap(QPixmap.fromImage(qimg))
                        layout.addWidget(lbl)
            elif path.endswith(".enc"):
                layout.addWidget(QLabel("📛 Preview tidak tersedia untuk file terenkripsi."))
            else:
                layout.addWidget(QLabel("❓ Format file tidak dikenali."))
        except Exception as e:
            layout.addWidget(QLabel(f"⚠️ Gagal menampilkan preview: {e}"))

    def preview_encrypted_content(self, content):
        layout = self.encrypted_preview.content_layout
        layout.addWidget(QLabel("✅ File terenkripsi siap disimpan."))
        btn = QPushButton("💾 Simpan File Terenkripsi")
        btn.clicked.connect(lambda: self.save_output_file(content, ".enc", binary=False))
        layout.addWidget(btn)

    def preview_decrypted_content(self, content):
        layout = self.encrypted_preview.content_layout
        try:
            from io import BytesIO
            for img in convert_from_bytes(BytesIO(content).read()):
                img = img.convert("RGB")
                img = img.resize((600, int(img.height * 600 / img.width)))
                qimg = QImage(img.tobytes(), img.width, img.height, QImage.Format_RGB888)
                lbl = QLabel()
                lbl.setPixmap(QPixmap.fromImage(qimg))
                layout.addWidget(lbl)
            btn = QPushButton("💾 Simpan PDF Hasil Dekripsi")
            btn.clicked.connect(lambda: self.save_output_file(content, ".pdf", binary=True))
            layout.addWidget(btn)
        except Exception as e:
            layout.addWidget(QLabel(f"⚠️ Gagal preview hasil dekripsi: {e}"))

    def select_file(self):
        global selected_file_path
        path, _ = QFileDialog.getOpenFileName(self, "Pilih File", "", "PDF (*.pdf);;Encrypted File (*.enc)")
        if path:
            selected_file_path = path
            QMessageBox.information(self, "Dipilih", f"File dipilih:\n{path}")
            self.clear_previews()
            self.preview_file(path, to_right=False)

    def encrypt_pdf(self):
        if not selected_file_path or not self.key_input.text():
            return QMessageBox.critical(self, "Error", "File dan Key wajib diisi")
        try:
            with open(selected_file_path, "rb") as f:
                encrypted = caesar_cipher(encrypt_aes(f.read(), self.key_input.text()), 3)
            self.encrypted_content = encrypted
            self.clear_previews()
            self.preview_file(selected_file_path, to_right=False)
            self.preview_encrypted_content(encrypted)
            self.key_input.clear()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Gagal enkripsi: {e}")

    def decrypt_pdf(self):
        if not selected_file_path or not self.key_input.text():
            return QMessageBox.critical(self, "Error", "File dan Key wajib diisi")
        try:
            with open(selected_file_path, "r", encoding="utf-8") as f:
                decrypted_data = decrypt_aes(caesar_decipher(f.read(), 3), self.key_input.text())
            self.decrypted_content = decrypted_data
            self.clear_previews()
            self.preview_file(selected_file_path, to_right=False)
            self.preview_decrypted_content(decrypted_data)
            self.key_input.clear()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Gagal dekripsi: {e}")

    def save_output_file(self, content, ext, binary=False):
        dest, _ = QFileDialog.getSaveFileName(self, "Simpan File", "", f"*{ext}")
        if dest:
            try:
                mode = "wb" if binary else "w"
                with open(dest, mode, encoding=None if binary else "utf-8") as f:
                    f.write(content)
                QMessageBox.information(self, "Berhasil", f"Tersimpan di {dest}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Gagal simpan: {e}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = PDFEncryptor()
    window.show()
    sys.exit(app.exec_())
