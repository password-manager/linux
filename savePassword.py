import base64
import json
import os
import sys
from ast import literal_eval

from PyQt5 import QtWidgets, uic
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QMessageBox
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

qt_creator_file = "guis/savePassword.ui"
Ui_MainWindow, QtBaseClass = uic.loadUiType(qt_creator_file)

with open('register.json', 'r') as file:
    data = json.load(file)
    salt = data['salt'].encode()
    password = data['master_password'].encode()

kdf = PBKDF2HMAC(
    algorithm=hashes.SHA512(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=default_backend()
)
key = base64.urlsafe_b64encode(kdf.derive(password))  # Can only use kdf once
fernet = Fernet(key)


def edit_in_file(oldName, newName, newPassword):
    """Delete selected password from file"""
    with open('passwords.txt', mode='r') as passwords:
        data = fernet.decrypt(str(passwords.read()).encode())
        data = literal_eval(data.decode())
        for row in data:
            if row['password_name'] == oldName:
                row['password_name'] = newName
                row['password'] = newPassword
    with open("passwords.txt", "w+") as f:
        encrypted = fernet.encrypt(str(data).encode())
        f.write(encrypted.decode())


class MainWindow(QtWidgets.QMainWindow, Ui_MainWindow):
    def __init__(self, passwordNameToEdit=None, passwordToEdit=None):
        """Show main window. If passwordName and password are given,
        show passwordName and decrypted password.
        Connect saveButton with on_save_button function
        and cancelButton with on_cancel_button function,
        checkBox with change_check_box function"""
        QtWidgets.QMainWindow.__init__(self)
        Ui_MainWindow.__init__(self)
        self.setupUi(self)
        self.passwordNameToEdit = passwordNameToEdit
        self.passwordToEdit = passwordToEdit
        self.passwordName.setText(passwordNameToEdit)
        self.password.setEchoMode(QtWidgets.QLineEdit.Password)
        self.password.setText(passwordToEdit)
        self.saveButton.pressed.connect(self.on_save_button)
        self.cancelButton.pressed.connect(self.on_cancel_button)
        self.checkBox.stateChanged.connect(self.change_check_box)

    def on_save_button(self):
        """Get input from passwordName and password,
        then save encrypted password with its name to default file. Clear data"""
        passwordName = self.passwordName.text()
        password = self.password.text()
        if not passwordName or not password:  # Don't add empty strings.
            QMessageBox.about(self, "No data", "Write password name and password, please")
        else:
            if self.passwordNameToEdit:
                edit_in_file(self.passwordNameToEdit, passwordName, password)
            else:
                if os.path.exists('passwords.txt'):
                    with open('passwords.txt', 'r') as passwords:
                        data = fernet.decrypt(str(passwords.read()).encode())
                        data = literal_eval(data.decode())
                else:
                    data = []
                data.append({'password_name': passwordName, 'password': password})
                encrypted = fernet.encrypt(str(data).encode())
                with open('passwords.txt', 'w+') as file:
                    file.write(encrypted.decode())
            self.on_cancel_button()

    def change_check_box(self, state):
        """If checkBox is checked - show password,
        if unchecked - hide it"""
        if state == Qt.Checked:
            self.password.setEchoMode(QtWidgets.QLineEdit.Normal)
        else:
            self.password.setEchoMode(QtWidgets.QLineEdit.Password)

    def clear_fields(self):
        """Empty inputs 'passwordName' and 'password'"""
        self.passwordName.setText("")
        self.password.setText("")

    def on_cancel_button(self):
        """Close savePasswordWindow and run showPasswords.py"""
        window.close()
        os.system('python showPasswords.py ')


if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    if len(sys.argv) == 3:
        window = MainWindow(sys.argv[1], sys.argv[2])
    else:
        window = MainWindow()
    window.show()
    app.exec_()
