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
    data_register = json.load(file)
    salt = data_register['salt'].encode()
    password = data_register['master_password'].encode()

kdf = PBKDF2HMAC(
    algorithm=hashes.SHA512(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=default_backend()
)
key = base64.urlsafe_b64encode(kdf.derive(password))  # Can only use kdf once
fernet = Fernet(key)

with open('passwords.txt', mode='r') as passwords:
    data = fernet.decrypt(str(passwords.read()).encode())
    data = literal_eval(data.decode())


class MainWindow(QtWidgets.QMainWindow, Ui_MainWindow):
    def __init__(self, current_path, passwordNameToEdit=None, passwordToEdit=None):
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
        self.current_path = current_path.split('/')
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
                self.edit_in_file(self.passwordNameToEdit, passwordName, password)
            else:
                tmp_data = data
                for folder in self.current_path:
                    for row in tmp_data:
                        if row['type'] == 'catalog' and row['name'] == folder:
                            tmp_data = row['data']
                tmp_data.append({'name': passwordName, 'data': password, 'type': 'password'})
            self.write_to_file()
            self.on_cancel_button()

    def edit_in_file(self, oldName, newName, newPassword):
        """Delete selected password from file"""
        tmp_data = data
        for folder in self.current_path:
            for row in tmp_data:
                if row['type'] == 'catalog' and row['name'] == folder:
                    tmp_data = row['data']
        for el in tmp_data:
            if el['type'] == 'password' and el['name'] == oldName:
                el['name'] = newName
                el['data'] = newPassword

    def write_to_file(self):
        with open("passwords.txt", "w+") as f:
            encrypted = fernet.encrypt(str(data).encode())
            f.write(encrypted.decode())

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
    if len(sys.argv) == 4:
        window = MainWindow(sys.argv[1], sys.argv[2], sys.argv[3])
    else:
        window = MainWindow(sys.argv[1])
    window.show()
    app.exec_()
