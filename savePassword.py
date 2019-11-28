import base64
import sys
from ast import literal_eval

import keyring
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import unpad, pad
from PyQt5 import QtWidgets, uic
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QMessageBox

qt_creator_file = "guis/savePassword.ui"
Ui_MainWindow, QtBaseClass = uic.loadUiType(qt_creator_file)
directory = keyring.get_password("system", "directory")
key = PBKDF2(keyring.get_password("system", "email") + keyring.get_password("system", "master_password"),
             keyring.get_password("system", "salt").encode(), 16, 100000)  # 128-bit key


def get_data():
    with open(directory + '/passwords.txt', 'rb') as passwords:
        raw = base64.b64decode(passwords.read())
        cipher = AES.new(key, AES.MODE_CBC, raw[:AES.block_size])
        return literal_eval(unpad(cipher.decrypt(raw[AES.block_size:]), AES.block_size).decode('utf-8'))


def write_data(new_data):
    with open(directory + '/passwords.txt', "wb") as f:
        iv = get_random_bytes(AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        f.write(base64.b64encode(iv + cipher.encrypt(pad(str(new_data).encode('utf-8'),
                                                         AES.block_size))))


class PasswordWindow(QtWidgets.QMainWindow, Ui_MainWindow):
    def __init__(self, folders_passwords_model):
        """Show main window. If passwordName and password are given,
        show passwordName and decrypted password.
        Connect saveButton with on_save_button function
        and cancelButton with on_cancel_button function,
        checkBox with change_check_box function"""
        QtWidgets.QMainWindow.__init__(self)
        Ui_MainWindow.__init__(self)
        self.folders_passwords_model = folders_passwords_model
        self.setupUi(self)
        self.passwordNameToEdit = None
        self.passwordToEdit = None
        self.data = []
        self.password.setEchoMode(QtWidgets.QLineEdit.Password)
        self.saveButton.pressed.connect(self.on_save_button)
        self.cancelButton.pressed.connect(self.on_cancel_button)
        self.checkBox.stateChanged.connect(self.change_check_box)

    def set_path(self, current_path, current_index):
        self.current_path = current_path.split('/')
        self.current_index = current_index

    def set_password_to_edit(self, passwordNameToEdit, passwordToEdit):
        self.passwordNameToEdit = passwordNameToEdit
        self.passwordToEdit = passwordToEdit
        self.passwordName.setText(passwordNameToEdit)
        self.password.setText(passwordToEdit)

    def on_save_button(self):
        """Get input from passwordName and password,
        then save encrypted password with its name to default file. Clear data"""
        passwordName = self.passwordName.text()
        password = self.password.text()
        self.data = get_data()
        if not passwordName or not password:  # Don't add empty strings.
            QMessageBox.about(self, "No data", "Write password name and password, please")
        else:
            if self.passwordNameToEdit:
                self.edit_in_file(self.passwordNameToEdit, passwordName, password)
            else:
                tmp_data = self.data
                for folder in self.current_path:
                    for row in tmp_data:
                        if row['type'] == 'catalog' and row['name'] == folder:
                            tmp_data = row['data']
                tmp_data.append({'name': passwordName, 'data': password, 'type': 'password'})
            self.folders_passwords_model.data = self.data
            self.folders_passwords_model.display_passwords(self.current_index)
            write_data(self.data)
            self.on_cancel_button()

    def edit_in_file(self, oldName, newName, newPassword):
        """Delete selected password from file"""
        tmp_data = self.data
        for folder in self.current_path:
            for row in tmp_data:
                if row['type'] == 'catalog' and row['name'] == folder:
                    tmp_data = row['data']
        for el in tmp_data:
            if el['type'] == 'password' and el['name'] == oldName:
                el['name'] = newName
                el['data'] = newPassword

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
        self.password.setEchoMode(QtWidgets.QLineEdit.Password)
        self.checkBox.setChecked(False)
        self.clear_fields()
        self.close()

    def closeEvent(self, event):
        self.on_cancel_button()


if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    if len(sys.argv) == 4:
        window = PasswordWindow(sys.argv[1], sys.argv[2], sys.argv[3])
    else:
        window = PasswordWindow(sys.argv[1])
    window.show()
    app.exec_()
