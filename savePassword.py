import base64
import ctypes
import json
import sys
import time
from ast import literal_eval

import keyring
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import unpad, pad
from PyQt5 import QtWidgets, uic
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QMessageBox

from generatePassword import GeneratorWindow

qt_creator_file = "guis/savePassword.ui"
Ui_MainWindow, QtBaseClass = uic.loadUiType(qt_creator_file)
# directory = keyring.get_password("system", "directory")
# key = PBKDF2(keyring.get_password("system", "email") + keyring.get_password("system", "master_password"),
#              keyring.get_password("system", "salt").encode(), 16, 100000)  # 128-bit key

def get_dir():
    directory = keyring.get_password("system", "directory")
    key = PBKDF2(keyring.get_password("system", "email") + keyring.get_password("system", "master_password"),
         keyring.get_password("system", "salt").encode(), 16, 100000)  # 128-bit key
    return directory

def get_key():
    key = PBKDF2(keyring.get_password("system", "email") + keyring.get_password("system", "master_password"),
         keyring.get_password("system", "salt").encode(), 16, 100000)  # 128-bit key
    return key

def clean_memory(var_to_clean):
    strlen = len(var_to_clean)
    offset = sys.getsizeof(var_to_clean) - strlen - 1
    ctypes.memset(id(var_to_clean) + offset, 0, strlen)
    del var_to_clean

def get_data():
    """decrypt data"""
    with open(get_dir() + '/passwords.txt', 'rb') as passwords:
        raw = base64.b64decode(passwords.read())
        cipher = AES.new(get_key(), AES.MODE_CBC, raw[:AES.block_size])
        return literal_eval(unpad(cipher.decrypt(raw[AES.block_size:]), AES.block_size).decode('utf-8'))


def write_data(new_data):
    """write encrypted data"""
    with open(get_dir() + '/passwords.txt', "wb") as f:
        iv = get_random_bytes(AES.block_size)
        cipher = AES.new(get_key(), AES.MODE_CBC, iv)
        f.write(base64.b64encode(iv + cipher.encrypt(pad(str(new_data).encode('utf-8'),
                                                         AES.block_size))))


class PasswordWindow(QtWidgets.QMainWindow, Ui_MainWindow):
    def __init__(self, folders_passwords_model):
        """Show main window. If passwordName and password are given,
        show passwordName and decrypted password.
        Connect saveButton with on_save_button function,
        checkBox with change_check_box function"""
        QtWidgets.QMainWindow.__init__(self)
        Ui_MainWindow.__init__(self)
        self.folders_passwords_model = folders_passwords_model
        self.password_generator = GeneratorWindow(self)
        self.setupUi(self)
        self.passwordNameToEdit = None
        self.passwordToEdit = None
        self.password.setEchoMode(QtWidgets.QLineEdit.Password)
        self.saveButton.pressed.connect(self.on_save_button)
        self.generateButton.pressed.connect(self.on_generate_button)
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
        if not passwordName or not password:  # Don't add empty strings.
            QMessageBox.about(self, "No data", "Write password name and password, please")
        else:
            if self.passwordNameToEdit:
                self.edit_in_file(self.passwordNameToEdit, passwordName, password)
            else:
                tmp_data = self.folders_passwords_model.data[1]
                timestamp = time.time() #self.folders_passwords_model.time_stamp
                for folder in self.current_path:
                    for row in tmp_data:
                        if row['type'] == 'directory' and row['name'] == folder and 'state' not in row.keys():
                            tmp_data = row['data']
                            row["timestamp"] = timestamp
                tmp_data.append({'type': 'password', 'name': passwordName, 'data': password, 'timestamp': timestamp}) #self.folders_passwords_model.time_stamp
                clean_memory(tmp_data)
            self.folders_passwords_model.display_passwords(self.current_index)
            write_data(self.folders_passwords_model.data)

            with open("passwords.json", "w") as f:  # TODO only for debugging purposes
                json.dump(self.folders_passwords_model.data, f)

            self.on_cancel()

    def edit_in_file(self, old_name, new_name, new_password):
        """Delete selected password from file"""
        tmp_data = self.folders_passwords_model.data[1]
        timestamp = self.folders_passwords_model.time_stamp
        for folder in self.current_path:
            for row in tmp_data:
                if row['type'] == 'directory' and row['name'] == folder and "state" not in row.keys():
                    row["timestamp"] = timestamp
                    tmp_data = row['data']
        for el in tmp_data:
            if el['type'] == 'password' and el['name'] == old_name and "state" not in el.keys():
                el['name'] = new_name
                el['data'] = new_password
                el['timestamp'] = timestamp #self.folders_passwords_model.time_stamp
        clean_memory(tmp_data)

    def on_generate_button(self):
        """Show generate passwords window"""
        self.password_generator.show()

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

    def on_cancel(self):
        """Clear fields and close window"""
        self.password.setEchoMode(QtWidgets.QLineEdit.Password)
        self.checkBox.setChecked(False)
        self.clear_fields()
        self.close()

    def closeEvent(self, event):
        self.on_cancel()


if __name__ == "__main__":
    pass
