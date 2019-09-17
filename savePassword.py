import base64
import json
import os
import sys
from ast import literal_eval

# from Crypto.Cipher import AES
# from Crypto.Protocol.KDF import PBKDF2
# from Crypto.Util.Padding import unpad, pad
from PyQt5 import QtWidgets, uic
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QMessageBox

qt_creator_file = "guis/savePassword.ui"
Ui_MainWindow, QtBaseClass = uic.loadUiType(qt_creator_file)

# with open('register.json', 'r') as file:
#     data_register = json.load(file)
#     salt = data_register['salt']
#     email = data_register['email']
#     password = data_register['master_password']
# key = PBKDF2(email + password, salt.encode(), dkLen=16)  # 128-bit key
# key = PBKDF2(b'verysecretaeskey', salt.encode(), 16, 100000)
# cipher = AES.new(key, AES.MODE_ECB)
# BLOCK_SIZE = 32

# with open('passwords.txt', mode='rb') as passwords:
#     data = unpad(cipher.decrypt(base64.b64decode(passwords.read())), BLOCK_SIZE)
#     data = literal_eval(data.decode())

with open('passwords.json', 'r') as read_file:  # TODO which data is being used?
    data = json.load(read_file)


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

    # def write_to_file(self):
    #     with open("passwords.txt", "wb+") as f:
    #         encrypted = cipher.encrypt(pad(str(data).encode(), BLOCK_SIZE))
    #         f.write(base64.b64encode(encrypted))

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
        os.system('python3 showPasswords.py ')


if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    if len(sys.argv) == 4:
        window = MainWindow(sys.argv[1], sys.argv[2], sys.argv[3])
    else:
        window = MainWindow(sys.argv[1])
    window.show()
    app.exec_()
