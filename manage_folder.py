import ast
import base64
import json
import os
import sys
from ast import literal_eval

# from Crypto.Cipher import AES
# from Crypto.Protocol.KDF import PBKDF2
# from Crypto.Util.Padding import unpad, pad
from PyQt5 import QtGui, QtWidgets, uic
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QMessageBox


qt_creator_file = "guis/folder.ui"
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
#     print(data)

with open("passwords.json", "r") as read_file:
    data = json.load(read_file)


class FolderWindow(QtWidgets.QMainWindow, Ui_MainWindow):
    def __init__(self, folders_passwords_model):
        """Show main window. Connect cancelButton with onCancelButton function
        and registerButton with onRegisterButton function"""
        QtWidgets.QMainWindow.__init__(self)
        Ui_MainWindow.__init__(self)
        self.setupUi(self)
        self.folders_passwords_model = folders_passwords_model
        self.connect_components()

    def connect_components(self):
        self.cancelPushButton.pressed.connect(self.on_cancel_push_button)
        self.okPushButton.pressed.connect(self.on_ok_push_button)

    def on_cancel_push_button(self):
        """Close folder window and run showPasswords.py"""
        window.close()

    def on_ok_push_button(self):  # todo dodawac tak zeby z parentem
        folder_name = self.folderNameLineEdit.text()  # get folder name
        print(">> " + str(self.folders_passwords_model))
        print(">> type " + str(type(self.folders_passwords_model.current_path)))

        new_data = self.add_folder_helper(data, self.folders_passwords_model.current_path, folder_name)
        with open('passwords.json', 'w') as f:
            json.dump(new_data, f)

        # test_items = [QtGui.QStandardItem("HALO")]
        # FoldersPasswordsWindow.window.folders_model.appendRow(test_items)
        # FoldersPasswordsWindow.window.folders_model.layoutChanged.emit()

    def add_folder_helper(self, json_data, array, folder_name):  # WHAT IF THE DATA BECOMES DECRYPTED?
        if len(json_data) > 0:
            curr_row = json_data[0]
            if len(array) == 0:  # we've found the specific folder
                json_data.append({"type": "catalog", "name": folder_name, "data": []})
            else:  # we assume that the folder structure for sure is in *.json file
                if curr_row['type'] == 'catalog' and curr_row['name'] == array[0]:
                    self.add_folder_helper(curr_row['data'], array[1:], folder_name)
                else:
                    self.add_folder_helper(json_data[1:], array, folder_name)
        else:
            json_data.append(
                {"type": "catalog", "name": folder_name, "data": []})  # TODO think about a better recursive solution
        return json_data


if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)
    if len(sys.argv) == 2:
        window = FolderWindow(ast.literal_eval(sys.argv[1]))  # parameter has to be passed as a string
    else:
        window = FolderWindow([])
    window.show()
    app.exec_()
