import ast
import base64
import json
import os
import sys
from ast import literal_eval
import keyring

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import unpad, pad
from PyQt5 import QtGui, QtWidgets, uic
from PyQt5.QtCore import Qt, QVariant
from PyQt5.QtGui import QStandardItem
from PyQt5.QtWidgets import QMessageBox

qt_creator_file = "guis/folder.ui"
Ui_MainWindow, QtBaseClass = uic.loadUiType(qt_creator_file)

# with open('register.json', 'r') as file:
#     data_register = json.load(file)
#     salt = data_register['salt']
#     email = data_register['email']
#     password = data_register['master_password']

salt = keyring.get_password("system", "salt")
email = keyring.get_password("system", "email")
password = keyring.get_password("system", "master_password")
directory = keyring.get_password("system", "directory")

key = PBKDF2(email + password, salt.encode(), 16, 100000)  # 128-bit key

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
        self.close()

    def on_ok_push_button(self):  # todo dodawac tak zeby z parentem
        folder_name = self.folderNameLineEdit.text()  # get folder name

        new_data = self.add_folder_helper(self.folders_passwords_model.data, self.folders_passwords_model.current_path,
                                          folder_name)

        # with open('passwords.json', 'w') as f:  # todo only for debugging purpose
        #     json.dump(new_data, f)


        with open(directory + '/passwords.txt', "wb") as f:
            iv = get_random_bytes(AES.block_size)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            f.write(base64.b64encode(iv + cipher.encrypt(pad(str(new_data).encode('utf-8'),
                                                             AES.block_size))))
        # with open(directory+"/passwords.txt", "wb") as f:
        #     encrypted = cipher.encrypt(pad(str(new_data).encode(), BLOCK_SIZE))
        #     f.write(base64.b64encode(encrypted))

        self.folders_passwords_model.data = new_data

        parent = self.folders_passwords_model.foldersTreeView.selectedIndexes()[0]  # -> List[QModelIndex]
        row = self.folders_passwords_model.folders_model.rowCount(parent)  # -> int

        new_item = QStandardItem(folder_name)
        parent_ref = self.folders_passwords_model.folders_model.itemFromIndex(parent)
        parent_ref.insertRow(row, new_item)

        # Trigger refresh.
        self.folders_passwords_model.folders_model.layoutChanged.emit()
        # self.folders_passwords_model.folders_model.dataChanged.emit()
        self.folderNameLineEdit.setText("")

        self.close()

    def add_folder_helper(self, json_data, array, folder_name):  # WHAT IF THE DATA BECOMES DECRYPTED?
        if len(json_data) > 0:
            curr_row = json_data[0]

            if len(array) == 1: #error checking -> todo extract it to a new method
                curr_folders = self.get_folder_names_within_level(curr_row['data'])
                if folder_name in curr_folders:
                    print("FOLDER OF THIS NAME ALREADY EXISTS")
                    return json_data

            if len(array) == 0:  # we've found the specified folder
                json_data.append({"type": "catalog", "name": folder_name, "data": [], "state": "ADD"})
            else:  # we assume that the folder structure for sure is in *.json file
                if curr_row['type'] == 'catalog' and curr_row['name'] == array[0]:
                    self.add_folder_helper(curr_row['data'], array[1:], folder_name)
                else:
                    self.add_folder_helper(json_data[1:], array, folder_name)
        else:
            json_data.append(
                {"type": "catalog", "name": folder_name, "data": [],
                 "state": "ADD"})  # TODO think about a better recursive solution
        return json_data

    def get_folder_names_within_level(self, json_data):  # we give the specific json data[] arr, no need to recurr
        folders_arr = []
        for el in json_data:
            if el['type'] == 'catalog':
                folders_arr.append(el['name'])
        return folders_arr


if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)
    if len(sys.argv) == 2:
        window = FolderWindow(ast.literal_eval(sys.argv[1]))  # parameter has to be passed as a string
    else:
        window = FolderWindow([])
    window.show()
    app.exec_()
