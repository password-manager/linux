import ast
import base64
import json
import os
import sys
from ast import literal_eval

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import unpad, pad
from PyQt5 import QtGui, QtWidgets, uic
from PyQt5.QtCore import Qt, QVariant
from PyQt5.QtGui import QStandardItem
from PyQt5.QtWidgets import QMessageBox
from json_utils import find_node_reference, find_exact_node
from errors_handling import *

qt_creator_file = "guis/folder.ui"
Ui_MainWindow, QtBaseClass = uic.loadUiType(qt_creator_file)

with open('register.json', 'r') as file:
    data_register = json.load(file)
    salt = data_register['salt']
    email = data_register['email']
    password = data_register['master_password']
key = PBKDF2(email + password, salt.encode(), dkLen=16)  # 128-bit key
key = PBKDF2(b'verysecretaeskey', salt.encode(), 16, 100000)
cipher = AES.new(key, AES.MODE_ECB)
BLOCK_SIZE = 32


class FolderWindow(QtWidgets.QMainWindow, Ui_MainWindow):
    def __init__(self, folders_passwords_model):
        """Show main window. Connect cancelButton with onCancelButton function
        and registerButton with onRegisterButton function"""
        QtWidgets.QMainWindow.__init__(self)
        Ui_MainWindow.__init__(self)
        self.setupUi(self)
        self.folders_passwords_model = folders_passwords_model
        self.connect_components()
        self.edit_mode = False

    def connect_components(self):
        self.cancelPushButton.pressed.connect(self.on_cancel_push_button)
        self.okPushButton.pressed.connect(self.on_ok_push_button)

    def on_cancel_push_button(self):
        """Close folder window and run showPasswords.py"""
        self.edit_mode = False
        self.folderNameLineEdit.setText("")
        self.close()

    def on_ok_push_button(self):
        folder_name = self.folderNameLineEdit.text()
        # folder_name1 = self.folderNameLineEdit.setText
        json_data_ref = self.folders_passwords_model.data

        try:
            timestamp = self.folders_passwords_model.time_stamp
            if self.edit_mode:
                self.add_folder_helper(json_data_ref, folder_name, self.folders_passwords_model.current_path[:-1], timestamp, self.folders_passwords_model.current_path[-1])
                parent = self.folders_passwords_model.foldersTreeView.selectedIndexes()[0]
                parent_ref = self.folders_passwords_model.folders_model.itemFromIndex(parent)
                parent_ref.setText(folder_name)
                parent_ref.emitDataChanged()
                self.folders_passwords_model.folders_model.layoutChanged.emit()

                self.edit_mode = False
            else:
                self.add_folder_helper(json_data_ref, folder_name, self.folders_passwords_model.current_path, timestamp)
                parent = self.folders_passwords_model.foldersTreeView.selectedIndexes()[0]
                row = self.folders_passwords_model.folders_model.rowCount(parent)

                new_item = QStandardItem(folder_name)
                parent_ref = self.folders_passwords_model.folders_model.itemFromIndex(parent)
                parent_ref.insertRow(row, new_item)

                # Trigger refresh.
                self.folders_passwords_model.folders_model.layoutChanged.emit()
        except FolderNameAlreadyExistsError:
            self.edit_mode = False
            reason = "Folder name already exists."
            show_message_box(self, reason)
        except WrongCharactersInInputError:
            self.edit_mode = False
            reason = "Folder name cannot contain special signs."
            show_message_box(self, reason)
        else:
            with open('passwords.json', 'w') as f:  # todo only for debugging purpose
                json.dump(json_data_ref, f)

            with open("passwords.txt", "wb") as f:
                encrypted = cipher.encrypt(pad(str(json_data_ref).encode(), BLOCK_SIZE))
                f.write(base64.b64encode(encrypted))

        self.folderNameLineEdit.setText("")
        self.close()

    def add_folder(self, node_reference, folder_name, timestamp):
        node_reference.append({"type": "directory", "name": folder_name, "data": [], "timestamp": timestamp})

    def add_folder_helper(self, json_data, folder_name, path, timestamp, old_folder_name = None):
        """
        Folder name has to be unique.
        Folder name cannot contain '/'.
        """
        node_reference = find_node_reference(json_data, path, timestamp)
        curr_folders = self.get_folder_names_within_level(node_reference)  # todo ['data']
        if folder_name in curr_folders:
            raise FolderNameAlreadyExistsError
        if '/' in folder_name:
            raise WrongCharactersInInputError
        else:
            if self.edit_mode:
                # directory_reference = find_directory_node(node_reference, old_folder_name)
                directory_reference = find_exact_node(node_reference, old_folder_name, "directory")
                node_reference[directory_reference]['name'] = folder_name
                node_reference[directory_reference]['timestamp'] = timestamp
            else:
                self.add_folder(node_reference, folder_name, timestamp)

    def get_folder_names_within_level(self, json_data):
        """Get all folder names within a level so as to use it to guarantee only unique names."""
        # todo omit deleted!!!!
        folders_arr = []
        for el in json_data:
            if el['type'] == 'directory' and 'state' not in el.keys():
                folders_arr.append(el['name'])
        return folders_arr

    # def show_message_box(self, reason):
    #     """Show MessageBox with an error and reason"""
    #     QMessageBox.about(self, "An error occured!", reason)


class Error(Exception):
    """Base class for other exceptions"""
    pass


class FolderNameAlreadyExistsError(Error):
    """Raised when the input value already exists in the path"""
    pass


class WrongCharactersInInputError(Error):
    """Raised when the input value contains unallowed characters such as slash"""
    pass


if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)
    if len(sys.argv) == 2:
        window = FolderWindow(ast.literal_eval(sys.argv[1]))  # parameter has to be passed as a string
    else:
        window = FolderWindow([])
    window.show()
    app.exec_()
