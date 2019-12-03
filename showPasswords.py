import base64
import copy
import json
import os
import sys
import time
from ast import literal_eval
from json_utils import find_node_reference, find_exact_node
from errors_handling import *

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad
from PyQt5 import QtGui, QtWidgets, QtCore
from PyQt5 import uic
from PyQt5.QtCore import Qt, QObject, QModelIndex, QVariant
from PyQt5.QtWidgets import QMenu, QAction, QMessageBox

import manage_folder as mf

qt_creator_file = "guis/passwordList.ui"
Ui_MainWindow, QtBaseClass = uic.loadUiType(qt_creator_file)

with open('register.json', 'r') as file:
    data_register = json.load(file)
    salt = data_register['salt']
    email = data_register['email']
    password = data_register['master_password']

key = PBKDF2(email + password, salt.encode(), dkLen=16)  # 128-bit key
key = PBKDF2(b'verysecretaeskey', salt, 16, 100000)
cipher = AES.new(key, AES.MODE_ECB)
BLOCK_SIZE = 32

with open('passwords.txt', mode='rb') as passwords:
    data = unpad(cipher.decrypt(base64.b64decode(passwords.read())), BLOCK_SIZE)
    data = literal_eval(data.decode())


def write_data(new_data):
    with open("passwords.txt", "wb") as f:
        encrypted = cipher.encrypt(pad(str(new_data).encode(), BLOCK_SIZE))
        f.write(base64.b64encode(encrypted))


class FoldersPasswordsWindow(QtWidgets.QMainWindow, Ui_MainWindow):
    def __init__(self):
        """
        Show main window.
        Connect UI components with actions.
        Load passwords from a file.
        """
        QtWidgets.QMainWindow.__init__(self)
        Ui_MainWindow.__init__(self)
        self.setupUi(self)
        self.passwords_model = QtGui.QStandardItemModel()
        self.folders_model = QtGui.QStandardItemModel()
        self.connect_components()
        self.setup_tree_view()
        self.data = data

    def connect_components(self):
        """
        Connect password/folders components with proper actions that should be invoked.
        """
        self.connect_password_components()
        self.connect_folders_components()

    def connect_password_components(self):
        """
        Make connections between:
        createButton and on_create_password_button function, so as to add a new password
        deleteButton with on_delete_password_button function, so as to delete a password
        doubleClicked password with onEditClock function, so as to edit a password
        """
        self.passwordsView.setModel(self.passwords_model)
        self.createButton.pressed.connect(self.on_create_password_button)
        self.deleteButton.pressed.connect(self.on_delete_password_button)
        self.passwordsView.doubleClicked.connect(self.on_edit_password_button)

    def connect_folders_components(self):
        """
        Set the widget's header name.
        Display folders as a tree structure.
        Use right-click context menu to add/delete/edit a folder.
        """
        self.folders_model.setColumnCount(1)
        self.folders_model.setHeaderData(0, QtCore.Qt.Horizontal, 'Directories')
        self.foldersTreeView.setModel(self.folders_model)
        self.foldersTreeView.clicked.connect(self.display_passwords)
        self.foldersTreeView.setContextMenuPolicy(Qt.CustomContextMenu)
        self.foldersTreeView.customContextMenuRequested.connect(self.display_folders_menu)

    def display_folders_menu(self, position):
        """
        Right-click folders context menu enables user to:
        add_folder
        delete_folder
        edit_folder
        """
        menu = QMenu(self)
        menu.addAction("Add folder", self.add_folder)
        menu.addAction("Delete folder", self.delete_folder)
        menu.addAction("Edit folder", self.edit_folder)
        menu.exec_(self.foldersTreeView.viewport().mapToGlobal(position))

    def closeEvent(self, event):
        # write_data()
        pass

    def on_create_password_button(self):
        """Close showPasswordsWindow and run savePassword.py"""
        # write_data()
        window.close()
        path = ""
        for folder in self.current_path:
            path += '{}/'.format(folder)
        os.system('python savePassword.py ' + '"{}"'.format(path[:-1]))

    def on_edit_password_button(self, item):  # TODO
        """Close showPasswordsWindow and
        run savePassword.py with args:passwordName and encrypted password
        """
        tmp_data = data
        for folder in self.current_path:
            for row in tmp_data:
                if row['type'] == 'directory' and row['name'] == folder:
                    tmp_data = row['data']
        for el in tmp_data:
            if el['type'] == 'password' and el['name'] == item.data():
                password = el['data']
        # write_data()
        window.close()
        path = ""
        for folder in self.current_path:
            path += '{}/'.format(folder)
        os.system('python savePassword.py ' + '"{}"'.format(path[:-1]) + ' ' + '"{}"'.format(
            item.data()) + ' ' + '"{}"'.format(password))

    def on_delete_password_button(self):
        """Delete selected password from View and from file"""
        indexes = self.passwordsView.selectedIndexes()
        if indexes:
            # Indexes is a list of a single item in single-select mode.
            index = indexes[0]
            item = self.passwords_model.itemFromIndex(index).text()
            self.passwords_model.removeRow(index.row())
            self.passwords_model.layoutChanged.emit()
            # Clear the selection (as it is no longer valid).
            self.passwordsView.clearSelection()
            self.delete_from_data(item)

            with open('passwords.json', 'w') as f:  # TODO only for debugging purposes
                json.dump(data, f)

            with open("passwords.txt", "wb") as f:
                encrypted = cipher.encrypt(pad(str(data).encode(), BLOCK_SIZE))
                f.write(base64.b64encode(encrypted))

    def delete_from_data(self, name):
        """Delete selected password from file"""
        tmp_data = self.data
        for folder in self.current_path:
            for row in tmp_data:
                if row['type'] == 'directory' and row['name'] == folder:
                    tmp_data = row['data']
        for el in tmp_data:
            if el['type'] == 'password' and el['name'] == name:
                el["state"] = "DEL"

    def setup_tree_view(self):
        """
        Display folders in as a hierarchical (tree) view.
        """
        self.folders_model.removeRows(0, self.folders_model.rowCount())
        self.extract_folders_from_data(data, None)

    def extract_folders_from_data(self, data, parent):
        """
        Recursively search the data and extract folder names.
        """
        if isinstance(data, list) and data:
            curr_row = data[0]
            if 'type' in curr_row.keys() and curr_row['type'] == 'directory':
                if 'state' not in curr_row.keys() or curr_row['state'] != 'DEL':  # TODO display only not-DEL passwords
                    item = QtGui.QStandardItem(curr_row['name'])

                    if parent:
                        parent.appendRow(item)
                    else:
                        self.folders_model.appendRow(item)

                    if 'data' in curr_row.keys() and curr_row['data'] is not None:
                        self.extract_folders_from_data(curr_row['data'], item)

            self.extract_folders_from_data(data[1:], parent)

    def display_passwords(self, item):
        """
        Display all passwords from a selected folder
        """
        self.passwords_model.removeRows(0, self.passwords_model.rowCount())  # clear display passwords UI element
        self.current_path = self.get_absolute_path_of_folder(item)
        self.pass_extract_helper(data, self.current_path)

    def pass_extract_helper(self, decrypted_data, path_to_folder):
        if len(decrypted_data) > 0:
            curr_row = decrypted_data[0]
            if len(path_to_folder) == 0:  # we have found the folder
                if curr_row['type'] == 'password':
                    item = QtGui.QStandardItem(curr_row['name'])
                    self.passwords_model.appendRow(item)
                self.pass_extract_helper(decrypted_data[1:], path_to_folder)
            else:  # we assume that the folder structure for sure is in *.json file
                if curr_row['type'] == 'directory' and curr_row['name'] == path_to_folder[0]:
                    self.pass_extract_helper(curr_row['data'], path_to_folder[1:])
                else:
                    self.pass_extract_helper(decrypted_data[1:], path_to_folder)

    def get_absolute_path_of_folder(self, folder):
        """
        Returns the absolute path to a chosen folder
        """
        path = self.get_absolute_path_of_folder_helper(folder, [])
        return path

    def get_absolute_path_of_folder_helper(self, folder, path):
        """
        Recursively search the hierarchical structure of folders so as to
        find the the absolute path of the specified folder.
        """
        path.append(folder.data())
        if folder.parent().data() is not None:
            self.get_absolute_path_of_folder_helper(folder.parent(), path)
        return path[::-1]  # return reversed result

    def add_folder(self):
        # TODO folders of only UNIQUE names
        """
        Take the chosen folder and find an absolute path of it.
        Call an external script to provide a name to the new sub-folder and save it.
        Update the GUI.
        """
        item = self.foldersTreeView.selectedIndexes()
        self.current_path = self.get_absolute_path_of_folder(item[0])
        self.set_time_stamp()
        folder_window.show()

    def delete_folder(self):
        """
        Get the path absolute path of the selected folder.
        Delete all data from that folder.
        """
        item = self.foldersTreeView.selectedIndexes()
        path = self.get_absolute_path_of_folder(item[0])
        try:
            self.delete_folder_helper(self.data, path)
        except DeleteRootFolderError:
            show_message_box(self, "Root node cannot be deleted.")
        else:
            with open('passwords.json', 'w') as f:  # todo ONLY FOR DEBUGGING PURPOSES
                json.dump(self.data, f)

            # write_data(self.data)

            with open("passwords.txt", "wb") as f:
                encrypted = cipher.encrypt(pad(str(self.data).encode(), BLOCK_SIZE))
                f.write(base64.b64encode(encrypted))

            # delete from GUI
            self.folders_model.removeRow(item[0].row(), item[0].parent())
            self.folders_model.layoutChanged.emit()

    def delete_folder_helper(self, json_data, path):
        if len(path) == 1 and path[0] == 'root':  # cannot delete root node
            raise DeleteRootFolderError
        else:
            self.set_time_stamp()
            node_reference = find_node_reference(json_data, path[:-1], self.time_stamp)  # self.get_time_stamp()
            directory_reference = find_exact_node(node_reference, path[-1], "directory")
            node_reference[directory_reference]['state'] = 'DEL'
            # remove from displayed
            self.passwords_model.removeRows(0, self.passwords_model.rowCount())  # clear display passwords UI element

            item = self.foldersTreeView.selectedIndexes()
            self.current_path = self.get_absolute_path_of_folder(item[0])

    def edit_folder(self):
        item = self.foldersTreeView.selectedIndexes()
        self.current_path = self.get_absolute_path_of_folder(item[0])
        path = self.current_path
        try:
            if len(path) == 1 and path[0] == 'root':  # cannot delete root node
                raise DeleteRootFolderError
        except DeleteRootFolderError:
            show_message_box(self, "Root node cannot be edited.")
        else:
            self.set_time_stamp()
            path = self.get_absolute_path_of_folder(item[0])
            folder_window.folderNameLineEdit.setText(item[0].data())
            folder_window.edit_mode = True
            folder_window.show()

    def set_time_stamp(self):
        self.time_stamp = time.time()

    def get_password_names_within_level(self, json_data):
        """Get all password names within a level so as to use it to guarantee only unique names."""
        # todo omit deleted!!!!
        passwords_arr = []
        for el in json_data:
            if el['type'] == 'password' and 'state' not in el.keys():
                passwords_arr.append(el['name'])
        return passwords_arr

if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    window = FoldersPasswordsWindow()
    folder_window = mf.FolderWindow(window)
    window.show()
    app.exec_()
