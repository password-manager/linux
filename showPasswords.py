import base64
import ctypes
import copy
import json
import os
import sys
from ast import literal_eval

# from crypto import cipher
from json_utils import find_node_reference, find_exact_node
from errors_handling import *

import keyring
import time
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from PyQt5 import QtGui, QtWidgets, QtCore
from PyQt5 import uic
from PyQt5.QtCore import Qt, QObject, QModelIndex, QVariant
from PyQt5.QtWidgets import QMenu, QAction, QMessageBox
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QMenu

import manage_folder as mf
from savePassword import PasswordWindow
from synchronize import get_logs_from_server, send_logs_to_server

qt_creator_file = "guis/passwordList.ui"
Ui_MainWindow, QtBaseClass = uic.loadUiType(qt_creator_file)

def get_dir():
    directory = keyring.get_password("system", "directory")
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


def write_data(new_data):
    with open(get_dir() + "/passwords.txt", "wb") as f:
        iv = get_random_bytes(AES.block_size)
        cipher = AES.new(get_key(), AES.MODE_CBC, iv)
        f.write(base64.b64encode(iv + cipher.encrypt(pad(str(new_data).encode("utf-8"),
                                                         AES.block_size))))


def get_data():
    if os.path.exists(get_dir() + "/passwords.txt"):
        with open(get_dir() + "/passwords.txt", mode="rb") as passwords:
            raw = base64.b64decode(passwords.read())
            cipher = AES.new(get_key(), AES.MODE_CBC, raw[:AES.block_size])
            return literal_eval(unpad(cipher.decrypt(raw[AES.block_size:]), AES.block_size).decode("utf-8"))
    else:
        timestamp = time.time()
        data = [[{"type": "directory", "name": "root", "data": [], "timestamp": timestamp}],
                [{"type": "directory", "name": "root", "data": [], "timestamp": timestamp}],
                0]
        write_data(data)
        return data


class FoldersPasswordsWindow(QtWidgets.QMainWindow, Ui_MainWindow):
    def __init__(self, loginWindow):
        """
        Show main window.
        Connect UI components with actions.
        Load passwords from a file.
        """
        # synchronize before the program starts
        self.loginWindow = loginWindow
        get_logs_from_server(self.loginWindow.s)
        send_logs_to_server(self.loginWindow.s)


        QtWidgets.QMainWindow.__init__(self)
        Ui_MainWindow.__init__(self)
        self.setupUi(self)
        self.data = get_data()
        self.passwords_model = QtGui.QStandardItemModel()
        self.folders_model = QtGui.QStandardItemModel()
        self.connect_components()
        self.setup_tree_view()
        self.folder_window = mf.FolderWindow(self)
        self.password_window = PasswordWindow(self)

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
        self.syncButton.pressed.connect(self.on_sync_button)

    def connect_folders_components(self):
        """
        Set the widget's header name.
        Display folders as a tree structure.
        Use right-click context menu to add/delete/edit a folder.
        """
        self.folders_model.setColumnCount(1)
        self.folders_model.setHeaderData(0, QtCore.Qt.Horizontal, "Directories")
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
        """Delete sensitive data from keyrings before exit, clean encrypted passwords from memory"""
        keyring.delete_password("system", "email")
        keyring.delete_password("system", "master_password")
        keyring.delete_password("system", "salt")
        keyring.delete_password("system", "directory")
        clean_memory(self.data)

    def on_create_password_button(self):
        """Close showPasswordsWindow and run savePassword.py"""
        self.data = get_data()
        self.set_time_stamp()
        path = ""
        for folder in self.current_path:
            path += "{}/".format(folder)
        indexes = self.foldersTreeView.selectedIndexes()
        if indexes:
            self.password_window.set_path(path[:-1], indexes[0])
            self.password_window.show()

    def on_edit_password_button(self, item):
        """Close showPasswordsWindow and
        run savePassword.py with args:passwordName and encrypted password
        """
        self.data = get_data()
        self.set_time_stamp()
        timestamp = self.time_stamp
        tmp_data = self.data[1]
        for folder in self.current_path:
            for row in tmp_data:
                if row["type"] == "directory" and row["name"] == folder and 'state' not in row.keys():
                    row["timestamp"] = timestamp
                    tmp_data = row["data"]
        for el in tmp_data:
            if el["type"] == "password" and el["name"] == item.data() and 'state' not in row.keys():
                password = el["data"]
                el["timestamp"] = timestamp
        path = ""
        for folder in self.current_path:
            path += "{}/".format(folder)
        indexes = self.foldersTreeView.selectedIndexes()
        if indexes:
            self.password_window.set_path(path[:-1], indexes[0])
            self.password_window.set_password_to_edit(item.data(), format(password))
            self.password_window.show()

    def on_delete_password_button(self):
        """Delete selected password from View and from file"""
        self.data = get_data()
        get_logs_from_server(self.loginWindow.s)
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

            write_data(self.data)

            send_logs_to_server(self.loginWindow.s)

    def delete_from_data(self, name):
        """Delete selected password from file"""
        self.set_time_stamp()
        timestamp = self.time_stamp
        tmp_data = self.data[1]
        for folder in self.current_path:
            for row in tmp_data:
                if row["type"] == "directory" and row["name"] == folder and 'state' not in row.keys():
                    row["timestamp"] = timestamp
                    tmp_data = row["data"]
        for el in tmp_data:
            if el["type"] == "password" and el["name"] == name and 'state' not in row.keys():
                el["state"] = "DEL_LOCAL"
                el["timestamp"] = timestamp

    def setup_tree_view(self):
        """
        Display folders in as a hierarchical (tree) view.
        """
        self.folders_model.removeRows(0, self.folders_model.rowCount())
        self.extract_folders_from_data(self.data[1], None)

    def extract_folders_from_data(self, data, parent):
        """
        Recursively search the data and extract folder names.
        """
        if isinstance(data, list) and data:
            curr_row = data[0]
            if "type" in curr_row.keys() and curr_row["type"] == "directory":
                if "state" not in curr_row.keys() or curr_row["state"] != "DEL_LOCAL":
                    item = QtGui.QStandardItem(curr_row["name"])

                    if parent:
                        parent.appendRow(item)
                    else:
                        self.folders_model.appendRow(item)

                    if "data" in curr_row.keys() and curr_row["data"] is not None:
                        self.extract_folders_from_data(curr_row["data"], item)

            self.extract_folders_from_data(data[1:], parent)

    def display_passwords(self, item):
        """
        Display all passwords from a selected folder
        """
        self.passwords_model.removeRows(0, self.passwords_model.rowCount())
        self.current_path = self.get_absolute_path_of_folder(item)
        self.pass_extract_helper(self.data[1], self.current_path)

    def pass_extract_helper(self, decrypted_data, path_to_folder):
        if len(decrypted_data) > 0:
            curr_row = decrypted_data[0]
            if len(path_to_folder) == 0:  # we have found the folder
                if curr_row["type"] == "password" and 'state' not in curr_row.keys():
                    item = QtGui.QStandardItem(curr_row["name"])
                    self.passwords_model.appendRow(item)
                self.pass_extract_helper(decrypted_data[1:], path_to_folder)
            else:  # we assume that the folder structure for sure is in *.json file
                if curr_row["type"] == "directory" and curr_row["name"] == path_to_folder[0]:
                    self.pass_extract_helper(curr_row["data"], path_to_folder[1:])
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
        """
        Take the chosen folder and find an absolute path of it.
        Call an external script to provide a name to the new sub-folder and save it.
        Update the GUI.
        """
        self.data = get_data()
        item = self.foldersTreeView.selectedIndexes()
        self.current_path = self.get_absolute_path_of_folder(item[0])
        self.set_time_stamp()
        self.folder_window.show()

    def delete_folder(self):
        """
        Get the path absolute path of the selected folder.
        Delete all data from that folder.
        """
        self.data = get_data()
        item = self.foldersTreeView.selectedIndexes()
        path = self.get_absolute_path_of_folder(item[0])
        try:
            get_logs_from_server(self.loginWindow.s)
            self.delete_folder_helper(self.data[1], path)
        except DeleteRootFolderError:
            show_message_box(self, "Root node cannot be deleted.")
        else:
            write_data(self.data)
            send_logs_to_server(self.loginWindow.s)
            self.setup_tree_view()

    def delete_folder_helper(self, json_data, path):
        if len(path) == 1 and path[0] == "root":
            raise DeleteRootFolderError
        else:
            self.set_time_stamp()
            node_reference = find_node_reference(json_data, path[:-1],self.time_stamp)
            directory_reference = find_exact_node(node_reference, path[-1], "directory")
            node_reference[directory_reference]["state"] = "DEL_LOCAL"
            # remove from displayed - clear display passwords UI element
            self.passwords_model.removeRows(0, self.passwords_model.rowCount())

            item = self.foldersTreeView.selectedIndexes()
            self.current_path = self.get_absolute_path_of_folder(item[0])


    def edit_folder(self):
        self.data = get_data()
        item = self.foldersTreeView.selectedIndexes()
        self.current_path = self.get_absolute_path_of_folder(item[0])
        path = self.current_path
        try:
            if len(path) == 1 and path[0] == "root":  # cannot delete root node
                raise DeleteRootFolderError
        except DeleteRootFolderError:
            show_message_box(self, "Root node cannot be edited.")
        else:
            self.set_time_stamp()
            path = self.get_absolute_path_of_folder(item[0])
            self.folder_window.folderNameLineEdit.setText(item[0].data())
            self.folder_window.edit_mode = True
            self.folder_window.show()

    def set_time_stamp(self):
        self.time_stamp = time.time()

    def get_password_names_within_level(self, json_data):
        """Get all password names within a level so as to use it to guarantee only unique names."""
        passwords_arr = []
        for el in json_data:
            if el["type"] == "password" and ("state" not in el.keys() or el["state"] != "DEL_LOCAL"):
                passwords_arr.append(el["name"])
        return passwords_arr

    def on_sync_button(self):
        self.data = get_data()
        get_logs_from_server(self.loginWindow.s)
        send_logs_to_server(self.loginWindow.s)
        self.setup_tree_view()

if __name__ == "__main__":
    pass
