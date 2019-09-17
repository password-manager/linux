import base64
import json
import os
import sys
import time
from ast import literal_eval

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad
from PyQt5 import QtGui, QtWidgets
from PyQt5 import uic
from PyQt5.QtCore import Qt, QObject
from PyQt5.QtWidgets import QMenu, QAction

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

with open('passwords.json', 'r') as read_file:  # TODO which data is being used?
    data = json.load(read_file)


def write_data():
    with open("passwords.txt", "wb") as f:
        encrypted = cipher.encrypt(pad(str(data).encode(), BLOCK_SIZE))
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
        deleteButton with on_delete_button function, so as to delete a password
        doubleClicked password with onEditClock function, so as to edit a password
        """
        self.passwordsView.setModel(self.passwords_model)
        self.createButton.pressed.connect(self.on_create_password_button)
        self.deleteButton.pressed.connect(self.on_delete_button)
        self.passwordsView.doubleClicked.connect(self.on_edit_password_button)

    def connect_folders_components(self):
        """
        Display folders as a tree structure.
        Use right-click context menu to add/delete/edit a folder.
        """
        self.foldersTreeView.setModel(self.folders_model)
        self.foldersTreeView.clicked.connect(self.display_passwords)
        self.foldersTreeView.setContextMenuPolicy(Qt.CustomContextMenu)
        self.foldersTreeView.customContextMenuRequested.connect(self.display_folders_menu)

    def display_folders_menu(self, position):
        """
        Right-click folders context menu enables user to:
        add_folder
        delete_folder
        edit_folder #TODO
        """
        menu = QMenu(self)
        menu.addAction("Add folder", self.add_folder)
        menu.addAction("Delete folder", self.delete_folder)
        menu.exec_(self.foldersTreeView.viewport().mapToGlobal(position))

    def closeEvent(self, event):
        write_data()

    def showContextMenu(self, position):
        menu = QMenu(self)
        add_folder = QAction("Add sub-folder", self)
        remove_folder = QAction("Remove", self)

        my_actions = []
        my_actions.append(add_folder)
        my_actions.append(remove_folder)

        menu.addActions(my_actions)

        add_folder.triggered.connect(self.setup_treeview)

        # reset.triggered.connect(self.FolderStructureTreeWidget.reset)
        menu.popup(self.FolderStructureTreeWidget.mapToGlobal(position))
        self.model = QtGui.QStandardItemModel()
        self.passwordsView.setModel(self.model)
        self.load_data()
        self.createButton.pressed.connect(self.on_create_button)
        self.deleteButton.pressed.connect(self.on_delete_button)
        self.passwordsView.doubleClicked.connect(self.on_edit_click)

    def on_create_button(self):
        """Close showPasswordsWindow and run savePassword.py"""
        write_data()
        window.close()
        path = ""
        for folder in self.current_path:
            path += '{}/'.format(folder)
        os.system('python savePassword.py ' + '"{}"'.format(path[:-1]))

    def on_edit_click(self, item):  # TO DO
        """Close showPasswordsWindow and
        run savePassword.py with args:passwordName and encrypted password
        """
        tmp_data = data
        for folder in self.current_path:
            for row in tmp_data:
                if row['type'] == 'catalog' and row['name'] == folder:
                    tmp_data = row['data']
        for el in tmp_data:
            if el['type'] == 'password' and el['name'] == item.data():
                password = el['data']
        write_data()
        window.close()
        path = ""
        for folder in self.current_path:
            path += '{}/'.format(folder)
        os.system('python savePassword.py ' + '"{}"'.format(path[:-1]) + ' ' + '"{}"'.format(
            item.data()) + ' ' + '"{}"'.format(password))

    def on_delete_button(self):
        """Delete selected password from View and from file"""
        indexes = self.passwordsView.selectedIndexes()
        if indexes:
            # Indexes is a list of a single item in single-select mode.
            index = indexes[0]
            item = self.model.itemFromIndex(index).text()
            self.model.removeRow(index.row())
            self.model.layoutChanged.emit()
            # Clear the selection (as it is no longer valid).
            self.passwordsView.clearSelection()
            self.delete_from_data(item)

    def delete_from_data(self, name):
        """Delete selected password from file"""
        tmp_data = data
        for folder in self.current_path:
            for row in tmp_data:
                if row['type'] == 'catalog' and row['name'] == folder:
                    tmp_data = row['data']
        for el in tmp_data:
            if el['type'] == 'password' and el['name'] == name:
                tmp_data.remove(el)

    def setup_tree_view(self):
        """
        Display folders in as a hierarchical (tree) view.
        """
        self.folders_model.removeRows(0, self.folders_model.rowCount())
        self.extract_folders_from_data(data, None)

    def extract_folders_from_data(self, data, parent):  # TODO a pattern how to check the structure
        """
        Recursively search the data and extract folder names.
        """
        if isinstance(data, list) and data:
            curr_row = data[0]
            if 'type' in curr_row.keys() and curr_row['type'] == 'catalog':
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
        self.current_path = self.get_absolute_path_of_folder(
            item)  # TODO think if is it ok to store curr path as a class variable
        self.pass_extract_helper(data, self.current_path)

    def pass_extract_helper(self, decrypted_data, path_to_folder):  # todo make better quality code
        if len(decrypted_data) > 0:
            curr_row = decrypted_data[0]
            if len(path_to_folder) == 0:  # we have found the folder
                if curr_row['type'] == 'password':
                    item = QtGui.QStandardItem(curr_row['name'])
                    self.passwords_model.appendRow(item)
                self.pass_extract_helper(decrypted_data[1:], path_to_folder)
            else:  # we assume that the folder structure for sure is in *.json file
                if curr_row['type'] == 'catalog' and curr_row['name'] == path_to_folder[0]:
                    self.pass_extract_helper(curr_row['data'], path_to_folder[1:])
                else:
                    self.pass_extract_helper(decrypted_data[1:], path_to_folder)

    def get_absolute_path_of_folder(self, folder):
        """
        Returns the absolute path to a chosen folder
        """
        path = self.get_absolute_path_of_folder_helper(folder, [])
        return path

    def get_absolute_path_of_folder_helper(self, folder, path):  # todo folder = QModelIndex
        """
        Recursively search the hierarchical structure of folders so as to
        find the the absolute path of the specified folder.
        """
        path.append(folder.data())
        if folder.parent().data() is not None:
            self.get_absolute_path_of_folder_helper(folder.parent(), path)
        return path[::-1]  # return reversed result

    def add_folder(self):
        # TODO better GUI with non-closable items after setup_tree_view()
        # TODO folders of only UNIQUE names
        """
        Take the chosen folder and find an absolute path of it.
        Call an external script to provide a name to the new sub-folder and save it.
        Update the GUI. #todo what should happen when a new sub-folder is added
        """
        item = self.foldersTreeView.selectedIndexes()
        path = self.get_absolute_path_of_folder(item[0])  # todo what if many selected?
        command = 'python3 manage_folder.py '
        command += f'"{path}"'
        # otherview = FolderWindow(command)
        # otherview.show()
        #
        os.system(command)
        test_items = QtGui.QStandardItem("BUU")  # todo display part DOESN'T WORK
        self.folders_model.insertRow(item[0].row(), test_items)
        self.folders_model.layoutChanged.emit()

    def delete_folder(self):
        # todo for now we delete all the data but when we chose a strategy ->
        # (delete all sub-directories and all-passwords one by one it will make more sense)
        item = self.foldersTreeView.selectedIndexes()
        path = self.get_absolute_path_of_folder(item[0])  # todo what if many selected?
        new_data = self.delete_folder_helper(data, path, [])

        with open('passwords.json', 'w') as f:
            json.dump(new_data, f)

        self.folders_model.removeRow(item[0].row(), item[0].parent())
        self.folders_model.layoutChanged.emit()

    def delete_folder_helper(self, json_data, path, result):
        if len(json_data) > 0:
            curr_row = json_data[0]

            if len(path) == 1:
                if curr_row['type'] == 'catalog' and curr_row['name'] == path[0]:
                    # result += json_data[1:]
                    curr_row['state'] = 'DEL'
                    global timestamp
                    timestamp = time.time()
                    curr_row['timestamp'] = timestamp
                    result.append(curr_row)
                    result += json_data[1:]
                    return result
                else:
                    result.append(curr_row)
                    self.delete_folder_helper(json_data[1:], path, result)  # as max depth is exactly 1
            else:
                if curr_row['type'] == 'catalog' and curr_row['name'] == path[0]:
                    curr_row['data'] = self.delete_folder_helper(curr_row['data'], path[1:], [])
                    curr_row['state'] = 'MOD'
                    #curr_row['timestamp'] = timestamp
                    result.append(curr_row)
                    result += json_data[1:]
                    return result
                else:
                    result.append(curr_row)
                    self.delete_folder_helper(json_data[1:], path, result)
        return result


# TODO CHECK IF DELETING PASSWORDS WORK FOR PATHS a/a/x and a/b/x (I mean the repetition of the previous folder name)

if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    window = FoldersPasswordsWindow()
    folder_window = mf.FolderWindow(window)
    window.show()
    app.exec_()
