import base64
import json
import os
import sys
from ast import literal_eval

from PyQt5 import QtGui, QtWidgets
from PyQt5 import uic
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QMenu, QAction, QTreeWidgetItem
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

qt_creator_file = "guis/passwordList.ui"
Ui_MainWindow, QtBaseClass = uic.loadUiType(qt_creator_file)

with open('register.json', 'r') as file:
    data_register = json.load(file)
    salt = data_register['salt'].encode()
    master_password = data_register['master_password'].encode()

kdf = PBKDF2HMAC(
    algorithm=hashes.SHA512(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=default_backend()
)
key = base64.urlsafe_b64encode(kdf.derive(master_password))  # Can only use kdf once
fernet = Fernet(key)

try:
    with open('passwords.txt', 'r') as file:
        data = fernet.decrypt(str(file.read()).encode())
        data = literal_eval(data.decode())
except Exception:
    data = []

with open("passwords.json", "r") as read_file:
    data = json.load(read_file)


def write_data():
    with open("passwords.txt", "w") as f:
        encrypted = fernet.encrypt(str(data).encode())
        f.write(encrypted.decode())


class MainWindow(QtWidgets.QMainWindow, Ui_MainWindow):
    def __init__(self):
        """Show main window. Load data.
        Connect createButton with on_create_button function,
        deleteButton with on_delete_button function,
        doubleClicked password with onEditClock function
        """
        QtWidgets.QMainWindow.__init__(self)
        Ui_MainWindow.__init__(self)
        self.setupUi(self)
        self.model = QtGui.QStandardItemModel()
        self.connect_components()
        self.setup_treeview()
        self.FolderStructureTreeWidget.setContextMenuPolicy(Qt.CustomContextMenu)
        self.FolderStructureTreeWidget.customContextMenuRequested.connect(self.showContextMenu)

    def showContextMenu(self, position):
        menu = QMenu(self)

        # todo extract to a function called OPEN MENU
        menu.addAction("Add sub-folder", self.add_folder)
        menu.addAction("Delete folder", self.delete_folder)

        menu.exec_(self.FolderStructureTreeWidget.viewport().mapToGlobal(position))  # TODO viewport()???

        # menu.popup(self.FolderStructureTreeWidget.mapToGlobal(position))
        self.model = QtGui.QStandardItemModel()
        self.passwordsView.setModel(self.model)
        # self.load_data()
        self.createButton.pressed.connect(self.on_create_button)
        self.deleteButton.pressed.connect(self.on_delete_button)
        self.passwordsView.doubleClicked.connect(self.on_edit_click)

    def load_data(self):
        """Load passwords from 'passwords.csv' to data to model"""
        if data:
            for row in data:
                item = QtGui.QStandardItem(row['password_name'])
                self.model.appendRow(item)

    def on_create_button(self):
        """Close showPasswordsWindow and run savePassword.py"""
        write_data()
        window.close()
        os.system('python3 savePassword.py')

    def on_edit_click(self, item):  # TO DO
        """Close showPasswordsWindow and
        run savePassword.py with args:passwordName and encrypted password
        """
        for row in data:
            if row['password_name'] == item.data():
                password = row['password']
        write_data()
        window.close()
        os.system('python3 savePassword.py ' + item.data() + " " + password)

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

    def load(self):
        """Load passwords from 'passwords.json' to data to model"""
        try:
            with open('passwords.json', 'r') as file:
                json_data = json.load(file)
                for row in json_data:
                    self.model.data.append([row['password_name'], row['password']])
        except Exception:
            pass

    def setup_treeview(self):
        with open("passwords.json", "r") as read_file:
            data = json.load(read_file)  # used as a global variable
        self.FolderStructureTreeWidget.clear()
        self.arr_extract(data, None)

    def arr_extract(self, array, parent):
        if isinstance(array, list) and array:
            curr_row = array[0]
            if 'type' in curr_row.keys() and curr_row['type'] == 'catalog':
                q_tree_widget_item = QTreeWidgetItem(list({curr_row["name"]}))
                if parent:
                    parent.addChild(q_tree_widget_item)
                else:
                    self.FolderStructureTreeWidget.addTopLevelItem(q_tree_widget_item)
                if 'data' in curr_row.keys() and curr_row['data'] is not None:
                    self.arr_extract(curr_row['data'], q_tree_widget_item)
            self.arr_extract(array[1:], parent)

    def connect_components(self):
        self.passwordsView.setModel(self.model)
        self.createButton.pressed.connect(self.on_create_button)
        self.deleteButton.pressed.connect(self.on_delete_button)
        self.passwordsView.doubleClicked.connect(self.on_edit_click)
        self.FolderStructureTreeWidget.itemClicked.connect(self.display_passwords)
        self.FolderStructureTreeWidget.setContextMenuPolicy(2)  # 2==Qt::ActionsContextMenu

    def display_passwords(self, item):
        self.model.removeRows(0, self.model.rowCount())
        with open("passwords.json", "r") as f:
            json_data = json.load(f)
            self.current_path = self.get_full_path(item)
            self.pass_extract_helper(json_data, self.current_path)

    def pass_extract_helper(self, json_data, array):
        if len(json_data) > 0:
            curr_row = json_data[0]
            if len(array) == 0:  # we've found the specific folder
                if curr_row['type'] == 'password':
                    item = QtGui.QStandardItem(curr_row['name'])
                    self.model.appendRow(item)
                self.pass_extract_helper(json_data[1:], array)
            else:  # we assume that the folder structure for sure is in *.json file
                if curr_row['type'] == 'catalog' and curr_row['name'] == array[0]:
                    self.pass_extract_helper(curr_row['data'], array[1:])
                else:
                    self.pass_extract_helper(json_data[1:], array)

    def get_full_path(self, item):
        res = self.get_full_path_helper(item, [])
        return res

    def get_full_path_helper(self, item, result):
        try:
            result.append(item.data(0, 0))
            self.get_full_path_helper(item.parent(), result)
            return result[::-1]  # return reversed result

        except AttributeError:  # we've reached the root of the tree structure
            return result[::-1]

    def add_folder(self):
        # TODO better GUI with non-closable items after setup_treeview()
        # TODO folders of only UNIQUE names
        item = self.FolderStructureTreeWidget.currentItem()
        path = self.get_full_path(item)
        command = 'python3 manage_folder.py'
        command += ' "' + str(path) + '"'
        print("COMMAND" + str(command))
        os.system(command)
        self.setup_treeview()

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

    def delete_folder(self):
        # todo for now we delete all the data but when we chose a strategy ->
        # (delete all sub-directories and all-passwords one by one it will make more sense)
        item = self.FolderStructureTreeWidget.currentItem()
        path = self.get_full_path(item)
        new_data = self.delete_folder_helper(data, path, [])

        print(new_data)

        with open('passwords.json', 'w') as f:
            json.dump(new_data, f)


    def delete_folder_helper(self, json_data, path, result):
        if len(json_data) > 0:
            curr_row = json_data[0]

            if len(path) == 1:
                if curr_row['type'] == 'catalog' and curr_row['name'] == path[0]:
                    result += json_data[1:]
                    return result
                else:
                    result.append(curr_row)
                    self.delete_folder_helper(json_data[1:], path, result)  # as max depth is exactly 1
            else:
                if curr_row['type'] == 'catalog' and curr_row['name'] == path[0]:
                    curr_row['data'] = self.delete_folder_helper(curr_row['data'], path[1:], [])
                    result.append(curr_row)
                    result += json_data[1:]
                    return result
                else:
                    result.append(curr_row)
                    self.delete_folder_helper(json_data[1:], path, result)
        return result


#TODO CHECK IF DELETING PASSWORDS WORK FOR PATHS a/a/x and a/b/x (I mean the repetition of the previous folder name)

if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    window = MainWindow()
    window.show()
    app.exec_()
