import base64
import json
import os
import sys
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QMenu, QAction, QTreeWidgetItem, QListWidgetItem
from ast import literal_eval

from PyQt5 import QtGui, QtWidgets
from PyQt5 import uic
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


def delete_from_file(name):
    """Delete selected password from file"""
    for row in data:
        if row['password_name'] == name:
            data_register.remove(row)


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
        self.passwordsView.setModel(self.model)
        self.load_data()
        self.createButton.pressed.connect(self.on_create_button)
        self.deleteButton.pressed.connect(self.on_delete_button)
        self.passwordsView.doubleClicked.connect(self.on_edit_click)



        self.FolderStructureTreeWidget.itemDoubleClicked.connect(self.display_passwords)
        self.setup_treeview()

        self.FolderStructureTreeWidget.setContextMenuPolicy(Qt.CustomContextMenu)
        self.FolderStructureTreeWidget.customContextMenuRequested.connect(self.showContextMenu)

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
        os.system('python savePassword.py')

    def on_edit_click(self, item):
        """Close showPasswordsWindow and
        run savePassword.py with args:passwordName and encrypted password
        """
        for row in data:
            if row['password_name'] == item.data():
                password = row['password']
        write_data()
        window.close()
        os.system('python savePassword.py ' + item.data() + " " + password)

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
            delete_from_file(item)
            self.deleteFromFile(data[0])

    def load(self):
        """Load passwords from 'passwords.json' to data to model"""
        try:
            with open('passwords.json', 'r') as file:
                json_data = json.load(file)
                for row in json_data:
                    self.model.data.append([row['password_name'], row['password']])
        except Exception:
            pass

    def deleteFromFile(self, name):
        """Delete selected password from file"""
        with open("passwords.json", "r") as f:
            data = json.load(f)
            for row in data:
                if row['password_name'] == name:
                    data.remove(row)

        with open("passwords.json", "w") as f:
            json.dump(data, f, indent=4)

    def setup_treeview(self):
        with open("passwords.json", "r") as f:
            data = json.load(f)
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

    # def connect_components(self):
    #     self.passwordsView.setModel(self.model)
    #     self.createButton.pressed.connect(self.onCreateButton)
    #     self.deleteButton.pressed.connect(self.onDeleteButton)
    #     self.passwordsView.doubleClicked.connect(self.onEditClick)
    #     self.FolderStructureTreeWidget.itemDoubleClicked.connect(self.display_passwords)

    def display_passwords(self, item):
        self.passwordsListWidget.clear()
        with open("passwords.json", "r") as f:
            json_data = json.load(f)
            array = self.get_full_path(item)
            self.pass_extract_helper(json_data, array)

    def pass_extract_helper(self, json_data, array):
        if len(json_data) > 0:
            curr_row = json_data[0]
            if len(array) == 0: # we've found the specific folder
                if curr_row['type'] == 'password':
                    print(curr_row['name'])
                    print(curr_row['data'])
                    q_list_widget_item = QListWidgetItem(curr_row['name'])
                    self.passwordsListWidget.addItem(q_list_widget_item)
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


if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    window = MainWindow()
    window.show()
    app.exec_()
