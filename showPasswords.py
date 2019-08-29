import base64
import json
import os
import sys
from ast import literal_eval

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from PyQt5 import QtGui, QtWidgets
from PyQt5 import uic
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QMenu, QAction, QTreeWidgetItem

qt_creator_file = "guis/passwordList.ui"
Ui_MainWindow, QtBaseClass = uic.loadUiType(qt_creator_file)

with open('register.json', 'r') as file:
    data_register = json.load(file)
    salt = data_register['salt'].encode()
    master_password = data_register['master_password'].encode()

key = 'verysecretaeskey'.encode()
cipher = AES.new(key, AES.MODE_ECB)
BLOCK_SIZE = 32

with open('passwords.txt', mode='rb') as passwords:
    data = unpad(cipher.decrypt(base64.b64decode(passwords.read())), BLOCK_SIZE)
    data = literal_eval(data.decode())


def write_data():
    with open("passwords.txt", "wb") as f:
        encrypted = cipher.encrypt(pad(str(data).encode(), BLOCK_SIZE))
        f.write(base64.b64encode(encrypted))


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

    def setup_treeview(self):
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
        self.FolderStructureTreeWidget.itemDoubleClicked.connect(self.display_passwords)

    def display_passwords(self, item):
        self.model.removeRows(0, self.model.rowCount())
        self.current_path = self.get_full_path(item)
        self.pass_extract_helper(data, self.current_path)

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


if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    window = MainWindow()
    window.show()
    app.exec_()
