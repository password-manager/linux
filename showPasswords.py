import base64
import json
import os
import sys
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


if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    window = MainWindow()
    window.show()
    app.exec_()
