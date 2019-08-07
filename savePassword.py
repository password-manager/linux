import sys
from ast import literal_eval

from PyQt5 import QtWidgets, uic
import os

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QMessageBox
from cryptography.fernet import Fernet

qt_creator_file = "guis/savePassword.ui"
Ui_MainWindow, QtBaseClass = uic.loadUiType(qt_creator_file)

with open('key.txt', 'rb') as file:
    key = file.read()


class MainWindow(QtWidgets.QMainWindow, Ui_MainWindow):
    def __init__(self, passwordNameToEdit=None, passwordToEdit=None):
        """Show main window. If passwordName and password are given,
        show passwordName and decrypted password.
        Connect saveButton with onSaveButton function
        and cancelButton with onCancelButton function,
        checkBox with changeCheckBox function"""
        QtWidgets.QMainWindow.__init__(self)
        Ui_MainWindow.__init__(self)
        self.setupUi(self)
        self.passwordNameToEdit = passwordNameToEdit
        self.passwordToEdit = passwordToEdit
        self.passwordName.setText(passwordNameToEdit)
        self.password.setEchoMode(QtWidgets.QLineEdit.Password)
        self.password.setText(passwordToEdit)
        self.saveButton.pressed.connect(self.onSaveButton)
        self.cancelButton.pressed.connect(self.onCancelButton)
        self.checkBox.stateChanged.connect(self.changeCheckBox)

    def onSaveButton(self):
        """Get input from passwordName and password,
        then save encrypted password with its name to default file. Clear data"""
        passwordName = self.passwordName.text()
        password = self.password.text()
        if not passwordName or not password:  # Don't add empty strings.
            QMessageBox.about(self, "No data", "Write password name and password, please")
        else:
            if self.passwordNameToEdit:
                self.editInFile(self.passwordNameToEdit, passwordName, password)
            else:
                if os.path.exists('passwords.txt'):
                    with open('passwords.txt', mode='r') as passwords:
                        data = passwords.read()
                        fernet = Fernet(key)
                        data = fernet.decrypt(str(data).encode())
                        data = literal_eval(data.decode())
                else:
                    data = []
                data.append({'password_name': passwordName, 'password': password})
                fernet = Fernet(key)
                encrypted = fernet.encrypt(str(data).encode())
                with open('passwords.txt', 'w+') as file:
                    file.write(encrypted.decode())
            self.onCancelButton()

    def editInFile(self, oldName, newName, newPassword):
        """Delete selected password from file"""
        with open('passwords.txt', mode='r') as passwords:
            data = passwords.read()
            fernet = Fernet(key)
            data = fernet.decrypt(str(data).encode())
            data = literal_eval(data.decode())
            for row in data:
                if row['password_name'] == oldName:
                    row['password_name'] = newName
                    row['password'] = newPassword
        with open("passwords.txt", "w+") as f:
            encrypted = fernet.encrypt(str(data).encode())
            f.write(encrypted.decode())

    def onClearButton(self):
        """Empty inputs 'passwordName' and 'password'"""
        self.passwordName.setText("")
        self.password.setText("")

    def onCancelButton(self):
        """Close savePasswordWindow and run showPasswords.py"""
        window.close()
        os.system('python showPasswords.py ')

    def changeCheckBox(self, state):
        """If checkBox is checked - show password,
        if unchecked - hide it"""
        if state == Qt.Checked:
            self.password.setEchoMode(QtWidgets.QLineEdit.Normal)
        else:
            self.password.setEchoMode(QtWidgets.QLineEdit.Password)


if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    if len(sys.argv) == 3:
        window = MainWindow(sys.argv[1], sys.argv[2])
    else:
        window = MainWindow()
    window.show()
    app.exec_()
