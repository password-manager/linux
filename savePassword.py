import sys

from PyQt5 import QtWidgets, uic
import json
import base64
import os

from PyQt5.QtCore import Qt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet

qt_creator_file = "guis/savePassword.ui"
Ui_MainWindow, QtBaseClass = uic.loadUiType(qt_creator_file)

# master_password in another place
master_password = "password"
master_password_encode = master_password.encode()  # Convert to type bytes
salt = b'\x9c\x92&v\xb5\x10\xec\x14|\xa0\x0e\xd1\x1c\xdbE\xac'  # how to choose
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=default_backend()
)
key = base64.urlsafe_b64encode(kdf.derive(master_password_encode))


class MainWindow(QtWidgets.QMainWindow, Ui_MainWindow):
    def __init__(self, passwordName=None, password=None):
        """Show main window. If passwordName and password are given,
        show passwordName and decrypted password.
        Connect saveButton with onSaveButton function
        and cancelButton with onCancelButton function,
        checkBox with changeCheckBox function"""
        QtWidgets.QMainWindow.__init__(self)
        Ui_MainWindow.__init__(self)
        self.setupUi(self)
        self.passwordName.setText(passwordName)
        self.password.setEchoMode(QtWidgets.QLineEdit.Password)
        if password:
            f = Fernet(key)
            password_encode = password.encode()
            decrypted = f.decrypt(password_encode)
            self.password.setText(decrypted.decode())
        self.saveButton.pressed.connect(self.onSaveButton)
        self.cancelButton.pressed.connect(self.onCancelButton)
        self.checkBox.stateChanged.connect(self.changeCheckBox)

    def onSaveButton(self):
        """Get input from passwordName and password,
        then save encrypted password with its name to default file. Clear data"""
        passwordName = self.passwordName.text()
        password = self.password.text()
        if password and passwordName:  # Don't add empty strings.
            with open('passwords.json', mode='r') as passwords:
                data = json.load(passwords)
                password_encode = password.encode()
                f = Fernet(key)
                encrypted = f.encrypt(password_encode)
                data.append({'password_name': passwordName, 'password': encrypted.decode()})
            with open('passwords.json', mode='w') as passwords:
                json.dump(data, passwords, indent=4)
            self.onClearButton()  # Empty the input

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
