import sys
from PyQt5 import QtWidgets, uic
import csv
import base64
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet


qt_creator_file = "guis/savePassword.ui"
Ui_MainWindow, QtBaseClass = uic.loadUiType(qt_creator_file)


class SavePasswordModel():

    def save(self, passwordName, password):
        with open('passwords.csv', mode='a+') as passwords:
            password_encode = password.encode()
            f = Fernet(key)
            encrypted = f.encrypt(password_encode)
            passwords = csv.writer(passwords, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
            passwords.writerow([passwordName, encrypted.decode()])


class MainWindow(QtWidgets.QMainWindow, Ui_MainWindow):
    def __init__(self, passwordName=None, password=None):
        QtWidgets.QMainWindow.__init__(self)
        Ui_MainWindow.__init__(self)
        self.setupUi(self)
        self.model = SavePasswordModel()
        self.passwordName.setText(passwordName)
        if password:
            f = Fernet(key)
            password_encode = password.encode()
            decrypted = f.decrypt(password_encode)
            self.password.setText(decrypted.decode())
        self.saveButton.pressed.connect(self.onSaveButton)
        self.cancelButton.pressed.connect(self.onCancelButton)

    def onSaveButton(self):
        """
        Get input from passwordName and password,
        then save them to default file. Clear data.
        """
        passwordName = self.passwordName.text()
        password = self.password.text()
        if password and passwordName:  # Don't add empty strings.
            # Add 'passwordName' and 'password' to passwords.csv
            self.model.save(passwordName, password)

            #  Empty the input
            self.onClearButton()

    def onClearButton(self):
        """Empty inputs 'passwordName' and 'password'"""
        self.passwordName.setText("")
        self.password.setText("")

    def onCancelButton(self):
        """Empty inputs 'passwordName' and 'password'"""
        window.close()
        os.system('python showPasswords.py ')


master_password = "password"  # This is input in the form of a string
master_password_encode = master_password.encode()  # Convert to type bytes
salt = b'\x9c\x92&v\xb5\x10\xec\x14|\xa0\x0e\xd1\x1c\xdbE\xac'  # CHANGE THIS - recommend using a key from os.urandom(16), must be of type bytes
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=default_backend()
)
key = base64.urlsafe_b64encode(kdf.derive(master_password_encode))



if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    if len(sys.argv) == 3:
        window = MainWindow(sys.argv[1], sys.argv[2])
    else:
        window = MainWindow()
    window.show()
    app.exec_()
