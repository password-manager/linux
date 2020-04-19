import random
import string

from PyQt5 import QtWidgets, uic

qt_creator_file = "guis/generatePassword.ui"
Ui_MainWindow, QtBaseClass = uic.loadUiType(qt_creator_file)


class GeneratorWindow(QtWidgets.QMainWindow, Ui_MainWindow):
    def __init__(self, password_model):
        QtWidgets.QMainWindow.__init__(self)
        Ui_MainWindow.__init__(self)
        self.password_model = password_model
        self.setupUi(self)
        self.generateButton.pressed.connect(self.on_generate_button)
        self.applyButton.pressed.connect(self.on_apply_button)
        self.init_default_vals()

    def init_default_vals(self):
        self.length.setText('20')
        self.lowercase.setChecked(True)
        self.uppercase.setChecked(True)
        self.digits.setChecked(True)
        self.special.setChecked(False)
        self.on_generate_button()

    def on_generate_button(self):
        length = int(self.length.text())
        chars = ''
        if self.lowercase.isChecked():
            chars += string.ascii_lowercase
        if self.uppercase.isChecked():
            chars += string.ascii_uppercase
        if self.digits.isChecked():
            chars += string.digits
        if self.special.isChecked():
            chars += string.punctuation
        self.generated.setText(''.join(random.choice(chars) for _ in range(length)))

    def on_apply_button(self):
        self.password_model.password.setText(self.generated.text())
        self.init_default_vals()
        self.close()


if __name__ == "__main__":
    pass
