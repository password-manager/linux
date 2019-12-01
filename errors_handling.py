from enum import Enum

from PyQt5.QtWidgets import QMessageBox


class Error(Exception):
    """Base class for other exceptions"""
    pass


class DeleteRootFolderError(Error):
    """Raised when the user tries to delete root node"""
    pass


class PasswordNameAlreadyExistsError(Error):
    """Raised when the password name already exists in the path"""
    pass


def show_message_box(instance, reason):
    """Show MessageBox with an error and reason"""
    QMessageBox.about(instance, "An error occured!", reason)

