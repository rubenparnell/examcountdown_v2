from flask import flash as flask_flash

def flash(message, category="info", persistent=False, position=None):
    """
    Flash a message with optional persistence and position.

    Args:
        message (str): The message to show.
        category (str): 'info', 'success', 'warning', 'danger'
        persistent (bool): If True, message won't auto-hide.
        position (str): 'top', 'bottom' (defaults based on category)
    """
    if position is None:
        position = 'top' if category == 'danger' else 'bottom'
    flask_flash({'message': message, 'persistent': persistent, 'position': position}, category)
