from flask_login import current_user

def format_datetime(value):
    if current_user.is_authenticated:
        if value.strftime('%H:%M') == "09:00":
            start_time = current_user.exam_start_time_am or "09:00"

        if value.strftime('%H:%M') == "13:30":
            start_time = current_user.exam_start_time_pm or "13:30"
        
        return value.strftime(f'%d/%m/%y {start_time}')
    
    return value.strftime('%d/%m/%y %H:%M')

def format_datetime_countdown(value):
    if current_user.is_authenticated:
        if value.strftime('%H:%M') == "09:00":
            start_time = current_user.exam_start_time_am or "09:00"

        if value.strftime('%H:%M') == "13:30":
            start_time = current_user.exam_start_time_pm or "13:30"
        
        return value.strftime(f'%Y-%m-%d {start_time}:00')
    
    return value.strftime('%Y-%m-%d %H:%M:%S')


def register_filters(app):
    app.jinja_env.filters['format_datetime'] = format_datetime
    app.jinja_env.filters['format_datetime_countdown'] = format_datetime_countdown