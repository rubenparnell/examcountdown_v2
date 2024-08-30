def format_time(value):
    return value.strftime('%d/%m/%y %H:%M')

def register_filters(app):
    app.jinja_env.filters['format_time'] = format_time
