from solder.render import template

@template('home')
def index():
    return dict(title='Welcome')
