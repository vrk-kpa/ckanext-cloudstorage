# -*- coding: utf-8 -*-

import ckan.plugins as p
from . import views, cli


class MixinPlugin(p.SingletonPlugin):
    p.implements(p.IClick)
    p.implements(p.IBlueprint)

    # IBlueprint

    def get_blueprint(self):
        return views.get_blueprints()

    # IClick

    def get_commands(self):
        return cli.get_commands()
