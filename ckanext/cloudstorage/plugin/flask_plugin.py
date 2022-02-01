# -*- coding: utf-8 -*-

import ckan.plugins as p
import ckanext.cloudstorage.cli as cli
from ckanext.cloudstorage import views

class MixinPlugin(p.SingletonPlugin):
    p.implements(p.IClick)
    p.implements(p.IBlueprint)

    # IClick

    def get_commands(self):
        return cli.get_commands()

    
    def get_blueprint(self):
        return [
            views.resource_blueprint
        ]