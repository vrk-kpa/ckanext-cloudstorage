# -*- coding: utf-8 -*-

import ckan.plugins as p
import ckanext.cloudstorage.cli as cli


class MixinPlugin(p.SingletonPlugin):
    p.implements(p.IClick)
    p.implements(p.IBlueprint)

    # IClick

    def get_commands(self):
        return cli.get_commands()
