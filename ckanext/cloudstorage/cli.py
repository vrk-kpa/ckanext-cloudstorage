import click

from ckanext.cloudstorage import utils

def get_commands():
    return [cloudstorage]

@click.group()
def cloudstorage():
    """
    Integrates with cloud providers
    """
    pass

@cloudstorage.command()
def initdb():
    utils.initdb()
