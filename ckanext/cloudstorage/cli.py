#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import os.path
import cgi

import click

from ckanapi import LocalCKAN
from ckanext.cloudstorage.storage import (
    CloudStorage,
    ResourceCloudStorage
)
from ckanext.cloudstorage.model import (
    create_tables,
    drop_tables
)

from ckan.logic import NotFound


def get_commands():
    return [cloudstorage]


@click.group()
def cloudstorage():
    'ckanext-cloudstorage maintence utilities.'
    pass


@cloudstorage.command()
@click.argument('domains')
@click.pass_context
def fix_cors(ctx, domains):
    'Update CORS rules where possible.'
    cs = CloudStorage()

    if cs.can_use_advanced_azure:
        from azure.storage import blob as azure_blob
        from azure.storage import CorsRule

        blob_service = azure_blob.BlockBlobService(
            cs.driver_options['key'],
            cs.driver_options['secret']
        )

        blob_service.set_blob_service_properties(
            cors=[
                CorsRule(
                    allowed_origins=domains,
                    allowed_methods=['GET']
                )
            ]
        )
        print('Done!')
    else:
        print(
            'The driver {driver_name} being used does not currently'
            ' support updating CORS rules through'
            ' cloudstorage.'.format(
                driver_name=cs.driver_name
            )
        )


@cloudstorage.command()
@click.argument('path_to_storage')
@click.pass_context
def migrate(ctx, path_to_storage):
    'Upload local storage to the remote.'

    if not os.path.isdir(path_to_storage):
        print('The storage directory cannot be found.')
        return

    lc = LocalCKAN()
    resources = {}

    # The resource folder is stuctured like so on disk:
    # - storage/
    #   - ...
    # - resources/
    #   - <3 letter prefix>
    #     - <3 letter prefix>
    #       - <remaining resource_id as filename>
    #       ...
    #     ...
    #   ...
    for root, dirs, files in os.walk(path_to_storage):
        # Only the bottom level of the tree actually contains any files. We
        # don't care at all about the overall structure.
        if not files:
            continue

        split_root = root.split('/')
        resource_id = split_root[-2] + split_root[-1]

        for file_ in files:
            resources[resource_id + file_] = os.path.join(
                root,
                file_
            )

    for i, resource in enumerate(resources.iteritems(), 1):
        resource_id, file_path = resource
        print('[{i}/{count}] Working on {id}'.format(
            i=i,
            count=len(resources),
            id=resource_id
        ))

        try:
            resource = lc.action.resource_show(id=resource_id)
        except NotFound:
            continue

        if resource['url_type'] != 'upload':
            continue

        with open(os.path.join(root, file_path), 'rb') as fin:
            resource['upload'] = FakeFileStorage(
                fin,
                resource['url'].split('/')[-1]
            )

            uploader = ResourceCloudStorage(resource)
            uploader.upload(resource['id'])


@cloudstorage.command('initdb')
@click.pass_context
def initdb(ctx):
    'Reinitalize database tables.'

    drop_tables()
    create_tables()
    print("DB tables are reinitialized")


class FakeFileStorage(cgi.FieldStorage):
    def __init__(self, fp, filename):
        self.file = fp
        self.filename = filename
