from ckanext.cloudstorage.model import (
    create_tables,
    drop_tables
)


def initdb():
    drop_tables()
    create_tables()
    print("DB tables are reinitialized")
