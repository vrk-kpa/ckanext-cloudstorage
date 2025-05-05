"""Create cloudstorage tables

Revision ID: 8daf8d1f572e
Revises: 
Create Date: 2025-02-10 11:35:26.678016

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.engine.reflection import Inspector


# revision identifiers, used by Alembic.
revision = '8daf8d1f572e'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    conn = op.get_bind()
    inspector = Inspector.from_engine(conn)
    tables = inspector.get_table_names()
    if "cloudstorage_multipart_upload" not in tables:
        op.create_table(
            "cloudstorage_multipart_upload",
            sa.Column("id", sa.UnicodeText, primary_key=True),
            sa.Column("resource_id", sa.UnicodeText),
            sa.Column("name", sa.UnicodeText),
            sa.Column("initiated", sa.DateTime),
            sa.Column("size", sa.Numeric),
            sa.Column("original_name", sa.UnicodeText),
            sa.Column("user_id", sa.UnicodeText),
        )

    if "cloudstorage_multipart_part" not in tables:
        op.create_table(
            "cloudstorage_multipart_part",
            sa.Column("n", sa.Integer, primary_key=True),
            sa.Column("etag", sa.UnicodeText, primary_key=True),
            sa.Column(
                "upload_id",
                sa.UnicodeText,
                sa.ForeignKey("cloudstorage_multipart_upload.id"),
                primary_key=True,
            ),
        )


def downgrade():
    pass
