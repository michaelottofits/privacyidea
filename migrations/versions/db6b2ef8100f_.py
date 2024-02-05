"""v3.10: Add case-insensitive usernames in policies

Revision ID: db6b2ef8100f
Revises: d0e7144947d0
Create Date: 2024-01-29 14:12:38.070014

"""

# revision identifiers, used by Alembic.
revision = 'db6b2ef8100f'
down_revision = 'e3a64b4ca634'

from alembic import op
import sqlalchemy as sa
from sqlalchemy.exc import OperationalError, ProgrammingError

def upgrade():
    try:
        # ### commands auto generated by Alembic - please adjust! ###
        op.add_column('policy', sa.Column('user_case_insensitive', sa.Boolean(), nullable=True))
        # ### end Alembic commands ###
    except (OperationalError, ProgrammingError) as exx:
        if "already exists" in str(exx.orig).lower():
            print("Ok, Table 'user_case_insensitive' already exists.")
        else:
            print(exx)
    except Exception as exx:
        print("Could not add table 'user_case_insensitive' to database")
        print(exx)


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('policy', 'user_case_insensitive')
    # ### end Alembic commands ###
