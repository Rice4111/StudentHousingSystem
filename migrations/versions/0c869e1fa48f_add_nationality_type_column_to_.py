"""Add nationality_type column to Preference model

Revision ID: 0c869e1fa48f
Revises: d75061425d24
Create Date: 2024-01-06 16:59:28.038228

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '0c869e1fa48f'
down_revision = 'd75061425d24'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('preference_ll')
    with op.batch_alter_table('preference', schema=None) as batch_op:
        batch_op.add_column(sa.Column('nationality_type', sa.String(length=50), nullable=False))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('preference', schema=None) as batch_op:
        batch_op.drop_column('nationality_type')

    op.create_table('preference_ll',
    sa.Column('id', sa.INTEGER(), nullable=False),
    sa.Column('rental_type', sa.VARCHAR(length=50), nullable=False),
    sa.Column('nationality_type', sa.VARCHAR(length=50), nullable=False),
    sa.Column('term_policy', sa.VARCHAR(length=50), nullable=False),
    sa.Column('additional_requirements', sa.VARCHAR(length=200), nullable=True),
    sa.Column('user_id', sa.INTEGER(), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###
