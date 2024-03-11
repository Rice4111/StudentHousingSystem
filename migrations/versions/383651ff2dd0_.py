"""empty message

Revision ID: 383651ff2dd0
Revises: 25e0653bb865
Create Date: 2024-01-02 13:49:18.138139

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '383651ff2dd0'
down_revision = '25e0653bb865'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('payment_details',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('card_number', sa.String(length=20), nullable=False),
    sa.Column('expiration_month', sa.String(length=2), nullable=False),
    sa.Column('expiration_year', sa.String(length=4), nullable=False),
    sa.Column('cvv', sa.String(length=4), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('payment_details')
    # ### end Alembic commands ###
