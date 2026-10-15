"""monitors: confirmacion de cambios

Dos columnas para que la vigilancia solo avise de lo que se ve en dos
ejecuciones seguidas (`core/change_confirmation.py`, ARQUITECTURA §12):
`pending_changes`, los cambios vistos y aún no avisados con su valor
anterior, y `last_discarded`, cuántos descartó la última ejecución como
ruido. Con valor por defecto en la base de datos: los monitores que ya
existen empiezan sin nada pendiente.

Revision ID: 8fd664bfa9de
Revises: 3dae87bb5b06
Create Date: 2026-10-15 15:20:11.599945

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '8fd664bfa9de'
down_revision: Union[str, Sequence[str], None] = '3dae87bb5b06'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column(
        'monitors',
        sa.Column('pending_changes', sa.JSON(), server_default='[]', nullable=False),
    )
    op.add_column(
        'monitors',
        sa.Column('last_discarded', sa.Integer(), server_default='0', nullable=False),
    )


def downgrade() -> None:
    """Downgrade schema."""
    # En lote: SQLite antiguo no sabe borrar columnas con ALTER TABLE.
    with op.batch_alter_table('monitors') as batch:
        batch.drop_column('last_discarded')
        batch.drop_column('pending_changes')
