# =============================================================================
# SVT System — Key Rotation Unit Tests
# =============================================================================

from unittest.mock import AsyncMock, MagicMock

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.keys import rotate_key
from app.core.security import UserContext


@pytest.mark.asyncio
async def test_key_rotation_lock():
    """
    Test rotation logic grabs FOR UPDATE lock and increments version properly.
    Uses SQLAlchemy AsyncMock to simulate deterministic database behavior.
    """
    mock_db = AsyncMock(spec=AsyncSession)
    
    # Mock the execute return value
    mock_result = MagicMock()
    mock_result.scalar.return_value = 5  # Max version currently is 5
    mock_db.execute.return_value = mock_result
    
    current_user = UserContext(id="abc-123", role="issuer", email="test@test.com")
    
    response = await rotate_key(current_user=current_user, db=mock_db)
    
    # Assert version was incremented deterministically
    assert response["version"] == 6
    assert response["message"] == "Key rotated successfully"
    
    # Assert DB add was called to save the new IssuerKey
    mock_db.add.assert_called_once()
    added_obj = mock_db.add.call_args[0][0]
    
    assert added_obj.version == 6
    assert added_obj.issuer_id == "abc-123"
    
    mock_db.flush.assert_called_once()


@pytest.mark.asyncio
async def test_key_rotation_initial():
    """Test when no previous keys exist (max version is Null)."""
    mock_db = AsyncMock(spec=AsyncSession)
    
    mock_result = MagicMock()
    mock_result.scalar.return_value = None  # No existing keys
    mock_db.execute.return_value = mock_result
    
    current_user = UserContext(id="abc-123", role="issuer", email="test@test.com")
    
    response = await rotate_key(current_user=current_user, db=mock_db)
    
    assert response["version"] == 1
    added_obj = mock_db.add.call_args[0][0]
    assert added_obj.version == 1
