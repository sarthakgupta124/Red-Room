"""End-to-end test for demo scenario."""

import pytest
import httpx


@pytest.mark.asyncio
async def test_fintech_race_condition():
    """Test that race condition can be exploited in demo app."""
    url = "http://localhost:8080/transfer"
    payload = {
        "from_account": "ACC001",
        "to_account": "ACC002",
        "amount": 100.0
    }
    
    async with httpx.AsyncClient() as client:
        # Send concurrent requests
        tasks = [
            client.post(url, json=payload)
            for _ in range(10)
        ]
        
        import asyncio
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Count successful transfers
        success_count = sum(
            1 for r in responses
            if not isinstance(r, Exception) and r.status_code == 200
        )
        
        # If more than 1 succeeded, race condition exists
        assert success_count > 1, "Race condition should allow multiple transfers"
        
        # Check final balance
        balance_response = await client.get("http://localhost:8080/balance/ACC001")
        balance_data = balance_response.json()
        
        # Balance should be negative (vulnerability exploited)
        assert balance_data["balance"] < 0, "Balance should go negative due to race condition"
