from decimal import Decimal
from unittest import TestCase
from unittest.mock import Mock

import httpx

from scripts.evaluate_analysis_quality import BoundedDeepSeek, BudgetExhausted


class EvaluationBudgetTests(TestCase):
    def test_rejects_other_origins_and_requests_above_budget_without_network(self):
        client = Mock()
        budget = BoundedDeepSeek(client, "https://fixture.invalid/v1", 100, Decimal(1), Decimal(1), Decimal(1))
        body = {"max_tokens": 50, "messages": [{"content": "Caso sintético."}]}
        for endpoint in ("https://other.invalid/v1/chat/completions", budget.endpoint):
            with self.assertRaises(BudgetExhausted):
                budget(endpoint, headers={}, json=body, timeout=1)
        client.post.assert_not_called()

    def test_measured_usage_replaces_the_reservation_and_is_not_retried(self):
        client = Mock()
        client.post.return_value = httpx.Response(200, json={"usage": {"prompt_tokens": 12, "completion_tokens": 4}})
        budget = BoundedDeepSeek(client, "https://fixture.invalid/v1", 1000, Decimal(1), Decimal(1), Decimal(2))
        response = budget(budget.endpoint, headers={}, json={"max_tokens": 50, "messages": [{"content": "Caso."}]},
                          timeout=1)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(budget.tokens, 16)
        self.assertEqual(budget.reserved_cost, Decimal("0.000020"))
        client.post.assert_called_once()
