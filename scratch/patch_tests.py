import re

with open('backend/tests/test_phase26_tool_validation.py', 'r', encoding='utf-8') as f:
    content = f.read()

if 'from unittest.mock import patch' not in content:
    content = content.replace('import pytest', 'import pytest\nfrom unittest.mock import patch')

content = re.sub(
    r'(    @pytest\.mark\.asyncio\n    async def test_\w+_missing_binary_returns_binary_unavailable\(self\):)',
    r'    @patch("backend.recon.recon_tool_availability.ReconToolAvailability.resolve_binary_path", return_value=None)\n\1',
    content
)

content = re.sub(
    r'(    def test_binary_missing_returns_binary_unavailable\(self\):)',
    r'    @patch("backend.recon.recon_tool_availability.ReconToolAvailability.resolve_binary_path", return_value=None)\n\1',
    content
)

content = re.sub(
    r'(    @pytest\.mark\.asyncio\n    async def test_suite_execution_with_truthful_reporting\(self\):)',
    r'    @patch("backend.recon.recon_tool_availability.ReconToolAvailability.resolve_binary_path", return_value=None)\n\1',
    content
)

with open('backend/tests/test_phase26_tool_validation.py', 'w', encoding='utf-8') as f:
    f.write(content)
