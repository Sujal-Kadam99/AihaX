import os
from unittest import mock
import pytest
from backend.recon.recon_tool_availability import ReconToolAvailability, DEFAULT_PROJECT_TOOLS_DIR

@pytest.fixture
def clean_env():
    with mock.patch.dict(os.environ, clear=True):
        yield

def test_explicit_custom_dir_wins(clean_env):
    rta = ReconToolAvailability(custom_bin_dir="/custom/dir/wins")
    assert rta.custom_bin_dir == "/custom/dir/wins"

def test_env_var_wins_over_default(clean_env):
    os.environ["AIHAX_TOOLS_DIR"] = "/env/dir/wins"
    rta = ReconToolAvailability()
    assert rta.custom_bin_dir == "/env/dir/wins"
    
def test_default_project_dir_used_when_unset(clean_env):
    rta = ReconToolAvailability()
    assert rta.custom_bin_dir == DEFAULT_PROJECT_TOOLS_DIR

def test_path_remains_final_fallback(clean_env):
    with mock.patch("shutil.which") as mock_which:
        mock_which.return_value = "/usr/bin/some_tool"
        rta = ReconToolAvailability(custom_bin_dir="/does/not/exist")
        path = rta.resolve_binary_path("some_tool")
        assert path is not None
        assert "some_tool" in path

@pytest.mark.asyncio
async def test_unavailable_binary_remains_unavailable(clean_env):
    rta = ReconToolAvailability(custom_bin_dir="/does/not/exist/surely")
    with mock.patch("shutil.which") as mock_which:
        mock_which.return_value = None
        inv = await rta.generate_inventory()
        subfinder_rec = next(r for r in inv if r.tool_name == "subfinder")
        assert subfinder_rec.availability_status == "BINARY_UNAVAILABLE"

@pytest.mark.asyncio
async def test_no_false_live_validated_status(clean_env):
    rta = ReconToolAvailability(custom_bin_dir="/does/not/exist")
    with mock.patch("shutil.which") as mock_which, \
         mock.patch("os.path.isfile", return_value=True), \
         mock.patch("os.access", return_value=True):
        mock_which.return_value = "/mock/subfinder"
        inv = await rta.generate_inventory()
        subfinder_rec = next(r for r in inv if r.tool_name == "subfinder")
        assert subfinder_rec.availability_status != "LIVE_VALIDATED"
