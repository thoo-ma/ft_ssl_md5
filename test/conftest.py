import pytest
from tester import FtSslTester


def pytest_addoption(parser):
    """Add command-line options for pytest."""
    parser.addoption(
        "--algorithm", 
        action="store", 
        default="md5", 
        help="Hash algorithm to test: md5, sha256, etc."
    )


def pytest_generate_tests(metafunc):
    """Dynamically modify test parameters based on command line options."""
    # If a test has the 'tester' fixture parameter and it's parameterized by 'algorithm'
    if "tester" in metafunc.fixturenames:
        # Get the algorithm from command line or use default
        algorithm = metafunc.config.getoption("algorithm")
        # Override the existing parameterization with our command line value
        metafunc.parametrize("tester", [algorithm], indirect=True)


@pytest.fixture
def tester(request):
    """Return a unified tester instance with the specified algorithm."""
    return FtSslTester(request.param)


@pytest.fixture
def test_file(tester):
    """Create a test file with 'bar' content and clean up afterward."""
    file_path = tester.create_test_file("file", "bar")
    yield "file"
    import os
    if os.path.exists("file"):
        os.remove("file")
