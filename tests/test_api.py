"""
API Tests for FortiGate Sniffer to PCAP Converter

Run with: pytest tests/test_api.py -v
"""
import os
import pytest
from pathlib import Path
from unittest.mock import patch
from fastapi.testclient import TestClient
from sqlmodel import SQLModel, Session, create_engine
from sqlmodel.pool import StaticPool

# Set test environment before importing app
os.environ["SECRET_KEY"] = "test-secret-key-for-testing-purposes-only-32chars"
os.environ["ENVIRONMENT"] = "development"
os.environ["DEBUG"] = "false"

from fastapi_app.main import app
from fastapi_app.core.database import get_session
from fastapi_app.models.user import User
from fastapi_app.models.conversion import Conversion
from fastapi_app.routers import auth


# Test database setup
@pytest.fixture(name="session")
def session_fixture():
    """Create a fresh in-memory database for each test."""
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        yield session


@pytest.fixture(name="client")
def client_fixture(session: Session):
    """Create a test client with the test database."""
    def get_session_override():
        return session

    app.dependency_overrides[get_session] = get_session_override

    # Disable rate limiting for tests
    auth.limiter.enabled = False

    client = TestClient(app)
    yield client

    # Re-enable rate limiting and clean up
    auth.limiter.enabled = True
    app.dependency_overrides.clear()


@pytest.fixture(name="sample_sniffer_file")
def sample_sniffer_file_fixture():
    """Load a sample sniffer file for testing."""
    sample_path = Path(__file__).parent / "samples" / "test3short.txt"
    if sample_path.exists():
        return sample_path.read_bytes()
    # Fallback minimal sniffer data if sample not found
    return b"""FG600C3913802320 (third) # diag snif pack any "port not 22" 6
interfaces=[any]
filters=[port not 22]
0.806164 wan1 in arp who-has 10.108.18.77 tell 10.108.17.106
0x0000	 ffff ffff ffff 94de 8061 a404 0806 0001	.........a......
0x0010	 0800 0604 0001 94de 8061 a404 0a6c 116a	.........a...l.j
0x0020	 0000 0000 0000 0a6c 124d 0000 0000 0000	.......l.M......
0x0030	 0000 0000 0000 0000 0000 0000          	............

"""


class TestAuth:
    """Test authentication endpoints."""

    def test_signup_success(self, client: TestClient):
        """Test successful user signup."""
        response = client.post(
            "/signup",
            json={
                "email": "test@example.com",
                "password": "SecurePassword123",
                "first_name": "Test"
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert data["email"] == "test@example.com"
        assert data["first_name"] == "Test"
        assert "id" in data
        assert "hashed_password" not in data

    def test_signup_duplicate_email(self, client: TestClient):
        """Test signup with existing email."""
        # First signup
        client.post(
            "/signup",
            json={
                "email": "duplicate@example.com",
                "password": "SecurePassword123",
                "first_name": "First"
            }
        )
        # Second signup with same email
        response = client.post(
            "/signup",
            json={
                "email": "duplicate@example.com",
                "password": "AnotherSecure123",
                "first_name": "Second"
            }
        )
        assert response.status_code == 400
        assert "Email already registered" in response.json()["detail"]

    def test_signup_weak_password(self, client: TestClient):
        """Test signup with weak password."""
        response = client.post(
            "/signup",
            json={
                "email": "weak@example.com",
                "password": "weak",
                "first_name": "Test"
            }
        )
        assert response.status_code == 422  # Validation error

    def test_login_success(self, client: TestClient):
        """Test successful login."""
        # Create user first
        client.post(
            "/signup",
            json={
                "email": "login@example.com",
                "password": "SecurePassword123",
                "first_name": "Login"
            }
        )
        # Login
        response = client.post(
            "/token",
            data={
                "username": "login@example.com",
                "password": "SecurePassword123"
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"

    def test_login_wrong_password(self, client: TestClient):
        """Test login with wrong password."""
        # Create user first
        client.post(
            "/signup",
            json={
                "email": "wrongpass@example.com",
                "password": "SecurePassword123",
                "first_name": "Wrong"
            }
        )
        # Login with wrong password
        response = client.post(
            "/token",
            data={
                "username": "wrongpass@example.com",
                "password": "WrongPassword123"
            }
        )
        assert response.status_code == 401
        assert "Incorrect username or password" in response.json()["detail"]

    def test_login_nonexistent_user(self, client: TestClient):
        """Test login with nonexistent user."""
        response = client.post(
            "/token",
            data={
                "username": "nonexistent@example.com",
                "password": "SomePassword123"
            }
        )
        assert response.status_code == 401


class TestConversion:
    """Test conversion endpoints."""

    def _get_auth_headers(self, client: TestClient, email: str = "user@example.com"):
        """Helper to create user and get auth headers."""
        # Create user
        client.post(
            "/signup",
            json={
                "email": email,
                "password": "SecurePassword123",
                "first_name": "Test"
            }
        )
        # Login
        response = client.post(
            "/token",
            data={"username": email, "password": "SecurePassword123"}
        )
        token = response.json()["access_token"]
        return {"Authorization": f"Bearer {token}"}

    def test_upload_file(self, client: TestClient, sample_sniffer_file: bytes):
        """Test file upload."""
        headers = self._get_auth_headers(client)
        response = client.post(
            "/upload",
            headers=headers,
            files={"files": ("test.txt", sample_sniffer_file, "text/plain")}
        )
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert data[0]["content"] == "test.txt"
        assert data[0]["has_converted_data"] is False

    def test_upload_multiple_files(self, client: TestClient, sample_sniffer_file: bytes):
        """Test uploading multiple files."""
        headers = self._get_auth_headers(client)
        response = client.post(
            "/upload",
            headers=headers,
            files=[
                ("files", ("test1.txt", sample_sniffer_file, "text/plain")),
                ("files", ("test2.txt", sample_sniffer_file, "text/plain")),
            ]
        )
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 2

    def test_upload_invalid_extension(self, client: TestClient):
        """Test upload with invalid file extension."""
        headers = self._get_auth_headers(client)
        response = client.post(
            "/upload",
            headers=headers,
            files={"files": ("test.exe", b"malicious content", "application/octet-stream")}
        )
        assert response.status_code == 400
        assert "Invalid file type" in response.json()["detail"]

    def test_upload_binary_file(self, client: TestClient):
        """Test upload with binary (non-text) content."""
        headers = self._get_auth_headers(client)
        # Binary content that isn't valid UTF-8
        binary_content = bytes([0x80, 0x81, 0x82, 0x83])
        response = client.post(
            "/upload",
            headers=headers,
            files={"files": ("test.txt", binary_content, "text/plain")}
        )
        assert response.status_code == 400
        assert "text-based" in response.json()["detail"]

    def test_upload_unauthorized(self, client: TestClient, sample_sniffer_file: bytes):
        """Test upload without authentication."""
        response = client.post(
            "/upload",
            files={"files": ("test.txt", sample_sniffer_file, "text/plain")}
        )
        assert response.status_code == 401

    def test_list_conversions(self, client: TestClient, sample_sniffer_file: bytes):
        """Test listing conversions."""
        headers = self._get_auth_headers(client)
        # Upload a file first
        client.post(
            "/upload",
            headers=headers,
            files={"files": ("test.txt", sample_sniffer_file, "text/plain")}
        )
        # List conversions
        response = client.get("/conversions", headers=headers)
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert data[0]["content"] == "test.txt"

    def test_list_conversions_empty(self, client: TestClient):
        """Test listing conversions when none exist."""
        headers = self._get_auth_headers(client)
        response = client.get("/conversions", headers=headers)
        assert response.status_code == 200
        assert response.json() == []

    def test_convert_file(self, client: TestClient, sample_sniffer_file: bytes):
        """Test file conversion."""
        headers = self._get_auth_headers(client)
        # Upload a file
        upload_response = client.post(
            "/upload",
            headers=headers,
            files={"files": ("test.txt", sample_sniffer_file, "text/plain")}
        )
        conversion_id = upload_response.json()[0]["id"]

        # Convert the file
        response = client.post(f"/convert/{conversion_id}", headers=headers)
        assert response.status_code == 200
        assert "packets" in response.json()["message"]

    def test_convert_nonexistent(self, client: TestClient):
        """Test converting nonexistent file."""
        headers = self._get_auth_headers(client)
        response = client.post("/convert/9999", headers=headers)
        assert response.status_code == 404

    def test_download_original(self, client: TestClient, sample_sniffer_file: bytes):
        """Test downloading original file."""
        headers = self._get_auth_headers(client)
        # Upload a file
        upload_response = client.post(
            "/upload",
            headers=headers,
            files={"files": ("test.txt", sample_sniffer_file, "text/plain")}
        )
        conversion_id = upload_response.json()[0]["id"]

        # Download original
        response = client.get(f"/conversions/{conversion_id}/download/original", headers=headers)
        assert response.status_code == 200
        assert response.content == sample_sniffer_file

    def test_download_pcap_not_converted(self, client: TestClient, sample_sniffer_file: bytes):
        """Test downloading PCAP before conversion."""
        headers = self._get_auth_headers(client)
        # Upload a file without converting
        upload_response = client.post(
            "/upload",
            headers=headers,
            files={"files": ("test.txt", sample_sniffer_file, "text/plain")}
        )
        conversion_id = upload_response.json()[0]["id"]

        # Try to download PCAP
        response = client.get(f"/conversions/{conversion_id}/download/pcap", headers=headers)
        assert response.status_code == 400
        assert "not converted" in response.json()["detail"]

    def test_download_pcap_after_conversion(self, client: TestClient, sample_sniffer_file: bytes):
        """Test downloading PCAP after conversion."""
        headers = self._get_auth_headers(client)
        # Upload and convert
        upload_response = client.post(
            "/upload",
            headers=headers,
            files={"files": ("test.txt", sample_sniffer_file, "text/plain")}
        )
        conversion_id = upload_response.json()[0]["id"]
        client.post(f"/convert/{conversion_id}", headers=headers)

        # Download PCAP
        response = client.get(f"/conversions/{conversion_id}/download/pcap", headers=headers)
        assert response.status_code == 200
        # PCAPNG files start with magic bytes
        assert len(response.content) > 0

    def test_delete_conversion(self, client: TestClient, sample_sniffer_file: bytes):
        """Test deleting a conversion."""
        headers = self._get_auth_headers(client)
        # Upload a file
        upload_response = client.post(
            "/upload",
            headers=headers,
            files={"files": ("test.txt", sample_sniffer_file, "text/plain")}
        )
        conversion_id = upload_response.json()[0]["id"]

        # Delete it
        response = client.delete(f"/conversions/{conversion_id}", headers=headers)
        assert response.status_code == 200

        # Verify it's gone
        list_response = client.get("/conversions", headers=headers)
        assert list_response.json() == []

    def test_rename_conversion(self, client: TestClient, sample_sniffer_file: bytes):
        """Test renaming a conversion."""
        headers = self._get_auth_headers(client)
        # Upload a file
        upload_response = client.post(
            "/upload",
            headers=headers,
            files={"files": ("test.txt", sample_sniffer_file, "text/plain")}
        )
        conversion_id = upload_response.json()[0]["id"]

        # Rename it
        response = client.put(
            f"/conversions/{conversion_id}",
            headers=headers,
            json={"new_name": "renamed.txt"}
        )
        assert response.status_code == 200

        # Verify the new name
        list_response = client.get("/conversions", headers=headers)
        assert list_response.json()[0]["content"] == "renamed.txt"


class TestUserIsolation:
    """Test that users can only access their own data."""

    def _create_user_and_upload(self, client: TestClient, email: str, sample_file: bytes):
        """Helper to create user, upload file, and return (headers, conversion_id)."""
        client.post(
            "/signup",
            json={"email": email, "password": "SecurePassword123", "first_name": "Test"}
        )
        response = client.post(
            "/token",
            data={"username": email, "password": "SecurePassword123"}
        )
        headers = {"Authorization": f"Bearer {response.json()['access_token']}"}

        upload_response = client.post(
            "/upload",
            headers=headers,
            files={"files": ("test.txt", sample_file, "text/plain")}
        )
        conversion_id = upload_response.json()[0]["id"]
        return headers, conversion_id

    def test_user_cannot_access_other_user_conversion(self, client: TestClient, sample_sniffer_file: bytes):
        """Test that users cannot access other users' conversions."""
        # User 1 uploads a file
        _, conversion_id = self._create_user_and_upload(
            client, "user1@example.com", sample_sniffer_file
        )

        # User 2 tries to access it
        headers2, _ = self._create_user_and_upload(
            client, "user2@example.com", sample_sniffer_file
        )

        response = client.get(f"/conversions/{conversion_id}/download/original", headers=headers2)
        assert response.status_code == 404

    def test_user_cannot_delete_other_user_conversion(self, client: TestClient, sample_sniffer_file: bytes):
        """Test that users cannot delete other users' conversions."""
        # User 1 uploads
        headers1, conversion_id = self._create_user_and_upload(
            client, "user1@example.com", sample_sniffer_file
        )

        # User 2 tries to delete
        headers2, _ = self._create_user_and_upload(
            client, "user2@example.com", sample_sniffer_file
        )

        response = client.delete(f"/conversions/{conversion_id}", headers=headers2)
        assert response.status_code == 404

        # Verify it still exists for user 1
        list_response = client.get("/conversions", headers=headers1)
        assert len(list_response.json()) == 1


class TestFilenameSanitization:
    """Test filename sanitization."""

    def test_path_traversal_blocked(self, client: TestClient, sample_sniffer_file: bytes):
        """Test that path traversal is blocked."""
        client.post(
            "/signup",
            json={"email": "path@example.com", "password": "SecurePassword123", "first_name": "Test"}
        )
        response = client.post(
            "/token",
            data={"username": "path@example.com", "password": "SecurePassword123"}
        )
        headers = {"Authorization": f"Bearer {response.json()['access_token']}"}

        response = client.post(
            "/upload",
            headers=headers,
            files={"files": ("../../../etc/passwd", sample_sniffer_file, "text/plain")}
        )
        assert response.status_code == 200
        # Filename should be sanitized
        assert ".." not in response.json()[0]["content"]
        assert "/" not in response.json()[0]["content"]

    def test_special_characters_removed(self, client: TestClient, sample_sniffer_file: bytes):
        """Test that special characters are removed from filename."""
        client.post(
            "/signup",
            json={"email": "special@example.com", "password": "SecurePassword123", "first_name": "Test"}
        )
        response = client.post(
            "/token",
            data={"username": "special@example.com", "password": "SecurePassword123"}
        )
        headers = {"Authorization": f"Bearer {response.json()['access_token']}"}

        response = client.post(
            "/upload",
            headers=headers,
            files={"files": ("file<>:\"|?*.txt", sample_sniffer_file, "text/plain")}
        )
        assert response.status_code == 200
        filename = response.json()[0]["content"]
        assert "<" not in filename
        assert ">" not in filename
        assert ":" not in filename
        assert '"' not in filename
        assert "|" not in filename
        assert "?" not in filename
        assert "*" not in filename
