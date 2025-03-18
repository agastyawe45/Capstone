import pytest
from app import create_app

@pytest.fixture
def client():
    app = create_app()
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_home_page(client):
    rv = client.get('/')
    assert rv.status_code == 200

def test_login_page(client):
    rv = client.post('/login', data={
        'username': 'admin',
        'password': 'admin123'
    })
    assert rv.status_code == 200 
