"""Verify that the two attack scenarios are blocked on app_fixed.py."""
from exploit import request

status, data = request('/login', {'username': "alice' -- ", 'password': 'wrong'})
print('SQL injection:', status, data)
assert status == 401
status, data = request('/notes', {'id': 2, 'user_id': 1})
print('Cross-user note access:', status, data)
assert status == 200 and data == {'error': 'Note not found'}
status, data = request('/notes', {'id': 2, 'user_id': 2})
print('Own note access:', status, data)
assert status == 200 and data['note']['owner_id'] == 2
print('Both attack scenarios blocked. Authorized note retrieval still works.')
