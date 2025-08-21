# Token Status List Implementation

This implementation follows the [IETF Token Status List draft specification](https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/10/) for managing credential revocation status.

## Features

- **Status List Token Generation**: Creates JWT tokens containing compressed status lists
- **Credential Revocation**: Mark credentials as revoked using status list indices
- **Status Verification**: Verify if a credential is revoked using status list tokens
- **RESTful API**: Complete API for managing status lists
- **Integration**: Seamless integration with credential issuance

## API Endpoints

### Core Status List Endpoints

- `GET /status-list/:id` - Get status list token JWT
- `POST /status-list` - Create new status list
- `PUT /status-list/:id/revoke/:index` - Revoke token at index
- `PUT /status-list/:id/unrevoke/:index` - Unrevoke token at index
- `GET /status-list/:id/status/:index` - Check token status
- `GET /status-lists` - List all status lists
- `DELETE /status-list/:id` - Delete status list
- `POST /status-list/verify` - Verify status list token

### Admin Endpoints

- `GET /status-list/:id/info` - Get status list information

## Usage Examples

### Creating a Status List
```bash
curl -X POST http://localhost:3000/status-list \
  -H "Content-Type: application/json" \
  -d '{"size": 1000, "bits": 1}'
```

### Revoking a Credential
```bash
curl -X PUT http://localhost:3000/status-list/{status-list-id}/revoke/42
```

### Getting Status List Token
```bash
curl -H "Accept: application/statuslist+jwt" \
  http://localhost:3000/status-list/{status-list-id}
```

### Verifying Token Status
```bash
curl -X POST http://localhost:3000/status-list/verify \
  -H "Content-Type: application/json" \
  -d '{"status_list_token": "...", "token_index": 42}'
```

## Integration with Credential Issuance

The status list functionality is automatically integrated with credential issuance. When a credential is issued:

1. A status list reference is created
2. The reference is included in the credential
3. The status list index is stored in the session

## Configuration

Add to `issuer-config.json`:
```json
{
  "status_list_endpoint": "https://server.example.com/status-list"
}
```

## Testing

Run the status list tests:
```bash
npm test tests/statusListTest.js
```

## Security Considerations

- Status list tokens are signed with ES256
- Tokens expire after 24 hours
- CORS headers are properly set
- Input validation on all endpoints
- Rate limiting recommended for production

## Implementation Details

- Uses zlib compression for status lists
- Supports 1, 2, 4, or 8 bits per status
- In-memory storage (use Redis/database for production)
- Automatic token caching for performance
