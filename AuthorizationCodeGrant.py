# main.py
class AuthorizationCodeGrant(grants.AuthorizationCodeGrant):
    def authenticate_user(self, authorization_code):
        user = db_helper.get_user_by_id(authorization_code.user_id)
        return user

    def save_authorization_code(self, code, request):
        # Save the authorization code to the database
        code_challenge = request.data.get('code_challenge')
        code_challenge_method = request.data.get('code_challenge_method')
        db_helper.save_authorization_code(
            code=code,
            client_id=request.client.client_id,
            redirect_uri=request.redirect_uri,
            scope=request.scope,
            user_id=request.user['id'],
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            expires_in=600  # Code expires in 10 minutes
        )

    def query_authorization_code(self, code, client):
        # Retrieve the authorization code from the database
        return db_helper.get_authorization_code(code, client.client_id)

    def delete_authorization_code(self, authorization_code):
        # Delete the used authorization code
        db_helper.delete_authorization_code(authorization_code.code)

    def validate_code_challenge(self, request):
        code_verifier = request.data.get('code_verifier')
        code_challenge = request.authorization_code.code_challenge
        code_challenge_method = request.authorization_code.code_challenge_method
        if not CodeChallenge(code_challenge_method).verify(code_verifier, code_challenge):
            raise InvalidGrantError('Invalid code verifier.')
