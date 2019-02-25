import jwt
import logging

log = logging.getLogger(__name__)

def get_user_data(token):
    """Decode tokent and return user's data"""
    try:
        return jwt.decode(token, verify=False)
    except jwt.exceptions.DecodeError as e:
        log.error('Error occured when decoding jwt token - {}'.format(e))
        raise

