"""
Re-export User model and enums from the shared library.
Keeps imports clean for auth-service code.
"""

from shared.app.models_base import User, UserPlan, UserRole, Base
