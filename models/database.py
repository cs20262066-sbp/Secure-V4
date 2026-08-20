"""
Shared SQLAlchemy instance. Imported by model modules and app factory.
"""
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()
