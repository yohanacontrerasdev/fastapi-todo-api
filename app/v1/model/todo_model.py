from dataclasses import dataclass
from datetime import datetime
from email.policy import default

import peewee

from app.v1.utils.db import db
from .user_model import User


class Todo(peewee.Model):
    title = peewee.CharField()
    created_at = peewee.DateTimeField(default=datetime.now)
    is_done = peewee.BooleanField(default=False)
    user = peewee.ForeignKeyField(User, backref="todos")


    class Meta:
        database = db