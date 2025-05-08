from app import db
from flask_login import UserMixin
from sqlalchemy.ext.mutable import MutableList
from sqlalchemy import JSON

#DATABASE CLASSES:
#create a model for db
class Users(db.Model, UserMixin):
  id = db.Column(db.Integer, primary_key=True)
  username = db.Column(db.String(20), nullable=False, unique=True)
  email = db.Column(db.String(100), nullable=False, unique=True)
  password_hash = db.Column(db.String(256), nullable=False)
  date_added = db.Column(db.DateTime, nullable=False)
  logged_in_counter = db.Column(db.Integer, nullable=False, default=0)
  selected_subjects = db.Column(MutableList.as_mutable(JSON), default=[])
  level = db.Column(db.String(2))
  exam_start_time_am = db.Column(db.String(10))
  exam_start_time_pm = db.Column(db.String(10))

  def __repr__(self):
    return '<Username %r>' %self.username

class Exams(db.Model):
  __tablename__ = 'exams'
  date = db.Column(db.DateTime)
  exam_series = db.Column(db.String(20))
  board = db.Column(db.String(20))
  qualification = db.Column(db.String(100))
  examination_code = db.Column(db.String(50), primary_key=True)
  category = db.Column(db.String(100))
  base_subject = db.Column(db.String(100))
  subject = db.Column(db.String(100))
  title = db.Column(db.String(200))
  time = db.Column(db.String(20))
  duration = db.Column(db.String(20))
  tier = db.Column(db.String(1))
  level = db.Column(db.String(2))

  def __repr__(self):
    return f'<Exam {self.subject} {self.examination_code} {self.date}>'