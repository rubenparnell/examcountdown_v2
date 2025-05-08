from flask import Blueprint, render_template, flash, url_for, redirect, request, jsonify, abort
from markupsafe import Markup
from flask_login import login_required, current_user, login_user, logout_user
from flask_mail import Message
from itsdangerous import SignatureExpired
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from sqlalchemy import and_
from uuid import uuid4
import requests
from app import db, mail, s
from app.forms import SignUpForm, LoginForm, UpdateForm, ConfirmPwdForm, EmailForm, PwdResetForm, QualForm, OldPwdResetForm, TimeForm
from app.models import Users, Exams
import os 
from collections import defaultdict

main = Blueprint('main', __name__)

@main.route("/")
def home():
  if current_user.is_authenticated:
    am_start_time=current_user.exam_start_time_am or "09:00"
    pm_start_time=current_user.exam_start_time_pm or "13:30"

    level = current_user.level

    shown_exams = []
    selected_exams = current_user.selected_subjects
    for exam in selected_exams:
      board = exam['board']
      subject = exam['subject']
      base_subject = exam['base_subject']
      tier = exam['tier'] if exam['tier'] != "-" else ""

      current_exams = Exams.query.filter(and_(Exams.time.isnot(None), 
                                              Exams.time != '', 
                                              Exams.level == level,
                                              Exams.base_subject == base_subject, 
                                              Exams.board == board, 
                                              Exams.subject == subject,
                                              Exams.tier == tier,
                                              )).order_by(Exams.date).all()

      for current_exam in current_exams:
        shown_exams.append(current_exam)

    #Get the date of the next exam:
    next_exam_date = None
    next_exam = None
    for exam in shown_exams:
      if isinstance(exam.date, datetime):
        if exam.date > datetime.now():
          if not next_exam_date or exam.date < next_exam_date:
            next_exam_date = exam.date
            next_exam = exam

    filtered_shown_exams = []

    for exam in shown_exams:
      if isinstance(exam.date, datetime) and exam.date > datetime.now():
        filtered_shown_exams.append(exam)

    return render_template("dashboard.html", 
                           next_exam_data=next_exam, 
                           exams=filtered_shown_exams,
                           am_start_time=am_start_time,
                           pm_start_time=pm_start_time,
                           )
  
  else:
    am_start_time = "09:00"
    pm_start_time = "13:30"

    # Get the current date and time
    now = datetime.now()

    # Helper function to group exams by (date, time)
    def group_exams_by_time(exams):
        grouped = defaultdict(list)

        # Group exams by (date, time)
        for exam in exams:
            key = (exam.date, exam.time)
            grouped[key].append(exam)

        if not grouped:
            return None

        # Get the first upcoming (date, time) group
        first_key = sorted(grouped.items())[0][0]
        exams_in_group = grouped[first_key]

        # Group exams by subject title
        subject_groups = defaultdict(list)
        for exam in exams_in_group:
            subject_groups[exam.base_subject].append(exam)

        # Format as a list of {subject: ..., exams: [...]}
        grouped_exams = sorted(
            [
                {
                    'subject': subject,
                    'exams': exams
                }
                for subject, exams in subject_groups.items()
            ],
            key=lambda x: x['subject'].lower()  # case-insensitive sorting
        )


        return {
            'date': first_key[0],
            'time': first_key[1],
            'subjects': grouped_exams
        }

    # Query exams
    gcse_exams = Exams.query.filter(
      and_(
        Exams.time.isnot(None),
        Exams.time != '',
        Exams.level == "2",
        Exams.date > now
      )
    ).order_by(Exams.date, Exams.time).all()

    as_exams = Exams.query.filter(
      and_(
        Exams.time.isnot(None),
        Exams.time != '',
        Exams.level == "3a",
        Exams.date > now
      )
    ).order_by(Exams.date, Exams.time).all()

    a_exams = Exams.query.filter(
      and_(
        Exams.time.isnot(None),
        Exams.time != '',
        Exams.level == "3b",
        Exams.date > now
      )
    ).order_by(Exams.date, Exams.time).all()

    # Group exams occurring at the same date and time
    next_gcse_exam_group = group_exams_by_time(gcse_exams)
    next_as_exam_group = group_exams_by_time(as_exams)
    next_a_exam_group = group_exams_by_time(a_exams)

    print(next_gcse_exam_group)

    return render_template("home.html",
                          next_gcse_exam=next_gcse_exam_group,
                          next_as_exam=next_as_exam_group,
                          next_a_exam=next_a_exam_group,
                          am_start_time=am_start_time,
                          pm_start_time=pm_start_time)

@main.route("/login", methods=['GET', 'POST'])
def login():
  form = LoginForm()
  if form.validate_on_submit():
    # Determine if the identifier is an email
    identifier = form.identifier.data
    if "@" in identifier:
      # It's an email
      user = db.session.query(Users).filter_by(email=identifier).first()
    else:
      # It's a username
      user = db.session.query(Users).filter_by(username=identifier).first()
      
    if user:
      #check the hash
      if check_password_hash(user.password_hash, form.password.data):
        login_user(user)
        current_user.logged_in_counter += 1
        db.session.commit()

        flash("Successfully logged in.", "success")

        if current_user.logged_in_counter == 1:
          return redirect(url_for('main.exam_options'))
        else:
          return redirect(url_for('main.home'))
      else:
        flash("Incorrect password.", "danger")
    else:
      flash(Markup("User not found! Try a different username or <a href="+url_for("main.signup")+">sign up</a>."), "danger")
  return render_template('login.html', form=form)


@main.route("/signup", methods=['GET', 'POST'])
def signup():
  VERIFY_URL = "https://www.google.com/recaptcha/api/siteverify"
  RECAPTCHA_SECRET_KEY = os.environ.get("RECAPTCHA_SECRET_KEY")

  form = SignUpForm()
  # Validate form
  if form.validate_on_submit():
    secret_response = request.form['g-recaptcha-response']
    verify_response = requests.post(url=f"{VERIFY_URL}?secret={RECAPTCHA_SECRET_KEY}&response={secret_response}").json()
    if verify_response['success'] == False or verify_response['score'] < 0.5:
      abort(403)

    form_email = form.email.data
    form_username = form.username.data
    form_password = form.password_hash.data
    form_password_2 = form.password2.data

    current_email = db.session.query(Users).filter_by(email=form_email).first()
    current_username = db.session.query(Users).filter_by(username=form_username).first()
    if current_email is None and current_username is None:
      if form_password != form_password_2:
        flash("Passwords do not match. Please try again.", "danger")
        form_password = ''
        form_password_2 = ''
        
      else: # filled in form successfully
        user_data = {
          'username': form_username, 
          'email': form_email,
          'password': form_password
          }
        token = s.dumps(user_data, salt='email-confirm')
        msg = Message('Confirm your email address - Exam Countdown', sender='inbox@myexams.net', recipients=[form_email])
        link = url_for('main.confirm_email', token=token, _external=True)
        msg.body = f'Hello, {form_username}!\nTo complete signing up with Exam Countdown, confirm your email using the link below:\n{link}\n\nThis link will expire in 1 hour.\n\nIf you did not sign up, you can ignore this email.'
        mail.send(msg)

        flash(Markup("A confirmation link has been sent to your email.<br>Please also check your junk folder."), "info")
        return redirect(url_for("main.login"))
    
    else:
      if not current_email is None:
        flash(Markup("That email is already used for another account. Please <a href="+url_for("main.login")+">log in</a> or use a different email."), "danger")
        form.email.data = ''
      if not current_username is None:
        flash("That username is already used. Please pick a different one.", "danger")
        form.username.data = ''

  # Catch validation errors and flash them
  if form.errors:
    for field, errors in form.errors.items():
      for error in errors:
        flash(Markup(f"<strong>{field.capitalize()} Error:</strong> {error}"), "danger")

  return render_template('signup.html', form=form, reCAPTCHA_site_key=os.environ.get("RECAPTCHA_SITE_KEY"))


@main.route('/confirm_email/<token>')
def confirm_email(token):
  try:
    user_data = s.loads(token, salt='email-confirm', max_age=3600)

    username = user_data['username']
    email = user_data['email']
    hashed_pw = generate_password_hash(user_data['password'])

    user = Users(username=username, email=email, password_hash=hashed_pw, date_added=datetime.now(), level="2")
    db.session.add(user)
    db.session.commit()

    flash("Email verified successfully. Please log in.", "success")
    return redirect(url_for("main.login"))

  except SignatureExpired:
    flash("That link has expired!", "danger")
    return redirect(url_for('main.signup'))
  
  except:
    flash("Email verified successfully. Please log in.", "success")
    return redirect(url_for("main.login"))


@main.route('/send_password_reset', methods=['GET', 'POST'])
def send_password_reset():
  form = EmailForm()
  #Validate form
  if request.method == "POST":
    if form.validate_on_submit():
      form_email = form.email.data

      user_search = db.session.query(Users).filter_by(email=form_email).first()
      if user_search is None:
        flash("That email could not be found.", "danger")
        form.email.data = ''
          
      else: # filled in form successfully
        username = user_search.username

        token = s.dumps(form_email, salt='password-reset')
        msg = Message('Password Reset - Exam Countdown', sender='inbox@myexams.net', recipients=[form_email])
        link = url_for('main.verify_password_reset', token=token, _external=True)
        msg.body = f'Hello, {username}!\nTo reset your Exam Countdown password, click the link below:\n{link}\n\nThis link will expire in 1 hour.\n\nIf you did not request a password reset, you can ignore this email.'
        mail.send(msg)

        flash(Markup("A password reset link has been sent to your email.<br>Please also check your junk folder."), "info")
        return redirect(url_for("main.login"))

  return render_template('send_password_reset.html', form=form)


@main.route('/verify_password_reset/<token>', methods=['GET', 'POST'])
def verify_password_reset(token):
  form = PwdResetForm()
  #Validate form
  if request.method == "POST":
    if form.validate_on_submit():
      password1 = form.password1.data
      password2 = form.password2.data

      if password1 != password2:
        flash("Passwords do not match! Please try again.")
        form.password1.data = ''
        form.password2.data = ''

      else:
        try:
          email = s.loads(token, salt='password-reset', max_age=3600)
          user = db.session.query(Users).filter_by(email=email).first()
          user.password_hash = generate_password_hash(password1)
          db.session.commit()
          
          flash("Password reset successfully. Please log in.", "success")
          return redirect(url_for("main.login"))

        except SignatureExpired:
          flash("That link has expired!", "danger")
          return redirect(url_for('main.signup'))

        except Exception as e:
          flash(f"An Error has occurred! {e}", "danger")

  try:
    email = s.loads(token, salt='password-reset', max_age=3600)

  except SignatureExpired:
    flash("That link has expired!", "danger")
    return redirect(url_for('main.signup'))

  except Exception as e:
    flash(f"An Error has occurred! {e}", "danger")

  return render_template("reset_password.html", form=form)


@main.route("/logout")
def logout():
  logout_user()
  flash("You have been logged out.", "success")
  return redirect(url_for("main.login"))


@main.route('/delete_user/<int:id>')
@login_required
def delete_user(id): 
	# Check logged in id vs. id to delete
  if id == current_user.id:
    try:
      user_to_delete = db.session.query(Users).get_or_404(id)

      db.session.delete(user_to_delete)
      db.session.commit()
      flash("User Deleted Successfully.", "success")

      return redirect(url_for("main.login"))

    except:
      flash("Error! We could not delete this user.", "danger")
      return redirect(url_for('main.profile_options'))
    
  else:
    flash("Sorry, you can't delete that user!", "danger")
    return redirect(url_for('main.profile_options'))

@main.route("/all_timetable/<level>")
def all_timetable(level):
  all_exams = Exams.query.filter(and_(Exams.time.isnot(None), 
                                          Exams.time != '', 
                                          Exams.level == level,
                                          )).order_by(Exams.date, Exams.subject, Exams.board).all()
  
  level = "GCSE" if level == "2" else "A Level" if level == "3a" else "AS Level"

  return render_template('timetable.html', exams=all_exams, level=level)


@main.route("/timetable")
@login_required
def timetable():
  level = current_user.level

  shown_exams = []
  selected_exams = current_user.selected_subjects
  for exam in selected_exams:
    board = exam['board']
    subject = exam['subject']
    base_subject = exam['base_subject']
    tier = exam['tier'] if exam['tier'] != "-" else ""

    current_exams = Exams.query.filter(and_(Exams.time.isnot(None), 
                                            Exams.time != '', 
                                            Exams.level == level,
                                            Exams.base_subject == base_subject, 
                                            Exams.board == board, 
                                            Exams.subject == subject,
                                            Exams.tier == tier,
                                            )).order_by(Exams.date).all()

    for current_exam in current_exams:
      shown_exams.append(current_exam)

  return render_template('timetable.html', exams=shown_exams)

def showExams(exams):
  # Get the current date and time
  now = datetime.now()

  # Dictionary to store the soonest future event for each base_subject grouped by category
  exams_by_category = {}

  for exam in exams:
    # Ensure the exam has a time value and is in the future
    if exam.time and exam.date > now:
      category = exam.category
      base_subject = exam.base_subject
      # Initialize the category key if it doesn't exist
      if category not in exams_by_category:
        exams_by_category[category] = {}

      # Check if the base_subject has a sooner exam date
      if base_subject not in exams_by_category[category] or exam.date < exams_by_category[category][base_subject].date:
        exams_by_category[category][base_subject] = exam

  # Define the desired order of categories
  ordered_categories = ["Maths", "English", "Science", "Humanities & Social Sciences", "Modern Languages", "Arts & Design", "Other"]

  # Filter and sort the exams by the ordered categories
  ordered_exams_by_category = {category: exams_by_category[category] for category in ordered_categories if category in exams_by_category}

  return ordered_exams_by_category


@main.route("/exams/<string:level>")
def exams(level):
  if current_user.is_authenticated:
    # Fetch all exams from the database
    subjects = []
    for subject in current_user.selected_subjects:
      subjects.append(subject['subject'])

    exams = Exams.query.filter(and_(Exams.subject.in_(subjects),
                                    Exams.level == level,
                                    )).all()

  else:
    exams = Exams.query.filter_by(level=level).all()

  ordered_exams_by_category = showExams(exams)

  return render_template('exams.html', exams_by_category=ordered_exams_by_category)


@main.route('/subject/<string:level>/<string:base_subject>')
def show_selected_subject(level, base_subject):
  if current_user.is_authenticated:
    shown_exams = []
    selected_exams = current_user.selected_subjects
    for exam in selected_exams:
      board = exam['board']
      subject = exam['subject']
      tier = exam['tier'] if exam['tier'] != "-" else ""

      current_exams = Exams.query.filter(and_(Exams.time.isnot(None), 
                                              Exams.time != '', 
                                              Exams.level == level,
                                              Exams.base_subject == base_subject, 
                                              Exams.board == board, 
                                              Exams.subject == subject,
                                              Exams.tier == tier,
                                              )).order_by(Exams.date).all()

      for current_exam in current_exams:
        shown_exams.append(current_exam)

  else:
    # Fetch all exams for the selected base_subject
    shown_exams = Exams.query.filter(and_(Exams.base_subject == base_subject, 
                                          Exams.time.isnot(None), 
                                          Exams.time != '',
                                          Exams.level == level
                                          )).order_by(Exams.date).all()
  return render_template('selected_subject.html', base_subject=base_subject, exams=shown_exams, level=level)


@main.route('/profile_options', methods=['GET', 'POST'])
@login_required
def profile_options():
  update_form = UpdateForm()
  confirm_pwd_form = ConfirmPwdForm()
  old_pwd_reset_form = OldPwdResetForm()

  user_to_update = db.session.get(Users, current_user.id)

  if request.method == "POST":
    form_type = request.form.get('form_type', '')  # Avoid KeyError
    
    if form_type == "update_profile":
      new_username = request.form.get('username', '').strip()
      new_email = request.form.get('email', '').strip()

      # Check if username/email were actually changed
      username_taken = new_username != current_user.username and Users.query.filter_by(username=new_username).first()
      email_taken = new_email != current_user.email and Users.query.filter_by(email=new_email).first()

      if not username_taken and not email_taken:
        user_to_update.username = new_username
        user_to_update.email = new_email

        try:
          db.session.commit()
          flash("User updated successfully.", "success")
          return redirect(url_for("main.profile_options"))  # Prevent resubmission
        except:
          flash("Error! Something went wrong while updating the profile.", "danger")
      else:
        if username_taken:
          flash("Error! A user with that username already exists. Please choose a different username.", "danger")
        if email_taken:
          flash("Error! A user with that email already exists. Please use a different email.", "danger")

    elif form_type == "confirm_pwd":
      password = request.form.get('password', '')

      if check_password_hash(current_user.password_hash, password):
        return redirect(url_for("main.delete_user", id=current_user.id))
      else:
        flash("Wrong password! Could not delete your account.", "danger")

    elif form_type == "password_reset":
      old_password = request.form.get('oldPassword', '')
      new_password1 = request.form.get('password1', '')
      new_password2 = request.form.get('password2', '')

      if check_password_hash(current_user.password_hash, old_password):
        if new_password1 == new_password2:
          current_user.password_hash = generate_password_hash(new_password1)
          db.session.commit()
          flash("Updated password successfully.", "success")
          return redirect(url_for("main.profile_options"))  # Prevent resubmission
        else:
          flash("The two new passwords don't match! Please try again.", "danger")
      else:
        flash("Wrong password! Could not update your password.", "danger")

  return render_template(
      "profile_options.html",
      update_form=update_form,
      confirm_pwd_form=confirm_pwd_form,
      old_pwd_reset_form=old_pwd_reset_form,
      user_to_update=user_to_update
  )


@main.route('/exam_options', methods=['GET', 'POST'])
@login_required
def exam_options():
  form_id = request.form.get('form_id')
  qualForm = QualForm()
  timeForm = TimeForm()

  if request.method == 'GET':
    qualForm.Qualification.data = str(current_user.level)  # Set default value

  elif request.method == 'POST':
    if qualForm.validate_on_submit():
      if current_user.level != qualForm.Qualification.data: # if changed
        current_user.level = qualForm.Qualification.data
        current_user.selected_subjects = []

        # Save the changes to the database
        db.session.commit()

        flash(f"Updated profile.", "success")

        return redirect(url_for('main.exam_options'))
    
    elif timeForm.validate_on_submit():
      current_user.exam_start_time_am = timeForm.AM_time.data.strftime('%H:%M')
      current_user.exam_start_time_pm = timeForm.PM_time.data.strftime('%H:%M')

      db.session.commit()

      flash(f"Updated exam times.", "success")

      return redirect(url_for('main.exam_options'))
    
    elif form_id == "add-subject-form":
      base_subject = request.form.get('base_subject')
      board = request.form.get('board')
      subject = request.form.get('subject')
      tier = request.form.get('tier')

      # Create a dictionary representing the exam selection
      exam_selection = {
          'id': str(uuid4()),
          'base_subject': base_subject,
          'board': board,
          'subject': subject,
          'tier': tier,
          'date_added': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
      }

      # Append this selection to the user's selected_exams list
      if current_user.selected_subjects is None:
          current_user.selected_subjects = []
      
      current_user.selected_subjects.append(exam_selection)
      
      # Save the changes to the database
      db.session.commit()

      flash(f"Added {base_subject}.", "success")

      return redirect(url_for('main.exam_options'))

  unique_categories = Exams.query.with_entities(Exams.category, Exams.base_subject).filter_by(level=current_user.level).distinct().all()

  categories = {}
  for category, subject in unique_categories:
    if category not in categories:
      categories[category] = []
    categories[category].append(subject)


  # Render the page with the current user's selected exams
  return render_template('exam_options.html', 
                          selected_subjects=current_user.selected_subjects,
                          categories=categories,
                          qualForm=qualForm,
                          timeForm=timeForm,
                          am_start_time=current_user.exam_start_time_am or "09:00",
                          pm_start_time=current_user.exam_start_time_pm or "13:30",
                          )

@main.route('/get_base_subjects', methods=['GET'])
def get_base_subjects():
  category = request.args.get('category')
  # Query unique boards for the selected base_subject
  unique_base_subjects = Exams.query.with_entities(Exams.base_subject).filter_by(level=current_user.level, category=category).distinct().all()
  unique_base_subjects = [x[0] for x in unique_base_subjects]
  
  return jsonify(unique_base_subjects)

@main.route('/get_boards', methods=['GET'])
def get_boards():
  base_subject = request.args.get('base_subject')
  # Query unique boards for the selected base_subject
  unique_boards = Exams.query.with_entities(Exams.board).filter_by(level=current_user.level, base_subject=base_subject).distinct().all()
  unique_boards = [x[0] for x in unique_boards]
  
  return jsonify(unique_boards)

@main.route('/get_subjects', methods=['GET'])
def get_subjects():
  base_subject = request.args.get('base_subject')
  board = request.args.get('board')
  # Query unique subjects for the selected base_subject and board
  unique_subjects = Exams.query.with_entities(Exams.subject).filter_by(level=current_user.level, base_subject=base_subject, board=board).distinct().all()
  unique_subjects = [x[0] for x in unique_subjects]
  
  return jsonify(unique_subjects)

@main.route('/get_tiers', methods=['GET'])
def get_tiers():
  base_subject = request.args.get('base_subject')
  board = request.args.get('board')
  subject = request.args.get('subject')

  # Query unique subjects for the selected base_subject and board
  unique_tiers = Exams.query.with_entities(Exams.tier).filter_by(level=current_user.level, base_subject=base_subject, board=board, subject=subject).distinct().all()
  unique_tiers = [x[0] for x in unique_tiers]
  
  return jsonify(unique_tiers)

@main.route('/check_subject_tier', methods=['GET'])
def check_subject_tier():
  base_subject = request.args.get('base_subject')
  board = request.args.get('board')
  subject = request.args.get('subject')

  exam_tiers = Exams.query.with_entities(Exams.tier).filter_by(level=current_user.level, base_subject=base_subject, board=board, subject=subject).all()
  try:
    has_tier = True if exam_tiers[0][0] != '' else False
  except IndexError:
    has_tier = False

  return jsonify({"has_tier": has_tier})

@main.route('/delete_subject', methods=['POST'])
def delete_subject():
  subject_id = request.form.get('subject_id')

  if current_user.is_authenticated:
    selected_subjects = current_user.selected_subjects
    
    # Filter out the subject to delete
    selected_subjects = [subject for subject in selected_subjects if subject.get('id') != subject_id]
    
    # Update the user's selected subjects
    current_user.selected_subjects = selected_subjects
    db.session.commit()
    
    flash('Subject successfully deleted.', 'success')
  else:
    flash('You need to be logged in to delete a subject.', 'danger')

  return redirect(url_for('main.exam_options'))


@main.route("/privacy_policy")
def privacy_policy():
  return render_template('privacy_policy.html')