from flask import Blueprint, render_template, flash, url_for, redirect, request, jsonify
from markupsafe import Markup
from flask_login import login_required, current_user, login_user, logout_user
from flask_mail import Message
from itsdangerous import SignatureExpired
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from sqlalchemy import and_
from uuid import uuid4
from app import db, mail, s
from app.forms import SignUpForm, LoginForm, UpdateForm, ConfirmPwdFrom, EmailForm, PwdResetForm, QualForm
from app.models import Users, GCSE_Exams

main = Blueprint('main', __name__)

@main.route("/")
def home():
  return render_template("home.html")

@main.route("/login", methods=['GET', 'POST'])
def login():
  form = LoginForm()
  if form.validate_on_submit():
    user = db.session.query(Users).filter_by(username=form.username.data).first()
    if user:
      #check the hash
      if check_password_hash(user.password_hash, form.password.data):
        login_user(user)
        current_user.logged_in_counter += 1
        db.session.commit()

        flash("Successfully logged in.", "success")

        if current_user.qualification:
          if current_user.qualification == "GCSE":
            return redirect(url_for('main.gcse'))
          elif current_user.qualification == "A Level":
            return redirect(url_for('main.a_level'))
        else:
          return redirect(url_for('main.home'))
      else:
        flash("Wrong password.", "danger")
    else:
      flash(Markup("User not found! Try a different username or <a href="+url_for("main.signup")+">sign up</a>."), "danger")
  return render_template('login.html', form=form)


@main.route("/signup", methods=['GET', 'POST'])
def signup():
  form = SignUpForm()
  #Validate form
  if form.validate_on_submit():
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
        msg = Message('Confirm your email address - Exam Countdown', sender='examcountdown@outlook.com', recipients=[form_email])
        link = url_for('main.confirm_email', token=token, _external=True)
        msg.body = f'Hello, {form_username}!\nTo complete signing up with Exam Countdown, confirm your email using the link below:\n{link}\n\nThis link will expire in 1 hour.\n\nIf you did not sign up, you can ignore this email.'
        mail.send(msg)

        flash(Markup("A comfirmation link has been sent to your email.<br>Please also check your junk folder."), "info")
        return redirect(url_for("main.login"))
    
    else:
      if not(current_email is None):
        flash(Markup("That email is already used for another account. Please <a href="+url_for("main.login")+">log in</a> or use a different email."), "danger")
        form.email.data = ''
      if not(current_username is None):
        flash("That username is already used. Please pick a different one.", "danger")
        form.username.data = ''

  return render_template('signup.html', form=form)


@main.route('/confirm_email/<token>')
def confirm_email(token):
  try:
    user_data = s.loads(token, salt='email-confirm', max_age=3600)

    username = user_data['username']
    email = user_data['email']
    hashed_pw = generate_password_hash(user_data['password'])

    user = Users(username=username, email=email, password_hash=hashed_pw, date_added=datetime.now())
    db.session.add(user)
    db.session.commit()

    flash("Email verified successfully. Please log in.", "success")
    return redirect(url_for("main.login"))

  except SignatureExpired:
    flash("That link has expired!", "danger")
    return redirect(url_for('main.signup'))


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
        msg = Message('Password Reset - Exam Countdown', sender='examcountdown@outlook.com', recipients=[form_email])
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

  return render_template("reset_password.html", form=form)


@main.route("/logout")
def logout():
  logout_user()
  flash("You have been logged out.", "success")
  return redirect(url_for("main.login"))


# @main.route('/delete_user/<int:id>')
# @login_required
# def delete(id):
# 	# Check logged in id vs. id to delete
#   if id == current_user.id:
#     try:
#       delete_user_bl_orders(id)
#       delete_user_bo_orders(id)
#       delete_user_bl_logs(id)
#       delete_user_bo_logs(id)

#       user_to_delete = db.session.query(Users).get_or_404(id)

#       if user_to_delete.BL_OrdersJobID:
#         scheduler.cancel(user_to_delete.BL_OrdersJobID)
#       if user_to_delete.BO_OrdersJobID:
#         scheduler.cancel(user_to_delete.BO_OrdersJobID)

#       db.session.delete(user_to_delete)
#       db.session.commit()
#       flash("User Deleted Successfully.", "success")

#       return redirect(url_for("main.login"))

#     except:
#       flash("Error! We could not delete this user.", "danger")
#       return redirect(url_for('main.profile'))
    
#   else:
#     flash("Sorry, you can't delete that user!", "danger")
#     return redirect(url_for('main.profile'))


@main.route("/a-level")
def a_level():
  return render_template("a-level.html")

@main.route("/gcse")
def gcse():
    # Fetch all exams from the database
    if current_user.is_authenticated:
      subjects = []
      for subject in current_user.selected_subjects:
        subjects.append(subject['subject'])

      exams = GCSE_Exams.query.filter(GCSE_Exams.subject.in_(subjects)).all()
    else:
      exams = GCSE_Exams.query.all()
    
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
    ordered_categories = ["Maths", "English", "Science", "Humanities", "Languages", "Sports", "Arts", "DT", "Other"]

    # Filter and sort the exams by the ordered categories
    ordered_exams_by_category = {category: exams_by_category[category] for category in ordered_categories if category in exams_by_category}

    return render_template('gcse.html', exams_by_category=ordered_exams_by_category)



@main.route('/subject/<string:base_subject>')
def show_selected_subject(base_subject):
  if current_user.is_authenticated:
    shown_exams = []
    selected_exams = current_user.selected_subjects
    for exam in selected_exams:
      board = exam['board']
      subject = exam['subject']
      tier = exam['tier'] if exam['tier'] != "-" else ""

      current_exams = GCSE_Exams.query.filter(and_(GCSE_Exams.time.isnot(None), 
                                                   GCSE_Exams.time != '', 
                                                   GCSE_Exams.base_subject == base_subject, 
                                                   GCSE_Exams.board == board, 
                                                   GCSE_Exams.subject == subject,
                                                   GCSE_Exams.tier == tier,
                                                   )).order_by(GCSE_Exams.date).all()

      for current_exam in current_exams:
        shown_exams.append(current_exam)

  else:
    # Fetch all exams for the selected base_subject
    shown_exams = GCSE_Exams.query.filter(and_(GCSE_Exams.base_subject == base_subject, GCSE_Exams.time.isnot(None), GCSE_Exams.time != '')).order_by(GCSE_Exams.date).all()
  return render_template('selected_subject.html', base_subject=base_subject, exams=shown_exams)

@main.route('/test')
def test():
  return current_user.selected_subjects

@main.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    form_id = request.form.get('form_id')
    qualForm = QualForm()

    if request.method == 'GET':
      qualForm.Qualification.data = current_user.qualification  # Set default value

    elif request.method == 'POST':
      if qualForm.validate_on_submit():
        qual_selected = qualForm.Qualification.data
    
        if qual_selected == "GCSE":
          current_user.qualification = "GCSE"
        elif qual_selected == "A Level":
          current_user.qualification = "A Level"

        # Save the changes to the database
        db.session.commit()

        flash(f"Updated profile.", "success")

        return redirect(url_for('main.profile'))
      
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

        return redirect(url_for('main.profile'))

    unique_categories = GCSE_Exams.query.with_entities(GCSE_Exams.category).distinct().all()
    unique_categories = [x[0] for x in unique_categories]

    # Render the page with the current user's selected exams
    return render_template('profile.html', 
                           selected_subjects=current_user.selected_subjects,
                           categories=unique_categories,
                           qualForm=qualForm
                           )

@main.route('/get_base_subjects', methods=['GET'])
def get_base_subjects():
    category = request.args.get('category')
    # Query unique boards for the selected base_subject
    unique_base_subjects = GCSE_Exams.query.with_entities(GCSE_Exams.base_subject).filter_by(category=category).distinct().all()
    unique_base_subjects = [x[0] for x in unique_base_subjects]
    
    return jsonify(unique_base_subjects)

@main.route('/get_boards', methods=['GET'])
def get_boards():
    base_subject = request.args.get('base_subject')
    # Query unique boards for the selected base_subject
    unique_boards = GCSE_Exams.query.with_entities(GCSE_Exams.board).filter_by(base_subject=base_subject).distinct().all()
    unique_boards = [x[0] for x in unique_boards]
    
    return jsonify(unique_boards)

@main.route('/get_subjects', methods=['GET'])
def get_subjects():
    base_subject = request.args.get('base_subject')
    board = request.args.get('board')
    # Query unique subjects for the selected base_subject and board
    unique_subjects = GCSE_Exams.query.with_entities(GCSE_Exams.subject).filter_by(base_subject=base_subject, board=board).distinct().all()
    unique_subjects = [x[0] for x in unique_subjects]
    
    return jsonify(unique_subjects)

@main.route('/get_tiers', methods=['GET'])
def get_tiers():
    base_subject = request.args.get('base_subject')
    board = request.args.get('board')
    subject = request.args.get('subject')

    # Query unique subjects for the selected base_subject and board
    unique_tiers = GCSE_Exams.query.with_entities(GCSE_Exams.tier).filter_by(base_subject=base_subject, board=board, subject=subject).distinct().all()
    unique_tiers = [x[0] for x in unique_tiers]
    
    return jsonify(unique_tiers)

@main.route('/check_subject_tier', methods=['GET'])
def check_subject_tier():
  base_subject = request.args.get('base_subject')
  board = request.args.get('board')
  subject = request.args.get('subject')

  exam_tiers = GCSE_Exams.query.with_entities(GCSE_Exams.tier).filter_by(base_subject=base_subject, board=board, subject=subject).all()
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

    return redirect(url_for('main.profile'))