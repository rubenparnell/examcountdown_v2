from flask import Blueprint, request, render_template, redirect, url_for, current_app, abort, session, jsonify
from markupsafe import Markup
from flask_login import login_user, logout_user, current_user, login_required
import os
import logging
from datetime import datetime
import requests
import uuid

from app import supabase, supabase_admin
from shared_db.db import db
from shared_db.models import Users, Exams, UserSubjects
from app.forms import LoginForm, SignUpForm, UpdateForm, MigrationForm, ConfirmPwdForm, OldPwdResetForm, PwdResetForm, EmailForm, QualForm, TimeForm
from app.helpers import flash

logging.basicConfig(level=logging.DEBUG)

user = Blueprint('user', __name__, url_prefix='/user')

@user.route("/signup", methods=['GET', 'POST'])
def signup():
    reCAPTCHA_site_key = os.environ.get("RECAPTCHA_SITE_KEY")

    VERIFY_URL = "https://www.google.com/recaptcha/api/siteverify"
    RECAPTCHA_SECRET_KEY = os.environ.get("RECAPTCHA_SECRET_KEY")

    form = SignUpForm()
    # Validate form
    if form.validate_on_submit():
        secret_response = request.form['g-recaptcha-response']
        verify_response = requests.post(url=f"{VERIFY_URL}?secret={RECAPTCHA_SECRET_KEY}&response={secret_response}").json()
        if verify_response['success'] == False or verify_response['score'] < 0.5:
            abort(403)

        form_email = form.email.data.strip().lower()
        form_username = form.username.data.strip()
        form_password = form.password1.data
        form_password_2 = form.password2.data

        # Basic validation
        if form_password != form_password_2:
            flash("Passwords do not match. Please try again.", "danger")
            return render_template('signup.html', form=form, reCAPTCHA_site_key=reCAPTCHA_site_key)

        # Check for existing username or email in the users table
        if db.session.query(Users).filter(Users.username.ilike(form_username)).first():
            flash("That username is already used. Please pick a different one.", "danger")
            return render_template('signup.html', form=form, reCAPTCHA_site_key=reCAPTCHA_site_key)
        
        if db.session.query(Users).filter(Users.email.ilike(form_email)).first():
            flash(Markup(f"A user with that email already exists. Please <a href=\"{url_for('user.login')}\">log in</a>."), "danger")
            return render_template('signup.html', form=form, reCAPTCHA_site_key=reCAPTCHA_site_key)

        # Create Supabase Auth user
        try:
            confirm_url = f"{request.url_root.strip('/')}{url_for('user.confirm_email')}"
            result = supabase.auth.sign_up({
                "email": form_email,
                "password": form_password,
                "options": {
                    "email_redirect_to": confirm_url
                }
            })

            user = result.user
            if user is None:
                flash("Signup failed. Please try again later.", "danger")
                return render_template('signup.html', form=form, reCAPTCHA_site_key=reCAPTCHA_site_key)

            # Add to your local Users table
            new_user = Users(
                auth_id=user.id,
                username=form_username,
                email=form_email,
                date_added=datetime.now(),
                is_admin=False
            )
            db.session.add(new_user)
            db.session.commit()

            login_user(new_user)
            session['supabase_user'] = user.id

            flash("Signed up successfully. Please check your email to confirm your account.", "info", persistent=True, position="top")

            return redirect(url_for('user.login'))
        
        except Exception as e:
            flash(f"Error creating user in Supabase: {e}", "danger")
            return render_template('signup.html', form=form, reCAPTCHA_site_key=reCAPTCHA_site_key)
    
    # Catch validation errors and flash them
    if form.errors:
        for field, errors in form.errors.items():
            for error in errors:
                flash(Markup(f"<strong>{field.capitalize()} Error:</strong> {error}"), "danger")

    return render_template('signup.html', form=form, reCAPTCHA_site_key=reCAPTCHA_site_key)


@user.route("/login", methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data.strip()
        password = form.password.data
        
        user = db.session.query(Users).filter(Users.email.ilike(email)).first()

        if user:
            if user.auth_id:
                try:
                    result = supabase.auth.sign_in_with_password({
                        "email": email,
                        "password": password
                    })
                except Exception as e:
                    flash(f"Login failed: {e}", "danger")
                    return render_template('login.html', form=form)

                sb_user = result.user
                if sb_user:
                    local_user = db.session.query(Users).filter_by(auth_id=sb_user.id).first()
                    if not local_user:
                        # auto-create if missing
                        local_user = Users(auth_id=sb_user.id, email=email, username=email.split('@')[0])
                        db.session.add(local_user)
                        db.session.commit()

                    login_user(local_user, remember=form.rememberMe.data)
                    session['supabase_user'] = sb_user.id

                    flash("Successfully logged in.", "success")
                    return redirect(url_for('main.home'))
                else:
                    flash("Invalid credentials.", "danger")
            
            else:
                # Legacy user → show migration notice
                session["pending_email"] = email
                return redirect(url_for("user.migration"))
        else:
            flash(Markup("User not found! Try a different username or <a href="+url_for("user.signup")+">sign up</a>."), "danger")

    return render_template('login.html', form=form)


@user.route("/migration", methods=['GET', 'POST'])
def migration():
    migration_form = MigrationForm()

    email = session.get("pending_email")
    db_user = db.session.query(Users).filter(Users.email.ilike(email)).first()

    if not db_user:
        return redirect(url_for("user.login"))

    if migration_form.validate_on_submit():
        form_password = migration_form.password1.data
        form_password_2 = migration_form.password2.data

        # Basic validation
        if form_password != form_password_2:
            flash("Passwords do not match. Please try again.", "danger")
            return render_template('signup.html', form=migration_form)

        # Create Supabase Auth user
        try:
            result = supabase.auth.sign_up({
                "email": email,
                "password": form_password,
                "options": {
                "email_redirect_to": url_for("user.confirm_email", _external=True)
                }
            })
        except Exception as e:
            flash(f"Error creating user in Supabase: {e}", "danger")
            return render_template('signup.html', form=migration_form)

        sb_user = result.user
        if sb_user is None:
            flash("Signup failed. Please try again later.", "danger")
            return render_template('signup.html', form=migration_form)

        # Add to your local Users table
        db_user.auth_id = sb_user.id
        db.session.commit()

        flash("Migrated successfully. Please check your email to confirm your account.", "info", persistent=True, position="top")

        return redirect(url_for('user.login'))

    # Catch validation errors and flash them
    if migration_form.errors:
        for field, errors in migration_form.errors.items():
            for error in errors:
                flash(Markup(f"<strong>{field.capitalize()} Error:</strong> {error}"), "danger")

    return render_template('migration.html', form=migration_form)


@user.route("/confirm_email")
def confirm_email():
    return render_template("confirm_email.html")


@user.route("/set_session", methods=["POST"])
def set_session():
    data = request.get_json()
    access_token = data.get("access_token")
    refresh_token = data.get("refresh_token")

    if not access_token:
        return jsonify({"error": "Missing access token"}), 400

    try:
        # Set the Supabase session and fetch user info
        supabase.auth.set_session(access_token, refresh_token)
        user_response = supabase.auth.get_user()
        supa_user = user_response.user

        if not supa_user:
            return jsonify({"error": "Invalid Supabase session"}), 400

        # Find local user in your database
        local_user = db.session.query(Users).filter_by(auth_id=supa_user.id).first()
        if not local_user:
            return jsonify({"error": "User not found in local database"}), 404

        # Log in the user locally
        login_user(local_user)
        session['supabase_user'] = supa_user.id

        flash("Email confirmed. You are now logged in.", "success")
        return jsonify({"success": True, "redirect": url_for('main.home')})

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@user.route("/logout")
@login_required
def logout():
    session.pop('supabase_user', None)
    logout_user()
    supabase.auth.sign_out()  # clears Supabase session token
    flash("You have been logged out.", "success")
    return redirect(url_for('user.login'))


@user.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    update_form = UpdateForm()
    confirm_pwd_form = ConfirmPwdForm()
    old_pwd_reset_form = OldPwdResetForm()

    if request.method == "POST":
        form_type = request.form.get('form_type', '')

        # --- Update profile info (not password) ---
        if form_type == "update_profile" and update_form.validate_on_submit():
            new_username = update_form.username.data.strip()

            username_taken = (
                new_username != current_user.username
                and db.session.query(Users).filter(Users.username.ilike(new_username)).first()
            )

            if username_taken:
                flash("A user with that username already exists. Please choose another.", "danger")
            else:
                # Update username, default level, subjects
                current_user.username = new_username

                # --- Handle profile picture upload ---
                file = update_form.profile_picture.data
                if file:
                    # Remove the old file
                    if current_user.profile_picture:
                        # Extract filename from URL
                        old_file = current_user.profile_picture.split("/")[-1]
                        supabase_admin.storage.from_("ProfilePictures").remove([old_file])

                    ext = file.filename.rsplit('.', 1)[-1].lower() if '.' in file.filename else 'jpg'
                    filename = f"{current_user.id}_{uuid.uuid4().hex}.{ext}"
                    try:
                        # Read the file bytes
                        file_bytes = file.read()

                        # Upload bytes to Supabase bucket
                        res = supabase_admin.storage.from_("ProfilePictures").upload(
                            path=filename,
                            file=file_bytes,
                            file_options={"content-type": file.mimetype}
                        )

                        public_url = supabase_admin.storage.from_("ProfilePictures").get_public_url(filename)
                        current_user.profile_picture = public_url
                    except Exception as e:
                        flash(f"Profile picture upload error: {e}", "danger")

                db.session.commit()
                flash("Profile updated successfully.", "success")

            return redirect(url_for("user.profile"))

        # --- Request account deletion confirmation ---
        elif form_type == "confirm_pwd" and confirm_pwd_form.validate_on_submit():
            password = confirm_pwd_form.password.data

            try:
                # Re-authenticate with Supabase
                session_data = supabase.auth.sign_in_with_password({
                    "email": current_user.email,
                    "password": password
                })

                if not session_data.user:
                    flash("Password is incorrect. Cannot delete account.", "danger")
                    return redirect(url_for("user.profile"))

                # Delete from Supabase using admin client
                if current_user.auth_id:
                    try:
                        supabase_admin.auth.admin.delete_user(current_user.auth_id)
                    except Exception as e:
                        flash(f"Error deleting user from Supabase: {e}", "danger")
                        return redirect(url_for("user.profile"))

                # Delete from local DB
                user_to_delete = db.session.query(Users).get_or_404(current_user.id)
                db.session.delete(user_to_delete)
                db.session.commit()

                flash("Your account has been deleted successfully.", "success")
                logout_user()
                return redirect(url_for("main.home"))

            except Exception as e:
                flash(f"Error deleting account: {e}", "danger")
                return redirect(url_for("user.profile"))

        # --- Change password using Supabase ---
        elif form_type == "password_reset" and old_pwd_reset_form.validate_on_submit():
            old_password = old_pwd_reset_form.oldPassword.data
            new_password1 = old_pwd_reset_form.password1.data
            new_password2 = old_pwd_reset_form.password2.data

            if new_password1 != new_password2:
                flash("The two new passwords don't match! Please try again.", "danger")
            else:
                try:
                    # Re-authenticate with Supabase
                    session_data = supabase.auth.sign_in_with_password({
                        "email": current_user.email,
                        "password": old_password
                    })

                    if not session_data.user:
                        flash("Old password is incorrect.", "danger")
                    else:
                        # Set the session so update_user uses it
                        supabase.auth.session = session_data.session

                        # Update the password
                        supabase.auth.update_user({"password": new_password1})

                        flash("Password updated successfully.", "success")
                        return redirect(url_for("user.profile"))

                except Exception as e:
                    flash(f"Error updating password: {e}", "danger")

    # Flash validation errors
    if update_form.errors:
        for field, errors in update_form.errors.items():
            for error in errors:
                flash(Markup(f"<strong>{field.capitalize()} Error:</strong> {error}"), "danger")

    return render_template(
        "profile_options.html",
        update_form=update_form,
        confirm_pwd_form=confirm_pwd_form,
        old_pwd_reset_form=old_pwd_reset_form,
    )


@user.route('/send_password_reset', methods=['GET', 'POST'])
def send_password_reset():
    form = EmailForm()
    if form.validate_on_submit():
        form_email = form.email.data.strip().lower()

        # Check if the user has migrated
        user = db.session.query(Users).filter_by(email=form_email).first()
        if user and user.auth_id:
            try:
                # Trigger Supabase to send reset link
                supabase.auth.reset_password_email(form_email, {"redirect_to": url_for("user.reset_password", _external=True)})
                flash(Markup(
                    "A password reset link has been sent to your email.<br>Please also check your junk folder."
                ), "info", persistent=True, position="top")
                return redirect(url_for("user.login"))
            except Exception as e:
                flash(f"Error sending reset email: {e}", "danger")

        elif user and not user.auth_id:
            session["pending_email"] = user.email
            return redirect(url_for("user.migration"))
        
        else:
            flash("User not found.", "danger")

    return render_template('send_password_reset.html', form=form)


@user.route("/reset_password", methods=["GET", "POST"])
def reset_password():
    form = PwdResetForm()

    if form.validate_on_submit():
        access_token = request.form.get("access_token")
        password1 = form.password1.data
        password2 = form.password2.data

        if password1 != password2:
            flash("Passwords do not match!", "danger")
            return render_template("reset_password.html", form=form)

        if not access_token:
            flash("Missing or invalid reset token.", "danger")
            return render_template("reset_password.html", form=form)

        # Use Supabase REST API to update password with token
        url = f"{os.getenv('SUPABASE_URL')}/auth/v1/user"
        headers = {
            "Authorization": f"Bearer {access_token}",
            "apikey": os.getenv("SUPABASE_KEY"),
            "Content-Type": "application/json"
        }
        payload = {"password": password1}

        resp = requests.put(url, headers=headers, json=payload)
        if resp.status_code == 200:
            flash("Password reset successfully. You can now log in.", "success")
            return redirect(url_for("user.login"))
        else:
            flash(f"Error resetting password: {resp.json().get('msg', resp.text)}", "danger")

    return render_template("reset_password.html", form=form)


@user.route('/exam_options', methods=['GET', 'POST'])
@login_required
def exam_options():
  form_id = request.form.get('form_id')
  qualForm = QualForm()
  timeForm = TimeForm()

  if request.method == 'GET':
    qualForm.Qualification.data = current_user.default_level

  elif request.method == 'POST':
    if qualForm.validate_on_submit():
      if current_user.default_level != qualForm.Qualification.data: # if changed
        current_user.default_level = qualForm.Qualification.data
        # Delete all selected subjects
        current_user.subjects.clear()

        # Save the changes to the database
        db.session.commit()

        flash(f"Updated profile.", "success")

        return redirect(url_for('user.exam_options'))
    
    elif timeForm.validate_on_submit():
      current_user.exam_start_time_am = timeForm.AM_time.data.strftime('%H:%M')
      current_user.exam_start_time_pm = timeForm.PM_time.data.strftime('%H:%M')

      db.session.commit()

      flash(f"Updated exam times.", "success")

      return redirect(url_for('user.exam_options'))
    
    elif form_id == "add-subject-form":
      base_subject = request.form.get('base_subject')
      board = request.form.get('board')
      subject = request.form.get('subject')
      tier = request.form.get('tier')
      if tier == "-":
        tier = None

      # Append this selection to the user's selected_exams list
      new_subject = UserSubjects(
        id=str(uuid.uuid4()),
        user_id=current_user.id,
        base_subject=base_subject,
        subject=subject,
        tier=tier,
        board=board,
        date_added=datetime.now()
      )

      current_user.subjects.append(new_subject)
      
      # Save the changes to the database
      db.session.commit()

      flash(f"Added {base_subject}.", "success")

      return redirect(url_for('user.exam_options'))

  unique_categories = (
    db.session.query(Exams).with_entities(Exams.category, Exams.base_subject)
    .filter_by(level=current_user.default_level)
    .distinct()
    .all()
  )

  categories = {}
  for category, subject in unique_categories:
    if category not in categories:
      categories[category] = []
    categories[category].append(subject)

  # Render the page with the current user's selected exams
  return render_template(
    'exam_options.html', 
    selected_subjects=current_user.subjects,
    categories=categories,
    qualForm=qualForm,
    timeForm=timeForm,
    am_start_time=current_user.exam_start_time_am or "09:00",
    pm_start_time=current_user.exam_start_time_pm or "13:30",
  )
