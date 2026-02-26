from flask import Blueprint, request, render_template, redirect, url_for, abort, session, jsonify
from markupsafe import Markup
from flask_login import login_user, logout_user, current_user, login_required
import os
from datetime import datetime, timedelta, timezone
import requests
import uuid
import csv
from collections import defaultdict
import random

from app import supabase, supabase_admin
from shared_db.db import db
from shared_db.models import Users, UserSubjects
from app.forms import LoginForm, SignUpForm, UpdateForm, MigrationForm, ConfirmPwdForm, OldPwdResetForm, PwdResetForm, EmailForm, QualForm, TimeForm
from app.helpers import flash

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

SUPABASE_AUTH_URL = f"{SUPABASE_URL}/auth/v1"

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
        form_username = form.username.data.strip()[:50]
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

            session['supabase_user'] = user.id

            flash("Signed up successfully. Please check your email to confirm your account.", "info", persistent=True, position="top")

            return render_template('sign_up_confirm.html')
        
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
                    # --- Store session tokens in Flask session ---
                    if result.session:
                        access_token = result.session.access_token
                        refresh_token = result.session.refresh_token
                        expires_in = result.session.expires_in or 3600

                        session["access_token"] = access_token
                        session["refresh_token"] = refresh_token
                        session["expires_at"] = (datetime.now(timezone.utc) + timedelta(seconds=expires_in)).timestamp()

                        # Also update the Supabase client session (useful for get_user() later)
                        supabase.auth.set_session(access_token, refresh_token)

                except Exception as e:
                    flash(f"Login failed: {e}", "danger")
                    return render_template('login.html', form=form)

                sb_user = result.user
                if sb_user:
                    local_user = db.session.query(Users).filter_by(auth_id=sb_user.id).first()
                    if not local_user:
                        # auto-create if missing
                        local_user = Users(
                            auth_id=user.id,
                            username=email.split('@')[0][:50],
                            email=email,
                            date_added=datetime.now(),
                            is_admin=False
                        )
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
            flash(Markup("User not found! Try a different email or <a href="+url_for("user.signup")+">sign up</a>."), "danger")

    return render_template('login.html', form=form)



@user.route("/login/google")
def google_login():
    # Supabase OAuth endpoint for Google
    redirect_uri = url_for("user.google_callback", _external=True)
    print(redirect_uri)
    google_url = (
        f"{SUPABASE_URL}/auth/v1/authorize"
        f"?provider=google"
        f"&redirect_to={redirect_uri}"
    )
    return redirect(google_url)


@user.route("/auth/callback", methods=["GET"])
def google_callback():
    # Supabase returns tokens in the URL fragment (after '#'), which isn't visible to Flask.
    # Serve a small page that extracts the fragment and forwards tokens to /user/set_session.
    # It will then redirect to the app home (or use the redirect returned by /set_session).
    return render_template("google_callback.html")


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
    expires_in = data.get("expires_in", 3600)

    if not access_token or not refresh_token:
        return jsonify({"error": "Missing tokens"}), 400

    try:
        # 1. Set Supabase session
        session["access_token"] = access_token
        session["refresh_token"] = refresh_token
        session["expires_at"] = (datetime.now(timezone.utc) + timedelta(seconds=expires_in)).timestamp()

        supabase.auth.set_session(access_token, refresh_token)

        # 2. Get user info from Supabase
        user_response = supabase.auth.get_user()
        if not user_response or not user_response.user:
            return jsonify({"error": "Failed to get user info"}), 400

        supabase_user = user_response.user
        email = supabase_user.email

        # 3. Check if user exists in your local DB
        user = db.session.query(Users).filter(Users.email.ilike(email)).first()

        # 4. Create user if they don't exist
        if not user:
            username = supabase_user.user_metadata.get("full_name", "").replace(" ", "")[:50] or email.split("@")[0][:50]
            # Check if the username is taken
            username_taken = db.session.query(Users).filter(Users.username.ilike(username)).first()
            while username_taken:
                username = f"{username}_{random.randint(0, 999)}"
                username_taken = db.session.query(Users).filter(Users.username.ilike(username)).first()
            
            user = Users(
                email=email,
                username=username.lower(),
                profile_picture=supabase_user.user_metadata.get("avatar_url", ""),
                auth_id=supabase_user.id,
                date_added=datetime.now()
            )
            db.session.add(user)
            db.session.commit()

        # 5. Log the user in
        login_user(user)

        # 6. Return success and redirect
        return jsonify({
            "success": True,
            "redirect": url_for("main.home")
        })

    except Exception as e:
        print("Error during Supabase session setup:", e)
        return jsonify({"error": str(e)}), 400


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

    try:
        access_token = session.get("access_token")
        refresh_token = session.get("refresh_token")
        expires_at = session.get("expires_at")


        if not access_token:
            raise ValueError("No access token")

        # Refresh if expired
        if datetime.now(timezone.utc).timestamp() > expires_at:
            refreshed = supabase.auth.refresh_session(refresh_token)
            if not refreshed.user:
                raise ValueError("Refresh failed")
            session["access_token"] = refreshed.session.access_token
            session["refresh_token"] = refreshed.session.refresh_token
            session["expires_at"] = (datetime.now(timezone.utc).timestamp() + refreshed.session.expires_in)

        # Set the valid session before calling get_user
        supabase.auth.set_session(session["access_token"], session["refresh_token"])
        user_response = supabase.auth.get_user()
        supabase_user = user_response.user
        provider = supabase_user.app_metadata.get("provider")

    except Exception as e:
        flash("Session expired or invalid. Please log in again.", "danger")
        logout_user()
        return redirect(url_for("user.login"))

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
            if provider == "email":
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
                
                except Exception as e:
                    db.session.rollback()
                    flash(f"Error deleting account: {e}", "danger")
                    return redirect(url_for("user.profile"))

            try:
                # Delete from DB
                user_to_delete = db.session.query(Users).get_or_404(current_user.id)
                db.session.delete(user_to_delete)
                db.session.commit()

                # Delete from Supabase
                if current_user.auth_id:
                    supabase_admin.auth.admin.delete_user(current_user.auth_id)

                flash("Your account has been deleted successfully.", "success")
                logout_user()
                return redirect(url_for("main.home"))

            except Exception as e:
                db.session.rollback()
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

                    session["access_token"] = session_data.session.access_token
                    session["refresh_token"] = session_data.session.refresh_token
                    session["expires_at"] = (datetime.now(timezone.utc) + timedelta(seconds=session_data.session.expires_in)).timestamp()

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
        provider=provider,
    )


@user.route('/send_password_reset', methods=['GET', 'POST'])
def send_password_reset():
    form = EmailForm()
    if form.validate_on_submit():
        form_email = form.email.data.strip().lower()

        # Check if the user has migrated
        user = db.session.query(Users).filter(Users.email.ilike(form_email)).first()
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
        url = f"{SUPABASE_URL}/auth/v1/user"
        headers = {
            "Authorization": f"Bearer {access_token}",
            "apikey": SUPABASE_KEY,
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


# --- Load exam combinations from CSV ---
exam_data = []
with open("app/static/exam_combinations.csv", newline="", encoding="utf-8-sig") as csvfile:
    reader = csv.DictReader(csvfile)
    for row in reader:
        exam_data.append(row)

# Build data structures filtered by user default level
def build_exam_structures(user_level):
    categories = defaultdict(set)
    boards_for_subject = defaultdict(set)
    specific_subjects = defaultdict(lambda: defaultdict(set))
    tiers = defaultdict(lambda: defaultdict(lambda: defaultdict(set)))

    for row in exam_data:
        if row["level"] != user_level:
            continue  # Skip exams that don't match the user's default level

        category = row["category"]
        subject = row["subject"]
        board = row["board"]
        specific = row["specific_subject"]
        tier = row["tier"]

        categories[category].add(subject)
        boards_for_subject[subject].add(board)
        specific_subjects[subject][board].add(specific)
        if tier:
            tiers[subject][board][specific].add(tier)

    # Convert sets → sorted lists
    categories = {c: sorted(list(s)) for c, s in categories.items()}
    boards_for_subject = {s: sorted(list(b)) for s, b in boards_for_subject.items()}
    specific_subjects = {s: {b: sorted(list(ss)) for b, ss in v.items()} for s, v in specific_subjects.items()}
    tiers = {s: {b: {ss: sorted(list(tset)) for ss, tset in bv.items()} for b, bv in v.items()} for s, v in tiers.items()}

    return categories, boards_for_subject, specific_subjects, tiers


@user.route('/subject_options', methods=['GET', 'POST'])
@login_required
def subject_options():
    qualForm = QualForm()
    timeForm = TimeForm()

    # Get the user's currently selected subjects
    selected_subjects = db.session.query(UserSubjects).filter_by(user_id=current_user.id).all()

    # Build filtered exam structures based on user's default_level
    categories, boards_for_subject, specific_subjects, tiers = build_exam_structures(current_user.default_level)

    if request.method == 'GET':
        qualForm.Qualification.data = current_user.default_level

    elif request.method == 'POST':
        # Update qualification
        if qualForm.validate_on_submit() and qualForm.Qualification.data != current_user.default_level:
            current_user.default_level = qualForm.Qualification.data
            current_user.subjects.clear()  # remove all selected exams
            db.session.commit()
            flash("Updated qualification. All selected exams cleared.", "success")
            return redirect(url_for("user.subject_options"))

        # Update exam times
        elif timeForm.validate_on_submit():
            current_user.exam_start_time_am = timeForm.AM_time.data.strftime('%H:%M')
            current_user.exam_start_time_pm = timeForm.PM_time.data.strftime('%H:%M')
            db.session.commit()
            flash("Updated exam times.", "success")
            return redirect(url_for("user.subject_options"))

        # Add a new subject
        elif request.form.get("form_id") == "add-subject-form":
            board = request.form["board"]
            base_subject = request.form["base_subject"]
            specific_subject = request.form["specific_subject"]
            tier = request.form.get("tier")

            new_subject = UserSubjects(
                id=str(uuid.uuid4()),
                user_id=current_user.id,
                base_subject=base_subject,
                subject=specific_subject,
                tier=tier,
                board=board,
                date_added=datetime.now()
            )
            current_user.subjects.append(new_subject)
            db.session.commit()
            flash(f"Successfully added {specific_subject}.", "success")
            return redirect(url_for("user.subject_options"))

    return render_template(
        "subject_options.html",
        categories=categories,
        selected_subjects=selected_subjects,
        qualForm=qualForm,
        timeForm=timeForm,
        am_start_time=current_user.exam_start_time_am or "09:00",
        pm_start_time=current_user.exam_start_time_pm or "13:30",
    )


@user.route("/delete/<string:subject_id>", methods=["POST"])
def delete_subject(subject_id):
    if current_user.is_authenticated:
        subject = db.session.query(UserSubjects).filter_by(user_id=current_user.id, id=subject_id).first()
        if subject:
            current_user.subjects.remove(subject)
            db.session.commit()
            flash("Subject successfully deleted.", "success")
    else:
        flash("You need to be logged in to delete a subject.", "danger")

    return redirect(url_for("user.subject_options"))

@user.route("/api/boards/<subject>")
def get_boards(subject):
    categories, boards_for_subject, specific_subjects, tiers = build_exam_structures(current_user.default_level)
    return {"boards": boards_for_subject.get(subject, [])}

@user.route("/api/specific_subjects/<subject>/<board>")
def get_specific(subject, board):
    categories, boards_for_subject, specific_subjects, tiers = build_exam_structures(current_user.default_level)
    return {"specific_subjects": specific_subjects.get(subject, {}).get(board, [])}

@user.route("/api/tiers/<subject>/<board>/<specific>")
def get_tiers(subject, board, specific):
    categories, boards_for_subject, specific_subjects, tiers = build_exam_structures(current_user.default_level)
    return {"tiers": tiers.get(subject, {}).get(board, {}).get(specific, [])}
