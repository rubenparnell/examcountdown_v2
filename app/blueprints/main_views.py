from flask import Blueprint, render_template, url_for, redirect, request, jsonify
from flask_login import login_required, current_user
from datetime import datetime
from sqlalchemy import and_, or_
from app import db
from shared_db.db import db
from shared_db.models import Exams, UserSubjects
from collections import defaultdict
from app.helpers import flash

main = Blueprint('main', __name__)

def get_shown_exams():
    shown_exams = []
    selected_subjects = current_user.subjects
    for subj in selected_subjects:
        board = subj.board
        subject = subj.subject
        base_subject = subj.base_subject
        tier = subj.tier

        current_exams = (
            db.session.query(Exams)
            .filter(
                and_(
                    Exams.time.isnot(None),
                    Exams.time != '',
                    Exams.level == current_user.default_level,
                    Exams.base_subject == base_subject,
                    Exams.board == board,
                    Exams.subject == subject,
                    Exams.tier == tier,
                )
            )
            .order_by(Exams.date)
            .all()
        )

        for current_exam in current_exams:
            shown_exams.append(current_exam)
  
    return shown_exams


@main.route("/")
def home():
    if current_user.is_authenticated:
        am_start_time=current_user.exam_start_time_am or "09:00"
        pm_start_time=current_user.exam_start_time_pm or "13:30"

        shown_exams = get_shown_exams()

        # Get the date of the next exam:
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
        gcse_exams = db.session.query(Exams).filter(
            and_(
                Exams.time.isnot(None),
                Exams.time != '',
                Exams.level == "GCSE",
                Exams.date > now
            )
        ).order_by(Exams.date, Exams.time).all()

        as_exams = db.session.query(Exams).filter(
            and_(
                Exams.time.isnot(None),
                Exams.time != '',
                Exams.level == "AS",
                Exams.date > now
            )
        ).order_by(Exams.date, Exams.time).all()

        a_exams = db.session.query(Exams).filter(
            and_(
                Exams.time.isnot(None),
                Exams.time != '',
                Exams.level == "A",
                Exams.date > now
            )
        ).order_by(Exams.date, Exams.time).all()

        # Group exams occurring at the same date and time
        next_gcse_exam_group = group_exams_by_time(gcse_exams)
        next_as_exam_group = group_exams_by_time(as_exams)
        next_a_exam_group = group_exams_by_time(a_exams)

        return render_template(
           "home.html",
           next_gcse_exam=next_gcse_exam_group,
           next_as_exam=next_as_exam_group,
           next_a_exam=next_a_exam_group,
           am_start_time=am_start_time,
           pm_start_time=pm_start_time
        )


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


@main.route("/exams")
@main.route("/exams/<string:level>")
def exams(level=None):
    if current_user.is_authenticated and level:
        # Fetch all exams from the database
        filters = []
        selected_subjects = db.session.query(UserSubjects).filter_by(user_id=current_user.id).all()
        for subj in selected_subjects:
            if not subj.tier:
                # Match exams where tier is NULL or empty string
                tier_filter = or_(Exams.tier.is_(None), Exams.tier == '')
            else:
                tier_filter = Exams.tier == subj.tier

            filters.append(and_(
                Exams.subject == subj.subject,
                Exams.board == subj.board,
                tier_filter,
                Exams.level == level
            ))

        exams = db.session.query(Exams).filter(or_(*filters)).all()

    elif level:
        exams = db.session.query(Exams).filter_by(level=level).all()

    else:
        exams = []

    ordered_exams_by_category = showExams(exams)

    return render_template('exams.html', exams_by_category=ordered_exams_by_category, level=level)


@main.route('/subject/<string:level>/<string:base_subject>')
def show_selected_subject(level, base_subject):
    if current_user.is_authenticated:
        shown_exams = get_shown_exams()

    else:
        # Fetch all exams for the selected base_subject
        shown_exams = (
            db.session.query(Exams)
            .filter(
                and_(
                    Exams.base_subject == base_subject, 
                    Exams.time.isnot(None), 
                    Exams.time != '',
                    Exams.level == level
                )
            )
            .order_by(Exams.date)
            .all()
        )

    return render_template('selected_subject.html', base_subject=base_subject, exams=shown_exams, level=level)


@main.route("/all_timetable/<level>")
def all_timetable(level):
    all_exams = (
        db.session.query(Exams)
        .filter(
            and_(
                Exams.time.isnot(None), 
                Exams.time != '', 
                Exams.level == level,
            )
        )
        .order_by(Exams.date, Exams.subject, Exams.board)
        .all()
    )
    
    level = "GCSE" if level == "GCSE" else "A Level" if level == "A" else "AS Level"

    return render_template('timetable.html', exams=all_exams, level=level)



@main.route("/timetable")
@login_required
def timetable():
    shown_exams = get_shown_exams()
    
    return render_template('timetable.html', exams=shown_exams)


@main.route("/privacy_policy")
def privacy_policy():
    return render_template('privacy_policy.html')


# For subjects page:
@main.route('/get_base_subjects', methods=['GET'])
def get_base_subjects():
    category = request.args.get('category')
    # Query unique boards for the selected base_subject
    unique_base_subjects = db.session.query(Exams).with_entities(Exams.base_subject).filter_by(level=current_user.default_level, category=category).distinct().all()
    unique_base_subjects = [x[0] for x in unique_base_subjects]
    
    return jsonify(unique_base_subjects)

@main.route('/get_boards', methods=['GET'])
def get_boards():
    base_subject = request.args.get('base_subject')
    # Query unique boards for the selected base_subject
    unique_boards = db.session.query(Exams).with_entities(Exams.board).filter_by(level=current_user.default_level, base_subject=base_subject).distinct().all()
    unique_boards = [x[0] for x in unique_boards]
    
    return jsonify(unique_boards)

@main.route('/get_subjects', methods=['GET'])
def get_subjects():
    base_subject = request.args.get('base_subject')
    board = request.args.get('board')
    # Query unique subjects for the selected base_subject and board
    unique_subjects = db.session.query(Exams).with_entities(Exams.subject).filter_by(level=current_user.default_level, base_subject=base_subject, board=board).distinct().all()
    unique_subjects = [x[0] for x in unique_subjects]
    
    return jsonify(unique_subjects)

@main.route('/get_tiers', methods=['GET'])
def get_tiers():
    base_subject = request.args.get('base_subject')
    board = request.args.get('board')
    subject = request.args.get('subject')

    # Query unique subjects for the selected base_subject and board
    unique_tiers = db.session.query(Exams).with_entities(Exams.tier).filter_by(level=current_user.default_level, base_subject=base_subject, board=board, subject=subject).distinct().all()
    unique_tiers = [x[0] for x in unique_tiers]
    
    return jsonify(unique_tiers)

@main.route('/check_subject_tier', methods=['GET'])
def check_subject_tier():
    base_subject = request.args.get('base_subject')
    board = request.args.get('board')
    subject = request.args.get('subject')

    exam_tiers = (
        db.session.query(Exams).with_entities(Exams.tier)
        .filter_by(
        level=current_user.level, 
        base_subject=base_subject, 
        board=board, 
        subject=subject
        )
        .all()
    )
    
    try:
        has_tier = True if exam_tiers[0][0] != None else False
    except IndexError:
        has_tier = False

    return jsonify({"has_tier": has_tier})

@main.route('/delete_subject', methods=['POST'])
def delete_subject():
    subject_id = request.form.get('subject_id')

    if current_user.is_authenticated:
        subject_to_delete = db.session.query(UserSubjects).filter_by(id=subject_id).first()
        current_user.subjects.remove(subject_to_delete)
        db.session.commit()
        
        flash('Subject successfully deleted.', 'success')
    else:
        flash('You need to be logged in to delete a subject.', 'danger')

    return redirect(url_for('user.exam_options'))