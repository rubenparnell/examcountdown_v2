import csv
import datetime
import mysql.connector

def import_csv_to_mysql(csv_file, db_config):
  """Imports CSV data into a MySQL database.

  Args:
    csv_file: Path to the CSV file.
    db_config: A dictionary containing database connection details.
  """

  try:
    # Connect to the database
    mydb = mysql.connector.connect(
      host=db_config['host'],
      user=db_config['user'],
      password=db_config['password'],
      database=db_config['database']
    )

    # Create a cursor
    mycursor = mydb.cursor()

    # Create the table (adjust column names and data types as needed)
    create_table_query = """
      CREATE TABLE exams (
        date DATETIME,
        exam_series VARCHAR(20),
        board VARCHAR(20),
        qualification VARCHAR(100),
        examination_code VARCHAR(50) PRIMARY KEY,
        category VARCHAR(100),
        base_subject VARCHAR(100),
        subject VARCHAR(100),
        title VARCHAR(200),
        time VARCHAR(20),
        duration VARCHAR(20),
        tier VARCHAR(1),
        level VARCHAR(2)
      )
    """
    try:
        mycursor.execute(create_table_query)
    except Exception as e:
      print("Tried and failed to create table: ", e)

    # Read the CSV file
    with open(csv_file, 'r', encoding='utf-8') as csvfile:
      csv_reader = csv.reader(csvfile)
      next(csv_reader)  # Skip header row

      # Insert data into the table
      insert_query = "INSERT INTO exams (date, exam_series, board, qualification, examination_code, category, base_subject, subject, title, time, duration, tier, level) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
      for row in csv_reader:
        # Convert date string to datetime object
        date_string = row[0]
        date_obj = datetime.datetime.strptime(date_string, "%d/%m/%Y").date()

        # Get the time value (AM/PM)
        time_value = row[9].strip().upper()  # Assuming 'AM' or 'PM' is in the 10th column (index 9)
        
        # Add appropriate time to date
        if time_value == 'AM':
            datetime_obj = datetime.datetime.combine(date_obj, datetime.time(9, 0, 0))
        elif time_value == 'PM':
            datetime_obj = datetime.datetime.combine(date_obj, datetime.time(13, 30, 0))
        else:
            datetime_obj = datetime.datetime.combine(date_obj, datetime.time(0, 0, 0))  # Default to midnight if time is not AM/PM

        # Update the row data
        row[0] = datetime_obj  # Replace date with combined datetime
        row[9] = time_value     # Retain the AM/PM value if needed

        # Execute the insert query
        mycursor.execute(insert_query, row)

    mydb.commit()
    print("Data imported successfully!")

  except mysql.connector.Error as error:
    print(f"Error: {error}")
  finally:
    if mydb.is_connected():
      mycursor.close()
      mydb.close()
      print("Database connection closed.")

db_config = {
  'host': 'localhost',
  'user': 'root',
  'password': 'PwfSQL2024!',
  'database': 'exam_countdown'
}

csv_files = [
    r"C:\Users\ruben\Documents\GitHub\examcountdown_v2\exams_csv\all_l2.csv",
    r"C:\Users\ruben\Documents\GitHub\examcountdown_v2\exams_csv\all_l3.csv",
  ]

for file in csv_files:
    import_csv_to_mysql(file, db_config)