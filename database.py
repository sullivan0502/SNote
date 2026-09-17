import sqlite3
from contextlib import contextmanager

DB_PATH = "app.db"


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


@contextmanager
def db_cursor(commit: bool = False):
    conn = get_connection()
    try:
        cur = conn.cursor()
        yield cur
        if commit:
            conn.commit()
    finally:
        conn.close()


def init_db():
    with db_cursor(commit=True) as cur:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                full_name TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('prof', 'eleve')),
                created_by INTEGER REFERENCES users(id),
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS classes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                teacher_id INTEGER NOT NULL REFERENCES users(id),
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS class_members (
                class_id INTEGER NOT NULL REFERENCES classes(id) ON DELETE CASCADE,
                student_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                PRIMARY KEY (class_id, student_id)
            )
        """)

        # Ressources = fichier OU texte, postées par un prof
        cur.execute("""
            CREATE TABLE IF NOT EXISTS resources (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                teacher_id INTEGER NOT NULL REFERENCES users(id),
                type TEXT NOT NULL CHECK(type IN ('file', 'text')),
                title TEXT NOT NULL,
                content TEXT,
                file_path TEXT,
                original_filename TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Accès sélectif : une ressource est visible par une classe entière
        # et/ou des élèves précis. Pas de ligne = visible par personne.
        cur.execute("""
            CREATE TABLE IF NOT EXISTS resource_access (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                resource_id INTEGER NOT NULL REFERENCES resources(id) ON DELETE CASCADE,
                target_type TEXT NOT NULL CHECK(target_type IN ('class', 'student')),
                target_id INTEGER NOT NULL
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS assignments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                teacher_id INTEGER NOT NULL REFERENCES users(id),
                class_id INTEGER NOT NULL REFERENCES classes(id) ON DELETE CASCADE,
                title TEXT NOT NULL,
                description TEXT,
                due_date TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS submissions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                assignment_id INTEGER NOT NULL REFERENCES assignments(id) ON DELETE CASCADE,
                student_id INTEGER NOT NULL REFERENCES users(id),
                file_path TEXT NOT NULL,
                original_filename TEXT NOT NULL,
                submitted_at TEXT DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(assignment_id, student_id)
            )
        """)

        # Coche "fait / pas fait" indépendante du dépôt de fichier
        cur.execute("""
            CREATE TABLE IF NOT EXISTS assignment_marks (
                assignment_id INTEGER NOT NULL REFERENCES assignments(id) ON DELETE CASCADE,
                student_id INTEGER NOT NULL REFERENCES users(id),
                done INTEGER NOT NULL DEFAULT 0,
                marked_at TEXT DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (assignment_id, student_id)
            )
        """)

        # Sous-groupes au sein d'une classe
        cur.execute("""
            CREATE TABLE IF NOT EXISTS class_groups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                class_id INTEGER NOT NULL REFERENCES classes(id) ON DELETE CASCADE,
                name TEXT NOT NULL
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS group_members (
                group_id INTEGER NOT NULL REFERENCES class_groups(id) ON DELETE CASCADE,
                student_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                PRIMARY KEY (group_id, student_id)
            )
        """)

        # Notes (carnet de notes libre, pas forcément liées à un devoir)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS grades (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                teacher_id INTEGER NOT NULL REFERENCES users(id),
                class_id INTEGER NOT NULL REFERENCES classes(id) ON DELETE CASCADE,
                student_id INTEGER NOT NULL REFERENCES users(id),
                label TEXT NOT NULL,
                value REAL NOT NULL,
                max_value REAL NOT NULL DEFAULT 20,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # QCM
        cur.execute("""
            CREATE TABLE IF NOT EXISTS quizzes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                teacher_id INTEGER NOT NULL REFERENCES users(id),
                class_id INTEGER NOT NULL REFERENCES classes(id) ON DELETE CASCADE,
                title TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS quiz_questions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                quiz_id INTEGER NOT NULL REFERENCES quizzes(id) ON DELETE CASCADE,
                question_text TEXT NOT NULL,
                position INTEGER NOT NULL DEFAULT 0
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS quiz_options (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                question_id INTEGER NOT NULL REFERENCES quiz_questions(id) ON DELETE CASCADE,
                option_text TEXT NOT NULL,
                is_correct INTEGER NOT NULL DEFAULT 0
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS quiz_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                quiz_id INTEGER NOT NULL REFERENCES quizzes(id) ON DELETE CASCADE,
                student_id INTEGER NOT NULL REFERENCES users(id),
                score INTEGER NOT NULL,
                total INTEGER NOT NULL,
                submitted_at TEXT DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(quiz_id, student_id)
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS quiz_answers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                attempt_id INTEGER NOT NULL REFERENCES quiz_attempts(id) ON DELETE CASCADE,
                question_id INTEGER NOT NULL REFERENCES quiz_questions(id),
                option_id INTEGER REFERENCES quiz_options(id)
            )
        """)

        # Migrations légères sur tables existantes (ajout de colonnes si absentes)
        cur.execute("PRAGMA table_info(users)")
        user_cols = {row["name"] for row in cur.fetchall()}
        if "profile_picture" not in user_cols:
            cur.execute("ALTER TABLE users ADD COLUMN profile_picture TEXT")

        cur.execute("PRAGMA table_info(assignments)")
        assignment_cols = {row["name"] for row in cur.fetchall()}
        if "group_id" not in assignment_cols:
            cur.execute("ALTER TABLE assignments ADD COLUMN group_id INTEGER REFERENCES class_groups(id)")

        cur.execute("PRAGMA table_info(resource_access)")
        # SQLite ne permet pas d'étendre un CHECK existant : on retire la contrainte
        # target_type en recréant la table si elle date d'avant les groupes.
        cur.execute("SELECT sql FROM sqlite_master WHERE name = 'resource_access'")
        row = cur.fetchone()
        if row and "'group'" not in row["sql"]:
            cur.execute("ALTER TABLE resource_access RENAME TO resource_access_old")
            cur.execute("""
                CREATE TABLE resource_access (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    resource_id INTEGER NOT NULL REFERENCES resources(id) ON DELETE CASCADE,
                    target_type TEXT NOT NULL CHECK(target_type IN ('class', 'student', 'group')),
                    target_id INTEGER NOT NULL
                )
            """)
            cur.execute("INSERT INTO resource_access SELECT * FROM resource_access_old")
            cur.execute("DROP TABLE resource_access_old")
