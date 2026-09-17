import json
import os
import shutil
import time
import uuid
from typing import List, Optional

from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.staticfiles import StaticFiles

from auth import (create_access_token, get_current_user, hash_password,
                   require_student, require_teacher, verify_password)
from database import db_cursor, init_db

app = FastAPI(title="Plateforme prof/élève")

STORAGE_FILES = "storage/files"
STORAGE_SUBMISSIONS = "storage/submissions"
STORAGE_AVATARS = "storage/avatars"
MAX_UPLOAD_BYTES = 50 * 1024 * 1024  # 50 Mo, pour éviter qu'un upload sature le disque
os.makedirs(STORAGE_FILES, exist_ok=True)
os.makedirs(STORAGE_SUBMISSIONS, exist_ok=True)
os.makedirs(STORAGE_AVATARS, exist_ok=True)

init_db()


# En-têtes de sécurité de base sur chaque réponse (protège contre des attaques
# classiques côté navigateur : clickjacking, sniffing de type MIME, etc.)
@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    return response


def save_upload_capped(upload_file, destination: str):
    """Copie un fichier uploadé en refusant tout ce qui dépasse MAX_UPLOAD_BYTES,
    pour éviter qu'un envoi (volontaire ou non) remplisse le disque du serveur."""
    written = 0
    with open(destination, "wb") as out:
        while True:
            chunk = upload_file.file.read(1024 * 1024)
            if not chunk:
                break
            written += len(chunk)
            if written > MAX_UPLOAD_BYTES:
                out.close()
                os.remove(destination)
                raise HTTPException(status_code=413, detail="Fichier trop volumineux (limite : 50 Mo)")
            out.write(chunk)


# ---------- Anti brute-force sur la connexion ----------

_login_attempts: dict[str, list[float]] = {}
LOGIN_MAX_ATTEMPTS = 5
LOGIN_WINDOW_SECONDS = 15 * 60


def _login_key(request: Request, username: str) -> str:
    return f"{request.client.host if request.client else 'unknown'}:{username.lower()}"


def _check_login_rate_limit(request: Request, username: str):
    key = _login_key(request, username)
    now = time.time()
    attempts = [t for t in _login_attempts.get(key, []) if now - t < LOGIN_WINDOW_SECONDS]
    _login_attempts[key] = attempts
    if len(attempts) >= LOGIN_MAX_ATTEMPTS:
        raise HTTPException(
            status_code=429,
            detail="Trop de tentatives de connexion. Réessaie dans quelques minutes.",
        )


def _register_login_failure(request: Request, username: str):
    key = _login_key(request, username)
    _login_attempts.setdefault(key, []).append(time.time())


# ---------- Auth ----------

@app.post("/auth/setup-teacher")
def setup_teacher(username: str = Form(...), password: str = Form(...), full_name: str = Form(...)):
    """Crée le tout premier compte prof. Ne fonctionne que si la base est vide
    (aucun utilisateur), pour éviter que n'importe qui se crée un compte prof
    une fois le site en ligne."""
    if len(password) < 8:
        raise HTTPException(status_code=400, detail="Mot de passe trop court (8 caractères minimum)")
    with db_cursor() as cur:
        cur.execute("SELECT COUNT(*) AS n FROM users")
        if cur.fetchone()["n"] > 0:
            raise HTTPException(status_code=403, detail="Un compte existe déjà. Le premier prof a déjà été créé.")

    with db_cursor(commit=True) as cur:
        cur.execute(
            "INSERT INTO users (username, password_hash, full_name, role) VALUES (?, ?, ?, 'prof')",
            (username, hash_password(password), full_name),
        )
    return {"status": "ok"}


@app.post("/auth/login")
def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends()):
    _check_login_rate_limit(request, form_data.username)
    with db_cursor() as cur:
        cur.execute("SELECT * FROM users WHERE username = ?", (form_data.username,))
        user = cur.fetchone()

    if not user or not verify_password(form_data.password, user["password_hash"]):
        _register_login_failure(request, form_data.username)
        raise HTTPException(status_code=401, detail="Identifiant ou mot de passe incorrect")

    token = create_access_token({"sub": str(user["id"]), "role": user["role"], "full_name": user["full_name"]})
    return {"access_token": token, "token_type": "bearer", "role": user["role"], "full_name": user["full_name"]}


@app.get("/me")
def me(user: dict = Depends(get_current_user)):
    with db_cursor() as cur:
        cur.execute("SELECT profile_picture FROM users WHERE id = ?", (user["id"],))
        row = cur.fetchone()
    user["profile_picture"] = row["profile_picture"] if row else None
    return user


@app.post("/me/profile-picture")
def upload_profile_picture(file: UploadFile = File(...), user: dict = Depends(get_current_user)):
    ext = os.path.splitext(file.filename)[1].lower()
    if ext not in (".png", ".jpg", ".jpeg", ".webp", ".gif"):
        raise HTTPException(status_code=400, detail="Format d'image non supporté")
    stored_name = f"{uuid.uuid4().hex}{ext}"
    stored_path = os.path.join(STORAGE_AVATARS, stored_name)
    save_upload_capped(file, stored_path)
    with db_cursor(commit=True) as cur:
        cur.execute("SELECT profile_picture FROM users WHERE id = ?", (user["id"],))
        old = cur.fetchone()
        cur.execute("UPDATE users SET profile_picture = ? WHERE id = ?", (f"/avatars/{stored_name}", user["id"]))
    if old and old["profile_picture"]:
        old_path = old["profile_picture"].lstrip("/")
        if os.path.exists(old_path):
            os.remove(old_path)
    return {"profile_picture": f"/avatars/{stored_name}"}


# ---------- Prof : gestion des élèves ----------

@app.post("/teacher/students")
def create_student(
    username: str = Form(...),
    password: str = Form(...),
    full_name: str = Form(...),
    teacher: dict = Depends(require_teacher),
):
    with db_cursor() as cur:
        cur.execute("SELECT id FROM users WHERE username = ?", (username,))
        if cur.fetchone():
            raise HTTPException(status_code=400, detail="Ce nom d'utilisateur existe déjà")

    with db_cursor(commit=True) as cur:
        cur.execute(
            "INSERT INTO users (username, password_hash, full_name, role, created_by) VALUES (?, ?, ?, 'eleve', ?)",
            (username, hash_password(password), full_name, teacher["id"]),
        )
        student_id = cur.lastrowid
    return {"id": student_id, "username": username, "full_name": full_name}


@app.get("/teacher/students")
def list_students(teacher: dict = Depends(require_teacher)):
    with db_cursor() as cur:
        cur.execute(
            "SELECT id, username, full_name FROM users WHERE role = 'eleve' AND created_by = ? ORDER BY full_name",
            (teacher["id"],),
        )
        return [dict(r) for r in cur.fetchall()]


# ---------- Prof : gestion des classes ----------

@app.post("/teacher/classes")
def create_class(name: str = Form(...), teacher: dict = Depends(require_teacher)):
    with db_cursor(commit=True) as cur:
        cur.execute("INSERT INTO classes (name, teacher_id) VALUES (?, ?)", (name, teacher["id"]))
        class_id = cur.lastrowid
    return {"id": class_id, "name": name}


@app.get("/teacher/classes")
def list_classes(teacher: dict = Depends(require_teacher)):
    with db_cursor() as cur:
        cur.execute("SELECT id, name FROM classes WHERE teacher_id = ? ORDER BY name", (teacher["id"],))
        classes = [dict(r) for r in cur.fetchall()]
        for c in classes:
            cur.execute(
                """SELECT u.id, u.full_name, u.username FROM class_members cm
                   JOIN users u ON u.id = cm.student_id WHERE cm.class_id = ?
                   ORDER BY u.full_name""",
                (c["id"],),
            )
            c["members"] = [dict(r) for r in cur.fetchall()]
            cur.execute("SELECT id, name FROM class_groups WHERE class_id = ? ORDER BY name", (c["id"],))
            groups = [dict(r) for r in cur.fetchall()]
            for g in groups:
                cur.execute(
                    """SELECT u.id, u.full_name FROM group_members gm
                       JOIN users u ON u.id = gm.student_id WHERE gm.group_id = ?""",
                    (g["id"],),
                )
                g["members"] = [dict(r) for r in cur.fetchall()]
            c["groups"] = groups
    return classes


def _assert_class_owner(cur, class_id: int, teacher_id: int):
    cur.execute("SELECT id FROM classes WHERE id = ? AND teacher_id = ?", (class_id, teacher_id))
    if not cur.fetchone():
        raise HTTPException(status_code=404, detail="Classe introuvable")


@app.post("/teacher/classes/{class_id}/members")
def add_class_member(class_id: int, student_id: int = Form(...), teacher: dict = Depends(require_teacher)):
    with db_cursor(commit=True) as cur:
        _assert_class_owner(cur, class_id, teacher["id"])
        cur.execute(
            "SELECT id FROM users WHERE id = ? AND role = 'eleve' AND created_by = ?",
            (student_id, teacher["id"]),
        )
        if not cur.fetchone():
            raise HTTPException(status_code=404, detail="Élève introuvable")
        cur.execute(
            "INSERT OR IGNORE INTO class_members (class_id, student_id) VALUES (?, ?)",
            (class_id, student_id),
        )
    return {"status": "ok"}


@app.delete("/teacher/classes/{class_id}/members/{student_id}")
def remove_class_member(class_id: int, student_id: int, teacher: dict = Depends(require_teacher)):
    with db_cursor(commit=True) as cur:
        _assert_class_owner(cur, class_id, teacher["id"])
        cur.execute(
            "DELETE FROM class_members WHERE class_id = ? AND student_id = ?", (class_id, student_id)
        )
    return {"status": "ok"}


# ---------- Prof : sous-groupes ----------

@app.post("/teacher/groups")
def create_group(class_id: int = Form(...), name: str = Form(...), teacher: dict = Depends(require_teacher)):
    with db_cursor(commit=True) as cur:
        _assert_class_owner(cur, class_id, teacher["id"])
        cur.execute("INSERT INTO class_groups (class_id, name) VALUES (?, ?)", (class_id, name))
        group_id = cur.lastrowid
    return {"id": group_id, "name": name}


def _assert_group_owner(cur, group_id: int, teacher_id: int):
    cur.execute(
        """SELECT g.id FROM class_groups g JOIN classes c ON c.id = g.class_id
           WHERE g.id = ? AND c.teacher_id = ?""",
        (group_id, teacher_id),
    )
    if not cur.fetchone():
        raise HTTPException(status_code=404, detail="Groupe introuvable")


@app.post("/teacher/groups/{group_id}/members")
def add_group_member(group_id: int, student_id: int = Form(...), teacher: dict = Depends(require_teacher)):
    with db_cursor(commit=True) as cur:
        _assert_group_owner(cur, group_id, teacher["id"])
        cur.execute(
            "INSERT OR IGNORE INTO group_members (group_id, student_id) VALUES (?, ?)", (group_id, student_id)
        )
    return {"status": "ok"}


@app.delete("/teacher/groups/{group_id}/members/{student_id}")
def remove_group_member(group_id: int, student_id: int, teacher: dict = Depends(require_teacher)):
    with db_cursor(commit=True) as cur:
        _assert_group_owner(cur, group_id, teacher["id"])
        cur.execute("DELETE FROM group_members WHERE group_id = ? AND student_id = ?", (group_id, student_id))
    return {"status": "ok"}


@app.delete("/teacher/groups/{group_id}")
def delete_group(group_id: int, teacher: dict = Depends(require_teacher)):
    with db_cursor(commit=True) as cur:
        _assert_group_owner(cur, group_id, teacher["id"])
        cur.execute("DELETE FROM class_groups WHERE id = ?", (group_id,))
    return {"status": "ok"}


# ---------- Prof : notes ----------

@app.post("/teacher/grades")
def create_grade(
    class_id: int = Form(...),
    student_id: int = Form(...),
    label: str = Form(...),
    value: float = Form(...),
    max_value: float = Form(20),
    teacher: dict = Depends(require_teacher),
):
    with db_cursor(commit=True) as cur:
        _assert_class_owner(cur, class_id, teacher["id"])
        cur.execute(
            "SELECT 1 FROM class_members WHERE class_id = ? AND student_id = ?", (class_id, student_id)
        )
        if not cur.fetchone():
            raise HTTPException(status_code=404, detail="Cet élève n'est pas dans cette classe")
        cur.execute(
            """INSERT INTO grades (teacher_id, class_id, student_id, label, value, max_value)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (teacher["id"], class_id, student_id, label, value, max_value),
        )
        grade_id = cur.lastrowid
    return {"id": grade_id, "status": "ok"}


@app.get("/teacher/grades")
def list_grades(class_id: Optional[int] = None, teacher: dict = Depends(require_teacher)):
    with db_cursor() as cur:
        if class_id:
            _assert_class_owner(cur, class_id, teacher["id"])
            cur.execute(
                """SELECT g.*, u.full_name AS student_name FROM grades g
                   JOIN users u ON u.id = g.student_id
                   WHERE g.class_id = ? ORDER BY g.created_at DESC""",
                (class_id,),
            )
        else:
            cur.execute(
                """SELECT g.*, u.full_name AS student_name FROM grades g
                   JOIN users u ON u.id = g.student_id
                   WHERE g.teacher_id = ? ORDER BY g.created_at DESC""",
                (teacher["id"],),
            )
        return [dict(r) for r in cur.fetchall()]


@app.delete("/teacher/grades/{grade_id}")
def delete_grade(grade_id: int, teacher: dict = Depends(require_teacher)):
    with db_cursor(commit=True) as cur:
        cur.execute("SELECT id FROM grades WHERE id = ? AND teacher_id = ?", (grade_id, teacher["id"]))
        if not cur.fetchone():
            raise HTTPException(status_code=404, detail="Note introuvable")
        cur.execute("DELETE FROM grades WHERE id = ?", (grade_id,))
    return {"status": "ok"}


# ---------- Prof : QCM ----------

@app.post("/teacher/quizzes")
def create_quiz(
    class_id: int = Form(...),
    title: str = Form(...),
    questions: str = Form(...),  # JSON: [{"question_text": "...", "options": [{"text": "...", "is_correct": true}, ...]}, ...]
    teacher: dict = Depends(require_teacher),
):
    try:
        parsed = json.loads(questions)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Format de questions invalide")
    if not parsed:
        raise HTTPException(status_code=400, detail="Ajoute au moins une question")
    for q in parsed:
        opts = q.get("options", [])
        if len(opts) < 2 or not any(o.get("is_correct") for o in opts):
            raise HTTPException(status_code=400, detail="Chaque question doit avoir 2+ réponses et 1 bonne réponse")

    with db_cursor(commit=True) as cur:
        _assert_class_owner(cur, class_id, teacher["id"])
        cur.execute(
            "INSERT INTO quizzes (teacher_id, class_id, title) VALUES (?, ?, ?)", (teacher["id"], class_id, title)
        )
        quiz_id = cur.lastrowid
        for i, q in enumerate(parsed):
            cur.execute(
                "INSERT INTO quiz_questions (quiz_id, question_text, position) VALUES (?, ?, ?)",
                (quiz_id, q["question_text"], i),
            )
            question_id = cur.lastrowid
            for opt in q["options"]:
                cur.execute(
                    "INSERT INTO quiz_options (question_id, option_text, is_correct) VALUES (?, ?, ?)",
                    (question_id, opt["text"], 1 if opt.get("is_correct") else 0),
                )
    return {"id": quiz_id, "status": "ok"}


@app.get("/teacher/quizzes")
def list_teacher_quizzes(teacher: dict = Depends(require_teacher)):
    with db_cursor() as cur:
        cur.execute(
            """SELECT q.id, q.title, q.created_at, c.name AS class_name, q.class_id
               FROM quizzes q JOIN classes c ON c.id = q.class_id
               WHERE q.teacher_id = ? ORDER BY q.created_at DESC""",
            (teacher["id"],),
        )
        quizzes = [dict(r) for r in cur.fetchall()]
        for qz in quizzes:
            cur.execute("SELECT COUNT(*) AS n FROM quiz_questions WHERE quiz_id = ?", (qz["id"],))
            qz["question_count"] = cur.fetchone()["n"]
            cur.execute(
                """SELECT a.score, a.total, u.full_name AS student_name, a.submitted_at
                   FROM quiz_attempts a JOIN users u ON u.id = a.student_id
                   WHERE a.quiz_id = ? ORDER BY a.submitted_at DESC""",
                (qz["id"],),
            )
            qz["attempts"] = [dict(r) for r in cur.fetchall()]
    return quizzes


@app.delete("/teacher/quizzes/{quiz_id}")
def delete_quiz(quiz_id: int, teacher: dict = Depends(require_teacher)):
    with db_cursor(commit=True) as cur:
        cur.execute("SELECT id FROM quizzes WHERE id = ? AND teacher_id = ?", (quiz_id, teacher["id"]))
        if not cur.fetchone():
            raise HTTPException(status_code=404, detail="QCM introuvable")
        cur.execute("DELETE FROM quizzes WHERE id = ?", (quiz_id,))
    return {"status": "ok"}


# ---------- Prof : ressources (fichiers / texte), accès sélectif ----------

@app.post("/teacher/resources")
def create_resource(
    type: str = Form(...),  # "file" ou "text"
    title: str = Form(...),
    content: Optional[str] = Form(None),
    access_classes: str = Form(""),   # ids séparés par des virgules, ex "1,2"
    access_students: str = Form(""),  # ids séparés par des virgules
    access_groups: str = Form(""),    # ids séparés par des virgules
    file: Optional[UploadFile] = File(None),
    teacher: dict = Depends(require_teacher),
):
    if type not in ("file", "text"):
        raise HTTPException(status_code=400, detail="type doit être 'file' ou 'text'")

    stored_path = None
    original_filename = None
    if type == "file":
        if not file:
            raise HTTPException(status_code=400, detail="Fichier manquant")
        ext = os.path.splitext(file.filename)[1]
        stored_name = f"{uuid.uuid4().hex}{ext}"
        stored_path = os.path.join(STORAGE_FILES, stored_name)
        save_upload_capped(file, stored_path)
        original_filename = file.filename
    elif not content:
        raise HTTPException(status_code=400, detail="Contenu texte manquant")

    class_ids = [int(x) for x in access_classes.split(",") if x.strip()]
    student_ids = [int(x) for x in access_students.split(",") if x.strip()]
    group_ids = [int(x) for x in access_groups.split(",") if x.strip()]
    if not class_ids and not student_ids and not group_ids:
        raise HTTPException(status_code=400, detail="Choisis au moins une classe, un groupe ou un élève destinataire")

    with db_cursor(commit=True) as cur:
        # vérifie que les classes/groupes/élèves appartiennent bien à ce prof
        for cid in class_ids:
            _assert_class_owner(cur, cid, teacher["id"])
        for gid in group_ids:
            _assert_group_owner(cur, gid, teacher["id"])
        for sid in student_ids:
            cur.execute(
                "SELECT id FROM users WHERE id = ? AND role = 'eleve' AND created_by = ?", (sid, teacher["id"])
            )
            if not cur.fetchone():
                raise HTTPException(status_code=404, detail=f"Élève {sid} introuvable")

        cur.execute(
            """INSERT INTO resources (teacher_id, type, title, content, file_path, original_filename)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (teacher["id"], type, title, content, stored_path, original_filename),
        )
        resource_id = cur.lastrowid
        for cid in class_ids:
            cur.execute(
                "INSERT INTO resource_access (resource_id, target_type, target_id) VALUES (?, 'class', ?)",
                (resource_id, cid),
            )
        for gid in group_ids:
            cur.execute(
                "INSERT INTO resource_access (resource_id, target_type, target_id) VALUES (?, 'group', ?)",
                (resource_id, gid),
            )
        for sid in student_ids:
            cur.execute(
                "INSERT INTO resource_access (resource_id, target_type, target_id) VALUES (?, 'student', ?)",
                (resource_id, sid),
            )
    return {"id": resource_id, "status": "ok"}


@app.get("/teacher/resources")
def list_teacher_resources(teacher: dict = Depends(require_teacher)):
    with db_cursor() as cur:
        cur.execute(
            "SELECT id, type, title, content, original_filename, created_at FROM resources WHERE teacher_id = ? ORDER BY created_at DESC",
            (teacher["id"],),
        )
        resources = [dict(r) for r in cur.fetchall()]
        for res in resources:
            cur.execute("SELECT target_type, target_id FROM resource_access WHERE resource_id = ?", (res["id"],))
            res["access"] = [dict(r) for r in cur.fetchall()]
    return resources


@app.delete("/teacher/resources/{resource_id}")
def delete_resource(resource_id: int, teacher: dict = Depends(require_teacher)):
    with db_cursor(commit=True) as cur:
        cur.execute("SELECT * FROM resources WHERE id = ? AND teacher_id = ?", (resource_id, teacher["id"]))
        res = cur.fetchone()
        if not res:
            raise HTTPException(status_code=404, detail="Ressource introuvable")
        if res["file_path"] and os.path.exists(res["file_path"]):
            os.remove(res["file_path"])
        cur.execute("DELETE FROM resources WHERE id = ?", (resource_id,))
    return {"status": "ok"}


# ---------- Prof : devoirs ----------

@app.post("/teacher/assignments")
def create_assignment(
    class_id: int = Form(...),
    title: str = Form(...),
    description: str = Form(""),
    due_date: Optional[str] = Form(None),
    group_id: Optional[int] = Form(None),
    teacher: dict = Depends(require_teacher),
):
    with db_cursor(commit=True) as cur:
        _assert_class_owner(cur, class_id, teacher["id"])
        if group_id:
            _assert_group_owner(cur, group_id, teacher["id"])
        cur.execute(
            """INSERT INTO assignments (teacher_id, class_id, title, description, due_date, group_id)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (teacher["id"], class_id, title, description, due_date, group_id),
        )
        assignment_id = cur.lastrowid
    return {"id": assignment_id, "status": "ok"}


@app.get("/teacher/assignments")
def list_teacher_assignments(teacher: dict = Depends(require_teacher)):
    with db_cursor() as cur:
        cur.execute(
            """SELECT a.*, c.name AS class_name, g.name AS group_name FROM assignments a
               JOIN classes c ON c.id = a.class_id
               LEFT JOIN class_groups g ON g.id = a.group_id
               WHERE a.teacher_id = ? ORDER BY a.created_at DESC""",
            (teacher["id"],),
        )
        assignments = [dict(r) for r in cur.fetchall()]
        for a in assignments:
            cur.execute(
                """SELECT s.id, s.student_id, u.full_name, s.original_filename, s.submitted_at
                   FROM submissions s JOIN users u ON u.id = s.student_id
                   WHERE s.assignment_id = ? ORDER BY s.submitted_at DESC""",
                (a["id"],),
            )
            a["submissions"] = [dict(r) for r in cur.fetchall()]
            cur.execute(
                """SELECT m.student_id, u.full_name FROM assignment_marks m
                   JOIN users u ON u.id = m.student_id
                   WHERE m.assignment_id = ? AND m.done = 1""",
                (a["id"],),
            )
            a["marked_done"] = [dict(r) for r in cur.fetchall()]
    return assignments


@app.get("/teacher/submissions/{submission_id}/download")
def download_submission(submission_id: int, teacher: dict = Depends(require_teacher)):
    with db_cursor() as cur:
        cur.execute(
            """SELECT s.* FROM submissions s
               JOIN assignments a ON a.id = s.assignment_id
               WHERE s.id = ? AND a.teacher_id = ?""",
            (submission_id, teacher["id"]),
        )
        sub = cur.fetchone()
    if not sub:
        raise HTTPException(status_code=404, detail="Rendu introuvable")
    return FileResponse(sub["file_path"], filename=sub["original_filename"])


# ---------- Élève ----------

def _student_class_ids(cur, student_id: int) -> List[int]:
    cur.execute("SELECT class_id FROM class_members WHERE student_id = ?", (student_id,))
    return [r["class_id"] for r in cur.fetchall()]


@app.get("/student/classes")
def student_classes(student: dict = Depends(require_student)):
    with db_cursor() as cur:
        cur.execute(
            """SELECT c.id, c.name, u.full_name AS teacher_name FROM classes c
               JOIN class_members cm ON cm.class_id = c.id
               JOIN users u ON u.id = c.teacher_id
               WHERE cm.student_id = ? ORDER BY c.name""",
            (student["id"],),
        )
        return [dict(r) for r in cur.fetchall()]


@app.get("/student/resources")
def student_resources(student: dict = Depends(require_student)):
    with db_cursor() as cur:
        class_ids = _student_class_ids(cur, student["id"])
        cur.execute("SELECT group_id FROM group_members WHERE student_id = ?", (student["id"],))
        group_ids = [r["group_id"] for r in cur.fetchall()]
        placeholders_c = ",".join("?" * len(class_ids)) if class_ids else "NULL"
        placeholders_g = ",".join("?" * len(group_ids)) if group_ids else "NULL"
        query = f"""
            SELECT DISTINCT r.id, r.type, r.title, r.content, r.original_filename, r.created_at,
                   u.full_name AS teacher_name
            FROM resources r
            JOIN resource_access ra ON ra.resource_id = r.id
            JOIN users u ON u.id = r.teacher_id
            WHERE (ra.target_type = 'student' AND ra.target_id = ?)
               OR (ra.target_type = 'class' AND ra.target_id IN ({placeholders_c}))
               OR (ra.target_type = 'group' AND ra.target_id IN ({placeholders_g}))
            ORDER BY r.created_at DESC
        """
        params = [student["id"]] + class_ids + group_ids
        cur.execute(query, params)
        return [dict(r) for r in cur.fetchall()]


@app.get("/student/resources/{resource_id}/download")
def download_resource(resource_id: int, student: dict = Depends(require_student)):
    with db_cursor() as cur:
        class_ids = _student_class_ids(cur, student["id"])
        cur.execute("SELECT group_id FROM group_members WHERE student_id = ?", (student["id"],))
        group_ids = {r["group_id"] for r in cur.fetchall()}
        cur.execute("SELECT * FROM resources WHERE id = ? AND type = 'file'", (resource_id,))
        res = cur.fetchone()
        if not res:
            raise HTTPException(status_code=404, detail="Fichier introuvable")
        cur.execute("SELECT target_type, target_id FROM resource_access WHERE resource_id = ?", (resource_id,))
        access = cur.fetchall()
        allowed = any(
            (a["target_type"] == "student" and a["target_id"] == student["id"])
            or (a["target_type"] == "class" and a["target_id"] in class_ids)
            or (a["target_type"] == "group" and a["target_id"] in group_ids)
            for a in access
        )
    if not allowed:
        raise HTTPException(status_code=403, detail="Accès non autorisé")
    return FileResponse(res["file_path"], filename=res["original_filename"])


@app.get("/student/assignments")
def student_assignments(student: dict = Depends(require_student)):
    with db_cursor() as cur:
        class_ids = _student_class_ids(cur, student["id"])
        if not class_ids:
            return []
        cur.execute("SELECT group_id FROM group_members WHERE student_id = ?", (student["id"],))
        my_group_ids = {r["group_id"] for r in cur.fetchall()}

        placeholders = ",".join("?" * len(class_ids))
        cur.execute(
            f"""SELECT a.*, c.name AS class_name FROM assignments a
                JOIN classes c ON c.id = a.class_id
                WHERE a.class_id IN ({placeholders}) ORDER BY a.due_date IS NULL, a.due_date""",
            class_ids,
        )
        assignments = [dict(r) for r in cur.fetchall() if not r["group_id"] or r["group_id"] in my_group_ids]
        for a in assignments:
            cur.execute(
                "SELECT id, original_filename, submitted_at FROM submissions WHERE assignment_id = ? AND student_id = ?",
                (a["id"], student["id"]),
            )
            sub = cur.fetchone()
            a["my_submission"] = dict(sub) if sub else None
            cur.execute(
                "SELECT done FROM assignment_marks WHERE assignment_id = ? AND student_id = ?",
                (a["id"], student["id"]),
            )
            mark = cur.fetchone()
            a["marked_done"] = bool(mark["done"]) if mark else False
    return assignments


@app.post("/student/assignments/{assignment_id}/mark-done")
def mark_assignment_done(assignment_id: int, done: bool = Form(...), student: dict = Depends(require_student)):
    with db_cursor() as cur:
        class_ids = _student_class_ids(cur, student["id"])
        cur.execute("SELECT class_id FROM assignments WHERE id = ?", (assignment_id,))
        a = cur.fetchone()
        if not a or a["class_id"] not in class_ids:
            raise HTTPException(status_code=404, detail="Devoir introuvable")
    with db_cursor(commit=True) as cur:
        cur.execute(
            """INSERT INTO assignment_marks (assignment_id, student_id, done, marked_at)
               VALUES (?, ?, ?, CURRENT_TIMESTAMP)
               ON CONFLICT(assignment_id, student_id) DO UPDATE SET
                 done = excluded.done, marked_at = CURRENT_TIMESTAMP""",
            (assignment_id, student["id"], 1 if done else 0),
        )
    return {"status": "ok"}


# ---------- Élève : notes ----------

@app.get("/student/grades")
def student_grades(student: dict = Depends(require_student)):
    with db_cursor() as cur:
        cur.execute(
            """SELECT g.id, g.label, g.value, g.max_value, g.created_at, c.name AS class_name
               FROM grades g JOIN classes c ON c.id = g.class_id
               WHERE g.student_id = ? ORDER BY g.created_at DESC""",
            (student["id"],),
        )
        return [dict(r) for r in cur.fetchall()]


# ---------- Élève : QCM ----------

@app.get("/student/quizzes")
def student_quizzes(student: dict = Depends(require_student)):
    with db_cursor() as cur:
        class_ids = _student_class_ids(cur, student["id"])
        if not class_ids:
            return []
        placeholders = ",".join("?" * len(class_ids))
        cur.execute(
            f"""SELECT q.id, q.title, q.created_at, c.name AS class_name FROM quizzes q
                JOIN classes c ON c.id = q.class_id
                WHERE q.class_id IN ({placeholders}) ORDER BY q.created_at DESC""",
            class_ids,
        )
        quizzes = [dict(r) for r in cur.fetchall()]
        for qz in quizzes:
            cur.execute("SELECT COUNT(*) AS n FROM quiz_questions WHERE quiz_id = ?", (qz["id"],))
            qz["question_count"] = cur.fetchone()["n"]
            cur.execute(
                "SELECT score, total, submitted_at FROM quiz_attempts WHERE quiz_id = ? AND student_id = ?",
                (qz["id"], student["id"]),
            )
            attempt = cur.fetchone()
            qz["my_attempt"] = dict(attempt) if attempt else None
    return quizzes


@app.get("/student/quizzes/{quiz_id}")
def get_quiz(quiz_id: int, student: dict = Depends(require_student)):
    with db_cursor() as cur:
        class_ids = _student_class_ids(cur, student["id"])
        cur.execute("SELECT * FROM quizzes WHERE id = ?", (quiz_id,))
        quiz = cur.fetchone()
        if not quiz or quiz["class_id"] not in class_ids:
            raise HTTPException(status_code=404, detail="QCM introuvable")
        cur.execute("SELECT id FROM quiz_attempts WHERE quiz_id = ? AND student_id = ?", (quiz_id, student["id"]))
        if cur.fetchone():
            raise HTTPException(status_code=400, detail="Tu as déjà répondu à ce QCM")
        cur.execute(
            "SELECT id, question_text FROM quiz_questions WHERE quiz_id = ? ORDER BY position", (quiz_id,)
        )
        questions = [dict(r) for r in cur.fetchall()]
        for q in questions:
            cur.execute("SELECT id, option_text FROM quiz_options WHERE question_id = ?", (q["id"],))
            q["options"] = [dict(r) for r in cur.fetchall()]
    return {"id": quiz["id"], "title": quiz["title"], "questions": questions}


@app.post("/student/quizzes/{quiz_id}/submit")
def submit_quiz(quiz_id: int, answers: str = Form(...), student: dict = Depends(require_student)):
    """answers : JSON {"<question_id>": <option_id>, ...}"""
    try:
        parsed_answers = {int(k): int(v) for k, v in json.loads(answers).items()}
    except (json.JSONDecodeError, ValueError, AttributeError):
        raise HTTPException(status_code=400, detail="Format de réponses invalide")

    with db_cursor() as cur:
        class_ids = _student_class_ids(cur, student["id"])
        cur.execute("SELECT * FROM quizzes WHERE id = ?", (quiz_id,))
        quiz = cur.fetchone()
        if not quiz or quiz["class_id"] not in class_ids:
            raise HTTPException(status_code=404, detail="QCM introuvable")
        cur.execute("SELECT id FROM quiz_attempts WHERE quiz_id = ? AND student_id = ?", (quiz_id, student["id"]))
        if cur.fetchone():
            raise HTTPException(status_code=400, detail="Tu as déjà répondu à ce QCM")

        cur.execute("SELECT id FROM quiz_questions WHERE quiz_id = ?", (quiz_id,))
        question_ids = [r["id"] for r in cur.fetchall()]
        score = 0
        results = []
        for qid in question_ids:
            cur.execute("SELECT id, is_correct FROM quiz_options WHERE question_id = ?", (qid,))
            options = cur.fetchall()
            correct_option_id = next((o["id"] for o in options if o["is_correct"]), None)
            selected = parsed_answers.get(qid)
            is_right = selected == correct_option_id
            if is_right:
                score += 1
            results.append({"question_id": qid, "selected": selected, "correct": correct_option_id, "is_right": is_right})

    with db_cursor(commit=True) as cur:
        cur.execute(
            "INSERT INTO quiz_attempts (quiz_id, student_id, score, total) VALUES (?, ?, ?, ?)",
            (quiz_id, student["id"], score, len(question_ids)),
        )
        attempt_id = cur.lastrowid
        for r in results:
            cur.execute(
                "INSERT INTO quiz_answers (attempt_id, question_id, option_id) VALUES (?, ?, ?)",
                (attempt_id, r["question_id"], r["selected"]),
            )
    return {"score": score, "total": len(question_ids), "details": results}


@app.post("/student/assignments/{assignment_id}/submit")
def submit_assignment(
    assignment_id: int, file: UploadFile = File(...), student: dict = Depends(require_student)
):
    with db_cursor() as cur:
        class_ids = _student_class_ids(cur, student["id"])
        cur.execute("SELECT * FROM assignments WHERE id = ?", (assignment_id,))
        a = cur.fetchone()
        if not a or a["class_id"] not in class_ids:
            raise HTTPException(status_code=404, detail="Devoir introuvable")

    ext = os.path.splitext(file.filename)[1]
    stored_name = f"{uuid.uuid4().hex}{ext}"
    stored_path = os.path.join(STORAGE_SUBMISSIONS, stored_name)
    save_upload_capped(file, stored_path)

    with db_cursor(commit=True) as cur:
        cur.execute(
            """INSERT INTO submissions (assignment_id, student_id, file_path, original_filename)
               VALUES (?, ?, ?, ?)
               ON CONFLICT(assignment_id, student_id) DO UPDATE SET
                 file_path = excluded.file_path,
                 original_filename = excluded.original_filename,
                 submitted_at = CURRENT_TIMESTAMP""",
            (assignment_id, student["id"], stored_path, file.filename),
        )
    return {"status": "ok"}


app.mount("/avatars", StaticFiles(directory=STORAGE_AVATARS), name="avatars")
app.mount("/", StaticFiles(directory="static", html=True), name="static")
