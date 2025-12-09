import csv
import io
import hashlib
import secrets
import json
import re
from datetime import datetime, timedelta
from typing import List, Optional

from fastapi import FastAPI, Depends, HTTPException, status, WebSocket, WebSocketDisconnect, UploadFile, File, Form, Query
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, DateTime, Text, Boolean, or_
from sqlalchemy.orm import sessionmaker, relationship, declarative_base, Session
from jose import JWTError, jwt

# --- KONFIGURASI ---
SECRET_KEY = secrets.token_hex(32)
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1440 

SQLALCHEMY_DATABASE_URL = "sqlite:///./ujian_online.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()

# --- UTILS ---
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password_hash(plain_password: str, hashed_password: str) -> bool:
    return hash_password(plain_password) == hashed_password

def update_session_status_if_expired(db: Session, session):
    if session.status == "ONGOING" and session.start_time:
        limit = session.start_time + timedelta(minutes=session.duration_minutes)
        if datetime.utcnow() > limit:
            session.status = "FINISHED"
            db.commit()

# --- DATABASE MODELS ---
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    password = Column(String) 
    role = Column(String) 
    full_name = Column(String, nullable=True) 
    class_name = Column(String, nullable=True) 
    address = Column(String, nullable=True)    
    active_token = Column(String, nullable=True) 

class ExamSession(Base):
    __tablename__ = "exam_sessions"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String)
    duration_minutes = Column(Integer)
    status = Column(String, default="WAITING") 
    start_time = Column(DateTime, nullable=True) 
    questions = relationship("Question", back_populates="session", cascade="all, delete-orphan")
    participants = relationship("SessionParticipant", back_populates="session", cascade="all, delete-orphan")

class Question(Base):
    __tablename__ = "questions"
    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(Integer, ForeignKey("exam_sessions.id"))
    text = Column(String)
    option_a = Column(String)
    option_b = Column(String)
    option_c = Column(String)
    option_d = Column(String)
    correct_answer = Column(String) 
    session = relationship("ExamSession", back_populates="questions")

class SessionParticipant(Base):
    __tablename__ = "session_participants"
    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(Integer, ForeignKey("exam_sessions.id"))
    user_id = Column(Integer, ForeignKey("users.id"))
    session = relationship("ExamSession", back_populates="participants")
    user = relationship("User")
    result = relationship("ExamResult", back_populates="participant", uselist=False, cascade="all, delete-orphan")

class ExamResult(Base):
    __tablename__ = "exam_results"
    id = Column(Integer, primary_key=True, index=True)
    participant_id = Column(Integer, ForeignKey("session_participants.id"))
    score = Column(Integer)
    answers_json = Column(Text) 
    participant = relationship("SessionParticipant", back_populates="result")

Base.metadata.create_all(bind=engine)

# --- DEPENDENCIES ---
def get_db():
    db = SessionLocal()
    try: yield db
    finally: db.close()

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None: raise HTTPException(401, "Invalid credentials")
    except JWTError: raise HTTPException(401, "Invalid credentials")
    user = db.query(User).filter(User.username == username).first()
    if user is None: raise HTTPException(401, "User not found")
    if user.active_token != token: raise HTTPException(status_code=401, detail="SESSION_EXPIRED")
    return user

# --- WEBSOCKET ---
class ConnectionManager:
    def __init__(self): self.active_connections: dict[int, List[WebSocket]] = {}
    async def connect(self, websocket: WebSocket, session_id: int):
        await websocket.accept()
        if session_id not in self.active_connections: self.active_connections[session_id] = []
        self.active_connections[session_id].append(websocket)
    def disconnect(self, websocket: WebSocket, session_id: int):
        if session_id in self.active_connections and websocket in self.active_connections[session_id]:
            self.active_connections[session_id].remove(websocket)
    async def broadcast(self, message: str, session_id: int):
        if session_id in self.active_connections:
            for connection in self.active_connections[session_id]:
                try: await connection.send_text(message)
                except: pass
manager = ConnectionManager()

# --- INIT DB ---
def init_db():
    db = SessionLocal()
    if not db.query(User).filter(User.username == "admin").first():
        db.add(User(username="admin", password=hash_password("admin"), role="admin", full_name="Administrator"))
        db.commit()
    db.close()
init_db()

# --- ROUTES: AUTH ---
@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()
    valid = False
    if user:
        if user.role == "admin": valid = verify_password_hash(form_data.password, user.password)
        else: valid = (user.password == form_data.password)
    
    if not valid: raise HTTPException(401, "Username/Password salah")

    # --- PERBAIKAN LOGIC LOGIN ---
    # Jika Admin: Boleh overwrite sesi lama (Force Login)
    # Jika Siswa: Tidak boleh overwrite (Strict Single Session)
    if user.role != "admin" and user.active_token is not None:
         raise HTTPException(status_code=403, detail="ALREADY_LOGGED_IN")
    
    access_token = create_access_token(data={"sub": user.username, "role": user.role})
    
    # Simpan token baru (jika admin, token lama otomatis tertimpa/invalid)
    user.active_token = access_token
    db.commit()
    
    return {"access_token": access_token, "token_type": "bearer", "role": user.role}

@app.post("/logout")
def logout(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    current_user.active_token = None
    db.commit()
    return {"message": "Logged out"}

@app.get("/users/me")
def get_me(current_user: User = Depends(get_current_user)):
    return {"username": current_user.username, "full_name": current_user.full_name, "role": current_user.role}

# --- ROUTES: ADMIN LOGIC ---

@app.post("/admin/change_password")
def change_admin_password(current_password: str = Form(...), new_password: str = Form(...), db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if current_user.role != "admin": raise HTTPException(403)
    if not verify_password_hash(current_password, current_user.password):
        raise HTTPException(status_code=400, detail="Password lama salah!")
    current_user.password = hash_password(new_password)
    db.commit()
    return {"message": "Password berhasil diganti"}

@app.post("/admin/reset_login/{user_id}")
def reset_user_login(user_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if current_user.role != "admin": raise HTTPException(403)
    user = db.query(User).get(user_id)
    if user: 
        user.active_token = None
        db.commit()
    return {"message": "Reset"}

@app.get("/admin/classes")
def get_classes(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if current_user.role != "admin": raise HTTPException(403)
    classes = db.query(User.class_name).filter(User.role == "student").distinct().all()
    return sorted([c[0] for c in classes if c[0]])

@app.get("/admin/students/search")
def search_students(q: str = "", class_filter: str = "", db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if current_user.role != "admin": raise HTTPException(403)
    query = db.query(User).filter(User.role == "student")
    if class_filter and class_filter.strip() != "": query = query.filter(User.class_name == class_filter)
    if q: query = query.filter(or_(User.username.contains(q), User.full_name.contains(q)))
    users = query.limit(20).all()
    return [{"id": u.id, "username": u.username, "full_name": u.full_name or u.username, "class_name": u.class_name or "-", "is_login": u.active_token is not None} for u in users]

@app.get("/admin/students/all")
def get_all_students(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if current_user.role != "admin": raise HTTPException(403)
    users = db.query(User).filter(User.role == "student").all()
    return [{
        "id": u.id, "username": u.username, "full_name": u.full_name or "", 
        "class_name": u.class_name or "", "address": u.address or "",
        "is_login": u.active_token is not None
    } for u in users]

@app.get("/admin/student/{user_id}/detail")
def get_student_detail(user_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if current_user.role != "admin": raise HTTPException(403)
    user = db.query(User).get(user_id)
    history = []
    for p in db.query(SessionParticipant).filter_by(user_id=user.id).all():
        score = p.result.score if p.result else "N/A"
        history.append({"session_name": p.session.name, "score": score})
    return {
        "id": user.id, "username": user.username, "full_name": user.full_name,
        "class_name": user.class_name, "address": user.address, "password": user.password, 
        "history": history, "is_login": user.active_token is not None
    }

@app.put("/admin/student/{user_id}/update")
def update_student(user_id: int, username: str = Form(...), full_name: str = Form(...), class_name: str = Form(""), address: str = Form(""), password: Optional[str] = Form(None), db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if current_user.role != "admin": raise HTTPException(403)
    user = db.query(User).get(user_id)
    user.username = username; user.full_name = full_name; user.class_name = class_name; user.address = address
    if password and password.strip(): user.password = password
    db.commit()
    return {"message": "Updated"}

@app.get("/admin/sessions")
def get_sessions(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if current_user.role != "admin": raise HTTPException(403)
    sessions = db.query(ExamSession).all()
    for s in sessions: update_session_status_if_expired(db, s)
    return [{"id": s.id, "name": s.name, "duration": s.duration_minutes, "status": s.status} for s in sessions]

@app.get("/admin/session/{session_id}")
def get_session_detail_admin(session_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if current_user.role != "admin": raise HTTPException(403)
    sess = db.query(ExamSession).get(session_id)
    update_session_status_if_expired(db, sess)
    questions = [{"text": q.text, "answer": q.correct_answer} for q in sess.questions]
    participants = [{"full_name": p.user.full_name or p.user.username, "class_name": p.user.class_name} for p in sess.participants]
    return {"id": sess.id, "name": sess.name, "status": sess.status, "questions": questions, "participants": participants}

@app.post("/admin/create_user")
def create_student(username: str = Form(...), password: str = Form(...), full_name: str = Form(...), class_name: str = Form(""), address: str = Form(""), current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if current_user.role != "admin": raise HTTPException(403)
    if db.query(User).filter(User.username == username).first(): raise HTTPException(400, "Username exists")
    db.add(User(username=username, password=password, role="student", full_name=full_name, class_name=class_name, address=address))
    db.commit()
    return {"message": "Siswa created"}

@app.post("/admin/create_session")
async def create_session(name: str = Form(...), duration: int = Form(...), file: UploadFile = File(...), current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if current_user.role != "admin": raise HTTPException(403)
    content = await file.read()
    try: decoded = content.decode('utf-8-sig') 
    except: decoded = content.decode('latin-1')
    lines = decoded.splitlines()
    delimiter = ';' if lines and ';' in lines[0] else ','
    reader = csv.reader(lines, delimiter=delimiter)
    
    new_session = ExamSession(name=name, duration_minutes=duration)
    db.add(new_session); db.commit(); db.refresh(new_session)
    
    questions = []
    for row in reader:
        if not row or len(row) < 6 or ('soal' in row[0].lower() and 'jawaban' in row[5].lower()): continue
        questions.append(Question(session_id=new_session.id, text=row[0], option_a=row[1], option_b=row[2], option_c=row[3], option_d=row[4], correct_answer=row[5].lower().strip()))
    if not questions: db.delete(new_session); db.commit(); raise HTTPException(400, "CSV Error/Empty")
    db.add_all(questions); db.commit()
    return {"message": "OK"}

@app.post("/admin/add_participant")
def add_participant(session_id: int = Form(...), user_id: int = Form(...), current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if current_user.role != "admin": raise HTTPException(403)
    if not db.query(SessionParticipant).filter_by(session_id=session_id, user_id=user_id).first():
        db.add(SessionParticipant(session_id=session_id, user_id=user_id)); db.commit()
    return {"message": "Added"}

@app.post("/admin/start_exam/{session_id}")
async def start_exam(session_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    sess = db.query(ExamSession).get(session_id)
    sess.status = "ONGOING"; sess.start_time = datetime.utcnow(); db.commit()
    await manager.broadcast("START", session_id)
    return {"msg": "OK"}

@app.post("/admin/stop_exam/{session_id}")
async def stop_exam(session_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    sess = db.query(ExamSession).get(session_id)
    sess.status = "FINISHED"; db.commit()
    await manager.broadcast("FORCE_SUBMIT", session_id)
    return {"msg": "OK"}

@app.get("/admin/export_results/{session_id}")
def export_results(session_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    sess = db.query(ExamSession).get(session_id)
    parts = db.query(SessionParticipant).filter_by(session_id=session_id).all()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Username", "Nama Lengkap", "Kelas", "Score", "Answers JSON"])
    for p in parts:
        score = p.result.score if p.result else 0
        ans = p.result.answers_json if p.result else "N/A"
        writer.writerow([p.user.username, p.user.full_name, p.user.class_name, score, ans])
    output.seek(0)
    safe_name = re.sub(r'[^a-zA-Z0-9]', '-', sess.name).lower()
    return StreamingResponse(io.StringIO(output.getvalue()), media_type="text/csv", headers={"Content-Disposition": f'attachment; filename="hasil-{safe_name}.csv"'})

# --- ROUTES: STUDENT ---
@app.get("/student/my_sessions")
def student_sessions(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    parts = db.query(SessionParticipant).filter_by(user_id=current_user.id).all()
    data = []
    for p in parts:
        s = p.session
        update_session_status_if_expired(db, s)
        is_done = db.query(ExamResult).filter_by(participant_id=p.id).first() is not None
        data.append({"session_id": s.id, "name": s.name, "status": s.status, "is_done": is_done})
    return data

@app.get("/student/exam/{session_id}")
def student_exam_data(session_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    part = db.query(SessionParticipant).filter_by(session_id=session_id, user_id=current_user.id).first()
    if not part: raise HTTPException(403)
    if db.query(ExamResult).filter_by(participant_id=part.id).first(): raise HTTPException(400, "Done")
    
    sess = db.query(ExamSession).get(session_id)
    update_session_status_if_expired(db, sess)
    
    if sess.status == "WAITING": return {"status": "WAITING"}
    if sess.status == "FINISHED": raise HTTPException(400, "Finished")
    
    elapsed = (datetime.utcnow() - sess.start_time).total_seconds()
    remaining = (sess.duration_minutes * 60) - elapsed
    if remaining <= 0: raise HTTPException(400, "TimeUp")
    
    questions = db.query(Question).filter_by(session_id=session_id).all()
    q_data = [{"id": q.id, "text": q.text, "options": {"a":q.option_a,"b":q.option_b,"c":q.option_c,"d":q.option_d}} for q in questions]
    return {"status": "ONGOING", "remaining_seconds": remaining, "questions": q_data}

@app.post("/student/submit_exam")
async def submit_exam(session_id: int = Form(...), answers: str = Form(...), current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    part = db.query(SessionParticipant).filter_by(session_id=session_id, user_id=current_user.id).first()
    if not part or db.query(ExamResult).filter_by(participant_id=part.id).first(): return {"msg": "Done"}
    ans_dict = json.loads(answers)
    questions = db.query(Question).filter_by(session_id=session_id).all()
    score = sum(1 for q in questions if ans_dict.get(str(q.id), "").lower() == q.correct_answer)
    final = (score/len(questions))*100 if questions else 0
    db.add(ExamResult(participant_id=part.id, score=int(final), answers_json=answers))
    db.commit()
    return {"score": final}

@app.websocket("/ws/{session_id}")
async def ws_endpoint(websocket: WebSocket, session_id: int):
    await manager.connect(websocket, session_id)
    try:
        while True: await websocket.receive_text()
    except WebSocketDisconnect: manager.disconnect(websocket, session_id)

# --- TEMPLATES ---
html_base = """
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Ujian Online</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <style> body { background: #f8f9fa; padding: 20px; } .hidden { display: none; } .card { box-shadow: 0 4px 6px rgba(0,0,0,0.05); border:none; } </style>
</head>
<body>
    <div class="container" id="app"></div>
    <script>
        let token = localStorage.getItem('token');
        function logout(message = null) {
            localStorage.clear();
            document.body.innerHTML = `
                <div class="d-flex justify-content-center align-items-center vh-100 flex-column">
                    <h3 class="text-danger">${message || "Sesi Berakhir"}</h3>
                    <p>Anda telah dikeluarkan atau logout.</p>
                    <div class="alert alert-warning">
                        Silakan tunggu <span id="cnt" class="fw-bold">10</span> detik untuk login kembali...
                    </div>
                </div>
            `;
            let sec = 10;
            let intv = setInterval(() => { sec--; document.getElementById('cnt').innerText = sec; if(sec <= 0) { clearInterval(intv); window.location.href = "/"; } }, 1000);
        }
        async function request(url, method="GET", data=null, isForm=false) {
            let headers = {};
            if (token) headers['Authorization'] = 'Bearer ' + token;
            let body = data;
            if (data && !isForm) { headers['Content-Type'] = 'application/json'; body = JSON.stringify(data); }
            let opts = { method, headers, body };
            const res = await fetch(url, opts);
            if (res.status === 401) { logout("Sesi Direset / Expired"); return null; }
            return res;
        }
        async function doRealLogout() { await request('/logout', 'POST'); logout("Berhasil Keluar"); }
    </script>
"""

@app.get("/", response_class=HTMLResponse)
def page_login():
    return html_base + """
    <div class="row justify-content-center mt-5">
        <div class="col-md-4">
            <div class="card p-4">
                <h3 class="text-center mb-4 text-primary">Login Ujian</h3>
                <div id="err_msg" class="alert alert-danger hidden"></div>
                <div class="mb-3"><label>Username</label><input type="text" id="user" class="form-control"></div>
                <div class="mb-3"><label>Password</label><input type="password" id="pass" class="form-control"></div>
                <button onclick="doLogin()" class="btn btn-primary w-100">Masuk</button>
            </div>
        </div>
    </div>
    <script>
        async function doLogin() {
            $('#err_msg').addClass('hidden');
            let fd = new FormData(); fd.append('username', $('#user').val()); fd.append('password', $('#pass').val());
            let res = await fetch('/token', { method: 'POST', body: fd });
            if (res.ok) {
                let data = await res.json();
                localStorage.setItem('token', data.access_token);
                localStorage.setItem('role', data.role);
                window.location.href = (data.role === 'admin') ? '/dashboard/admin' : '/dashboard/student';
            } else {
                let err = await res.json();
                let msg = "Username/Password Salah";
                if(res.status === 403 && err.detail === "ALREADY_LOGGED_IN") msg = "Akun sedang aktif! Hubungi Admin untuk reset.";
                $('#err_msg').text(msg).removeClass('hidden');
            }
        }
    </script></body></html>
    """

@app.get("/dashboard/admin", response_class=HTMLResponse)
def page_admin():
    return html_base + """
    <nav class="navbar navbar-expand-lg navbar-dark bg-primary mb-4 shadow rounded px-3">
        <a class="navbar-brand" href="#">Administrator</a>
        <div class="ms-auto">
            <button onclick="showSection('section-exam')" class="btn btn-light btn-sm me-2 text-primary fw-bold">Ujian</button>
            <button onclick="showSection('section-students')" class="btn btn-outline-light btn-sm me-2">Data Siswa</button>
            <button onclick="$('#changePassModal').modal('show')" class="btn btn-warning btn-sm me-2">Ganti Password</button>
            <button onclick="doRealLogout()" class="btn btn-danger btn-sm">Logout</button>
        </div>
    </nav>
    
    <div id="section-exam">
        <div class="row">
            <div class="col-md-4">
                <div class="card p-3 mb-3">
                    <h5 class="text-primary">Buat Sesi Ujian</h5>
                    <input type="text" id="sess_name" placeholder="Nama Ujian" class="form-control mb-2">
                    <input type="number" id="sess_dur" placeholder="Durasi (Menit)" class="form-control mb-2">
                    <label class="small text-muted">Upload CSV (soal,a,b,c,d,jawaban)</label>
                    <input type="file" id="sess_file" class="form-control mb-2">
                    <button onclick="createSession()" class="btn btn-primary w-100">Simpan Sesi</button>
                </div>
            </div>
            <div class="col-md-8">
                <div class="card p-3">
                    <div class="d-flex justify-content-between align-items-center">
                        <h5 class="m-0">Daftar Sesi</h5>
                        <button onclick="loadSessions()" class="btn btn-sm btn-light border">Refresh</button>
                    </div>
                    <table class="table table-hover mt-3">
                        <thead class="table-light"><tr><th>Nama</th><th>Status</th><th>Aksi</th></tr></thead>
                        <tbody id="session_table"></tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>

    <div id="section-students" class="hidden">
        <div class="row">
            <div class="col-md-4">
                <div class="card p-3 mb-3">
                    <h5 class="text-success">Tambah Siswa</h5>
                    <input type="text" id="new_st_full" placeholder="Nama Lengkap" class="form-control mb-2">
                    <input type="text" id="new_st_user" placeholder="Username" class="form-control mb-2">
                    <input type="text" id="new_st_pass" placeholder="Password" class="form-control mb-2">
                    <input type="text" id="new_st_class" placeholder="Kelas" class="form-control mb-2">
                    <input type="text" id="new_st_addr" placeholder="Alamat" class="form-control mb-2">
                    <button onclick="createStudent()" class="btn btn-success w-100">Simpan Siswa</button>
                </div>
            </div>
            <div class="col-md-8">
                <div class="card p-3">
                    <div class="d-flex justify-content-between">
                         <h5 class="m-0">Database Siswa</h5>
                         <button onclick="loadAllStudents()" class="btn btn-sm btn-light border">Refresh</button>
                    </div>
                    <div style="max-height: 500px; overflow-y:auto;" class="mt-2">
                        <table class="table table-sm table-striped">
                            <thead><tr><th>Nama</th><th>Kelas</th><th>Status</th><th>Aksi</th></tr></thead>
                            <tbody id="all_students_table"></tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- MODAL DETAIL SESI -->
    <div class="modal fade" id="detailModal" tabindex="-1">
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <div class="modal-header"><h5 class="modal-title">Manajemen Peserta</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div>
                <div class="modal-body">
                    <div class="row">
                        <div class="col-md-6 border-end">
                            <h6>Tambah Peserta</h6>
                            <div class="input-group mb-2">
                                <select id="filter_class" class="form-select" onchange="searchStudent()" style="max-width: 100px;"><option value="">Semua</option></select>
                                <input type="text" id="search_input" class="form-control" placeholder="Cari Nama..." onkeyup="searchStudent()">
                            </div>
                            <input type="hidden" id="selected_student_id">
                            <ul id="search_results" class="list-group position-absolute w-50 shadow" style="z-index:999; display:none; max-height:200px; overflow:auto;"></ul>
                            <button onclick="addParticipant()" class="btn btn-info w-100 text-white">Tambahkan</button>
                            <hr>
                            <ul id="participant_list" class="small text-muted ps-3 mb-0" style="max-height:150px; overflow:auto;"></ul>
                        </div>
                        <div class="col-md-6">
                            <h6>Info</h6>
                            <p>Jumlah Soal: <span id="q_count"></span></p>
                            <button onclick="downloadResult()" class="btn btn-secondary w-100">Download Hasil (CSV)</button>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- MODAL EDIT SISWA -->
    <div class="modal fade" id="studentDetailModal" tabindex="-1">
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <div class="modal-header bg-warning"><h5 class="modal-title">Edit Siswa</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div>
                <div class="modal-body">
                    <form id="editStudentForm"><input type="hidden" id="edit_id">
                        <div class="row">
                            <div class="col-md-6">
                                <input type="text" id="edit_full" class="form-control mb-2" placeholder="Nama">
                                <input type="text" id="edit_user" class="form-control mb-2" placeholder="Username">
                                <input type="text" id="edit_class" class="form-control mb-2" placeholder="Kelas">
                                <input type="text" id="edit_addr" class="form-control mb-2" placeholder="Alamat">
                                <input type="text" id="edit_pass" class="form-control mb-2" placeholder="Password Baru (Opsional)">
                            </div>
                            <div class="col-md-6">
                                <h6>Riwayat</h6>
                                <table class="table table-sm table-bordered"><thead><tr><th>Sesi</th><th>Nilai</th></tr></thead><tbody id="history_table"></tbody></table>
                            </div>
                        </div>
                    </form>
                </div>
                <div class="modal-footer">
                    <button onclick="resetLogin()" class="btn btn-danger me-auto">Reset Login (Kick)</button>
                    <button onclick="saveStudentChanges()" class="btn btn-primary">Simpan</button>
                </div>
            </div>
        </div>
    </div>

    <!-- MODAL GANTI PASSWORD ADMIN -->
    <div class="modal fade" id="changePassModal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header bg-warning"><h5 class="modal-title">Ganti Password Admin</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div>
                <div class="modal-body">
                    <div class="mb-3"><label>Password Lama</label><input type="password" id="old_admin_pass" class="form-control"></div>
                    <div class="mb-3"><label>Password Baru</label><input type="password" id="new_admin_pass" class="form-control"></div>
                </div>
                <div class="modal-footer">
                    <button onclick="doChangePass()" class="btn btn-primary">Ganti</button>
                </div>
            </div>
        </div>
    </div>

    <script>
        let currentSessId = null;
        let searchTimeout;

        function showSection(id) {
            $('#section-exam, #section-students').addClass('hidden');
            $('#' + id).removeClass('hidden');
            if(id === 'section-students') loadAllStudents(); else loadSessions();
        }

        async function createSession() {
            let fd = new FormData();
            fd.append('name', $('#sess_name').val()); fd.append('duration', $('#sess_dur').val());
            fd.append('file', $('#sess_file')[0].files[0]);
            let res = await request('/admin/create_session', 'POST', fd, true);
            if(res && res.ok) { alert('Sesi dibuat'); loadSessions(); }
        }

        async function loadSessions() {
            let res = await request('/admin/sessions');
            if(res && res.ok) {
                let html = '';
                (await res.json()).forEach(s => {
                    let st = s.status=='ONGOING' ? '<span class="badge bg-success">Jalan</span>' : (s.status=='FINISHED'?'<span class="badge bg-dark">Selesai</span>':'<span class="badge bg-secondary">Tunggu</span>');
                    let btn = s.status=='WAITING' ? `<button onclick="act(${s.id},'start')" class="btn btn-success btn-sm">Start</button>` : (s.status=='ONGOING' ? `<button onclick="act(${s.id},'stop')" class="btn btn-danger btn-sm">Stop</button>` : '');
                    html += `<tr><td>${s.name}</td><td>${st}</td><td>${btn} <button onclick="openSessDetail(${s.id})" class="btn btn-info btn-sm text-white">Detail</button></td></tr>`;
                });
                $('#session_table').html(html);
            }
        }
        async function act(id, type) { request(`/admin/${type}_exam/${id}`, 'POST').then(()=>loadSessions()); }
        
        async function openSessDetail(id) {
            currentSessId = id;
            let res = await request(`/admin/session/${id}`);
            let d = await res.json();
            $('#q_count').text(d.questions.length);
            $('#participant_list').html(d.participants.map(p => `<li>${p.full_name} (${p.class_name||'-'})</li>`).join(''));
            let cls = await request('/admin/classes');
            if(cls.ok) { let opts = '<option value="">Semua</option>'; (await cls.json()).forEach(c => opts += `<option value="${c}">${c}</option>`); $('#filter_class').html(opts); }
            $('#search_input').val(''); $('#search_results').hide();
            new bootstrap.Modal(document.getElementById('detailModal')).show();
        }
        
        function searchStudent() {
            clearTimeout(searchTimeout);
            let q = $('#search_input').val(); let cls = $('#filter_class').val();
            if(q.length < 1 && cls === "") { $('#search_results').hide(); return; }
            searchTimeout = setTimeout(async () => {
                let res = await request(`/admin/students/search?q=${q}&class_filter=${cls}`);
                if(res && res.ok) {
                    let users = await res.json();
                    let html = users.map(u => `<li class="list-group-item list-group-item-action" style="cursor:pointer" onclick="selectStudent(${u.id}, '${u.full_name}')">
                        <strong>${u.full_name}</strong> ${u.is_login ? '<span class="badge bg-success">Login</span>':''}
                    </li>`).join('');
                    $('#search_results').html(html || '<li class="list-group-item text-muted">Tidak ditemukan</li>').show();
                }
            }, 300);
        }
        function selectStudent(id, name) { $('#selected_student_id').val(id); $('#search_input').val(name); $('#search_results').hide(); }
        async function addParticipant() {
            let uid = $('#selected_student_id').val();
            let fd = new FormData(); fd.append('session_id', currentSessId); fd.append('user_id', uid);
            let res = await request('/admin/add_participant', 'POST', fd, true);
            if(res && res.ok) { alert('Ditambahkan'); openSessDetail(currentSessId); }
        }
        function downloadResult() {
            fetch(`/admin/export_results/${currentSessId}`, { headers: {'Authorization': 'Bearer '+token} })
            .then(r=>r.blob()).then(b=>{ 
                let a=document.createElement('a'); a.href=window.URL.createObjectURL(b); 
                a.download=`hasil-${currentSessId}.csv`; a.click(); 
            });
        }

        async function createStudent() {
            let fd = new FormData();
            fd.append('username', $('#new_st_user').val()); fd.append('password', $('#new_st_pass').val());
            fd.append('full_name', $('#new_st_full').val()); fd.append('class_name', $('#new_st_class').val()); 
            fd.append('address', $('#new_st_addr').val());
            let res = await request('/admin/create_user', 'POST', fd, true);
            if(res && res.ok) { alert('Siswa dibuat'); loadAllStudents(); }
        }

        async function loadAllStudents() {
            let res = await request('/admin/students/all');
            if(res && res.ok) {
                let html = '';
                (await res.json()).forEach(u => {
                    let status = u.is_login ? '<span class="badge bg-success">Sedang Login</span>' : '<span class="badge bg-secondary">Offline</span>';
                    html += `<tr><td>${u.full_name}</td><td>${u.class_name}</td><td>${status}</td>
                        <td><button onclick="editStudent(${u.id})" class="btn btn-warning btn-sm py-0">Edit</button></td></tr>`;
                });
                $('#all_students_table').html(html);
            }
        }

        async function editStudent(id) {
            let res = await request(`/admin/student/${id}/detail`);
            if(res && res.ok) {
                let d = await res.json();
                $('#edit_id').val(d.id); $('#edit_user').val(d.username); $('#edit_full').val(d.full_name);
                $('#edit_class').val(d.class_name); $('#edit_addr').val(d.address); $('#edit_pass').val('');
                $('#history_table').html(d.history.map(h => `<tr><td>${h.session_name}</td><td>${h.score}</td></tr>`).join(''));
                new bootstrap.Modal(document.getElementById('studentDetailModal')).show();
            }
        }

        async function saveStudentChanges() {
            let id = $('#edit_id').val();
            let fd = new FormData();
            fd.append('username', $('#edit_user').val()); fd.append('full_name', $('#edit_full').val());
            fd.append('class_name', $('#edit_class').val()); fd.append('address', $('#edit_addr').val());
            if($('#edit_pass').val()) fd.append('password', $('#edit_pass').val());
            let res = await request(`/admin/student/${id}/update`, 'PUT', fd, true);
            if(res && res.ok) { alert('Disimpan'); loadAllStudents(); }
        }
        
        async function resetLogin() {
            if(!confirm("Paksa logout siswa ini?")) return;
            let id = $('#edit_id').val();
            let res = await request(`/admin/reset_login/${id}`, 'POST');
            if(res && res.ok) { alert('Sesi login siswa direset.'); loadAllStudents(); }
        }

        async function doChangePass() {
            let oldp = $('#old_admin_pass').val();
            let newp = $('#new_admin_pass').val();
            if(!oldp || !newp) return alert("Isi semua field");
            
            let fd = new FormData();
            fd.append('current_password', oldp);
            fd.append('new_password', newp);
            
            let res = await request('/admin/change_password', 'POST', fd, true);
            if(res && res.ok) {
                alert('Password Berhasil Diganti. Silakan Login Ulang.');
                doRealLogout();
            } else {
                let err = await res.json();
                alert('Gagal: ' + err.detail);
            }
        }
        
        loadSessions();
    </script></body></html>
    """

@app.get("/dashboard/student", response_class=HTMLResponse)
def page_student():
    return html_base + """
    <nav class="navbar navbar-light bg-white border-bottom mb-4">
        <div class="container d-flex justify-content-between">
            <span class="navbar-brand mb-0 h1 text-primary">Sistem Ujian</span>
            <button onclick="doRealLogout()" class="btn btn-outline-danger btn-sm">Keluar</button>
        </div>
    </nav>
    <div class="container">
        <div class="card p-4 mb-4 bg-primary text-white shadow-sm">
            <h2 class="fw-bold">Halo, <span id="fullname">...</span></h2>
            <p class="mb-0">Selamat datang di dashboard ujian.</p>
        </div>
        <h5 class="mb-3 text-secondary">Daftar Ujian Saya</h5>
        <div id="list" class="row"></div>
    </div>
    
    <script>
        async function init() {
            let me = await request('/users/me');
            if(me && me.ok) $('#fullname').text((await me.json()).full_name);
            let res = await request('/student/my_sessions');
            if(res && res.ok) {
                let data = await res.json();
                if(data.length === 0) return $('#list').html('<div class="col-12 alert alert-warning">Belum ada ujian.</div>');
                let html = '';
                data.forEach(s => {
                    let badge = '', btn = '';
                    if(s.is_done) { 
                        badge = '<span class="badge bg-success mb-2">Selesai</span>'; 
                        btn = '<button disabled class="btn btn-secondary w-100">Sudah Selesai</button>';
                    } else if (s.status === 'FINISHED') {
                        badge = '<span class="badge bg-dark mb-2">Waktu Habis</span>';
                        btn = '<button disabled class="btn btn-secondary w-100">Sesi Berakhir</button>';
                    } else if (s.status === 'WAITING') {
                        badge = '<span class="badge bg-warning text-dark mb-2">Menunggu Admin</span>';
                        btn = `<a href="/exam_room/${s.session_id}" class="btn btn-outline-primary w-100">Masuk Ruang Tunggu</a>`;
                    } else {
                        badge = '<span class="badge bg-danger mb-2">Sedang Berlangsung</span>';
                        btn = `<a href="/exam_room/${s.session_id}" class="btn btn-primary w-100 fw-bold">MULAI KERJAKAN</a>`;
                    }
                    html += `<div class="col-md-4 mb-3"><div class="card h-100 p-3 shadow-sm border-0"><h5>${s.name}</h5><div>${badge}</div><div class="mt-auto pt-3">${btn}</div></div></div>`;
                });
                $('#list').html(html);
            }
        }
        init();
    </script></body></html>
    """

@app.get("/exam_room/{session_id}", response_class=HTMLResponse)
def page_exam(session_id: int):
    return html_base + f"""
    <div class="row justify-content-center">
        <div class="col-md-8">
            <div id="wait" class="alert alert-info text-center mt-5 shadow-sm p-5">
                <h4>Menunggu Admin...</h4>
                <p class="text-muted">Halaman akan refresh otomatis.</p>
            </div>
            <div id="exam" class="hidden">
                <div class="sticky-top bg-white py-3 border-bottom d-flex justify-content-between align-items-center mb-4">
                    <h5 class="m-0">Soal</h5>
                    <div class="bg-danger text-white px-3 py-2 rounded fw-bold shadow-sm">Sisa Waktu: <span id="timer">--:--</span></div>
                </div>
                <div id="q_area" class="mb-5"></div>
                <div class="d-grid gap-2 mb-5"><button onclick="submit()" class="btn btn-success btn-lg shadow">KIRIM JAWABAN SAYA</button></div>
            </div>
        </div>
    </div>
    <script>
        const ID = {session_id};
        let ws, ans={{}};
        async function check() {{
            let res = await request('/student/exam/'+ID);
            if(!res) return;
            if(!res.ok) {{ alert((await res.json()).detail); window.location.href='/dashboard/student'; return; }}
            let d = await res.json();
            if(d.status=='WAITING') initWS(); else {{ render(d); initWS(); }}
        }}
        function initWS() {{
            let proto = location.protocol === 'https:' ? 'wss' : 'ws';
            ws = new WebSocket(`${{proto}}://${{location.host}}/ws/${{ID}}`);
            ws.onmessage = e => {{ 
                if(e.data=='START') location.reload(); 
                if(e.data=='FORCE_SUBMIT') {{ alert('Waktu Habis!'); submit(); }}
            }};
        }}
        function render(d) {{
            $('#wait').hide(); $('#exam').removeClass('hidden');
            $('#q_area').html(d.questions.map((q,i)=>`
                <div class="card p-4 mb-4 border-0 shadow-sm"><h6 class="fw-bold mb-3">${{i+1}}. ${{q.text}}</h6>
                ${{['a','b','c','d'].map(o=>`<label class="list-group-item d-flex gap-3 border rounded p-3"><input class="form-check-input flex-shrink-0" type="radio" name="q_${{q.id}}" value="${{o}}" onchange="ans[${{q.id}}]='${{o}}'"><span><strong>${{o.toUpperCase()}}.</strong> ${{q.options[o]}}</span></label>`).join('')}}
                </div>`).join(''));
            let s = Math.floor(d.remaining_seconds);
            setInterval(()=>{{ s--; if(s<0) {{ submit(); return; }} let m=Math.floor(s/60); let sec=s%60; $('#timer').text(`${{m}}:${{sec<10?'0'+sec:sec}}`); }},1000);
        }}
        async function submit() {{
            let fd = new FormData(); fd.append('session_id', ID); fd.append('answers', JSON.stringify(ans));
            $('button').prop('disabled', true).text('Mengirim...');
            await request('/student/submit_exam', 'POST', fd, true);
            window.location.href='/dashboard/student';
        }}
        check();
    </script></body></html>
    """

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)