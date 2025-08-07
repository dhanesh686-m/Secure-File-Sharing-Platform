# app.py
# Core Flask application for the Secure File Sharing Platform

import os
import uuid
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session,
    send_from_directory,
    abort,
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
import base64

# --- Flask App Configuration ---
app = Flask(__name__)

# Generate a strong secret key for session management
app.config["SECRET_KEY"] = os.environ.get(
    "SECRET_KEY", "your_super_secret_key_please_change_this_in_production"
)

# Database configuration (SQLite for simplicity, use PostgreSQL for production)
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
    "DATABASE_URL", "sqlite:///secure_share.db"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Directory to store uploaded (encrypted) files
UPLOAD_FOLDER = "uploads"
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# Master encryption key for the server.
# IMPORTANT: In a real application, this should be managed securely (e.g., KMS, environment variable, not hardcoded).
# For demonstration, we generate one if not found.
MASTER_KEY_FILE = "master_key.key"
if os.path.exists(MASTER_KEY_FILE):
    with open(MASTER_KEY_FILE, "rb") as key_file:
        MASTER_KEY = key_file.read()
else:
    MASTER_KEY = Fernet.generate_key()
    with open(MASTER_KEY_FILE, "wb") as key_file:
        key_file.write(MASTER_KEY)
print(f"Master Key: {MASTER_KEY.decode()}") # For debugging, DO NOT print in production!

# Initialize Fernet cipher with the master key
MASTER_CIPHER = Fernet(MASTER_KEY)

db = SQLAlchemy(app)


# --- Database Models ---


class User(db.Model):
    """
    Represents a user in the file sharing platform.
    """

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    # Relationship to uploaded files
    files = db.relationship("File", backref="uploader", lazy=True)

    def set_password(self, password):
        """Hashes the password and stores it."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Checks if the provided password matches the stored hash."""
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f"<User {self.username}>"


class File(db.Model):
    """
    Represents an uploaded file.
    Stores metadata, path to encrypted file, and the encrypted file-specific key.
    """

    id = db.Column(db.Integer, primary_key=True)
    uploader_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    stored_filename = db.Column(
        db.String(255), unique=True, nullable=False
    )  # Unique filename on disk
    encrypted_file_key = db.Column(
        db.String(255), nullable=False
    )  # File-specific key, encrypted by master key
    upload_date = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    # Relationship to share links
    share_links = db.relationship("ShareLink", backref="file", lazy=True)

    def __repr__(self):
        return f"<File {self.original_filename}>"


class ShareLink(db.Model):
    """
    Represents a shareable link for a file.
    Includes access token, expiration, and optional access count.
    """

    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey("file.id"), nullable=False)
    access_token = db.Column(
        db.String(64), unique=True, nullable=False
    )  # UUID for the link
    expires_at = db.Column(db.DateTime, nullable=True)  # Null for no expiration
    max_downloads = db.Column(
        db.Integer, nullable=True
    )  # Null for unlimited downloads
    current_downloads = db.Column(db.Integer, default=0)

    def __repr__(self):
        return f"<ShareLink {self.access_token}>"


# --- Authentication Decorator ---


def login_required(f):
    """Decorator to ensure a user is logged in before accessing a route."""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            flash("You need to be logged in to access this page.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)

    return decorated_function


# --- Encryption/Decryption Helpers ---


def encrypt_file(file_data):
    """
    Encrypts file data using a new Fernet key, and returns the encrypted data
    along with the *encrypted* file key (encrypted by the master key).
    """
    file_key = Fernet.generate_key()
    file_cipher = Fernet(file_key)
    encrypted_data = file_cipher.encrypt(file_data)
    encrypted_file_key = MASTER_CIPHER.encrypt(file_key)
    return encrypted_data, encrypted_file_key


def decrypt_file(encrypted_data, encrypted_file_key):
    """
    Decrypts file data using the file-specific key, which is first decrypted
    by the master key.
    """
    try:
        file_key = MASTER_CIPHER.decrypt(encrypted_file_key)
        file_cipher = Fernet(file_key)
        decrypted_data = file_cipher.decrypt(encrypted_data)
        return decrypted_data
    except Exception as e:
        print(f"Decryption error: {e}")
        return None


# --- Routes ---


@app.route("/")
def index():
    """Home page."""
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Handles user registration."""
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        if not username or not password:
            flash("Username and password are required.", "danger")
            return redirect(url_for("register"))

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash("Username already taken. Please choose another.", "danger")
            return redirect(url_for("register"))

        new_user = User(username=username)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        flash("Registration successful! Please log in.", "success")
        return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Handles user login."""
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            session["user_id"] = user.id
            session["username"] = user.username
            flash("Logged in successfully!", "success")
            return redirect(url_for("my_files"))
        else:
            flash("Invalid username or password.", "danger")
    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    """Logs out the current user."""
    session.pop("user_id", None)
    session.pop("username", None)
    flash("You have been logged out.", "info")
    return redirect(url_for("index"))


@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload_file():
    """Handles file upload and encryption."""
    if request.method == "POST":
        if "file" not in request.files:
            flash("No file part", "danger")
            return redirect(request.url)
        file = request.files["file"]
        if file.filename == "":
            flash("No selected file", "danger")
            return redirect(request.url)
        if file:
            original_filename = file.filename
            file_data = file.read()

            encrypted_data, encrypted_file_key = encrypt_file(file_data)
            if encrypted_data is None:
                flash("File encryption failed.", "danger")
                return redirect(request.url)

            # Generate a unique filename for storage
            stored_filename = str(uuid.uuid4()) + ".enc"
            file_path = os.path.join(app.config["UPLOAD_FOLDER"], stored_filename)

            with open(file_path, "wb") as f:
                f.write(encrypted_data)

            new_file = File(
                uploader_id=session["user_id"],
                original_filename=original_filename,
                stored_filename=stored_filename,
                encrypted_file_key=encrypted_file_key.decode(),  # Store as string
            )
            db.session.add(new_file)
            db.session.commit()
            flash("File uploaded and encrypted successfully!", "success")
            return redirect(url_for("my_files"))
    return render_template("upload.html")


@app.route("/my_files")
@login_required
def my_files():
    """Displays files uploaded by the current user."""
    user_files = File.query.filter_by(uploader_id=session["user_id"]).all()
    # For each file, fetch its share links
    files_with_links = []
    now_utc = datetime.now(timezone.utc)  # Get current UTC time once
    for f in user_files:
        links = ShareLink.query.filter_by(file_id=f.id).all()
        # Filter out expired links for display
        active_links = []
        for link in links:
            if link.expires_at:
                # Ensure link.expires_at is timezone-aware before comparison
                # If it's already aware, replace does nothing or keeps it aware
                # If it's naive, this makes it aware (assuming it was stored as UTC)
                aware_expires_at = (
                    link.expires_at.replace(tzinfo=timezone.utc)
                    if link.expires_at.tzinfo is None
                    else link.expires_at
                )
                if aware_expires_at > now_utc:
                    active_links.append(link)
            else:
                active_links.append(link)  # No expiration, always active
        files_with_links.append({"file": f, "links": active_links})

    return render_template("my_files.html", files_with_links=files_with_links)


@app.route("/generate_link/<int:file_id>", methods=["GET", "POST"])
@login_required
def generate_link(file_id):
    """Generates a shareable link for a file."""
    file_to_share = File.query.get_or_404(file_id)

    # Ensure the logged-in user owns the file
    if file_to_share.uploader_id != session["user_id"]:
        flash("You do not have permission to share this file.", "danger")
        return redirect(url_for("my_files"))

    if request.method == "POST":
        expires_in_hours = request.form.get("expires_in_hours", type=int)
        max_downloads = request.form.get("max_downloads", type=int)

        expires_at = None
        if expires_in_hours and expires_in_hours > 0:
            expires_at = datetime.now(timezone.utc) + timedelta(hours=expires_in_hours)

        access_token = str(uuid.uuid4())
        new_link = ShareLink(
            file_id=file_to_share.id,
            access_token=access_token,
            expires_at=expires_at,
            max_downloads=max_downloads
            if max_downloads and max_downloads > 0
            else None,
        )
        db.session.add(new_link)
        db.session.commit()

        shareable_url = url_for(
            "download_file_via_link", token=access_token, _external=True
        )
        flash(f"Share link generated! Share this URL: {shareable_url}", "success")
        return redirect(url_for("my_files"))

    return render_template("generate_link.html", file=file_to_share)


@app.route("/download/<token>")
def download_file_via_link(token):
    """Handles file download via a shareable link."""
    share_link = ShareLink.query.filter_by(access_token=token).first()

    if not share_link:
        flash("Invalid or expired share link.", "danger")
        abort(404)  # Or render a specific error page

    now_utc = datetime.now(timezone.utc)  # Get current UTC time once
    # Check expiration
    if share_link.expires_at:
        # Ensure share_link.expires_at is timezone-aware before comparison
        aware_expires_at = (
            share_link.expires_at.replace(tzinfo=timezone.utc)
            if share_link.expires_at.tzinfo is None
            else share_link.expires_at
        )
        if aware_expires_at < now_utc:
            flash("This share link has expired.", "danger")
            # Optionally delete the link after it expires
            # db.session.delete(share_link)
            # db.session.commit()
            abort(410)  # Gone

    # Check max downloads
    if (
        share_link.max_downloads is not None
        and share_link.current_downloads >= share_link.max_downloads
    ):
        flash("This share link has reached its maximum download limit.", "danger")
        # Optionally delete the link after max downloads
        # db.session.delete(share_link)
        # db.session.commit()
        abort(403)  # Forbidden

    file_record = File.query.get(share_link.file_id)
    if not file_record:
        flash("File associated with this link not found.", "danger")
        abort(404)

    file_path = os.path.join(app.config["UPLOAD_FOLDER"], file_record.stored_filename)

    if not os.path.exists(file_path):
        flash("File not found on server.", "danger")
        abort(404)

    try:
        with open(file_path, "rb") as f:
            encrypted_data = f.read()

        decrypted_data = decrypt_file(
            encrypted_data, file_record.encrypted_file_key.encode()
        )

        if decrypted_data is None:
            flash(
                "Failed to decrypt file. It might be corrupted or the key is invalid.",
                "danger",
            )
            abort(500)

        # Increment download count
        share_link.current_downloads += 1
        db.session.commit()

        # Send the decrypted file as a response
        # Using a temporary file to send decrypted data without saving it unencrypted
        temp_decrypted_file_path = os.path.join(
            app.config["UPLOAD_FOLDER"],
            f"temp_decrypted_{uuid.uuid4()}_{file_record.original_filename}",
        )
        with open(temp_decrypted_file_path, "wb") as temp_f:
            temp_f.write(decrypted_data)

        # Send the file and then clean up the temporary file
        response = send_from_directory(
            app.config["UPLOAD_FOLDER"],
            os.path.basename(temp_decrypted_file_path),
            as_attachment=True,
            download_name=file_record.original_filename,
        )

        # After sending, delete the temporary file
        @response.call_on_close
        def remove_temp_file():
            try:
                os.remove(temp_decrypted_file_path)
            except Exception as e:
                print(f"Error removing temporary file {temp_decrypted_file_path}: {e}")

        return response

    except Exception as e:
        print(f"Error during download: {e}")
        flash("An error occurred during download.", "danger")
        abort(500)


@app.route("/delete_file/<int:file_id>", methods=["POST"])
@login_required
def delete_file(file_id):
    """Deletes a file and its associated share links."""
    file_to_delete = File.query.get_or_404(file_id)

    if file_to_delete.uploader_id != session["user_id"]:
        flash("You do not have permission to delete this file.", "danger")
        return redirect(url_for("my_files"))

    # Delete associated share links first
    ShareLink.query.filter_by(file_id=file_to_delete.id).delete()
    db.session.delete(file_to_delete)
    db.session.commit()

    # Delete the actual encrypted file from disk
    file_path = os.path.join(app.config["UPLOAD_FOLDER"], file_to_delete.stored_filename)
    if os.path.exists(file_path):
        os.remove(file_path)
        flash("File and its links deleted successfully.", "success")
    else:
        flash("File record deleted, but physical file not found.", "warning")

    return redirect(url_for("my_files"))


@app.route("/delete_link/<int:link_id>", methods=["POST"])
@login_required
def delete_link(link_id):
    """Deletes a specific share link."""
    link_to_delete = ShareLink.query.get_or_404(link_id)

    # Ensure the logged-in user owns the file associated with the link
    file_owner_id = link_to_delete.file.uploader_id
    if file_owner_id != session["user_id"]:
        flash("You do not have permission to delete this link.", "danger")
        return redirect(url_for("my_files"))

    db.session.delete(link_to_delete)
    db.session.commit()
    flash("Share link deleted successfully.", "success")
    return redirect(url_for("my_files"))


# --- Error Handlers ---
@app.errorhandler(404)
def page_not_found(e):
    """Custom 404 error page."""
    return render_template("404.html", error_message="Page Not Found"), 404


@app.errorhandler(403)
def forbidden(e):
    """Custom 403 error page."""
    return render_template("404.html", error_message="Forbidden Access"), 403


@app.errorhandler(410)
def gone(e):
    """Custom 410 error page (for expired links)."""
    return render_template("404.html", error_message="Link Expired or Gone"), 410


@app.errorhandler(500)
def internal_server_error(e):
    """Custom 500 error page."""
    return render_template("404.html", error_message="Internal Server Error"), 500


# --- Main execution ---
if __name__ == "__main__":
    # Create database tables within the application context
    with app.app_context():
        db.create_all()
    # The host is set to the specific public IP address
    app.run(debug=True, host="0.0.0.0", port=65323)
