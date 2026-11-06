import html
import os
import secrets
from pathlib import Path

from flask import Flask, jsonify, request, redirect, url_for, session, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    logout_user,
    login_required,
    current_user
)
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

app.config["SECRET_KEY"] = "security-lab-secret-key"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///security_lab.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

LAB_FILES_ROOT = Path(__file__).resolve().parent / "lab_files"
PUBLIC_FILES_ROOT = LAB_FILES_ROOT / "public"

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="user")


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route("/")
def home():
    featured_product = Product.query.order_by(Product.id).first()
    return render_template("store.html", featured_product=featured_product)


@app.route("/lab")
def lab_index():
    """Compatibility URL for the local demonstration storefront."""
    return home()


@app.get("/api/products")
def product_catalog():
    return jsonify({"products": [
        {"id": product.id, "name": product.name, "description": product.description, "price": product.price}
        for product in Product.query.order_by(Product.id).all()
    ]})


@app.post("/cart/checkout")
@login_required
def checkout():
    product_ids = request.form.getlist("product_id")[:20]
    products = [Product.query.get_or_404(int(product_id)) for product_id in product_ids]
    if not products:
        return jsonify({"error": "Your bag is empty."}), 400
    orders = [Order(product=product.name, amount=product.price, user_id=current_user.id) for product in products]
    db.session.add_all(orders)
    db.session.commit()
    return jsonify({"orders": [{"order_id": order.id, "product": order.product, "amount": order.amount} for order in orders]}), 201


@app.route("/health")
def health():
    return jsonify({
        "status": "ok",
        "application": "security-assessment-target"
    })


@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "GET":
        return render_template("login.html", error="")

    username = request.form.get("username")
    password = request.form.get("password")

    user = User.query.filter_by(username=username).first()

    if user and check_password_hash(user.password, password):

        login_user(user)

        return redirect(url_for("dashboard"))

    return render_template("login.html", error="The username or password was not recognized."), 401


@app.route("/logout")
@login_required
def logout():

    logout_user()

    return redirect(url_for("home"))


@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("account.html", username=current_user.username, role=current_user.role)


@app.route("/profile")
@login_required
def profile():

    return jsonify({
        "id": current_user.id,
        "username": current_user.username,
        "role": current_user.role
    })

@app.route("/orders")
@login_required
def orders():

    user_orders = Order.query.filter_by(
        user_id=current_user.id
    ).all()

    return jsonify([
        {
            "id": order.id,
            "product": order.product,
            "amount": order.amount
        }
        for order in user_orders
    ])


@app.route("/api/orders/<int:order_id>")
@login_required
def get_order(order_id):
    order = Order.query.get_or_404(order_id)

    # Enforce object-level authorization.
    if order.user_id != current_user.id and current_user.role != "admin":
        return jsonify({"error": "Forbidden"}), 403

    return jsonify({
        "id": order.id,
        "product": order.product,
        "amount": order.amount,
        "user_id": order.user_id
    })


@app.route("/api/orders/insecure/<int:order_id>")
@login_required
def get_order_insecure(order_id):
    """Intentionally omits the ownership check for local IDOR training."""
    order = Order.query.get_or_404(order_id)
    return jsonify({
        "id": order.id,
        "product": order.product,
        "amount": order.amount,
        "user_id": order.user_id,
    })



@app.route("/admin/users")
@login_required
def admin_users():
    if current_user.role != "admin":
        return jsonify({"error": "Forbidden"}), 403

    users = User.query.all()

    return jsonify([
        {
            "id": user.id,
            "username": user.username,
            "role": user.role
        }
        for user in users
    ])


@app.get("/admin")
@login_required
def store_admin():
    return render_template("admin.html")


@app.route("/admin/lab/users")
def lab_users_insecure():
    """Intentionally unrestricted read-only route for local RBAC training."""
    return jsonify([
        {"id": user.id, "username": user.username, "role": user.role}
        for user in User.query.order_by(User.id).all()
    ])


@app.route("/admin/orders")
@login_required
def admin_orders():
    if current_user.role != "admin":
        return jsonify({"error": "Forbidden"}), 403

    return jsonify([
        {
            "id": order.id,
            "product": order.product,
            "amount": order.amount,
            "user_id": order.user_id,
        }
        for order in Order.query.order_by(Order.id).all()
    ])


@app.route("/api/admin/reports")
@login_required
def admin_reports():
    if current_user.role != "admin":
        return jsonify({"error": "Forbidden"}), 403

    total_orders = Order.query.count()

    total_revenue = sum(
        order.amount for order in Order.query.all()
    )

    return jsonify({
        "total_orders": total_orders,
        "total_revenue": total_revenue
    })

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product = db.Column(db.String(100), nullable=False)
    amount = db.Column(db.Float, nullable=False)

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False
    )

    user = db.relationship(
        "User",
        backref=db.backref("orders", lazy=True)
    )


class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False, index=True)
    description = db.Column(db.String(500), nullable=False)
    price = db.Column(db.Float, nullable=False)


class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.String(500), nullable=False)


@app.get("/api/products/search")
def search_products_vulnerable():
    """Training-only SQL injection sink; never use this pattern in real code."""
    term = request.args.get("q", "")
    query = (
        "SELECT id, name, description, price FROM product "
        f"WHERE name LIKE '%{term}%' ORDER BY id"
    )
    try:
        rows = db.session.execute(text(query)).mappings().all()
    except SQLAlchemyError as error:
        # Intentionally exposes a database error to demonstrate the risk.
        db.session.rollback()
        return jsonify({"error": "database query failed", "database_error": str(error)}), 500
    return jsonify({"products": [dict(row) for row in rows]})


@app.get("/api/products/search/secure")
def search_products_secure():
    term = request.args.get("q", "")
    rows = db.session.execute(
        text(
            "SELECT id, name, description, price FROM product "
            "WHERE name LIKE :pattern ORDER BY id"
        ),
        {"pattern": f"%{term}%"},
    ).mappings().all()
    return jsonify({"products": [dict(row) for row in rows]})


@app.get("/products/preview")
def product_preview_vulnerable():
    """Training-only reflected XSS sink using unescaped user input."""
    term = request.args.get("q", "")
    return (
        "<!doctype html><html><body><h1>Product search</h1>"
        f"<p>Search results for: {term}</p></body></html>"
    )


@app.get("/products/preview/secure")
def product_preview_secure():
    term = html.escape(request.args.get("q", ""), quote=True)
    return (
        "<!doctype html><html><body><h1>Product search</h1>"
        f"<p>Search results for: {term}</p></body></html>"
    )


@app.route("/reviews", methods=["GET", "POST"])
def reviews_vulnerable():
    if request.method == "POST":
        body = request.form.get("body", "")[:500]
        if not body.strip():
            return jsonify({"error": "Review text is required."}), 400
        review = Review(body=body)
        db.session.add(review)
        db.session.commit()
        return jsonify({"saved": True, "review_id": review.id, "review_length": len(body)}), 201
    reviews = Review.query.order_by(Review.id).all()
    items = "".join(f"<li>{review.body}</li>" for review in reviews)
    return render_template("review-list.html", items=items, has_reviews=bool(reviews))


@app.get("/admin/reviews")
@login_required
def admin_review_list():
    if current_user.role != "admin":
        return jsonify({"error": "Forbidden"}), 403
    return jsonify([{"id": review.id, "body": review.body} for review in Review.query.order_by(Review.id).all()])


@app.delete("/admin/reviews/<int:review_id>")
@login_required
def admin_delete_review(review_id):
    if current_user.role != "admin":
        return jsonify({"error": "Forbidden"}), 403
    review = Review.query.get_or_404(review_id)
    db.session.delete(review)
    db.session.commit()
    return "", 204


@app.post("/reviews/add/secure")
def add_review_secure():
    body = request.form.get("body", "")[:500]
    if not body.strip():
        return jsonify({"error": "Review text is required."}), 400
    db.session.add(Review(body=body))
    db.session.commit()
    return jsonify({"saved": True, "review_length": len(body)}), 201


@app.get("/reviews/secure")
def reviews_secure():
    reviews = Review.query.order_by(Review.id).all()
    items = "".join(f"<li>{html.escape(review.body, quote=True)}</li>" for review in reviews)
    return render_template("review-list.html", items=items, has_reviews=bool(reviews))


@app.get("/products/dom-preview")
def dom_preview_vulnerable():
    return """<!doctype html><html><body><h1>DOM search preview</h1>
    <p id="preview"></p><script>
    const fragment = window.location.hash.slice(1);
    document.getElementById("preview").innerHTML = fragment;
    </script></body></html>"""


@app.get("/products/dom-preview/secure")
def dom_preview_secure():
    return """<!doctype html><html><body><h1>DOM search preview</h1>
    <p id="preview"></p><script>
    const fragment = window.location.hash.slice(1);
    document.getElementById("preview").textContent = fragment;
    </script></body></html>"""


@app.route("/account/preferences", methods=["GET", "POST"])
@login_required
def preferences_vulnerable():
    if request.method == "POST":
        session["display_name"] = request.form.get("display_name", "")[:80]
        return "Preference saved", 200
    return """<!doctype html><html><body>
    <h1>Display name</h1>
    <form method="post" action="/account/preferences">
      <input name="display_name" value="">
      <button type="submit">Save</button>
    </form></body></html>"""


@app.route("/account/preferences/secure", methods=["GET", "POST"])
@login_required
def preferences_secure():
    if request.method == "POST":
        expected = session.get("preferences_csrf_token", "")
        supplied = request.form.get("_csrf_token", "")
        if not expected or not secrets.compare_digest(expected, supplied):
            return "Invalid CSRF token", 400
        session["display_name"] = request.form.get("display_name", "")[:80]
        return "Preference saved", 200

    token = secrets.token_urlsafe(24)
    session["preferences_csrf_token"] = token
    return f"""<!doctype html><html><body>
    <h1>Display name</h1>
    <form method="post" action="/account/preferences/secure">
      <input type="hidden" name="_csrf_token" value="{html.escape(token, quote=True)}">
      <input name="display_name" value="">
      <button type="submit">Save</button>
    </form></body></html>"""


def is_within(path, root):
    try:
        return os.path.commonpath((str(path), str(root))) == str(root)
    except ValueError:
        return False


@app.get("/api/files/download")
def download_file_vulnerable():
    """Training-only traversal; traversal remains inside lab_files."""
    name = request.args.get("name", "")
    candidate = (PUBLIC_FILES_ROOT / name).resolve()
    lab_root = LAB_FILES_ROOT.resolve()
    if not is_within(candidate, lab_root):
        return jsonify({"error": "path outside lab fixture root"}), 403
    try:
        return jsonify({"name": name, "content": candidate.read_text(encoding="utf-8")})
    except OSError:
        return jsonify({"error": "file not found"}), 404


@app.get("/api/files/download/secure")
def download_file_secure():
    name = request.args.get("name", "")
    public_root = PUBLIC_FILES_ROOT.resolve()
    candidate = (public_root / name).resolve()
    if not is_within(candidate, public_root):
        return jsonify({"error": "path traversal rejected"}), 400
    try:
        return jsonify({"name": name, "content": candidate.read_text(encoding="utf-8")})
    except OSError:
        return jsonify({"error": "file not found"}), 404


def initialize_database():

    db.create_all()

    if Product.query.count() == 0:
        db.session.add_all([
            Product(name="Keyboard", description="Mechanical keyboard", price=79.0),
            Product(name="Monitor", description="24 inch display", price=189.0),
            Product(name="Headphones", description="Wired headphones", price=39.0),
        ])
        db.session.commit()

    # Remove demo reviews inserted by older releases; reviews now come from visitors.
    Review.query.filter(Review.body.in_([
        "TRAINING_REVIEW_<svg/onload=alert(1)>",
        "Really useful on my desk — the finish feels <em>well made</em>.",
    ])).delete(synchronize_session=False)
    db.session.commit()

    if User.query.count() == 0:

        admin = User(
            username="admin",
            password=generate_password_hash("admin123"),
            role="admin"
        )

        alice = User(
            username="alice",
            password=generate_password_hash("alice123"),
            role="user"
        )

        bob = User(
            username="bob",
            password=generate_password_hash("bob123"),
            role="user"
        )

        db.session.add_all([admin, alice, bob])
        db.session.commit()

        orders = [
            Order(
                product="Laptop",
                amount=75000,
                user_id=alice.id
            ),

            Order(
                product="Headphones",
                amount=5000,
                user_id=alice.id
            ),

            Order(
                product="Monitor",
                amount=25000,
                user_id=bob.id
            ),

            Order(
                product="Keyboard",
                amount=3000,
                user_id=bob.id
            )
        ]

        db.session.add_all(orders)
        db.session.commit()

    # Convert the older lab's obviously synthetic rupee-scale examples into
    # plausible Northstar demo receipts while preserving their stable IDs.
    legacy_receipts = {
        "Laptop": ("Keyboard", 79.0, 75000.0),
        "Headphones": ("Headphones", 39.0, 5000.0),
        "Monitor": ("Monitor", 189.0, 25000.0),
        "Keyboard": ("Keyboard", 79.0, 3000.0),
    }
    changed = False
    for order in Order.query.all():
        legacy = legacy_receipts.get(order.product)
        if legacy and order.amount == legacy[2]:
            order.product, order.amount = legacy[0], legacy[1]
            changed = True
    if changed:
        db.session.commit()



if __name__ == "__main__":

    with app.app_context():
        initialize_database()

    app.run(
        host="0.0.0.0" if os.environ.get("SECURITY_LAB_CONTAINER") == "1" else "127.0.0.1",
        port=5001,
        debug=False
    )
