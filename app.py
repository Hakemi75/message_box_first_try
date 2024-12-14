from flask import Flask, flash, render_template, redirect, request, url_for
from flask_login import LoginManager, login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from peewee import IntegrityError
from config import User

app = Flask(__name__)
app.secret_key = "secret"  # 秘密鍵を設定
login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.unauthorized_handler
def unauthorized_handler():
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        # 入力データの検証:未入力の確認
        if not request.form["name"] or not request.form["password"] or not request.form["email"]:
            flash("未入力の項目があります。")
            return redirect(request.url)

        # 入力データの検証:重複の確認
        if User.select().where(User.name == request.form["name"]):
            flash("そのメールアドレスはすでに使われています。")
            return redirect(request.url)
        if User.select().where(User.email == request.form["email"]):
            return redirect(request.url)
        # ユーザー登録処理
        try:
            User.create(
                name=request.form["name"],
                email=request.form["email"],
                # password=request.form["password"],
                password=generate_password_hash(request.form["password"]),
            )
            return render_template("index.html")
        except IntegrityError as e:
            flash(f"{e}")
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if not request.form["password"] or not request.form["email"]:
            flash("未入力の項目があります。")
            return redirect(request.url)
        # ここでユーザーを認証して、okならログインする
        user = User.select().where(User.email == request.form["email"]).first()
        if user is not None and check_password_hash(user.password, request.form["password"]):
            login_user(user)
            flash(f"ようこそ！{user.name}さん")
            return redirect(url_for("index"))
        # NGならフラッシュメッセージを設定する
        flash("認証を失敗しました。")
    return render_template("login.html")


@login_manager.user_loader
def load_user(user_id):
    return User.get_by_id(user_id)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("ログアウトしました！")
    return redirect("/")


# ユーザーの削除
@app.route("/unregister")
@login_required
def unregister():
    current_user.delete_instance()
    logout_user()
    return redirect("/")


@app.route("/")
def index():
    return render_template("index.html")


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000, debug=True)
