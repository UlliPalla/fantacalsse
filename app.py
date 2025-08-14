import os
import json
from datetime import datetime
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///fantaclasse.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key')

db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Player(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    cost = db.Column(db.Integer, nullable=False)


class Team(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), unique=True, nullable=False)
    user = db.relationship('User', backref=db.backref('team', uselist=False))


class TeamPlayer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    team_id = db.Column(db.Integer, db.ForeignKey('team.id'), nullable=False)
    player_id = db.Column(db.Integer, db.ForeignKey('player.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    team = db.relationship('Team', backref=db.backref('team_players', cascade='all, delete-orphan'))
    player = db.relationship('Player')

    __table_args__ = (db.UniqueConstraint('team_id', 'player_id', name='uix_team_player'),)


class RuleConfig(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    json_data = db.Column(db.Text, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class PlayerPerformance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    player_id = db.Column(db.Integer, db.ForeignKey('player.id'), nullable=False)
    data_json = db.Column(db.Text, nullable=False)
    points = db.Column(db.Integer, nullable=False)
    note = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    player = db.relationship('Player')


# Utilities

def get_current_user():
    user_id = session.get('user_id')
    if not user_id:
        return None
    return User.query.get(user_id)


def login_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if not get_current_user():
            flash('Devi effettuare il login per continuare.', 'warning')
            return redirect(url_for('login', next=request.path))
        return view_func(*args, **kwargs)
    return wrapped


def admin_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        user = get_current_user()
        if not user or not user.is_admin:
            flash('Accesso amministratore richiesto.', 'danger')
            return redirect(url_for('index'))
        return view_func(*args, **kwargs)
    return wrapped


def get_rule_config():
    rule = RuleConfig.query.first()
    if not rule:
        default = {
            "budget": 100,
            "points": {
                "goal": 5,
                "assist": 3,
                "clean_sheet": 4
            },
            "rules_text": "Punteggi base: goal=5, assist=3, porta inviolata=4. Budget iniziale: 100."
        }
        rule = RuleConfig(json_data=json.dumps(default, ensure_ascii=False))
        db.session.add(rule)
        db.session.commit()
        return default
    try:
        return json.loads(rule.json_data)
    except Exception:
        return {"budget": 100, "points": {}, "rules_text": ""}


def set_rule_config(data_dict):
    rule = RuleConfig.query.first()
    payload = json.dumps(data_dict, ensure_ascii=False)
    if not rule:
        rule = RuleConfig(json_data=payload)
        db.session.add(rule)
    else:
        rule.json_data = payload
    db.session.commit()


def ensure_team_for_user(user):
    if not user.team:
        team = Team(user=user)
        db.session.add(team)
        db.session.commit()


def calculate_user_points(user):
    ensure_team_for_user(user)
    team_player_ids = [tp.player_id for tp in user.team.team_players]
    if not team_player_ids:
        return 0
    total = db.session.query(db.func.coalesce(db.func.sum(PlayerPerformance.points), 0)).filter(
        PlayerPerformance.player_id.in_(team_player_ids)
    ).scalar() or 0
    return int(total)


def calculate_team_spent(user):
    ensure_team_for_user(user)
    total_cost = 0
    for tp in user.team.team_players:
        total_cost += tp.player.cost
    return total_cost


@app.context_processor
def inject_globals():
    return {
        'current_user': get_current_user(),
        'datetime': datetime
    }


# Routes

@app.route('/')
def index():
    return redirect(url_for('classifica'))


@app.route('/setup')
def setup():
    db.create_all()

    # Seed admin
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        default_admin_password = os.environ.get('ADMIN_DEFAULT_PASSWORD', 'admin123')
        admin = User(
            username='admin',
            password_hash=generate_password_hash(default_admin_password),
            is_admin=True
        )
        db.session.add(admin)
        db.session.commit()
        ensure_team_for_user(admin)

    # Seed demo players
    if Player.query.count() == 0:
        demo_players = [
            ("Mario Rossi", 15),
            ("Luigi Bianchi", 13),
            ("Giuseppe Verdi", 12),
            ("Andrea Neri", 11),
            ("Paolo Gialli", 10),
            ("Marco Blu", 9),
            ("Stefano Viola", 8),
            ("Luca Arancioni", 7),
            ("Franco Rosa", 6),
            ("Davide Azzurri", 5)
        ]
        for name, cost in demo_players:
            db.session.add(Player(name=name, cost=cost))
        db.session.commit()

    # Seed default rules
    get_rule_config()

    flash('Setup completato. Utente admin creato e giocatori iniziali caricati.', 'success')
    return redirect(url_for('index'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        next_url = request.args.get('next') or url_for('index')
        user = User.query.filter_by(username=username).first()
        if not user:
            flash('Utente non trovato. Registrati prima di accedere.', 'warning')
            return redirect(url_for('register'))
        if not check_password_hash(user.password_hash, password):
            flash('Password errata.', 'danger')
            return render_template('login.html')
        session['user_id'] = user.id
        flash(f'Benvenuto {user.username}!', 'success')
        return redirect(next_url)
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        if not username or not password:
            flash('Inserisci username e password.', 'warning')
            return render_template('register.html')
        if User.query.filter_by(username=username).first():
            flash('Username già in uso.', 'danger')
            return render_template('register.html')
        user = User(username=username, password_hash=generate_password_hash(password), is_admin=False)
        db.session.add(user)
        db.session.commit()
        ensure_team_for_user(user)
        flash('Registrazione completata. Ora puoi effettuare il login.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/logout')
@login_required
def logout():
    session.pop('user_id', None)
    flash('Logout effettuato.', 'info')
    return redirect(url_for('index'))


@app.route('/classifica')
def classifica():
    users = User.query.order_by(User.username.asc()).all()
    rows = []
    for u in users:
        points = calculate_user_points(u)
        rows.append({
            'username': u.username,
            'points': points
        })
    rows.sort(key=lambda r: r['points'], reverse=True)
    return render_template('leaderboard.html', rows=rows)


@app.route('/crea-squadra', methods=['GET'])
@login_required
def crea_squadra():
    user = get_current_user()
    ensure_team_for_user(user)
    players = Player.query.order_by(Player.cost.desc()).all()
    team_player_ids = {tp.player_id for tp in user.team.team_players}
    rules = get_rule_config()
    budget = int(rules.get('budget', 100))
    spent = calculate_team_spent(user)
    remaining = budget - spent
    return render_template(
        'team.html',
        players=players,
        team_player_ids=team_player_ids,
        budget=budget,
        spent=spent,
        remaining=remaining,
        rules=rules
    )


@app.route('/acquista/<int:player_id>', methods=['POST'])
@login_required
def acquista(player_id):
    user = get_current_user()
    ensure_team_for_user(user)
    player = Player.query.get_or_404(player_id)
    already = TeamPlayer.query.filter_by(team_id=user.team.id, player_id=player.id).first()
    if already:
        flash('Giocatore già nella tua squadra.', 'info')
        return redirect(url_for('crea_squadra'))
    rules = get_rule_config()
    budget = int(rules.get('budget', 100))
    spent = calculate_team_spent(user)
    if spent + player.cost > budget:
        flash('Budget insufficiente per acquistare questo giocatore.', 'danger')
        return redirect(url_for('crea_squadra'))
    tp = TeamPlayer(team_id=user.team.id, player_id=player.id)
    db.session.add(tp)
    db.session.commit()
    flash(f'Hai acquistato {player.name}.', 'success')
    return redirect(url_for('crea_squadra'))


@app.route('/vendi/<int:player_id>', methods=['POST'])
@login_required
def vendi(player_id):
    user = get_current_user()
    ensure_team_for_user(user)
    tp = TeamPlayer.query.filter_by(team_id=user.team.id, player_id=player_id).first()
    if not tp:
        flash('Questo giocatore non è nella tua squadra.', 'warning')
        return redirect(url_for('crea_squadra'))
    db.session.delete(tp)
    db.session.commit()
    flash('Giocatore venduto.', 'info')
    return redirect(url_for('crea_squadra'))


@app.route('/regole')
def regole():
    rules = get_rule_config()
    return render_template('rules.html', rules=rules)


@app.route('/admin')
@admin_required
def admin_home():
    return render_template('admin.html')


@app.route('/admin/regole', methods=['GET', 'POST'])
@admin_required
def admin_regole():
    rules = get_rule_config()
    if request.method == 'POST':
        budget = request.form.get('budget', '100').strip()
        rules_text = request.form.get('rules_text', '').strip()
        points_json_text = request.form.get('points_json', '{}').strip()
        try:
            budget_val = int(budget)
            points_dict = json.loads(points_json_text) if points_json_text else {}
            if not isinstance(points_dict, dict):
                raise ValueError('Formato punti non valido.')
        except Exception as e:
            flash(f'Errore di validazione: {e}', 'danger')
            return render_template('admin_rules.html', rules=rules, points_json=points_json_text)
        new_rules = {
            'budget': budget_val,
            'rules_text': rules_text,
            'points': points_dict
        }
        set_rule_config(new_rules)
        flash('Regole aggiornate con successo.', 'success')
        return redirect(url_for('admin_regole'))
    points_json = json.dumps(rules.get('points', {}), ensure_ascii=False, indent=2)
    return render_template('admin_rules.html', rules=rules, points_json=points_json)


@app.route('/admin/assegna-punti', methods=['GET', 'POST'])
@admin_required
def admin_assegna_punti():
    rules = get_rule_config()
    players = Player.query.order_by(Player.name.asc()).all()
    point_keys = list(rules.get('points', {}).keys())
    if request.method == 'POST':
        player_id = int(request.form.get('player_id'))
        extra_points = int(request.form.get('extra_points', '0') or '0')
        note = request.form.get('note', '').strip()
        player = Player.query.get_or_404(player_id)

        counts = {}
        total = 0
        for key in point_keys:
            count_val = int(request.form.get(f'count_{key}', '0') or '0')
            counts[key] = count_val
            total += count_val * int(rules['points'].get(key, 0))
        total += extra_points

        perf = PlayerPerformance(
            player_id=player.id,
            data_json=json.dumps({'counts': counts, 'extra': extra_points}, ensure_ascii=False),
            points=total,
            note=note
        )
        db.session.add(perf)
        db.session.commit()
        flash(f'Assegnati {total} punti a {player.name}.', 'success')
        return redirect(url_for('admin_assegna_punti'))

    return render_template('admin_award.html', players=players, point_keys=point_keys, rules=rules)


if __name__ == '__main__':
    # For local development
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)