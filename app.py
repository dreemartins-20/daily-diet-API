from flask import Flask, request, jsonify
from models.user import User, Diet
from database import db
from flask_login import LoginManager, login_user, current_user, logout_user, login_required
import bcrypt

app = Flask(__name__)
app.config['SECRET_KEY'] = "your_secret_key"
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:admin123@127.0.0.1:3306/daily-diet'

login_manager = LoginManager()
db.init_app(app)
login_manager.init_app(app)


login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

@app.route('/login', methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    if username and password:
        user = User.query.filter_by(username=username).first()

        if user and bcrypt.checkpw(str.encode(password),str.encode(user.password)):
            login_user(user)
            print(current_user.is_authenticated)
            return jsonify({"message": "Autenticação realizada com sucesso"})
    
    return jsonify({"message": "Credencias inválidas"}), 400


@app.route('/logout', methods=["GET"])
@login_required
def logout():
    logout_user()
    return jsonify({"message": "Logout realizado com sucesso"})



@app.route('/user', methods=["POST"])
def create_user():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    if username and password:
        hashed_password = bcrypt.hashpw(str.encode(password), bcrypt.gensalt())
        user = User(username=username, password=hashed_password, role='user')
        db.session.add(user)
        db.session.commit()
        return jsonify({"message": "Usuário cadastrado com sucesso"})

    return jsonify({"message": "Dados inválidos"}), 400   

@app.route('/user/<int:id_user>', methods=["GET"])
@login_required
def read_user(id_user):
    user = User.query.get(id_user)

    if user: 
        return ({"username": user.username})
    
    return jsonify({"message": "Usuário não encontrado"}), 404


@app.route('/user/<int:id_user>', methods=["PUT"])
@login_required
def update_user(id_user):
    data = request.json
    user = User.query.get(id_user)

    if id_user != current_user.id and current_user.role == "user":
        return jsonify({"message":"Operação não permitida"}), 403

    if user and data.get("password"): 
        user.password = data.get("password")
        db.session.commit()

        return jsonify({"message": f"Usuário {id_user} atualizado com sucesso"})
    
    return jsonify({"message": "Usuário não encontrado"}), 404


@app.route('/user/<int:id_user>', methods=["DELETE"])
@login_required
def delete_user(id_user):
    user = User.query.get(id_user)

    if current_user.role!= 'admin':
        return jsonify({"message": "Operação não permitida"}), 403
    
    if user and id_user!= current_user.id: 
       db.session.delete(user)
       db.session.commit()
       return jsonify({"message": f"Usuário {id_user} deletado com sucesso"})
    
    return jsonify({"message": "Usuário não encontrado"}), 404

@app.route('/diets', methods=['POST'])
@login_required
def create_diet():
    data = request.get_json()
    new_diet = Diet(
        name=data['name'], 
        description=data.get('description'), 
        date=data['date'], 
        in_diet=bool(data['in_diet'].lower() == 'true'),
        user_id=current_user.id
    )
    db.session.add(new_diet)
    db.session.commit()
    return jsonify(new_diet.to_dict())

@app.route('/diets/<int:user_id>', methods=['GET'])
@login_required
def read_diets(user_id):
    diets = Diet.query.filter_by(user_id=user_id).all()

    if diets and current_user.id == user_id:
        return jsonify([diet.to_dict() for diet in diets])
    
    return jsonify({"message": "Nenhuma refeição encontrada"}), 404


@app.route('/diets/<int:diet_id>', methods=['PUT'])
@login_required
def update_diet(diet_id):
    data = request.get_json()
    diet = Diet.query.get(diet_id)

    if not diet:
        return jsonify({"message": "Refeição não encontrada"}), 404

    if diet.user_id != current_user.id:
        return jsonify({"message": "Não autorizado"}), 403

    diet.name = data.get('name', diet.name)
    diet.description = data.get('description', diet.description)
    diet.date = data.get('date', diet.date)
    diet.in_diet = bool(data['in_diet'].lower() == 'true') if 'in_diet' in data else diet.in_diet

    db.session.commit()
    return jsonify(diet.to_dict())


@app.route('/diets/<int:diet_id>', methods=['DELETE'])
@login_required
def delete_diet(diet_id):
    diet = Diet.query.get(diet_id)

    if not diet:
        return jsonify({"message": "Refeição não encontrada"}), 404

    if diet.user_id != current_user.id:
        return jsonify({"message": "Não autorizado"}), 403

    db.session.delete(diet)
    db.session.commit()
    return jsonify({"message": "Refeição deletada com sucesso"})



if __name__ == '__main__':
    app.run(debug=True)