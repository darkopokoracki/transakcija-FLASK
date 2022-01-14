import re
from flask import Flask, request, render_template, redirect, url_for, session
import mysql.connector
from passlib.hash import sha256_crypt #za hasovanje passworda

app = Flask(__name__)
app.config['SECRET_KEY'] = 'hdh63ghascbja23djasjbdSJDjas'

mydb = mysql.connector.connect(
    host = 'localhost',
    user = 'root',
    password = '',
    database = 'transakcija'
)

@app.route('/')
@app.route('/index')
@app.route('/home')
def index():
    return render_template(
        'home.html'
    )


@app.route('/register', methods=['GET', 'POST'])
def register():
    #Ako je neko ulogovan necemo mu dozvoliti da pristupi register stranici
    # i zato ga redirektujemo na home page
    if 'username' in session:
        return redirect(
            url_for('index')
        )

    if request.method == 'GET':
        return render_template(
            'register.html'
        )

    ime = request.form['ime']
    prezime = request.form['prezime']
    username = request.form['username']
    email = request.form['email']
    password = request.form['password']
    confirm = request.form['confirm']

    cursor = mydb.cursor(prepared = True)
    sql = "SELECT * FROM user WHERE username = ? OR email = ?"
    values = (username, email)
    cursor.execute(sql, values)

    result = cursor.fetchone()

    if result != None:
        result = dekodiraj(result)
        if username == result[3]:
            return render_template(
                'register.html',
                username_unique_error = 'Ovakav username vec postoji'
            )
        
        if email == result[4]:
            return render_template(
                'register.html',
                email_unique_error = 'Ovakav email vec postoji'
            )

    if len(ime) < 2:
        return render_template(
            'register.html',
            ime_error = 'Ime mora da sadrzi minimum 2 karaktera!'
        )

    if len(prezime) < 2:
        return render_template(
            'register.html',
            prezime_error = 'Prezime mora da sadrzi minimum 2 karaktera!'
        )

    if len(password) < 6:
        return render_template(
            'register.html',
            password_error = 'Lozinka ne sme biti manja od 6 karaktera'
        )

    if password != confirm:
        return render_template(
            'register.html',
            confirm_error = 'Lozinke se ne poklapaju!'
        )
    
    #Hash password
    hash_password = sha256_crypt.encrypt(password)

    cursor = mydb.cursor(prepared = True)
    sql = "INSERT INTO user VALUES(null,?,?,?,?,?,2,0)"
    values = (ime, prezime, username, email, hash_password)
    cursor.execute(sql, values)
    mydb.commit()

    return redirect(
        url_for('index')
    )


@app.route('/login', methods=['GET', 'POST'])
def login():
    #Ako je neko ulogovan necemo dozvoliti da pristupi login stranici
    #I zato ga redirektujemo na home page
    if 'username' in session:
        return redirect(
            url_for('index')
        )

    if request.method == 'GET':
        return render_template(
            'login.html'
        )

    username_email = request.form['username_email']
    password = request.form['password']

    cursor = mydb.cursor(prepared = True)
    sql = "SELECT * FROM user WHERE username = ? OR email = ?"
    values = (username_email, username_email)
    cursor.execute(sql, values)

    result = cursor.fetchone()

    if result == None:
        return render_template(
            'login.html',
            username_email_error = 'Nalog ne postoji.'
        )

    result = dekodiraj(result)
    #sha256_crypt.verify(loinka_unosa, lozinka_u_bazi) -> vraca True ili False
    # Uporedjuje 2 lozinke hashovane
    if sha256_crypt.verify(password, result[5]) == False:
        return render_template(
            'login.html',
            password_error = 'Pogresna Lozinka'
        )
 
    save_session(result[3], result[6]) #Cuva login podatke u sesiju pomocu funkcije

    if session['privilegija'] == 1:
        return redirect(
            url_for('admin_panel', username = session['username'])
        )

    if session['privilegija'] != 1:
        return redirect(
            url_for('profil', username = session['username'])
        )


@app.route('/admin/<username>', methods=['GET', 'POST'])
def admin_panel(username):
    #Ako korisnik nije ulogovan i ako nije admin, ne moze da pristupi ovoj stranici
    if 'username' not in session:
        return redirect(
            url_for('index')
        )
    
    if session['privilegija'] != 1:
        return redirect(
            url_for('index')
        )

    cursor = mydb.cursor(prepared = True)
    sql = "SELECT * FROM user WHERE username = ?"
    values = (username, )
    cursor.execute(sql, values)

    result = dekodiraj(cursor.fetchone())

    if request.method == 'GET':
        return render_template(
            'admin.html',
            admin = result
        )


@app.route('/users')
def users():
    cursor = mydb.cursor(prepared = True)
    sql = "SELECT * FROM user"
    cursor.execute(sql)

    result = cursor.fetchall()
    n = len(list(result))
    for i in range(n):
        result[i] = dekodiraj(result[i])

    return render_template(
        'users.html',
        users = result
    )


@app.route('/profil/<username>', methods=['GET', 'POST'])
def profil(username):

    cursor = mydb.cursor(prepared = True)
    sql = "SELECT * FROM user WHERE username = ?"
    values = (username, )
    cursor.execute(sql, values)

    result = dekodiraj(cursor.fetchone())

    izbor_cursor = mydb.cursor(prepared = True)
    izbor_sql = "SELECT * FROM user"
    izbor_cursor.execute(izbor_sql)

    izbor_result = izbor_cursor.fetchall()

    n = len(list(izbor_result))
    for i in range(n):
        izbor_result[i] = dekodiraj(izbor_result[i])


    if request.method == 'GET':
        return render_template(
            'profil.html',
            user = result,
            users = izbor_result
        )


@app.route('/delete/<username>', methods=['POST'])
def delete(username):
    cursor = mydb.cursor(prepared = True)
    sql = "DELETE FROM user WHERE username = ?"
    values = (username, )
    cursor.execute(sql, values)

    mydb.commit()

    return redirect(
        url_for('users')
    )


@app.route('/update/<username>', methods=['GET', 'POST'])
def update(username):
    if 'username' not in session:
        return redirect(
            url_for('index')
        )


    cursor = mydb.cursor(prepared = True)
    sql = "SELECT * FROM user WHERE username = ?"
    values = (username, )
    cursor.execute(sql, values)

    result = cursor.fetchone()
    result = dekodiraj(result)

    if request.method == 'GET':
        return render_template(
            'update.html',
            user = result
        )

    ime = request.form['ime']
    prezime = request.form['prezime']
    stanje = request.form['stanje']

    if len(ime) < 2:
        return render_template(
            'update.html',
            ime_error = 'Ime mora da sadrzi minimum 2 karaktera!',
            user = result
        )

    if len(prezime) < 2:
        return render_template(
            'update.html',
            prezime_error = 'Prezime mora da sadrzi minimum 2 karaktera!',
            user = result
        )

    if session['privilegija'] != 1:
        password = request.form['password']

        if sha256_crypt.verify(password, result[5]) == False:
            return render_template(
                'update.html',
                password_error = 'Pogresna Lozinka',
                user = result
            )

    cursor = mydb.cursor(prepared = True)
    sql = "UPDATE user SET ime = ?, prezime = ?, stanje = ? WHERE username = ?"
    values = (ime, prezime, stanje, username)
    cursor.execute(sql, values)
    mydb.commit()

    if session['privilegija'] != 1:
        return redirect(
            url_for('profil', username = session['username'])
        )

    return redirect(
        url_for('admin_panel', username = session['username'])
    )

@app.route('/logout')
def logout():
    if len(session) != 0:
        drop_session() #Funkcija koja izbacuje login podatke iz sesije
        return redirect(
            url_for('login')
        )
    else:
        return redirect(
            url_for('login')
        )


@app.route('/transakcija/<username>', methods=['POST'])
def transakcija(username):
        izbor = request.form['izbor']
        suma = request.form['suma']

        cursor1 = mydb.cursor(prepared = True)
        sql1 = "SELECT * FROM user WHERE username = ?"
        values1 = (username, )
        cursor1.execute(sql1, values1)

        result1 = cursor1.fetchone()
        result1 = dekodiraj(result1)

        if int(suma) > int(result1[7]):
            return "Nemate toliko novca"

        cursor2 = mydb.cursor(prepared = True)
        sql2 = "SELECT * FROM user WHERE username = ?"
        values2 = (izbor, )
        cursor2.execute(sql2, values2)

        result2 = cursor2.fetchone()
        result2 = dekodiraj(result2)

        update_cursor = mydb.cursor(prepared = True)
        update_sql = "UPDATE user SET stanje = ? WHERE username = ?"
        update_values = (result1[7] - float(suma), username)
        update_cursor.execute(update_sql, update_values)
        mydb.commit()

        update_cursor = mydb.cursor(prepared = True)
        update_sql = "UPDATE user SET stanje = ? WHERE username = ?"
        update_values = (result2[7] + float(suma), izbor)
        update_cursor.execute(update_sql, update_values)
        mydb.commit()

        return 'Transakcija je uspesno obavljena!'



def save_session(username, privilegija):
    session['username'] = username
    session['privilegija'] = privilegija


def drop_session():
    if len(session) > 0:
        session.pop('username')
        session.pop('privilegija')


def dekodiraj(data):
    data = list(data)
    n = len(data)

    for i in range(n):
        if isinstance(data[i], bytearray):
            data[i] = data[i].decode()

    return data

app.run(debug = True)