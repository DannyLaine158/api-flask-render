import sqlite3
import os
import bcrypt

# Ruta donde se guardará la base de datos
db_path = './data/users.db'

# Crea la carpeta si no existe
os.makedirs('./data', exist_ok=True)

# Conexión a sqlite
conn = sqlite3.connect(db_path)
cursor = conn.cursor()

# Creación de tabla
cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )
''')

init_users = [
    ('usuario1', '1234'), # id: 1
    ('fotofan', '1234'), # id: 2
    ('Usuario789', '789'), # id: 3
    ('Daniel', '123456')  # id: 4
]

# Insertar usuarios a la base de datos
for username, password in init_users:

    # Tipo de datos byte
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    cursor.execute('''
        INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)
    ''', (username, hashed_password.decode('utf-8')))

conn.commit()
conn.close()

print("Base de datos y tabla 'users' creadas correctamente")
print("Usuarios iniciales insertados correctamente")