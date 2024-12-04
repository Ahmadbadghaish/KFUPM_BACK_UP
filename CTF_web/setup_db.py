import sqlite3

def create_database():
    conn = sqlite3.connect('ctf_lab.db')
    cursor = conn.cursor()

    # Create users table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL
    )
    ''')

    # Create files table for memes
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        file_number INTEGER NOT NULL,
        filename TEXT NOT NULL,
        description TEXT
    )
    ''')

    # Insert sample user data
    cursor.executemany('''
    INSERT OR IGNORE INTO users (username, password)
    VALUES (?, ?)
    ''', [
        ('Sean', 'admin123'),
        ('ahmad', 'admin123'),
        ('osama', 'admin123')
    ])  # Replace with hashed password in production.



    # Clear any existing data
    cursor.execute('DELETE FROM files')

    # Insert memes with IDs varying from 0 to 20
    memes = [
        (0, 1, 'meme1.jpg', 'Funny meme 1'),
        (3, 2, 'meme2.jpg', 'Funny meme 2'),
        (5, 3, 'meme3.jpg', 'Funny meme 3'),
        (8, 4, 'meme4.jpg', 'Funny meme 4'),
        (12, 5, 'meme5.jpg', 'Funny meme 5'),
        (15, 6, 'meme6.jpg', 'Funny meme 6'),
        (18, 7, 'meme7.jpg', 'Funny meme 7'),
        (20, 8, 'meme8.jpg', 'Funny meme 8')
    ]

    # Include the `id` column in the query
    cursor.executemany(
        'INSERT OR IGNORE INTO files (id, file_number, filename, description) VALUES (?, ?, ?, ?)', 
        memes
    )

    conn.commit()
    conn.close()
    print("Database setup completed.")

if __name__ == '__main__':
    create_database()
