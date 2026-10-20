def lookup(cursor, name):
    cursor.execute("SELECT * FROM users WHERE name = ?", (name,))
