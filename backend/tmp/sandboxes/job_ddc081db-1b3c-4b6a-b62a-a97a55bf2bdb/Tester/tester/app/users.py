from fastapi import HTTPException

from app.database import get_connection


def get_user_by_username(username: str):
    conn = get_connection()
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor = conn.execute(query)
    row = cursor.fetchone()
    conn.close()
    return row


def get_all_users():
    conn = get_connection()
    cursor = conn.execute("SELECT * FROM users")
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]
