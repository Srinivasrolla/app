import streamlit as st
import sqlite3
import hashlib

# Function to hash passwords (for security)
def hash_password(password):
    return hashlib.sha256(str.encode(password)).hexdigest()

# Function to verify hashed passwords
def verify_password(input_password, stored_password):
    return hash_password(input_password) == stored_password

# Initialize SQLite database
conn = sqlite3.connect('users.db')
c = conn.cursor()

# Create user table if it doesn't exist
def create_table():
    c.execute('CREATE TABLE IF NOT EXISTS users(username TEXT, password TEXT)')
    conn.commit()

# Add new user to the database
def add_user(username, password):
    c.execute('INSERT INTO users(username, password) VALUES (?, ?)', (username, hash_password(password)))
    conn.commit()

# Check if user exists in the database
def check_user(username, password):
    c.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, hash_password(password)))
    return c.fetchone()

# Check if username exists
def username_exists(username):
    c.execute('SELECT * FROM users WHERE username = ?', (username,))
    return c.fetchone()

# Main app logic
def main():
    st.title("User Registration and Login System")

    menu = ["Home", "Login", "Register"]
    choice = st.sidebar.selectbox("Menu", menu)

    create_table()

    if choice == "Home":
        st.subheader("Welcome to the User Registration and Login System")

    elif choice == "Login":
        st.subheader("Login")

        username = st.text_input("Username")
        password = st.text_input("Password", type="password")

        if st.button("Login"):
            user = check_user(username, password)
            if user:
                st.success(f"Welcome {username}!")
            else:
                st.error("Invalid username or password, or you are not registered.")

    elif choice == "Register":
        st.subheader("Register")

        new_user = st.text_input("Username")
        new_password = st.text_input("Password", type="password")

        if st.button("Register"):
            if username_exists(new_user):
                st.error("Username already exists! Please try another.")
            else:
                add_user(new_user, new_password)
                st.success("You have successfully registered! You can now log in.")

if __name__ == '__main__':
    main()
